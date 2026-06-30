//! Concurrent sequence matcher — the core of knock-daemon and its main point of
//! difference from classic `knockd`.
//!
//! `knockd` walks packets through a single global set of door state machines and
//! gets confused when several clients knock at once, or when doors share ports.
//! Here, in-flight progress is partitioned **per source IP**, and within an IP we
//! track an independent attempt for every door. Because each source is isolated,
//! simultaneous sequences from different clients never interfere, and overlapping
//! doors (sharing a prefix) both advance from the same packet.
//!
//! The matcher is deliberately pure: it takes a logical millisecond timestamp on
//! each event rather than reading the clock, so its behaviour is fully
//! deterministic and unit-testable without real packets or sleeps.

use std::collections::HashMap;
use std::net::IpAddr;

/// Transport protocol a knock step is sent over.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Proto {
    Tcp,
    Udp,
}

/// How the matcher treats an out-of-order hit to a port the door cares about.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum MatchMode {
    /// Default: a stray hit never derails an in-flight attempt; correctness
    /// leans on `seq_timeout`. More robust to background noise and concurrency.
    #[default]
    Tolerant,
    /// knockd parity: a hit to one of the door's own sequence ports that isn't
    /// the next expected step aborts that attempt (the classic reset-on-stray).
    Reset,
}

/// A single expected hit in a door's sequence: a port on a given protocol.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct PortSpec {
    pub port: u16,
    pub proto: Proto,
}

/// A door: an ordered port sequence that, when completed in time, fires an action.
#[derive(Clone, Debug)]
pub struct DoorSpec {
    pub name: String,
    pub sequence: Vec<PortSpec>,
    /// Maximum wall-clock time (ms) from the first hit to the last for the whole
    /// sequence to count. Mirrors knockd's `seq_timeout`.
    pub seq_timeout_ms: u64,
}

/// An observed packet relevant to knocking, normalised by the capture layer.
#[derive(Clone, Copy, Debug)]
pub struct PacketEvent {
    pub src: IpAddr,
    pub port: u16,
    pub proto: Proto,
    /// Monotonic logical timestamp in milliseconds.
    pub at_ms: u64,
}

/// A completed door for a given source IP, emitted by [`Matcher::process`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Completed {
    pub door: usize,
    pub src: IpAddr,
}

/// One in-flight attempt at a single door from a single source IP.
#[derive(Clone, Copy, Debug)]
struct Attempt {
    door: usize,
    /// Index of the next expected step in the door's sequence.
    stage: usize,
    started_ms: u64,
}

/// Per-IP attempt cap. A misbehaving or hostile source can otherwise spawn an
/// unbounded number of partial attempts (one per packet to any door's first
/// port). Bounding state per source keeps the daemon's memory predictable; the
/// oldest attempts are dropped first.
const MAX_ATTEMPTS_PER_IP: usize = 256;

pub struct Matcher {
    doors: Vec<DoorSpec>,
    inflight: HashMap<IpAddr, Vec<Attempt>>,
    mode: MatchMode,
}

impl Matcher {
    /// Build a matcher with the default [`MatchMode::Tolerant`] policy.
    #[allow(dead_code)] // convenience constructor used by tests; runtime uses `with_mode`
    pub fn new(doors: Vec<DoorSpec>) -> Self {
        Self::with_mode(doors, MatchMode::Tolerant)
    }

    /// Build a matcher with an explicit out-of-order policy.
    pub fn with_mode(doors: Vec<DoorSpec>, mode: MatchMode) -> Self {
        Self {
            doors,
            inflight: HashMap::new(),
            mode,
        }
    }

    /// Number of source IPs with at least one in-flight attempt. Exposed for
    /// observability and tests.
    #[allow(dead_code)] // consumed by tests today; reserved for a future stats endpoint
    pub fn tracked_sources(&self) -> usize {
        self.inflight.len()
    }

    /// Feed one observed packet. Returns every door that this packet completed
    /// for the packet's source IP (usually zero, occasionally one, rarely more
    /// when overlapping doors finish on the same hit).
    pub fn process(&mut self, ev: PacketEvent) -> Vec<Completed> {
        // Split the borrow: `doors`/`mode` are read-only while we mutate one IP's bucket.
        let doors = &self.doors;
        let mode = self.mode;
        let entry = self.inflight.entry(ev.src).or_default();

        // 1. Reap attempts whose whole-sequence timeout has elapsed.
        entry.retain(|a| ev.at_ms.saturating_sub(a.started_ms) <= doors[a.door].seq_timeout_ms);

        let mut completed = Vec::new();

        // 2. Advance existing attempts whose next expected step matches this hit.
        let mut i = 0;
        while i < entry.len() {
            let a = &mut entry[i];
            let seq = &doors[a.door].sequence;
            let expected = seq[a.stage];
            if expected.port == ev.port && expected.proto == ev.proto {
                a.stage += 1;
                if a.stage == seq.len() {
                    completed.push(Completed {
                        door: a.door,
                        src: ev.src,
                    });
                    entry.remove(i);
                    continue; // don't advance `i`; the next element shifted down
                }
            } else if mode == MatchMode::Reset
                && seq.iter().any(|p| p.port == ev.port && p.proto == ev.proto)
            {
                // knockd parity: a monitored-but-out-of-order hit aborts this
                // attempt. (A fresh hit to the door's *first* step still opens a
                // new candidate in step 3, so the client effectively restarts.)
                entry.remove(i);
                continue;
            }
            i += 1;
        }

        // 3. Open a fresh attempt for every door whose first step matches. This
        //    is what lets retries and interleaved sequences coexist: a stray hit
        //    to a door's opening port starts a new candidate rather than
        //    corrupting an in-flight one.
        for (di, d) in doors.iter().enumerate() {
            match d.sequence.first() {
                Some(p) if p.port == ev.port && p.proto == ev.proto => {
                    if d.sequence.len() == 1 {
                        // Single-step door completes immediately.
                        completed.push(Completed {
                            door: di,
                            src: ev.src,
                        });
                    } else {
                        entry.push(Attempt {
                            door: di,
                            stage: 1,
                            started_ms: ev.at_ms,
                        });
                    }
                }
                _ => {}
            }
        }

        // 4. Bound per-IP state; drop the oldest attempts beyond the cap.
        if entry.len() > MAX_ATTEMPTS_PER_IP {
            let overflow = entry.len() - MAX_ATTEMPTS_PER_IP;
            entry.drain(0..overflow);
        }

        if entry.is_empty() {
            self.inflight.remove(&ev.src);
        }

        completed
    }
}

/// Map a source IP to one of `n_shards` matcher shards.
///
/// Because matching state is partitioned per source IP, a source can be handled
/// by *any* shard as long as it always lands on the **same** one — so the routing
/// only has to be deterministic. A fixed-seed hash gives that without a clock or
/// randomness, keeping the choice reproducible across runs and in tests. `n_shards`
/// is treated as at least 1.
pub fn shard_for(src: &IpAddr, n_shards: usize) -> usize {
    use std::hash::{Hash, Hasher};
    let n = n_shards.max(1) as u64;
    // DefaultHasher::new() uses fixed keys, so this is deterministic across
    // processes (unlike RandomState) — important for a stable shard mapping.
    let mut h = std::collections::hash_map::DefaultHasher::new();
    src.hash(&mut h);
    (h.finish() % n) as usize
}

/// A matcher partitioned into independent shards by source IP.
///
/// Each shard is a self-contained [`Matcher`]; a source always routes to the same
/// shard via [`shard_for`], so the shards share no state and need no coordination.
/// This is the data model behind multi-worker matching: the runtime can drive each
/// shard from its own thread (see `main.rs`), and because the partition is by
/// source, the per-source isolation guarantee is preserved exactly. Used directly
/// (single-threaded) for the `--demo` pipeline and to prove the routing in tests.
pub struct ShardedMatcher {
    shards: Vec<Matcher>,
}

impl ShardedMatcher {
    /// Build `n_shards` (at least 1) shards, each a full matcher over `doors`.
    pub fn new(doors: Vec<DoorSpec>, mode: MatchMode, n_shards: usize) -> Self {
        let n = n_shards.max(1);
        let shards = (0..n)
            .map(|_| Matcher::with_mode(doors.clone(), mode))
            .collect();
        Self { shards }
    }

    /// Route a packet to its source's shard and process it there.
    pub fn process(&mut self, ev: PacketEvent) -> Vec<Completed> {
        let s = shard_for(&ev.src, self.shards.len());
        self.shards[s].process(ev)
    }

    /// Total source IPs with in-flight attempts across all shards.
    #[allow(dead_code)] // reserved for the stats endpoint when run single-sharded
    pub fn tracked_sources(&self) -> usize {
        self.shards.iter().map(|m| m.tracked_sources()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
    }

    fn tcp(port: u16) -> PortSpec {
        PortSpec {
            port,
            proto: Proto::Tcp,
        }
    }

    fn door(name: &str, ports: &[u16], timeout: u64) -> DoorSpec {
        DoorSpec {
            name: name.into(),
            sequence: ports.iter().map(|&p| tcp(p)).collect(),
            seq_timeout_ms: timeout,
        }
    }

    fn ev(src: IpAddr, port: u16, at_ms: u64) -> PacketEvent {
        PacketEvent {
            src,
            port,
            proto: Proto::Tcp,
            at_ms,
        }
    }

    #[test]
    fn completes_a_simple_sequence() {
        let mut m = Matcher::new(vec![door("ssh", &[7000, 8000, 9000], 10_000)]);
        assert!(m.process(ev(ip(1), 7000, 0)).is_empty());
        assert!(m.process(ev(ip(1), 8000, 100)).is_empty());
        let done = m.process(ev(ip(1), 9000, 200));
        assert_eq!(
            done,
            vec![Completed {
                door: 0,
                src: ip(1)
            }]
        );
        // State is cleaned up once the door fires.
        assert_eq!(m.tracked_sources(), 0);
    }

    #[test]
    fn wrong_port_does_not_reset_but_timeout_does() {
        let mut m = Matcher::new(vec![door("ssh", &[7000, 8000, 9000], 10_000)]);
        m.process(ev(ip(1), 7000, 0));
        // Noise to an unrelated port is ignored; the attempt survives.
        m.process(ev(ip(1), 1234, 50));
        m.process(ev(ip(1), 8000, 100));
        assert_eq!(
            m.process(ev(ip(1), 9000, 200)),
            vec![Completed {
                door: 0,
                src: ip(1)
            }]
        );
    }

    #[test]
    fn sequence_expires_after_timeout() {
        let mut m = Matcher::new(vec![door("ssh", &[7000, 8000, 9000], 1_000)]);
        m.process(ev(ip(1), 7000, 0));
        m.process(ev(ip(1), 8000, 500));
        // Final hit arrives after seq_timeout from the first hit → no match.
        assert!(m.process(ev(ip(1), 9000, 1_500)).is_empty());
    }

    #[test]
    fn concurrent_sources_do_not_interfere() {
        // The defining knockd failure: two clients knocking the same door at the
        // same time, fully interleaved. Both must succeed independently.
        let mut m = Matcher::new(vec![door("ssh", &[7000, 8000, 9000], 10_000)]);
        m.process(ev(ip(1), 7000, 0));
        m.process(ev(ip(2), 7000, 10));
        m.process(ev(ip(2), 8000, 20));
        m.process(ev(ip(1), 8000, 30));
        assert_eq!(
            m.process(ev(ip(1), 9000, 40)),
            vec![Completed {
                door: 0,
                src: ip(1)
            }]
        );
        assert_eq!(
            m.process(ev(ip(2), 9000, 50)),
            vec![Completed {
                door: 0,
                src: ip(2)
            }]
        );
    }

    #[test]
    fn overlapping_doors_both_advance() {
        // Two doors sharing a prefix; one packet drives both candidates forward.
        let mut m = Matcher::new(vec![
            door("a", &[7000, 8000], 10_000),
            door("b", &[7000, 9000], 10_000),
        ]);
        m.process(ev(ip(1), 7000, 0));
        assert_eq!(
            m.process(ev(ip(1), 8000, 10)),
            vec![Completed {
                door: 0,
                src: ip(1)
            }]
        );
        assert_eq!(
            m.process(ev(ip(1), 9000, 20)),
            vec![Completed {
                door: 1,
                src: ip(1)
            }]
        );
    }

    #[test]
    fn single_step_door_fires_immediately() {
        let mut m = Matcher::new(vec![door("ping", &[12345], 1_000)]);
        assert_eq!(
            m.process(ev(ip(1), 12345, 0)),
            vec![Completed {
                door: 0,
                src: ip(1)
            }]
        );
        assert_eq!(m.tracked_sources(), 0);
    }

    #[test]
    fn reset_mode_aborts_on_out_of_order_monitored_hit() {
        // knockd parity: hitting another of the door's own ports out of order
        // derails the attempt. 7000 → 9000 (skips 8000) → 8000 → 9000 must fail.
        let mut m = Matcher::with_mode(
            vec![door("ssh", &[7000, 8000, 9000], 10_000)],
            MatchMode::Reset,
        );
        m.process(ev(ip(1), 7000, 0));
        m.process(ev(ip(1), 9000, 10)); // out of order, monitored → reset, no new attempt
        m.process(ev(ip(1), 8000, 20));
        assert!(m.process(ev(ip(1), 9000, 30)).is_empty());
        assert_eq!(m.tracked_sources(), 0);
    }

    #[test]
    fn reset_mode_ignores_unrelated_noise() {
        // A hit to a port the door doesn't use is still tolerated, even in Reset
        // mode — only the door's own ports reset it.
        let mut m = Matcher::with_mode(
            vec![door("ssh", &[7000, 8000, 9000], 10_000)],
            MatchMode::Reset,
        );
        m.process(ev(ip(1), 7000, 0));
        m.process(ev(ip(1), 1234, 10)); // unrelated noise
        m.process(ev(ip(1), 8000, 20));
        assert_eq!(
            m.process(ev(ip(1), 9000, 30)),
            vec![Completed {
                door: 0,
                src: ip(1)
            }]
        );
    }

    #[test]
    fn reset_mode_lets_a_restart_succeed() {
        // Re-hitting the first port restarts the sequence: 7000,7000,8000,9000 ok.
        let mut m = Matcher::with_mode(
            vec![door("ssh", &[7000, 8000, 9000], 10_000)],
            MatchMode::Reset,
        );
        m.process(ev(ip(1), 7000, 0));
        m.process(ev(ip(1), 7000, 10)); // resets the first attempt, opens a fresh one
        m.process(ev(ip(1), 8000, 20));
        assert_eq!(
            m.process(ev(ip(1), 9000, 30)),
            vec![Completed {
                door: 0,
                src: ip(1)
            }]
        );
    }

    #[test]
    fn sharding_matches_a_single_matcher() {
        // Sharding must not change *which* knocks complete: the per-source
        // partition is transparent. Run an interleaved multi-source stream
        // through one matcher and through a 4-shard sharded matcher; the streams
        // of completions must be identical.
        let doors = vec![
            door("ssh", &[7000, 8000, 9000], 10_000),
            door("admin", &[7000, 8500], 10_000),
        ];
        let events = [
            (ip(1), 7000, 0),
            (ip(2), 7000, 5),
            (ip(3), 7000, 8),
            (ip(2), 8500, 12), // ip(2) completes "admin"
            (ip(1), 8000, 18),
            (ip(3), 8000, 20),
            (ip(1), 9000, 25), // ip(1) completes "ssh"
            (ip(4), 1234, 26), // noise from a fresh source
            (ip(3), 9000, 30), // ip(3) completes "ssh"
        ];

        let mut single = Matcher::new(doors.clone());
        let mut sharded = ShardedMatcher::new(doors, MatchMode::Tolerant, 4);
        for &(src, port, t) in &events {
            assert_eq!(
                single.process(ev(src, port, t)),
                sharded.process(ev(src, port, t))
            );
        }
    }

    #[test]
    fn sharded_sources_are_isolated() {
        // Two clients on the same door, interleaved, must both succeed even when
        // spread across shards — the multi-worker analogue of the single-matcher
        // concurrency test.
        let mut m = ShardedMatcher::new(
            vec![door("ssh", &[7000, 8000, 9000], 10_000)],
            MatchMode::Tolerant,
            8,
        );
        m.process(ev(ip(1), 7000, 0));
        m.process(ev(ip(2), 7000, 10));
        m.process(ev(ip(2), 8000, 20));
        m.process(ev(ip(1), 8000, 30));
        assert_eq!(
            m.process(ev(ip(1), 9000, 40)),
            vec![Completed {
                door: 0,
                src: ip(1)
            }]
        );
        assert_eq!(
            m.process(ev(ip(2), 9000, 50)),
            vec![Completed {
                door: 0,
                src: ip(2)
            }]
        );
        assert_eq!(m.tracked_sources(), 0);
    }

    #[test]
    fn shard_for_is_deterministic_and_in_range() {
        for n in [1usize, 2, 4, 7, 16] {
            for octet in 0..32u8 {
                let s = shard_for(&ip(octet), n);
                assert!(s < n);
                // Stable across calls.
                assert_eq!(s, shard_for(&ip(octet), n));
            }
        }
        // n_shards = 0 is treated as 1.
        assert_eq!(shard_for(&ip(1), 0), 0);
    }

    #[test]
    fn tolerant_mode_survives_out_of_order_monitored_hit() {
        // The same sequence the Reset test rejects succeeds under the default
        // policy, because a stray monitored hit doesn't derail the attempt.
        let mut m = Matcher::new(vec![door("ssh", &[7000, 8000, 9000], 10_000)]);
        m.process(ev(ip(1), 7000, 0));
        m.process(ev(ip(1), 9000, 10));
        m.process(ev(ip(1), 8000, 20));
        assert_eq!(
            m.process(ev(ip(1), 9000, 30)),
            vec![Completed {
                door: 0,
                src: ip(1)
            }]
        );
    }
}
