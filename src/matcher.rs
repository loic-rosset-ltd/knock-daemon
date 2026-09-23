//! Concurrent sequence matcher — the core of knock-daemon and its main point of
//! difference from classic `knockd`.
//!
//! `knockd` also partitions by source IP, but keeps at most one in-flight
//! attempt per source per door and destroys it on any packet that isn't the
//! exact next step — including a re-hit of the door's own first port, so a retry
//! or a TCP retransmit silently kills the sequence and starts nothing in its
//! place. Here we track a *set* of live attempts per source and add to it: every
//! hit on a door's first step opens a new candidate beside the running ones, so
//! retries, retransmits and clients sharing one source address (NAT, CGNAT, a
//! jump host) all resolve independently. Overlapping doors sharing a prefix both
//! advance from the same packet.
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
                    let door = a.door;
                    // One packet opens a door once. Several candidates for the
                    // same door can be in flight at the same stage (that is the
                    // point of tracking a set — a retry or a retransmit starts
                    // another one), and the final hit completes all of them.
                    // Report the door once, not once per candidate, so the
                    // firewall command does not run twice for a single knock.
                    if !completed.iter().any(|c: &Completed| c.door == door) {
                        completed.push(Completed { door, src: ev.src });
                    }
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

        // 2b. A door that just opened for this source has no use for its other
        //     in-flight candidates; drop them so a duplicate of the final
        //     packet cannot re-open the same door.
        if !completed.is_empty() {
            entry.retain(|a| !completed.iter().any(|c| c.door == a.door));
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
    fn duplicate_opening_packet_opens_the_door_exactly_once() {
        // A retry or a TCP retransmit of the first step starts a second
        // candidate alongside the first — that is what keeps the knock alive.
        // Both candidates then complete on the same final packet, and the door
        // must still be reported once, or the firewall command runs twice.
        let mut m = Matcher::new(vec![door("ssh", &[7000, 8000, 9000], 10_000)]);
        let src = ip(10);

        assert!(m.process(ev(src, 7000, 0)).is_empty());
        assert!(m.process(ev(src, 7000, 5)).is_empty()); // the duplicate
        assert!(m.process(ev(src, 8000, 10)).is_empty());

        let done = m.process(ev(src, 9000, 15));
        assert_eq!(done.len(), 1, "one packet must open the door once");
        assert_eq!(done[0].door, 0);
        assert_eq!(done[0].src, src);

        // Nothing is left over that a repeat of the final packet could re-open.
        assert!(m.process(ev(src, 9000, 20)).is_empty());
        assert_eq!(m.tracked_sources(), 0);
    }

    /// An **ascending** door sequence is completed by an ordinary ascending
    /// port scan, in both match modes. This is a property of port knocking, not
    /// a bug in this matcher — but it is the reason no example sequence in this
    /// repository is monotonic, and the reason `SECURITY.md` says so out loud.
    /// Kept as a test so that a future edit which "tidies" an example back into
    /// ascending order fails here instead of in someone's threat model.
    fn ascending_sweep(mode: MatchMode, ports: &[u16]) -> bool {
        let mut m = Matcher::with_mode(vec![door("ssh", ports, 10_000)], mode);
        // One source sweeping *every* port in ascending order, a millisecond
        // apart. The full range matters: it means a sequence survives because
        // its ports are out of ascending order, not because the scan stopped
        // short of them. Any three ports are all reached here.
        (1u16..=u16::MAX).any(|port| !m.process(ev(ip(1), port, u64::from(port))).is_empty())
    }

    #[test]
    fn ascending_sequence_falls_to_a_port_scan() {
        assert!(
            ascending_sweep(MatchMode::Tolerant, &[7000, 8000, 9000]),
            "ascending sequence should be completed by an ascending sweep (tolerant)"
        );
        assert!(
            ascending_sweep(MatchMode::Reset, &[7000, 8000, 9000]),
            "ascending sequence should be completed by an ascending sweep (reset) \
             — `reset` is not the safer mode here"
        );
    }

    /// The loopback case from the install rehearsal (finding F-05): on `lo`,
    /// every frame is observed twice — once outbound, once looped back — so the
    /// matcher sees the whole sequence doubled.
    ///
    /// Two different outcomes, both verified against a live daemon on `lo`:
    ///
    /// * **Tolerant** opens the door exactly **once**. A duplicate is just
    ///   another candidate, and the door is reported once per packet with its
    ///   siblings dropped, so a non-idempotent `open_command` runs once.
    /// * **Reset** opens it **zero** times. A second copy of a step is
    ///   indistinguishable from a stray hit to a monitored port, which is
    ///   precisely what `reset` is defined to abort on. This is not a matcher
    ///   bug — it is why the AF_PACKET backend sets `PACKET_IGNORE_OUTGOING`,
    ///   without which a migrated `knockd.conf` (which defaults to `reset`)
    ///   never opens a door on an interface that sees its own traffic.
    #[test]
    fn a_doubled_sequence_opens_once_in_tolerant_and_never_in_reset() {
        let ports = [41953u16, 8271, 22986];
        let opens = |mode| {
            let mut m = Matcher::with_mode(vec![door("ssh", &ports, 10_000)], mode);
            let mut n = 0;
            for (i, &port) in ports.iter().enumerate() {
                let t = (i as u64) * 10;
                n += m.process(ev(ip(1), port, t)).len();
                n += m.process(ev(ip(1), port, t + 2)).len();
            }
            n
        };
        assert_eq!(
            opens(MatchMode::Tolerant),
            1,
            "a doubled sequence must open the door once, not twice"
        );
        assert_eq!(
            opens(MatchMode::Reset),
            0,
            "reset aborts on the duplicate — the capture layer must not deliver it"
        );
    }

    /// `reset` is not the safer mode. Both modes open a fresh candidate whenever
    /// a door's first port is hit, so an attacker who knows *which* three ports a
    /// door uses — but not their order — completes it with one short burst that
    /// covers every ordering. The README says this; this test is why it may.
    ///
    /// The burst is the 9-symbol superpermutation of three symbols,
    /// `1 2 3 1 2 1 3 2 1`, which contains all six permutations as substrings.
    #[test]
    fn known_port_set_falls_to_one_burst_in_both_modes() {
        const SUPERPERM: [usize; 9] = [0, 1, 2, 0, 1, 0, 2, 1, 0];
        let ports = [41953u16, 8271, 22986];

        // All six orderings of the same three ports.
        let orderings = [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ];

        for mode in [MatchMode::Tolerant, MatchMode::Reset] {
            for order in orderings {
                let secret: Vec<u16> = order.iter().map(|&i| ports[i]).collect();
                let mut m = Matcher::with_mode(vec![door("ssh", &secret, 10_000)], mode);
                let opened = SUPERPERM
                    .iter()
                    .enumerate()
                    .any(|(t, &i)| !m.process(ev(ip(1), ports[i], t as u64)).is_empty());
                assert!(
                    opened,
                    "9-packet burst should open {secret:?} in {mode:?} — knowing the \
                     port set, not the order, is enough in either mode"
                );
            }
        }
    }

    #[test]
    fn non_monotonic_sequence_survives_a_port_scan() {
        // The shape every example in this repo now uses. All three ports are
        // hit by the sweep above — 8271, then 22986, then 41953 — but the
        // door's *first* step is the highest, so it is reached only after the
        // steps that would have followed it. A monotonic scan cannot walk a
        // non-monotonic sequence in order, whatever its range.
        for mode in [MatchMode::Tolerant, MatchMode::Reset] {
            assert!(
                !ascending_sweep(mode, &[41953, 8271, 22986]),
                "non-monotonic sequence must not be completed by an ascending sweep ({mode:?})"
            );
        }
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
