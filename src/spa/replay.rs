//! Replay protection.
//!
//! This is the capability `knockd` cannot have at all — a knock sequence is a
//! cleartext secret and replaying it is trivial — and the one `fwknop` has that
//! we did not. It is deliberately *not* a reimplementation of fwknop's design.
//!
//! fwknop keeps a digest cache on disk (`server/replay_cache.c`) that grows
//! with every packet it has ever accepted. That is durable across restarts, but
//! it is unbounded, it is I/O on the packet path, and pruning it is the
//! operator's problem.
//!
//! Here the timestamp window does the pruning. A packet is only acceptable
//! inside a bounded skew window, so nothing older than that window can ever be
//! replayed successfully, so nothing older than that window needs remembering.
//! Memory is therefore bounded by `accept rate x window`, not by uptime, and
//! there is a hard entry cap on top of that so a flood cannot grow it without
//! limit.
//!
//! Like `matcher`, this takes the current time as a parameter rather than
//! reading the clock, so every expiry and eviction path is deterministically
//! testable without sleeping. That invariant is pinned in `CONTRIBUTING.md`.

use std::collections::{HashMap, VecDeque};

/// Identifier carried in every SPA payload, remembered to detect a replay.
pub type PacketId = [u8; 16];

/// Why a packet was refused on timing or replay grounds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReplayVerdict {
    /// First time seen, and inside the window.
    Fresh,
    /// Exact packet already accepted.
    Replayed,
    /// Sender's clock is far behind ours, or the packet was captured and held.
    TooOld { age_secs: i64 },
    /// Sender's clock is far ahead of ours. Accepting these would let an
    /// attacker bank packets for future use, so they are refused.
    TooNew { skew_secs: i64 },
}

/// Bounded replay guard.
pub struct ReplayGuard {
    /// How far either side of our clock a timestamp may sit.
    window_secs: u64,
    /// Hard cap on remembered ids, independent of the window. Protects memory
    /// when the accept rate is adversarially high.
    max_entries: usize,
    seen: HashMap<PacketId, u64>,
    /// Insertion order, for O(1) amortised eviction. Ids can appear here more
    /// than once only if re-inserted after expiry, which `seen` disambiguates.
    order: VecDeque<(u64, PacketId)>,
}

impl ReplayGuard {
    pub fn new(window_secs: u64, max_entries: usize) -> Self {
        Self {
            window_secs,
            max_entries: max_entries.max(1),
            seen: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Entries currently remembered. Exposed for metrics and for the tests that
    /// assert memory stays bounded.
    pub fn tracked(&self) -> usize {
        self.seen.len()
    }

    /// Check a packet and, if it is fresh, remember it.
    ///
    /// `now_secs` is the server's clock; `stamp_secs` is the sender's claim.
    /// Both are unix seconds. Signed arithmetic throughout: a sender whose
    /// clock is ahead produces a negative age, and computing that in `u64`
    /// would wrap and silently turn a future packet into an ancient one.
    pub fn check(&mut self, id: PacketId, stamp_secs: u64, now_secs: u64) -> ReplayVerdict {
        let age = now_secs as i64 - stamp_secs as i64;
        let window = self.window_secs as i64;

        if age > window {
            return ReplayVerdict::TooOld { age_secs: age };
        }
        if age < -window {
            return ReplayVerdict::TooNew { skew_secs: -age };
        }

        self.expire(now_secs);

        if self.seen.contains_key(&id) {
            return ReplayVerdict::Replayed;
        }

        self.seen.insert(id, stamp_secs);
        self.order.push_back((stamp_secs, id));
        self.enforce_cap();
        ReplayVerdict::Fresh
    }

    /// Drop everything that can no longer be replayed anyway, because its
    /// timestamp has fallen out of the acceptance window.
    fn expire(&mut self, now_secs: u64) {
        let cutoff = now_secs as i64 - self.window_secs as i64;
        while let Some(&(stamp, id)) = self.order.front() {
            if (stamp as i64) < cutoff {
                self.order.pop_front();
                // Only forget it if this is still the live entry for that id.
                if self.seen.get(&id) == Some(&stamp) {
                    self.seen.remove(&id);
                }
            } else {
                break;
            }
        }
    }

    /// Last-resort bound. Evicting the oldest is safe: anything evicted early
    /// is closer to leaving the window than anything retained.
    fn enforce_cap(&mut self) {
        while self.seen.len() > self.max_entries {
            match self.order.pop_front() {
                Some((stamp, id)) => {
                    if self.seen.get(&id) == Some(&stamp) {
                        self.seen.remove(&id);
                    }
                }
                None => break,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> PacketId {
        [n; 16]
    }

    #[test]
    fn accepts_a_fresh_packet_once_and_rejects_the_replay() {
        let mut g = ReplayGuard::new(30, 1000);
        assert_eq!(g.check(id(1), 1_000, 1_000), ReplayVerdict::Fresh);
        assert_eq!(g.check(id(1), 1_000, 1_000), ReplayVerdict::Replayed);
        // A third attempt is still a replay, not accidentally re-armed.
        assert_eq!(g.check(id(1), 1_000, 1_001), ReplayVerdict::Replayed);
    }

    #[test]
    fn distinct_packets_at_the_same_instant_are_all_fresh() {
        let mut g = ReplayGuard::new(30, 1000);
        for n in 0..50u8 {
            assert_eq!(g.check(id(n), 1_000, 1_000), ReplayVerdict::Fresh);
        }
        assert_eq!(g.tracked(), 50);
    }

    #[test]
    fn rejects_a_packet_older_than_the_window() {
        let mut g = ReplayGuard::new(30, 1000);
        assert_eq!(
            g.check(id(1), 1_000, 1_031),
            ReplayVerdict::TooOld { age_secs: 31 }
        );
        // Right on the boundary is still acceptable.
        assert_eq!(g.check(id(2), 1_000, 1_030), ReplayVerdict::Fresh);
    }

    /// A packet timestamped in the future must be refused, not accepted and not
    /// wrapped into a huge positive age. This is the bug that signed arithmetic
    /// exists to prevent.
    #[test]
    fn rejects_a_future_packet_without_integer_wraparound() {
        let mut g = ReplayGuard::new(30, 1000);
        assert_eq!(
            g.check(id(1), 2_000, 1_000),
            ReplayVerdict::TooNew { skew_secs: 1000 }
        );
        assert_eq!(g.check(id(2), 1_030, 1_000), ReplayVerdict::Fresh);
    }

    /// The whole reason the on-disk cache is unnecessary: once a packet's
    /// timestamp leaves the window it is refused on age, so forgetting it is
    /// safe. Memory tracks the window, not uptime.
    #[test]
    fn memory_is_bounded_by_the_window_not_by_uptime() {
        let mut g = ReplayGuard::new(10, 1_000_000);
        for t in 0..10_000u64 {
            assert_eq!(
                g.check(id((t % 251) as u8), 1_000 + t, 1_000 + t),
                ReplayVerdict::Fresh
            );
        }
        // 10 000 accepted packets, but only a window's worth is retained.
        assert!(
            g.tracked() <= 12,
            "expected the window to bound memory, tracked = {}",
            g.tracked()
        );
    }

    /// An expired id can legitimately be reused later — but only because a
    /// packet bearing its old timestamp would now be refused on age anyway.
    #[test]
    fn an_expired_id_is_only_reusable_with_a_fresh_timestamp() {
        let mut g = ReplayGuard::new(10, 1000);
        assert_eq!(g.check(id(1), 1_000, 1_000), ReplayVerdict::Fresh);
        // Same id, new timestamp, much later: fresh.
        assert_eq!(g.check(id(1), 2_000, 2_000), ReplayVerdict::Fresh);
        // The original packet replayed late is refused on age, not on the set.
        assert!(matches!(
            g.check(id(1), 1_000, 2_000),
            ReplayVerdict::TooOld { .. }
        ));
    }

    /// A flood inside one window must not grow memory without limit.
    #[test]
    fn hard_cap_bounds_memory_under_a_same_instant_flood() {
        let mut g = ReplayGuard::new(3600, 64);
        for n in 0..1_000u32 {
            let mut i = [0u8; 16];
            i[..4].copy_from_slice(&n.to_be_bytes());
            g.check(i, 1_000, 1_000);
        }
        assert!(g.tracked() <= 64, "cap breached: {}", g.tracked());
    }
}
