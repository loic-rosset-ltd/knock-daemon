//! Per-source-IP rate limiting.
//!
//! A hostile source can flood the daemon with packets to a door's opening port,
//! each one starting a fresh in-flight attempt. The matcher already bounds state
//! per IP (`MAX_ATTEMPTS_PER_IP`), but processing every packet still costs CPU and
//! can be used to drown out legitimate knocks. A rate limiter sheds that load
//! early: a source that exceeds its budget has further packets dropped before they
//! reach the matcher at all.
//!
//! The limiter is a clock-injected token bucket, in the same spirit as the
//! matcher: it never reads the wall clock itself, it is handed the same monotonic
//! millisecond timestamp the capture layer stamps on each packet. That keeps it
//! pure and fully unit-testable without sleeps. One bucket per source IP gives
//! each client an independent budget — a flood from one address can't starve
//! another's knock. Because sources are independent, a limiter lives entirely
//! inside a single matcher shard with no cross-shard coordination.

use std::collections::HashMap;
use std::net::IpAddr;

/// One source's token bucket: a fractional token count and when it was last
/// refilled. A fresh bucket starts full, so a brand-new source gets its whole
/// burst immediately.
#[derive(Clone, Copy)]
struct Bucket {
    tokens: f64,
    last_ms: u64,
}

/// A per-source token-bucket rate limiter.
///
/// Each source is allowed a burst of `capacity` packets and then refills at
/// `refill_per_ms` tokens per millisecond (i.e. a sustained rate of
/// `refill_per_ms * 1000` packets/second). The bucket map is bounded at
/// `max_tracked` so the limiter can't itself become a memory-exhaustion vector;
/// when full, the least-recently-active source is evicted (it fails open, which
/// is the benign direction — an idle source gets a fresh full budget).
pub struct RateLimiter {
    capacity: f64,
    refill_per_ms: f64,
    max_tracked: usize,
    buckets: HashMap<IpAddr, Bucket>,
}

impl RateLimiter {
    /// Build a limiter allowing a burst of `capacity` packets per source,
    /// refilling at `refill_per_ms` tokens/ms. `capacity` is clamped to at least
    /// 1 so a single packet can always pass.
    pub fn new(capacity: f64, refill_per_ms: f64, max_tracked: usize) -> Self {
        Self {
            capacity: capacity.max(1.0),
            refill_per_ms: refill_per_ms.max(0.0),
            max_tracked: max_tracked.max(1),
            buckets: HashMap::new(),
        }
    }

    /// Charge one packet from `src` observed at `at_ms`. Returns `true` if the
    /// packet is within budget (and should be processed), `false` if the source
    /// is over its rate (and the packet should be dropped).
    pub fn allow(&mut self, src: IpAddr, at_ms: u64) -> bool {
        let capacity = self.capacity;
        let refill = self.refill_per_ms;

        if !self.buckets.contains_key(&src) {
            self.evict_if_full(src);
        }

        let bucket = self.buckets.entry(src).or_insert(Bucket {
            tokens: capacity,
            last_ms: at_ms,
        });

        // Refill for the elapsed time, capped at capacity. `saturating_sub`
        // tolerates out-of-order timestamps (treats them as zero elapsed).
        let elapsed = at_ms.saturating_sub(bucket.last_ms);
        bucket.tokens = (bucket.tokens + elapsed as f64 * refill).min(capacity);
        bucket.last_ms = at_ms;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Number of sources currently holding a bucket. Exposed for tests/stats.
    #[cfg(test)]
    pub fn tracked(&self) -> usize {
        self.buckets.len()
    }

    /// If the map is at capacity and `incoming` would be a new entry, drop the
    /// least-recently-active source to make room.
    fn evict_if_full(&mut self, incoming: IpAddr) {
        if self.buckets.len() < self.max_tracked || self.buckets.contains_key(&incoming) {
            return;
        }
        if let Some(victim) = self
            .buckets
            .iter()
            .min_by_key(|(_, b)| b.last_ms)
            .map(|(ip, _)| *ip)
        {
            self.buckets.remove(&victim);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
    }

    #[test]
    fn allows_a_full_burst_then_throttles() {
        // capacity 3, no refill: exactly 3 packets pass, the 4th is dropped.
        let mut rl = RateLimiter::new(3.0, 0.0, 1024);
        assert!(rl.allow(ip(1), 0));
        assert!(rl.allow(ip(1), 0));
        assert!(rl.allow(ip(1), 0));
        assert!(!rl.allow(ip(1), 0));
    }

    #[test]
    fn refills_over_time() {
        // capacity 1, 1 token per 1000ms (1/s). After draining, a packet 1s later
        // is allowed again; one just before is not.
        let mut rl = RateLimiter::new(1.0, 1.0 / 1000.0, 1024);
        assert!(rl.allow(ip(1), 0));
        assert!(!rl.allow(ip(1), 999));
        assert!(rl.allow(ip(1), 1000));
    }

    #[test]
    fn sources_are_independent() {
        // One source flooding doesn't consume another's budget.
        let mut rl = RateLimiter::new(1.0, 0.0, 1024);
        assert!(rl.allow(ip(1), 0));
        assert!(!rl.allow(ip(1), 0)); // .1 is now throttled
        assert!(rl.allow(ip(2), 0)); // .2 still has its full budget
    }

    #[test]
    fn bounds_tracked_sources() {
        // With room for only 2 sources, a third evicts the oldest rather than
        // growing the map without limit.
        let mut rl = RateLimiter::new(5.0, 0.0, 2);
        rl.allow(ip(1), 0);
        rl.allow(ip(2), 10);
        rl.allow(ip(3), 20); // evicts ip(1) (oldest last_ms)
        assert_eq!(rl.tracked(), 2);
        // ip(1) was evicted, so it fails open with a fresh full bucket.
        assert!(rl.allow(ip(1), 30));
    }

    #[test]
    fn capacity_is_floored_at_one() {
        // A nonsensical sub-1 capacity still lets a single packet through.
        let mut rl = RateLimiter::new(0.0, 0.0, 16);
        assert!(rl.allow(ip(1), 0));
    }
}
