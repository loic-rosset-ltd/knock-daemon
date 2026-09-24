//! Runtime counters and a tiny observability endpoint.
//!
//! [`Stats`] is a bag of atomic counters the capture/match/act pipeline bumps as
//! it runs; it is shared (`Arc`) across every worker shard and the optional HTTP
//! endpoint thread. Counters use `Relaxed` ordering — they're monotonic tallies
//! with no happens-before relationship to protect, so the cheapest ordering is
//! correct.
//!
//! [`serve`] exposes a snapshot in Prometheus text-exposition format over a
//! minimal HTTP/1.1 listener, so `curl http://<addr>/metrics` or a Prometheus
//! scrape Just Works. The socket plumbing is thin and, like the capture and
//! nftables backends, isn't exercised in CI; the value-producing part — the
//! [`render`] formatter — is pure and unit-tested.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

use anyhow::{Context, Result};

/// Process-wide pipeline counters.
pub struct Stats {
    packets_observed: AtomicU64,
    packets_rate_limited: AtomicU64,
    knocks_accepted: AtomicU64,
    spa_observed: AtomicU64,
    spa_accepted: AtomicU64,
    spa_rejected: AtomicU64,
    spa_replay_tracked: AtomicU64,
    /// Cumulative AF_PACKET `tp_packets` — frames that passed the cBPF prefilter
    /// and reached the socket (the kernel's total; per `packet(7)` it includes
    /// any then dropped for a full buffer). Fed by the capture backend via
    /// [`Stats::add_kernel_stats`]; zero on non-AF_PACKET builds.
    kernel_packets: AtomicU64,
    /// Cumulative AF_PACKET `tp_drops` — the subset of the above the kernel then
    /// dropped because the socket's receive buffer was full.
    kernel_drops: AtomicU64,
    /// Per-door accepted-knock counts, indexed by door position in the config.
    per_door_accepted: Vec<AtomicU64>,
    /// Door names, parallel to `per_door_accepted`, for metric labels.
    door_names: Vec<String>,
    /// Each shard publishes its current tracked-source count here; the gauge is
    /// the sum. One slot per shard so workers never contend on a shared counter.
    tracked_per_shard: Vec<AtomicUsize>,
}

impl Stats {
    /// Build counters for the given door names and shard count.
    pub fn new(door_names: Vec<String>, shards: usize) -> Self {
        let per_door_accepted = door_names.iter().map(|_| AtomicU64::new(0)).collect();
        let tracked_per_shard = (0..shards.max(1)).map(|_| AtomicUsize::new(0)).collect();
        Self {
            packets_observed: AtomicU64::new(0),
            packets_rate_limited: AtomicU64::new(0),
            knocks_accepted: AtomicU64::new(0),
            spa_observed: AtomicU64::new(0),
            spa_accepted: AtomicU64::new(0),
            spa_rejected: AtomicU64::new(0),
            spa_replay_tracked: AtomicU64::new(0),
            kernel_packets: AtomicU64::new(0),
            kernel_drops: AtomicU64::new(0),
            per_door_accepted,
            door_names,
            tracked_per_shard,
        }
    }

    /// Count one packet handed to the pipeline by the capture layer.
    pub fn record_observed(&self) {
        self.packets_observed.fetch_add(1, Ordering::Relaxed);
    }

    /// Count one packet dropped by the rate limiter before matching.
    pub fn record_rate_limited(&self) {
        self.packets_rate_limited.fetch_add(1, Ordering::Relaxed);
    }

    /// Count one accepted knock for the door at `door_idx`.
    pub fn record_accepted(&self, door_idx: usize) {
        self.knocks_accepted.fetch_add(1, Ordering::Relaxed);
        if let Some(c) = self.per_door_accepted.get(door_idx) {
            c.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// An SPA datagram reached the verifier. Counted separately from
    /// `record_observed`, which means "knock packets seen" and would otherwise
    /// silently change meaning.
    pub fn record_spa_observed(&self) {
        self.spa_observed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_spa_accepted(&self) {
        self.spa_accepted.fetch_add(1, Ordering::Relaxed);
    }

    /// One rejected SPA packet. The *reason* goes to the log rather than to a
    /// label: a per-reason metric would let anyone who can reach `/metrics`
    /// learn which of their guesses got furthest, which is a scoreboard for an
    /// attacker.
    pub fn record_spa_rejected(&self) {
        self.spa_rejected.fetch_add(1, Ordering::Relaxed);
    }

    /// Current size of the replay table. Exported as a gauge because "memory is
    /// bounded by the timestamp window, not by uptime" is a design claim, and a
    /// gauge is how an operator confirms it rather than trusting it.
    pub fn set_spa_replay_tracked(&self, n: usize) {
        self.spa_replay_tracked.store(n as u64, Ordering::Relaxed);
    }

    /// Fold in a kernel-side capture-stats sample. `packets`/`drops` are the
    /// deltas since the previous sample — AF_PACKET's `PACKET_STATISTICS`
    /// getsockopt is read-and-reset, so the backend reports increments, not
    /// absolute totals.
    // Only the AF_PACKET backend feeds this; suppress the unused warning where
    // that backend isn't compiled (the trait impl below still forwards to it).
    #[cfg_attr(
        not(all(target_os = "linux", feature = "capture-afpacket")),
        allow(dead_code)
    )]
    pub fn add_kernel_stats(&self, packets: u64, drops: u64) {
        self.kernel_packets.fetch_add(packets, Ordering::Relaxed);
        self.kernel_drops.fetch_add(drops, Ordering::Relaxed);
    }

    /// Publish shard `shard`'s current in-flight source count.
    pub fn set_tracked(&self, shard: usize, n: usize) {
        if let Some(slot) = self.tracked_per_shard.get(shard) {
            slot.store(n, Ordering::Relaxed);
        }
    }

    /// Take a consistent-enough point-in-time copy for rendering.
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            packets_observed: self.packets_observed.load(Ordering::Relaxed),
            packets_rate_limited: self.packets_rate_limited.load(Ordering::Relaxed),
            knocks_accepted: self.knocks_accepted.load(Ordering::Relaxed),
            spa_observed: self.spa_observed.load(Ordering::Relaxed),
            spa_accepted: self.spa_accepted.load(Ordering::Relaxed),
            spa_rejected: self.spa_rejected.load(Ordering::Relaxed),
            spa_replay_tracked: self.spa_replay_tracked.load(Ordering::Relaxed),
            kernel_packets: self.kernel_packets.load(Ordering::Relaxed),
            kernel_drops: self.kernel_drops.load(Ordering::Relaxed),
            per_door: self
                .door_names
                .iter()
                .zip(&self.per_door_accepted)
                .map(|(name, c)| (name.clone(), c.load(Ordering::Relaxed)))
                .collect(),
            tracked_sources: self
                .tracked_per_shard
                .iter()
                .map(|s| s.load(Ordering::Relaxed))
                .sum(),
        }
    }
}

/// An immutable copy of the counters, decoupled from the atomics so [`render`]
/// can be a pure function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub packets_observed: u64,
    pub packets_rate_limited: u64,
    pub knocks_accepted: u64,
    pub spa_observed: u64,
    pub spa_accepted: u64,
    pub spa_rejected: u64,
    pub spa_replay_tracked: u64,
    pub kernel_packets: u64,
    pub kernel_drops: u64,
    pub per_door: Vec<(String, u64)>,
    pub tracked_sources: usize,
}

/// Render a snapshot as Prometheus text-exposition format.
pub fn render(s: &Snapshot) -> String {
    let mut out = String::new();
    let counter = |out: &mut String, name: &str, help: &str, value: u64| {
        out.push_str(&format!("# HELP {name} {help}\n"));
        out.push_str(&format!("# TYPE {name} counter\n"));
        out.push_str(&format!("{name} {value}\n"));
    };

    counter(
        &mut out,
        "knockd2_packets_observed_total",
        "Packets handed to the matcher by the capture layer.",
        s.packets_observed,
    );
    counter(
        &mut out,
        "knockd2_packets_rate_limited_total",
        "Packets dropped by the per-source rate limiter before matching.",
        s.packets_rate_limited,
    );
    counter(
        &mut out,
        "knockd2_knocks_accepted_total",
        "Completed knock sequences across all doors.",
        s.knocks_accepted,
    );
    counter(
        &mut out,
        "knockd2_spa_observed_total",
        "SPA datagrams handed to the verifier by the capture layer.",
        s.spa_observed,
    );
    counter(
        &mut out,
        "knockd2_spa_accepted_total",
        "SPA packets that passed every check and opened a door.",
        s.spa_accepted,
    );
    counter(
        &mut out,
        "knockd2_spa_rejected_total",
        "SPA packets refused. Deliberately not broken down by reason: that would tell anyone who can read /metrics which of their guesses got furthest.",
        s.spa_rejected,
    );
    out.push_str("# HELP knockd2_spa_replay_tracked Packet ids currently remembered for replay detection; bounded by the timestamp window, not by uptime.\n");
    out.push_str("# TYPE knockd2_spa_replay_tracked gauge\n");
    out.push_str(&format!(
        "knockd2_spa_replay_tracked {}\n",
        s.spa_replay_tracked
    ));
    counter(
        &mut out,
        "knockd2_afpacket_kernel_packets_total",
        "Frames that passed the AF_PACKET cBPF prefilter and reached the socket (kernel tp_packets; includes any then buffer-dropped).",
        s.kernel_packets,
    );
    counter(
        &mut out,
        "knockd2_afpacket_kernel_drops_total",
        "Frames dropped by the kernel after the prefilter because the socket receive buffer was full (tp_drops).",
        s.kernel_drops,
    );

    out.push_str("# HELP knockd2_door_accepted_total Completed knocks per door.\n");
    out.push_str("# TYPE knockd2_door_accepted_total counter\n");
    for (name, value) in &s.per_door {
        out.push_str(&format!(
            "knockd2_door_accepted_total{{door=\"{}\"}} {value}\n",
            escape_label(name)
        ));
    }

    out.push_str(
        "# HELP knockd2_tracked_sources Source IPs with at least one in-flight attempt.\n",
    );
    out.push_str("# TYPE knockd2_tracked_sources gauge\n");
    out.push_str(&format!("knockd2_tracked_sources {}\n", s.tracked_sources));

    out
}

/// Escape a Prometheus label value: backslash, double-quote, and newline.
fn escape_label(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Bind `addr` and serve metric snapshots over a minimal HTTP/1.1 listener in a
/// background thread. Returns once the socket is bound (so a bind failure is
/// reported synchronously); the accept loop then runs until the process exits.
pub fn serve(addr: &str, stats: Arc<Stats>) -> Result<()> {
    let listener =
        TcpListener::bind(addr).with_context(|| format!("binding stats endpoint on {addr}"))?;
    tracing::info!(%addr, "stats endpoint listening (GET /metrics)");
    spawn_accept_loop(listener, stats);
    Ok(())
}

/// Serve connections from an already-bound listener until it errors/closes.
/// Split out from [`serve`] so the request→response cycle can be tested over a
/// real socket without depending on a fixed port.
fn spawn_accept_loop(listener: TcpListener, stats: Arc<Stats>) {
    thread::spawn(move || {
        for conn in listener.incoming() {
            match conn {
                Ok(stream) => {
                    if let Err(e) = handle_conn(stream, &stats) {
                        tracing::debug!(error = %e, "stats connection error");
                    }
                }
                Err(e) => tracing::warn!(error = %e, "stats accept failed"),
            }
        }
    });
}

/// Drain the request (so the client doesn't see a reset) and write the metrics.
fn handle_conn(mut stream: TcpStream, stats: &Stats) -> std::io::Result<()> {
    // Read the request headers but cap it — we don't route on the path, we just
    // need to consume enough that the peer's write completes before we respond.
    let mut scratch = [0u8; 1024];
    let _ = stream.read(&mut scratch);

    let body = render(&stats.snapshot());
    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes())
}

/// Let the capture layer report kernel-side counters without depending on the
/// concrete [`Stats`] type — it only sees the [`crate::capture::KernelStatsSink`]
/// interface.
impl crate::capture::KernelStatsSink for Stats {
    fn add_kernel_stats(&self, packets: u64, drops: u64) {
        Stats::add_kernel_stats(self, packets, drops);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_and_snapshots() {
        let stats = Stats::new(vec!["ssh".into(), "admin".into()], 2);
        stats.record_observed();
        stats.record_observed();
        stats.record_rate_limited();
        stats.record_accepted(0);
        stats.record_accepted(0);
        stats.record_accepted(1);
        stats.set_tracked(0, 3);
        stats.set_tracked(1, 4);
        // Kernel-stats samples are deltas (PACKET_STATISTICS is read-and-reset);
        // successive reports accumulate.
        stats.add_kernel_stats(5, 1);
        stats.add_kernel_stats(4, 2);

        let snap = stats.snapshot();
        assert_eq!(snap.packets_observed, 2);
        assert_eq!(snap.packets_rate_limited, 1);
        assert_eq!(snap.knocks_accepted, 3);
        assert_eq!(snap.kernel_packets, 9);
        assert_eq!(snap.kernel_drops, 3);
        assert_eq!(snap.per_door, vec![("ssh".into(), 2), ("admin".into(), 1)]);
        assert_eq!(snap.tracked_sources, 7);
    }

    #[test]
    fn accept_for_unknown_door_is_ignored_but_total_counts() {
        // A door index out of range bumps the global total but no per-door slot.
        let stats = Stats::new(vec!["ssh".into()], 1);
        stats.record_accepted(9);
        let snap = stats.snapshot();
        assert_eq!(snap.knocks_accepted, 1);
        assert_eq!(snap.per_door, vec![("ssh".into(), 0)]);
    }

    #[test]
    fn renders_prometheus_text() {
        let snap = Snapshot {
            packets_observed: 10,
            packets_rate_limited: 2,
            spa_observed: 9,
            spa_accepted: 4,
            spa_rejected: 5,
            spa_replay_tracked: 6,
            knocks_accepted: 3,
            kernel_packets: 42,
            kernel_drops: 7,
            per_door: vec![("ssh".into(), 3)],
            tracked_sources: 1,
        };
        let text = render(&snap);
        assert!(text.contains("knockd2_packets_observed_total 10"));
        assert!(text.contains("knockd2_packets_rate_limited_total 2"));
        assert!(text.contains("knockd2_knocks_accepted_total 3"));
        assert!(text.contains("knockd2_afpacket_kernel_packets_total 42"));
        assert!(text.contains("knockd2_afpacket_kernel_drops_total 7"));
        assert!(text.contains("knockd2_door_accepted_total{door=\"ssh\"} 3"));
        assert!(text.contains("knockd2_tracked_sources 1"));
        assert!(text.contains("knockd2_spa_observed_total 9"));
        assert!(text.contains("knockd2_spa_accepted_total 4"));
        assert!(text.contains("knockd2_spa_rejected_total 5"));
        // SPA counters are separate from the knock ones on purpose: reusing
        // `packets_observed` would silently change what that metric means.
        assert!(!text.contains("knockd2_packets_observed_total 19"));
        // Rejections are a single counter with no reason label -- a per-reason
        // breakdown would tell a prober which guess got furthest.
        assert!(!text.contains("knockd2_spa_rejected_total{"));
        // Every metric carries a TYPE line.
        assert!(text.contains("knockd2_spa_replay_tracked 6"));
        assert!(text.contains("# TYPE knockd2_spa_replay_tracked gauge"));
        assert_eq!(text.matches("# TYPE ").count(), 11);
    }

    #[test]
    fn endpoint_serves_metrics_over_http() {
        use std::io::{Read as _, Write as _};
        use std::net::{TcpListener, TcpStream};

        let stats = Arc::new(Stats::new(vec!["ssh".into()], 1));
        stats.record_observed();
        stats.record_accepted(0);

        // Bind an ephemeral port and serve from it, then make a real request.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        spawn_accept_loop(listener, stats);

        let mut conn = TcpStream::connect(addr).unwrap();
        conn.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        let mut resp = String::new();
        conn.read_to_string(&mut resp).unwrap(); // server closes the connection

        assert!(resp.starts_with("HTTP/1.1 200 OK"), "response: {resp}");
        assert!(resp.contains("Content-Type: text/plain"));
        assert!(resp.contains("knockd2_packets_observed_total 1"));
        assert!(resp.contains("knockd2_door_accepted_total{door=\"ssh\"} 1"));
    }

    #[test]
    fn escapes_label_values() {
        let snap = Snapshot {
            packets_observed: 0,
            packets_rate_limited: 0,
            spa_observed: 0,
            spa_accepted: 0,
            spa_rejected: 0,
            spa_replay_tracked: 0,
            knocks_accepted: 0,
            kernel_packets: 0,
            kernel_drops: 0,
            per_door: vec![("we\"ird\\door".into(), 0)],
            tracked_sources: 0,
        };
        let text = render(&snap);
        assert!(text.contains("door=\"we\\\"ird\\\\door\""));
    }
}
