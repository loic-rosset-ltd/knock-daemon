//! knock-daemon — a concurrent port-knocking daemon.
//!
//! Unlike classic `knockd`, in-flight knock sequences are partitioned per source
//! IP, so many clients can knock simultaneously (even the same door, fully
//! interleaved) without corrupting each other's progress. See `matcher.rs` for
//! the core and DESIGN.md for the rationale.

mod capture;
mod config;
mod firewall;
mod knockd;
mod matcher;
mod ratelimit;
mod stats;

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;

use capture::{Capture, ReplayCapture};
use config::{Config, ResolvedDoor};
use matcher::{MatchMode, Matcher, PacketEvent, Proto, ShardedMatcher};

/// Per-shard cap on the number of source IPs the rate limiter tracks. Bounds the
/// limiter's own memory so it can't become an exhaustion vector itself.
const RATE_LIMIT_MAX_SOURCES: usize = 65_536;

#[derive(Parser, Debug)]
#[command(
    name = "knockd2",
    version,
    about = "Concurrent port-knocking daemon (knockd replacement)"
)]
struct Cli {
    /// Path to the TOML config file.
    #[arg(short, long, default_value = "knockd.toml")]
    config: PathBuf,

    /// Run a built-in replay that demonstrates concurrent matching, then exit.
    /// Requires neither root, libpcap, nor a real config.
    #[arg(long)]
    demo: bool,

    /// Parse and validate the config, print a summary, and exit.
    #[arg(long)]
    check: bool,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "knockd2=info".into()),
        )
        .init();

    let cli = Cli::parse();

    if cli.demo {
        return run_demo();
    }

    let raw = std::fs::read_to_string(&cli.config)
        .with_context(|| format!("reading config {}", cli.config.display()))?;
    // knockd `.conf` files use the legacy INI format; everything else is our TOML.
    let cfg: Config = if cli.config.extension().and_then(|e| e.to_str()) == Some("conf") {
        knockd::parse_conf(&raw).context("parsing knockd .conf")?
    } else {
        toml::from_str(&raw).context("parsing config TOML")?
    };
    let fw_kind = cfg.firewall_kind()?;
    let mode = cfg.match_mode()?;
    // Validate the runtime tunables here too, so `--check` rejects a malformed
    // rate_limit instead of the daemon failing only at startup.
    let rate = cfg.rate_limit()?;
    let shards = cfg.shard_count();
    let doors = cfg.resolve(fw_kind).context("validating config")?;

    if cli.check {
        let iface = cfg.interface.as_deref().unwrap_or("<capture default>");
        println!(
            "config OK: interface = {iface}, {} door(s), firewall backend = {:?}, matching = {:?}",
            doors.len(),
            fw_kind,
            mode
        );
        println!(
            "  shards = {shards}, rate_limit = {}, stats endpoint = {}",
            cfg.matching.rate_limit.as_deref().unwrap_or("none"),
            cfg.stats_listen().unwrap_or("disabled"),
        );
        for d in &doors {
            println!(
                "  - {} ({} steps, seq_timeout {}ms)",
                d.spec.name,
                d.spec.sequence.len(),
                d.spec.seq_timeout_ms
            );
        }
        return Ok(());
    }

    run_live(cfg, doors, fw_kind, mode, shards, rate)
}

/// Drive the capture → matcher → firewall pipeline against live traffic, using
/// whichever capture backend this binary was built with.
///
/// Matching is sharded by source IP across `cfg.shard_count()` worker threads:
/// the capture loop only hashes each packet to a shard and forwards it down a
/// channel, so packet decoding never blocks on matching or firewall I/O. Because
/// sources partition cleanly across shards, the per-source isolation guarantee is
/// preserved with zero cross-shard coordination.
fn run_live(
    cfg: Config,
    doors: Vec<ResolvedDoor>,
    fw_kind: firewall::FirewallKind,
    mode: MatchMode,
    n_shards: usize,
    rate: Option<config::RateSpec>,
) -> Result<()> {
    let ports: Vec<u16> = doors
        .iter()
        .flat_map(|d| d.spec.sequence.iter().map(|p| p.port))
        .collect();

    let firewall = firewall_arc(fw_kind)?;
    let stats = Arc::new(stats::Stats::new(
        doors.iter().map(|d| d.spec.name.clone()).collect(),
        n_shards,
    ));

    // The capture backend reports its kernel-side counters into `stats`, so build
    // it after the counters exist.
    let mut cap = capture::open_live(
        cfg.interface.clone(),
        &ports,
        Some(stats.clone() as Arc<dyn capture::KernelStatsSink>),
    )?;

    if let Some(addr) = cfg.stats_listen() {
        stats::serve(addr, stats.clone())?;
    }

    // One worker thread per shard, each owning its own matcher + rate limiter.
    let specs: Vec<matcher::DoorSpec> = doors.iter().map(|d| d.spec.clone()).collect();
    let doors = Arc::new(doors);
    let mut senders = Vec::with_capacity(n_shards);
    let mut handles = Vec::with_capacity(n_shards);
    for shard in 0..n_shards {
        let (tx, rx) = mpsc::channel::<PacketEvent>();
        senders.push(tx);
        let worker = Worker {
            shard,
            matcher: Matcher::with_mode(specs.clone(), mode),
            limiter: rate.map(|r| r.build(RATE_LIMIT_MAX_SOURCES)),
            doors: doors.clone(),
            firewall: firewall.clone(),
            stats: stats.clone(),
        };
        handles.push(thread::spawn(move || worker.run(rx)));
    }

    tracing::info!(
        shards = n_shards,
        rate_limited = rate.is_some(),
        "knock-daemon up; capturing live traffic"
    );

    let result = cap.run(&mut |ev| {
        stats.record_observed();
        let s = matcher::shard_for(&ev.src, n_shards);
        // A worker only stops if it panicked; surface that rather than silently
        // dropping the source's traffic.
        if senders[s].send(ev).is_err() {
            tracing::error!(shard = s, "matcher worker stopped; dropping packet");
        }
    });

    // Closing the senders ends each worker's `for ev in rx` loop; join so any
    // in-flight close timers and logging flush before we return.
    drop(senders);
    for h in handles {
        let _ = h.join();
    }
    result
}

/// One matcher shard: owns a [`Matcher`] (and optional rate limiter) for the
/// subset of source IPs that hash to it, and acts on completed knocks.
struct Worker {
    shard: usize,
    matcher: Matcher,
    limiter: Option<ratelimit::RateLimiter>,
    doors: Arc<Vec<ResolvedDoor>>,
    firewall: Arc<dyn firewall::Firewall + Sync>,
    stats: Arc<stats::Stats>,
}

impl Worker {
    /// Consume packets from the shard channel until it closes.
    fn run(mut self, rx: mpsc::Receiver<PacketEvent>) {
        for ev in rx {
            if let Some(limiter) = self.limiter.as_mut() {
                if !limiter.allow(ev.src, ev.at_ms) {
                    self.stats.record_rate_limited();
                    continue;
                }
            }
            for done in self.matcher.process(ev) {
                self.stats.record_accepted(done.door);
                open_door(&self.firewall, &self.doors[done.door], done.src);
            }
            self.stats
                .set_tracked(self.shard, self.matcher.tracked_sources());
        }
    }
}

/// Run a door's open side effect and, for backends that don't self-expire,
/// schedule the matching close. Shared by the live workers and the `--demo` path.
fn open_door(firewall: &Arc<dyn firewall::Firewall + Sync>, door: &ResolvedDoor, src: IpAddr) {
    tracing::info!(door = %door.spec.name, src = %src, "knock accepted");
    if let Err(e) = firewall.open(&door.action, src) {
        tracing::error!(door = %door.spec.name, error = %e, "open failed");
        return;
    }
    // nftables expires the element in-kernel; only userspace backends need a
    // timer to run the close action.
    if !firewall.auto_expires() {
        schedule_close(firewall.clone(), door, src);
    }
}

/// The matching + action half of the pipeline for the single-threaded `--demo`
/// replay, where deterministic ordering matters more than throughput.
struct Engine {
    matcher: ShardedMatcher,
    doors: Vec<ResolvedDoor>,
    firewall: Arc<dyn firewall::Firewall + Sync>,
}

impl Engine {
    fn new(
        doors: Vec<ResolvedDoor>,
        fw_kind: firewall::FirewallKind,
        mode: MatchMode,
    ) -> Result<Self> {
        let specs = doors.iter().map(|d| d.spec.clone()).collect();
        let firewall = firewall_arc(fw_kind)?;
        Ok(Self {
            // A single shard keeps the replay deterministic while still
            // exercising the sharded routing used in production.
            matcher: ShardedMatcher::new(specs, mode, 1),
            doors,
            firewall,
        })
    }

    /// Feed one packet; run actions for any completed doors.
    fn on_packet(&mut self, ev: PacketEvent) {
        for done in self.matcher.process(ev) {
            open_door(&self.firewall, &self.doors[done.door], done.src);
        }
    }
}

/// Build a `Sync`-capable firewall handle. Both backends are stateless.
fn firewall_arc(kind: firewall::FirewallKind) -> Result<Arc<dyn firewall::Firewall + Sync>> {
    match kind {
        firewall::FirewallKind::Command => Ok(Arc::new(firewall::CommandFirewall)),
        firewall::FirewallKind::Nftables => Ok(Arc::new(firewall::NftablesFirewall::default())),
    }
}

/// If the door has a `cmd_timeout` and a `close_command`, spawn a timer that
/// runs the close action after the delay.
fn schedule_close(firewall: Arc<dyn firewall::Firewall + Sync>, door: &ResolvedDoor, src: IpAddr) {
    let (Some(timeout_ms), true) = (door.action.timeout_ms, door.action.close_command.is_some())
    else {
        return;
    };
    let name = door.spec.name.clone();
    let action = door.action.clone();
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(timeout_ms));
        tracing::info!(door = %name, src = %src, "auto-closing after cmd_timeout");
        if let Err(e) = firewall.close(&action, src) {
            tracing::error!(door = %name, error = %e, "close failed");
        }
    });
}

/// Replay a canned, interleaved scenario so the concurrency story is visible
/// without root or libpcap.
fn run_demo() -> Result<()> {
    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, n))
    }
    fn tcp(src: IpAddr, port: u16, at_ms: u64) -> PacketEvent {
        PacketEvent {
            src,
            port,
            proto: Proto::Tcp,
            at_ms,
        }
    }

    let doors = vec![ResolvedDoor {
        spec: matcher::DoorSpec {
            name: "ssh".into(),
            sequence: vec![
                matcher::PortSpec {
                    port: 7000,
                    proto: Proto::Tcp,
                },
                matcher::PortSpec {
                    port: 8000,
                    proto: Proto::Tcp,
                },
                matcher::PortSpec {
                    port: 9000,
                    proto: Proto::Tcp,
                },
            ],
            seq_timeout_ms: 10_000,
        },
        action: firewall::Action {
            open_command: Some("echo would-open %IP%".into()),
            ..Default::default()
        },
    }];

    // Two clients (.10 and .20) knock the SAME door at the SAME time, fully
    // interleaved — the exact case classic knockd mishandles.
    let events = vec![
        tcp(ip(10), 7000, 0),
        tcp(ip(20), 7000, 5),
        tcp(ip(20), 8000, 12),
        tcp(ip(10), 8000, 18),
        tcp(ip(20), 9000, 25), // .20 completes first
        tcp(ip(10), 9000, 31), // .10 completes too
    ];

    let mut engine = Engine::new(doors, firewall::FirewallKind::Command, MatchMode::Tolerant)?;
    let mut cap = ReplayCapture::new(events);
    println!("--- knock-daemon demo: two interleaved clients knocking the same door ---");
    cap.run(&mut |ev| engine.on_packet(ev))?;
    println!("--- both clients accepted independently; no cross-talk ---");
    Ok(())
}
