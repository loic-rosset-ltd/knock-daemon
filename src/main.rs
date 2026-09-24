//! knock-daemon — a concurrent port-knocking daemon.
//!
//! Unlike classic `knockd`, in-flight knock sequences are partitioned per source
//! IP, so many clients can knock simultaneously (even the same door, fully
//! interleaved) without corrupting each other's progress. See `matcher.rs` for
//! the core and DESIGN.md for the rationale.

mod capture;
mod config;
mod firewall;
#[cfg(feature = "compat-fwknop")]
mod fwknop;
mod knockd;
mod matcher;
mod ratelimit;
mod spa;
mod stats;

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;

use capture::{Capture, Captured, ReplayCapture};
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
    let spa_cfg = cfg.resolve_spa().context("validating [spa]")?;

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
        match &spa_cfg {
            None => println!("  spa = disabled"),
            Some(sp) => {
                // Name the mode explicitly: "enabled" alone has caught people out
                // who set a passphrase and expected public-key mode.
                let mode = match (&sp.passphrase_file, &sp.static_key_file) {
                    (Some(_), Some(_)) => "psk + public-key",
                    (Some(_), None) => "psk",
                    (None, Some(_)) => "public-key",
                    (None, None) => unreachable!("resolve_spa rejects a keyless [spa]"),
                };
                println!(
                    "  spa = enabled on udp/{} ({mode}), window {}s, duration {}s (max {}s)",
                    sp.port, sp.window_secs, sp.default_duration_secs, sp.max_duration_secs
                );
                // Loading proves the files parse, which is the whole point of
                // --check: a broken key file should fail here, not at 3am on the
                // first knock.
                let v = build_spa_verifier(sp).context("loading SPA key material")?;
                if let Some(pk) = v.static_public() {
                    println!(
                        "  spa static public key: {} {}",
                        spa::keys::TAG_SRV_PUB,
                        spa::keys::encode_hex32(&pk)
                    );
                }
            }
        }
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

    run_live(cfg, doors, fw_kind, mode, shards, rate, spa_cfg)
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
    spa_cfg: Option<config::ResolvedSpa>,
) -> Result<()> {
    // Only watch the SPA port when SPA is actually on: an unused port in the
    // cBPF filter costs one of a budget of 64 that door sequences also draw on.
    let spa_ports: Vec<u16> = spa_cfg.iter().map(|s| s.port).collect();
    // The kernel prefilter drops anything outside this union before userspace
    // ever sees it, so the SPA port has to be in it or SPA is invisible.
    let ports: Vec<u16> = doors
        .iter()
        .flat_map(|d| d.spec.sequence.iter().map(|p| p.port))
        .chain(spa_ports.iter().copied())
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
        &spa_ports[..],
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

    // The SPA verifier owns replay state, so exactly one thread holds it.
    let spa_tx = match &spa_cfg {
        None => None,
        Some(sp) => {
            let verifier = build_spa_verifier(sp).context("loading SPA key material")?;
            let (tx, rx) = mpsc::channel::<capture::SpaDatagram>();
            let worker = SpaWorker {
                verifier,
                limiter: rate.map(|r| r.build(RATE_LIMIT_MAX_SOURCES)),
                doors: doors.clone(),
                firewall: firewall.clone(),
                stats: stats.clone(),
            };
            handles.push(thread::spawn(move || worker.run(rx)));
            Some(tx)
        }
    };

    tracing::info!(
        shards = n_shards,
        rate_limited = rate.is_some(),
        spa = spa_cfg.is_some(),
        "knock-daemon up; capturing live traffic"
    );

    let result = cap.run(&mut |captured| match captured {
        Captured::Knock(ev) => {
            stats.record_observed();
            let s = matcher::shard_for(&ev.src, n_shards);
            // A worker only stops if it panicked; surface that rather than
            // silently dropping the source's traffic.
            if senders[s].send(ev).is_err() {
                tracing::error!(shard = s, "matcher worker stopped; dropping packet");
            }
        }
        Captured::Spa(datagram) => {
            // With SPA off, the port is not in the capture filter at all, so
            // this arm is unreachable rather than merely unused.
            if let Some(tx) = spa_tx.as_ref() {
                if tx.send(datagram).is_err() {
                    tracing::error!("SPA worker stopped; dropping datagram");
                }
            }
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

/// Replay a canned scenario so the matcher's tolerance of duplicate and
/// interleaved packets is visible without root or libpcap.
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
            // Not in ascending order, like every other example in this
            // repository: an ascending sequence is completed by an ordinary
            // ascending port scan. See SECURITY.md.
            sequence: vec![
                matcher::PortSpec {
                    port: 41953,
                    proto: Proto::Tcp,
                },
                matcher::PortSpec {
                    port: 8271,
                    proto: Proto::Tcp,
                },
                matcher::PortSpec {
                    port: 22986,
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

    // .10's opening packet is delivered twice — a retry or a TCP retransmit.
    // Classic knockd destroys the in-flight attempt on that duplicate and starts
    // nothing in its place (`stage = -1`), so .10 never opens. Here the duplicate
    // simply opens a second candidate beside the first. .20 knocks interleaved
    // throughout, which both daemons handle.
    let events = vec![
        tcp(ip(10), 41953, 0),
        tcp(ip(20), 41953, 5),
        tcp(ip(10), 41953, 9), // <-- the duplicate that ends a knockd sequence
        tcp(ip(20), 8271, 12),
        tcp(ip(10), 8271, 18),
        tcp(ip(20), 22986, 25), // .20 completes
        tcp(ip(10), 22986, 31), // .10 completes despite the duplicate
    ];

    // The sequence, for annotating each replayed packet with the step it is.
    let seq: Vec<u16> = doors[0].spec.sequence.iter().map(|p| p.port).collect();
    let n_steps = seq.len();

    let mut engine = Engine::new(doors, firewall::FirewallKind::Command, MatchMode::Tolerant)?;
    let mut cap = ReplayCapture::new(events);

    println!("--- knock-daemon demo: a duplicated opening packet, and two interleaved clients ---");
    println!(
        "door \"ssh\" = {} (seq_timeout 10s, mode = tolerant)\n",
        seq.iter()
            .map(|p| format!(":{p}"))
            .collect::<Vec<_>>()
            .join(" → ")
    );
    println!("  replayed packets, in the order the capture layer sees them:");

    // Show the stream, not just its outcome. A skeptic's objection to the old
    // output was fair: two "accepted" lines prove a door can open, they do not
    // show that the packets were interleaved or that one arrived twice.
    let mut seen_first: Vec<IpAddr> = Vec::new();
    cap.run(&mut |captured| {
        // The replay only ever emits knocks; SPA has no scripted form here.
        let Captured::Knock(ev) = captured else {
            return;
        };
        let step = seq.iter().position(|&p| p == ev.port);
        let dup = step == Some(0) && seen_first.contains(&ev.src);
        if step == Some(0) {
            seen_first.push(ev.src);
        }
        println!(
            "  t={:>3}ms  {:<14} → :{:<6} {}{}",
            ev.at_ms,
            ev.src.to_string(),
            ev.port,
            step.map(|i| format!("[ssh {}/{}]", i + 1, n_steps))
                .unwrap_or_default(),
            if dup { "   <-- duplicate" } else { "" },
        );
        engine.on_packet(ev)
    })?;

    println!(
        "\n--- both sources completed the door. Note .10's opening packet arrived twice (t=0ms,\n\
         \x20   t=9ms): classic knockd discards the in-flight attempt on that duplicate and starts\n\
         \x20   nothing in its place, so .10 would never have opened. ---"
    );
    Ok(())
}

/// Build an [`spa::SpaVerifier`] from validated config, loading whatever key
/// material the operator configured.
///
/// Both modes may be on at once: a fleet usually wants public-key mode, but a
/// PSK is a reasonable way to get started, and refusing the combination would
/// force an all-or-nothing migration.
fn build_spa_verifier(sp: &config::ResolvedSpa) -> Result<spa::SpaVerifier> {
    let mut v = spa::SpaVerifier::new(sp.window_secs, sp.max_replay_entries)
        .with_durations(sp.default_duration_secs, sp.max_duration_secs)
        .allow_explicit_addr(sp.allow_explicit_addr);

    if let (Some(pass_path), Some(salt)) = (&sp.passphrase_file, &sp.salt) {
        let passphrase = spa::keys::load_passphrase(Path::new(pass_path))?;
        // Argon2id at 64 MiB runs exactly here, once, at startup -- never on the
        // packet path, where a flood could otherwise force it.
        let key = spa::crypto::derive_psk(&passphrase, salt.as_bytes())
            .map_err(|e| anyhow::anyhow!("deriving SPA pre-shared key: {e}"))?;
        v = v.with_psk(key);
    }

    if let Some(secret_path) = &sp.static_key_file {
        let secret = spa::keys::load_static_secret(Path::new(secret_path))?;
        v = v.with_static_secret(secret);
        if let Some(auth_path) = &sp.authorized_keys {
            let keys = spa::keys::load_authorized_keys(Path::new(auth_path))?;
            if keys.is_empty() {
                // Not fatal -- the verifier fails closed -- but silence here
                // would look exactly like a working setup.
                tracing::warn!(
                    file = %auth_path,
                    "SPA authorized_keys is empty; no client can be authorised yet"
                );
            }
            for k in keys {
                v = v.authorize(k.public);
            }
        }
    }
    Ok(v)
}

/// Owns the SPA verifier and turns accepted packets into firewall openings.
///
/// One thread, not a shard set: `SpaVerifier::verify` takes `&mut self` because
/// the replay guard is state, and replay detection is only sound if every packet
/// is checked against the same guard. Sharding it by source would let the same
/// packet be accepted once per shard.
struct SpaWorker {
    verifier: spa::SpaVerifier,
    limiter: Option<ratelimit::RateLimiter>,
    doors: Arc<Vec<ResolvedDoor>>,
    firewall: Arc<dyn firewall::Firewall + Sync>,
    stats: Arc<stats::Stats>,
}

impl SpaWorker {
    fn run(mut self, rx: mpsc::Receiver<capture::SpaDatagram>) {
        for dg in rx {
            self.stats.record_spa_observed();

            // Rate-limit before any cryptography, so an unauthenticated flood
            // costs us a hash lookup rather than an AEAD open.
            if let Some(l) = self.limiter.as_mut() {
                if !l.allow(dg.src, dg.at_ms) {
                    self.stats.record_rate_limited();
                    continue;
                }
            }

            let verdict = self.verifier.verify(&dg.payload, dg.src, dg.at_unix);
            // Publish replay-table size after every packet: the claim that memory
            // tracks the window rather than uptime is only worth making if an
            // operator can watch it.
            self.stats
                .set_spa_replay_tracked(self.verifier.tracked_replays());
            match verdict {
                Ok(authorized) => self.apply(&dg, authorized),
                Err(e) => {
                    self.stats.record_spa_rejected();
                    // The reason is logged, never sent: the daemon answers
                    // nothing, so a prober learns nothing from a refusal.
                    tracing::debug!(src = %dg.src, error = %e, "SPA packet refused");
                }
            }
        }
    }

    fn apply(&self, dg: &capture::SpaDatagram, authorized: spa::Authorized) {
        let Some(idx) = self
            .doors
            .iter()
            .position(|d| d.spec.name == authorized.door)
        else {
            // Authenticated, but naming a door this server does not have. Worth a
            // warning rather than a debug: the packet was legitimate, so this is
            // a configuration mismatch between client and server, not an attack.
            self.stats.record_spa_rejected();
            tracing::warn!(
                src = %dg.src,
                door = %authorized.door,
                "SPA packet authorised but names an unknown door"
            );
            return;
        };

        let door = &self.doors[idx];
        let who = authorized
            .client_pub
            .map(|k| spa::keys::encode_hex32(&k))
            .unwrap_or_else(|| "psk".to_string());

        match self.firewall.open_for(
            &door.action,
            authorized.addr,
            Some(authorized.duration_secs),
        ) {
            Ok(()) => {
                self.stats.record_spa_accepted();
                self.stats.record_accepted(idx);
                tracing::info!(
                    door = %authorized.door,
                    addr = %authorized.addr,
                    // The address the packet arrived at, which on a multi-homed
                    // host is the only way to tell which service was meant.
                    via = %dg.dst,
                    duration_secs = authorized.duration_secs,
                    identity = %who,
                    "SPA knock accepted"
                );
                // A backend that cannot expire on its own needs the same
                // userspace close timer a sequence knock gets -- but for the
                // duration this packet asked for, not the door's default.
                if !self.firewall.auto_expires() {
                    let fw = self.firewall.clone();
                    let mut action = door.action.clone();
                    action.timeout_ms = Some(u64::from(authorized.duration_secs) * 1000);
                    let addr = authorized.addr;
                    thread::spawn(move || {
                        thread::sleep(Duration::from_millis(action.timeout_ms.unwrap_or_default()));
                        if let Err(e) = fw.close(&action, addr) {
                            tracing::error!(error = %e, "closing SPA access failed");
                        }
                    });
                }
            }
            Err(e) => {
                self.stats.record_spa_rejected();
                tracing::error!(error = %e, door = %authorized.door, "opening SPA door failed");
            }
        }
    }
}
