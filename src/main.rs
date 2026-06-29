//! knock-daemon — a concurrent port-knocking daemon.
//!
//! Unlike classic `knockd`, in-flight knock sequences are partitioned per source
//! IP, so many clients can knock simultaneously (even the same door, fully
//! interleaved) without corrupting each other's progress. See `matcher.rs` for
//! the core and DESIGN.md for the rationale.

mod capture;
mod config;
mod firewall;
mod matcher;

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;

use capture::{Capture, ReplayCapture};
use config::{Config, ResolvedDoor};
use matcher::{Matcher, PacketEvent, Proto};

#[derive(Parser, Debug)]
#[command(name = "knockd2", version, about = "Concurrent port-knocking daemon (knockd replacement)")]
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
    let cfg: Config = toml::from_str(&raw).context("parsing config TOML")?;
    let doors = cfg.resolve().context("validating config")?;
    let fw_kind = cfg.firewall_kind()?;

    if cli.check {
        let iface = cfg.interface.as_deref().unwrap_or("<capture default>");
        println!("config OK: interface = {iface}, {} door(s), firewall backend = {:?}", doors.len(), fw_kind);
        for d in &doors {
            println!("  - {} ({} steps, seq_timeout {}ms)", d.spec.name, d.spec.sequence.len(), d.spec.seq_timeout_ms);
        }
        return Ok(());
    }

    run_live(cfg, doors, fw_kind)
}

/// Drive the capture → matcher → firewall pipeline against live traffic.
#[cfg(feature = "capture-pcap")]
fn run_live(cfg: Config, doors: Vec<ResolvedDoor>, fw_kind: firewall::FirewallKind) -> Result<()> {
    let ports: Vec<u16> = doors
        .iter()
        .flat_map(|d| d.spec.sequence.iter().map(|p| p.port))
        .collect();
    let mut cap = capture::PcapCapture::new(cfg.interface.clone(), &ports);
    let engine = Engine::new(doors, fw_kind)?;
    tracing::info!("knock-daemon up; capturing live traffic");
    run_pipeline(&mut cap, engine)
}

#[cfg(not(feature = "capture-pcap"))]
fn run_live(_cfg: Config, _doors: Vec<ResolvedDoor>, _fw_kind: firewall::FirewallKind) -> Result<()> {
    anyhow::bail!(
        "live capture requires the `capture-pcap` feature.\n\
         Rebuild with: cargo build --release --features capture-pcap\n\
         (or run `--demo` / `--check`, which need no capture backend)"
    )
}

/// The matching + action half of the pipeline, independent of the capture source.
struct Engine {
    matcher: Matcher,
    doors: Vec<ResolvedDoor>,
    firewall: Arc<dyn firewall::Firewall + Sync>,
}

// CommandFirewall is stateless; mark the trait-object usage Sync-safe via Arc.
// (Box<dyn Firewall> is Send; we wrap in Arc and require Sync at construction.)
impl Engine {
    fn new(doors: Vec<ResolvedDoor>, fw_kind: firewall::FirewallKind) -> Result<Self> {
        let specs = doors.iter().map(|d| d.spec.clone()).collect();
        let firewall = firewall_arc(fw_kind)?;
        Ok(Self { matcher: Matcher::new(specs), doors, firewall })
    }

    /// Feed one packet; run actions for any completed doors.
    fn on_packet(&mut self, ev: PacketEvent) {
        for done in self.matcher.process(ev) {
            let door = &self.doors[done.door];
            tracing::info!(door = %door.spec.name, src = %done.src, "knock accepted");
            if let Err(e) = self.firewall.open(&door.open_command, done.src) {
                tracing::error!(door = %door.spec.name, error = %e, "open command failed");
                continue;
            }
            schedule_close(self.firewall.clone(), door, done.src);
        }
    }
}

/// Build a `Sync`-capable firewall handle. The command backend is stateless.
fn firewall_arc(kind: firewall::FirewallKind) -> Result<Arc<dyn firewall::Firewall + Sync>> {
    match kind {
        firewall::FirewallKind::Command => Ok(Arc::new(firewall::CommandFirewall)),
        firewall::FirewallKind::Nftables => {
            anyhow::bail!("nftables backend is not implemented yet; use backend = \"command\"")
        }
    }
}

/// If the door has a `cmd_timeout` and a `close_command`, spawn a timer that
/// runs the close action after the delay.
fn schedule_close(
    firewall: Arc<dyn firewall::Firewall + Sync>,
    door: &ResolvedDoor,
    src: IpAddr,
) {
    let (Some(timeout_ms), Some(close)) = (door.cmd_timeout_ms, door.close_command.clone()) else {
        return;
    };
    let name = door.spec.name.clone();
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(timeout_ms));
        tracing::info!(door = %name, src = %src, "auto-closing after cmd_timeout");
        if let Err(e) = firewall.close(&close, src) {
            tracing::error!(door = %name, error = %e, "close command failed");
        }
    });
}

#[cfg(feature = "capture-pcap")]
fn run_pipeline(cap: &mut dyn Capture, mut engine: Engine) -> Result<()> {
    cap.run(&mut |ev| engine.on_packet(ev))
}

/// Replay a canned, interleaved scenario so the concurrency story is visible
/// without root or libpcap.
fn run_demo() -> Result<()> {
    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, n))
    }
    fn tcp(src: IpAddr, port: u16, at_ms: u64) -> PacketEvent {
        PacketEvent { src, port, proto: Proto::Tcp, at_ms }
    }

    let doors = vec![ResolvedDoor {
        spec: matcher::DoorSpec {
            name: "ssh".into(),
            sequence: vec![
                matcher::PortSpec { port: 7000, proto: Proto::Tcp },
                matcher::PortSpec { port: 8000, proto: Proto::Tcp },
                matcher::PortSpec { port: 9000, proto: Proto::Tcp },
            ],
            seq_timeout_ms: 10_000,
        },
        open_command: "echo would-open %IP%".into(),
        close_command: None,
        cmd_timeout_ms: None,
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

    let mut engine = Engine::new(doors, firewall::FirewallKind::Command)?;
    let mut cap = ReplayCapture::new(events);
    println!("--- knock-daemon demo: two interleaved clients knocking the same door ---");
    cap.run(&mut |ev| engine.on_packet(ev))?;
    println!("--- both clients accepted independently; no cross-talk ---");
    Ok(())
}
