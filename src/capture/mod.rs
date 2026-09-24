//! Packet capture abstraction.
//!
//! The matcher consumes a stream of normalised [`PacketEvent`]s; how those are
//! produced is pluggable. Backends:
//!
//! - `afpacket` (feature `capture-afpacket`, Linux): pure-Rust `AF_PACKET` raw
//!   socket, no libpcap C dependency. Preferred live backend when built in.
//! - `pcap` (feature `capture-pcap`): libpcap-backed live capture.
//! - `replay`: deterministic, used by `--demo` and tests.
//!
//! Frame decoding is shared by every live backend in the pure [`parse`] module.

use std::net::IpAddr;
use std::sync::Arc;

use crate::matcher::PacketEvent;

/// A UDP datagram addressed to a Single Packet Authorization port, with its
/// body copied out.
///
/// SPA needs bytes, which a knock never does — a knock is fully described by
/// (source, port, protocol, time). Rather than give [`PacketEvent`] a payload
/// field and cost it its `Copy`-ness (it is moved packet-by-packet down the
/// shard channels on the hot path), SPA gets its own event type. One allocation
/// per SPA datagram is irrelevant; one per knock would not be.
#[derive(Clone, Debug)]
pub struct SpaDatagram {
    pub src: IpAddr,
    /// The address the datagram was sent *to*. A multi-homed server needs this
    /// to decide which of its addresses the client meant.
    pub dst: IpAddr,
    /// The UDP body, copied out of the capture buffer (which the next recv
    /// overwrites) and truncated to the longest datagram SPA can accept.
    pub payload: Vec<u8>,
    /// Monotonic logical timestamp in milliseconds, as for a knock.
    pub at_ms: u64,
    /// Seconds since the UNIX epoch. SPA replay windows are expressed in wall
    /// clock time, which `at_ms` (a per-process monotonic clock) cannot supply.
    pub at_unix: u64,
}

/// One captured, decoded packet: either a knock or an SPA datagram.
#[derive(Clone, Debug)]
pub enum Captured {
    Knock(PacketEvent),
    Spa(SpaDatagram),
}

/// A source of knock-relevant packets. Implementations call `sink` once per
/// observed TCP SYN / UDP packet, in arrival order.
pub trait Capture {
    /// Run the capture loop, invoking `sink` for each event. Blocks until the
    /// source is exhausted (replay) or an error/shutdown occurs (live).
    fn run(&mut self, sink: &mut dyn FnMut(Captured)) -> anyhow::Result<()>;
}

/// Receives kernel-side capture counters from a live backend. The AF_PACKET
/// backend periodically samples `PACKET_STATISTICS` and reports here; backends
/// without kernel counters never call it. Kept as a trait so the capture layer
/// stays decoupled from the concrete `stats::Stats` type.
pub trait KernelStatsSink: Send + Sync {
    /// Fold in a sample: `packets` frames that passed the kernel prefilter and
    /// `drops` frames it then shed (buffer-full) *since the previous report*.
    /// Deltas, not totals — the underlying `PACKET_STATISTICS` getsockopt is
    /// read-and-reset.
    // Only the AF_PACKET backend calls this; in builds that don't compile it the
    // sink is created but never fed, so allow the method to look unused there.
    #[cfg_attr(
        not(all(target_os = "linux", feature = "capture-afpacket")),
        allow(dead_code)
    )]
    fn add_kernel_stats(&self, packets: u64, drops: u64);
}

/// Wall-clock seconds since the UNIX epoch, for stamping SPA datagrams.
///
/// Live backends call this once per receive, never per packet and never inside
/// the decoder — [`parse`] takes both clocks as parameters so it stays pure and
/// testable. A clock before the epoch is impossible in practice and not worth a
/// capture failure, so it reads as 0 and the SPA verifier rejects the packet.
#[cfg_attr(
    not(any(
        feature = "capture-pcap",
        all(target_os = "linux", feature = "capture-afpacket")
    )),
    allow(dead_code)
)]
fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

mod bpf;
mod parse;
mod replay;
pub use replay::ReplayCapture;

// Compile the pcap backend only when it will actually be the live backend:
// on Linux the AF_PACKET backend supersedes it (see `open_live`), so enabling
// both features there leaves pcap unused rather than dead.
#[cfg(all(
    feature = "capture-pcap",
    not(all(target_os = "linux", feature = "capture-afpacket"))
))]
mod pcap_backend;
#[cfg(all(
    feature = "capture-pcap",
    not(all(target_os = "linux", feature = "capture-afpacket"))
))]
pub use pcap_backend::PcapCapture;

#[cfg(all(target_os = "linux", feature = "capture-afpacket"))]
mod afpacket;
#[cfg(all(target_os = "linux", feature = "capture-afpacket"))]
pub use afpacket::AfPacketCapture;

/// Open the best available live-capture backend for this build/platform.
///
/// Prefers the pure-Rust `AF_PACKET` backend (Linux + `capture-afpacket`),
/// falls back to libpcap (`capture-pcap`), and otherwise reports that the binary
/// was built without a capture backend. `ports` is the union of door ports, used
/// for the kernel BPF prefilter (pcap) or userspace filtering (afpacket).
/// `spa_ports` are the UDP ports whose datagrams are decoded as SPA (payload
/// copied out) rather than as knocks; a backend folds them into its prefilter so
/// they are not dropped in-kernel before the decoder ever sees them.
///
/// `kstats`, when present, receives the backend's kernel-side capture counters
/// (AF_PACKET `PACKET_STATISTICS`); backends without such counters ignore it.
// Each feature/platform combination compiles exactly one arm; the explicit
// `return`s keep the cfg-gated blocks uniform, so the per-config "needless
// return" is expected.
#[allow(unused_variables, clippy::needless_return)]
pub fn open_live(
    interface: Option<String>,
    ports: &[u16],
    spa_ports: &[u16],
    kstats: Option<Arc<dyn KernelStatsSink>>,
) -> anyhow::Result<Box<dyn Capture>> {
    #[cfg(all(target_os = "linux", feature = "capture-afpacket"))]
    {
        return Ok(Box::new(AfPacketCapture::new(
            interface, ports, spa_ports, kstats,
        )));
    }
    #[cfg(all(
        feature = "capture-pcap",
        not(all(target_os = "linux", feature = "capture-afpacket"))
    ))]
    {
        return Ok(Box::new(PcapCapture::new(interface, ports, spa_ports)));
    }
    #[cfg(not(any(
        all(target_os = "linux", feature = "capture-afpacket"),
        feature = "capture-pcap"
    )))]
    {
        anyhow::bail!(
            "live capture needs a capture backend.\n\
             Build with --features capture-afpacket (Linux, pure-Rust AF_PACKET)\n\
             or --features capture-pcap (libpcap).\n\
             (`--demo` and `--check` need no capture backend.)"
        );
    }
}
