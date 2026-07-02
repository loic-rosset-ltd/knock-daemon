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

use std::sync::Arc;

use crate::matcher::PacketEvent;

/// A source of knock-relevant packets. Implementations call `sink` once per
/// observed TCP SYN / UDP packet, in arrival order.
pub trait Capture {
    /// Run the capture loop, invoking `sink` for each event. Blocks until the
    /// source is exhausted (replay) or an error/shutdown occurs (live).
    fn run(&mut self, sink: &mut dyn FnMut(PacketEvent)) -> anyhow::Result<()>;
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
    kstats: Option<Arc<dyn KernelStatsSink>>,
) -> anyhow::Result<Box<dyn Capture>> {
    #[cfg(all(target_os = "linux", feature = "capture-afpacket"))]
    {
        return Ok(Box::new(AfPacketCapture::new(interface, ports, kstats)));
    }
    #[cfg(all(
        feature = "capture-pcap",
        not(all(target_os = "linux", feature = "capture-afpacket"))
    ))]
    {
        return Ok(Box::new(PcapCapture::new(interface, ports)));
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
