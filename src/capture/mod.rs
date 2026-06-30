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

use crate::matcher::PacketEvent;

/// A source of knock-relevant packets. Implementations call `sink` once per
/// observed TCP SYN / UDP packet, in arrival order.
pub trait Capture {
    /// Run the capture loop, invoking `sink` for each event. Blocks until the
    /// source is exhausted (replay) or an error/shutdown occurs (live).
    fn run(&mut self, sink: &mut dyn FnMut(PacketEvent)) -> anyhow::Result<()>;
}

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
// Each feature/platform combination compiles exactly one arm; the explicit
// `return`s keep the cfg-gated blocks uniform, so the per-config "needless
// return" is expected.
#[allow(unused_variables, clippy::needless_return)]
pub fn open_live(interface: Option<String>, ports: &[u16]) -> anyhow::Result<Box<dyn Capture>> {
    #[cfg(all(target_os = "linux", feature = "capture-afpacket"))]
    {
        return Ok(Box::new(AfPacketCapture::new(interface, ports)));
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
