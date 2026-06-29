//! Packet capture abstraction.
//!
//! The matcher consumes a stream of normalised [`PacketEvent`]s; how those are
//! produced is pluggable. The MVP ships a `pcap` backend (libpcap, feature
//! `capture-pcap`) and a `replay` backend used by the `--demo` path and tests.
//! A pure-Rust `AF_PACKET`/eBPF backend is planned to drop the libpcap C
//! dependency (see DESIGN.md).

use crate::matcher::PacketEvent;

/// A source of knock-relevant packets. Implementations call `sink` once per
/// observed TCP SYN / UDP packet, in arrival order.
pub trait Capture {
    /// Run the capture loop, invoking `sink` for each event. Blocks until the
    /// source is exhausted (replay) or an error/shutdown occurs (live).
    fn run(&mut self, sink: &mut dyn FnMut(PacketEvent)) -> anyhow::Result<()>;
}

mod replay;
pub use replay::ReplayCapture;

#[cfg(feature = "capture-pcap")]
mod pcap_backend;
#[cfg(feature = "capture-pcap")]
pub use pcap_backend::PcapCapture;
