//! libpcap-backed live capture (feature `capture-pcap`).
//!
//! Status: MVP. Frame decoding (Ethernet/VLAN/IPv4/IPv6/TCP-SYN/UDP) lives in
//! the shared, unit-tested [`super::parse`] module; this backend only owns the
//! libpcap handle and the kernel BPF prefilter. Not yet exercised against live
//! traffic in CI — the pure matcher and parser are what the test suite covers.

use std::time::Instant;

use anyhow::{Context, Result};
use pcap::{Capture as PcapHandle, Device};

use crate::matcher::PacketEvent;

use super::{parse, Capture};

pub struct PcapCapture {
    interface: Option<String>,
    /// BPF filter to push capture cost into the kernel.
    filter: String,
    start: Instant,
}

impl PcapCapture {
    /// `ports` is the union of every door's ports; we build a BPF filter so the
    /// kernel only hands us packets that could matter.
    pub fn new(interface: Option<String>, ports: &[u16]) -> Self {
        let filter = if ports.is_empty() {
            "tcp[tcpflags] & tcp-syn != 0 or udp".to_string()
        } else {
            let port_list = ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(" or port ");
            format!("(tcp[tcpflags] & tcp-syn != 0 or udp) and (port {port_list})")
        };
        Self {
            interface,
            filter,
            start: Instant::now(),
        }
    }
}

impl Capture for PcapCapture {
    fn run(&mut self, sink: &mut dyn FnMut(PacketEvent)) -> Result<()> {
        let device = match &self.interface {
            Some(name) => Device::from(name.as_str()),
            None => Device::lookup()
                .context("looking up default capture device")?
                .context("no default capture device available")?,
        };

        let mut cap = PcapHandle::from_device(device)
            .context("opening capture device")?
            .immediate_mode(true)
            .open()
            .context("activating capture (need CAP_NET_RAW / root)")?;
        cap.filter(&self.filter, true)
            .context("installing BPF filter")?;

        loop {
            match cap.next_packet() {
                Ok(packet) => {
                    let at_ms = self.start.elapsed().as_millis() as u64;
                    if let Some(ev) = parse::parse_ethernet(packet.data, at_ms) {
                        sink(ev);
                    }
                }
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(e) => return Err(e).context("reading packet"),
            }
        }
    }
}
