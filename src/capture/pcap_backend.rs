//! libpcap-backed live capture (feature `capture-pcap`).
//!
//! Status: MVP. Frame decoding (Ethernet/VLAN/IPv4/IPv6/TCP-SYN/UDP) lives in
//! the shared, unit-tested [`super::parse`] module; this backend only owns the
//! libpcap handle and the kernel BPF prefilter. Not yet exercised against live
//! traffic in CI — the pure matcher and parser are what the test suite covers.

use std::time::Instant;

use anyhow::{Context, Result};
use pcap::{Capture as PcapHandle, Device};

use super::{parse, unix_secs, Capture, Captured};

pub struct PcapCapture {
    interface: Option<String>,
    /// BPF filter to push capture cost into the kernel.
    filter: String,
    /// UDP ports whose datagrams are decoded as SPA rather than as knocks.
    spa_ports: Vec<u16>,
    start: Instant,
}

impl PcapCapture {
    /// `ports` is the union of every door's ports and `spa_ports` the SPA
    /// listeners; we build a BPF filter so the kernel only hands us packets that
    /// could matter. The SPA term is its own disjunct rather than relying on the
    /// caller having folded those ports into `ports`: a filter that drops SPA
    /// in-kernel would be invisible at this layer and look like a client bug.
    pub fn new(interface: Option<String>, ports: &[u16], spa_ports: &[u16]) -> Self {
        let mut spa_ports = spa_ports.to_vec();
        spa_ports.sort_unstable();
        spa_ports.dedup();

        let knock_term = if ports.is_empty() {
            // No door ports: take every SYN/UDP, which already covers SPA.
            "tcp[tcpflags] & tcp-syn != 0 or udp".to_string()
        } else {
            let port_list = ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(" or port ");
            format!("(tcp[tcpflags] & tcp-syn != 0 or udp) and (port {port_list})")
        };
        let filter = if spa_ports.is_empty() || ports.is_empty() {
            knock_term
        } else {
            let spa_list = spa_ports
                .iter()
                .map(|p| format!("udp dst port {p}"))
                .collect::<Vec<_>>()
                .join(" or ");
            format!("({knock_term}) or ({spa_list})")
        };
        Self {
            interface,
            filter,
            spa_ports,
            start: Instant::now(),
        }
    }
}

impl Capture for PcapCapture {
    fn run(&mut self, sink: &mut dyn FnMut(Captured)) -> Result<()> {
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
                    // Both clocks are read once per delivered frame, here, so
                    // the decoder itself never touches one.
                    let at_ms = self.start.elapsed().as_millis() as u64;
                    let at_unix = unix_secs();
                    if let Some(ev) =
                        parse::parse_ethernet(packet.data, at_ms, at_unix, &self.spa_ports)
                    {
                        sink(ev);
                    }
                }
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(e) => return Err(e).context("reading packet"),
            }
        }
    }
}
