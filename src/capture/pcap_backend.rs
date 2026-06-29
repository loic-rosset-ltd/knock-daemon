//! libpcap-backed live capture (feature `capture-pcap`).
//!
//! Status: MVP. Parses Ethernet + IPv4 + TCP/UDP and emits a [`PacketEvent`] for
//! each inbound TCP SYN and each UDP datagram. IPv6 and non-Ethernet link types
//! are TODO (see DESIGN.md). Not yet exercised against live traffic in CI — the
//! pure matcher is what the test suite covers.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;

use anyhow::{Context, Result};
use pcap::{Capture as PcapHandle, Device};

use crate::matcher::{PacketEvent, Proto};

use super::Capture;

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
        Self { interface, filter, start: Instant::now() }
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
        cap.filter(&self.filter, true).context("installing BPF filter")?;

        loop {
            match cap.next_packet() {
                Ok(packet) => {
                    if let Some(ev) = parse_ethernet_ipv4(packet.data, self.start) {
                        sink(ev);
                    }
                }
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(e) => return Err(e).context("reading packet"),
            }
        }
    }
}

/// Minimal Ethernet/IPv4 parser. Returns `None` for anything we don't handle.
fn parse_ethernet_ipv4(data: &[u8], start: Instant) -> Option<PacketEvent> {
    const ETH_HDR: usize = 14;
    const ETHERTYPE_IPV4: u16 = 0x0800;

    if data.len() < ETH_HDR {
        return None;
    }
    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    if ethertype != ETHERTYPE_IPV4 {
        return None; // TODO: IPv6 (0x86DD), VLAN tags.
    }

    let ip = &data[ETH_HDR..];
    if ip.len() < 20 {
        return None;
    }
    let ihl = (ip[0] & 0x0f) as usize * 4;
    if ihl < 20 || ip.len() < ihl {
        return None;
    }
    let protocol = ip[9];
    let src = IpAddr::V4(Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]));
    let l4 = &ip[ihl..];

    let at_ms = start.elapsed().as_millis() as u64;

    match protocol {
        6 => {
            // TCP — only count SYN-without-ACK (connection openers).
            if l4.len() < 20 {
                return None;
            }
            let dst_port = u16::from_be_bytes([l4[2], l4[3]]);
            let flags = l4[13];
            let syn = flags & 0x02 != 0;
            let ack = flags & 0x10 != 0;
            if syn && !ack {
                Some(PacketEvent { src, port: dst_port, proto: Proto::Tcp, at_ms })
            } else {
                None
            }
        }
        17 => {
            // UDP.
            if l4.len() < 8 {
                return None;
            }
            let dst_port = u16::from_be_bytes([l4[2], l4[3]]);
            Some(PacketEvent { src, port: dst_port, proto: Proto::Udp, at_ms })
        }
        _ => None,
    }
}
