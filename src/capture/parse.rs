//! Pure link-layer → [`PacketEvent`] parsing, shared by every capture backend.
//!
//! Every backend (libpcap, AF_PACKET, …) hands raw bytes; this module turns an
//! Ethernet frame into a normalised event, or `None` if it isn't knock-relevant.
//! It understands Ethernet II, 802.1Q / 802.1ad VLAN tags (including stacked
//! QinQ), IPv4 and IPv6 (skipping a bounded chain of extension headers), and
//! pulls the destination port from TCP **SYN-without-ACK** segments and UDP
//! datagrams. It is pure — no clock, no I/O — so the whole thing is unit-tested
//! against hand-built frames without sockets or root.
//!
//! The parser is consumed by the feature-gated live backends (pcap / afpacket)
//! and by this module's own tests. In a build with no capture backend it has no
//! production caller, so suppress dead-code there rather than gate the module
//! (and its tests) out entirely.
#![cfg_attr(
    not(any(
        feature = "capture-pcap",
        all(target_os = "linux", feature = "capture-afpacket")
    )),
    allow(dead_code)
)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::matcher::{PacketEvent, Proto};

const ETH_HDR_LEN: usize = 14;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86DD;
const ETHERTYPE_VLAN: u16 = 0x8100; // 802.1Q
const ETHERTYPE_QINQ: u16 = 0x88A8; // 802.1ad (service tag / QinQ)

/// Stacked VLAN tags we'll peel before giving up (QinQ is two; allow a little slack).
const MAX_VLAN_TAGS: usize = 3;
/// Upper bound on the IPv6 extension-header chain we'll walk before giving up.
const MAX_IPV6_EXT_HEADERS: usize = 8;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

/// Parse one Ethernet frame into a [`PacketEvent`], stamping it with `at_ms`
/// (the caller's logical/monotonic millisecond clock). Returns `None` for
/// anything that isn't an inbound TCP SYN or UDP datagram we can read.
pub fn parse_ethernet(frame: &[u8], at_ms: u64) -> Option<PacketEvent> {
    if frame.len() < ETH_HDR_LEN {
        return None;
    }

    // Peel the EtherType, walking past any VLAN tags (single 802.1Q or stacked
    // QinQ). Each tag is 4 bytes: 2 of TCI followed by the inner EtherType.
    let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let mut offset = ETH_HDR_LEN;
    let mut tags = 0;
    while matches!(ethertype, ETHERTYPE_VLAN | ETHERTYPE_QINQ) {
        if tags >= MAX_VLAN_TAGS || frame.len() < offset + 4 {
            return None;
        }
        ethertype = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
        offset += 4;
        tags += 1;
    }

    let l3 = frame.get(offset..)?;
    match ethertype {
        ETHERTYPE_IPV4 => parse_ipv4(l3, at_ms),
        ETHERTYPE_IPV6 => parse_ipv6(l3, at_ms),
        _ => None,
    }
}

fn parse_ipv4(ip: &[u8], at_ms: u64) -> Option<PacketEvent> {
    if ip.len() < 20 || ip[0] >> 4 != 4 {
        return None;
    }
    let ihl = (ip[0] & 0x0f) as usize * 4;
    if ihl < 20 || ip.len() < ihl {
        return None;
    }
    // Only the first fragment (offset 0) carries the L4 header; ignore the rest.
    let frag_offset = u16::from_be_bytes([ip[6], ip[7]]) & 0x1fff;
    if frag_offset != 0 {
        return None;
    }
    let protocol = ip[9];
    let src = IpAddr::V4(Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]));
    parse_l4(protocol, src, ip.get(ihl..)?, at_ms)
}

fn parse_ipv6(ip: &[u8], at_ms: u64) -> Option<PacketEvent> {
    const IPV6_HDR_LEN: usize = 40;
    if ip.len() < IPV6_HDR_LEN || ip[0] >> 4 != 6 {
        return None;
    }
    let src = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&ip[8..24]).ok()?));

    // Walk the next-header chain to the transport header. We can skip the
    // ordinary TLV option headers; anything exotic (AH/ESP) means it's not a
    // plain knock packet, so we bail.
    let mut next = ip[6];
    let mut off = IPV6_HDR_LEN;
    for _ in 0..MAX_IPV6_EXT_HEADERS {
        match next {
            IPPROTO_TCP | IPPROTO_UDP => return parse_l4(next, src, ip.get(off..)?, at_ms),
            // Hop-by-Hop (0), Routing (43), Destination Options (60): TLV with a
            // length in 8-octet units, not counting the first 8.
            0 | 43 | 60 => {
                let hdr = ip.get(off..off + 2)?;
                next = hdr[0];
                off += (hdr[1] as usize + 1) * 8;
            }
            // Fragment (44): fixed 8 bytes; only the first fragment has the L4 header.
            44 => {
                let hdr = ip.get(off..off + 8)?;
                let frag_offset = u16::from_be_bytes([hdr[2], hdr[3]]) & 0xfff8;
                if frag_offset != 0 {
                    return None;
                }
                next = hdr[0];
                off += 8;
            }
            _ => return None,
        }
    }
    None
}

fn parse_l4(protocol: u8, src: IpAddr, l4: &[u8], at_ms: u64) -> Option<PacketEvent> {
    match protocol {
        IPPROTO_TCP => {
            // Need through the flags byte (offset 13).
            if l4.len() < 14 {
                return None;
            }
            let port = u16::from_be_bytes([l4[2], l4[3]]);
            let flags = l4[13];
            let syn = flags & 0x02 != 0;
            let ack = flags & 0x10 != 0;
            // Connection openers only: SYN without ACK.
            (syn && !ack).then_some(PacketEvent {
                src,
                port,
                proto: Proto::Tcp,
                at_ms,
            })
        }
        IPPROTO_UDP => {
            if l4.len() < 8 {
                return None;
            }
            let port = u16::from_be_bytes([l4[2], l4[3]]);
            Some(PacketEvent {
                src,
                port,
                proto: Proto::Udp,
                at_ms,
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- frame builders -----------------------------------------------------

    /// Ethernet header with a given EtherType (src/dst MACs are arbitrary).
    fn eth(ethertype: u16) -> Vec<u8> {
        let mut f = vec![
            0x52, 0x54, 0x00, 0x11, 0x22, 0x33, // dst MAC
            0x52, 0x54, 0x00, 0x44, 0x55, 0x66, // src MAC
        ];
        f.extend_from_slice(&ethertype.to_be_bytes());
        f
    }

    /// One VLAN tag: TCI (vid in the low bits) + inner EtherType.
    fn vlan_tag(vid: u16, inner: u16) -> Vec<u8> {
        let mut t = Vec::new();
        t.extend_from_slice(&vid.to_be_bytes());
        t.extend_from_slice(&inner.to_be_bytes());
        t
    }

    /// Minimal IPv4 header (20 bytes, no options) for a given L4 protocol/source.
    fn ipv4(protocol: u8, src: [u8; 4]) -> Vec<u8> {
        let mut h = vec![0x45, 0x00, 0x00, 0x00]; // v4, IHL=5, len ignored
        h.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // id, flags+frag=0
        h.extend_from_slice(&[0x40, protocol, 0x00, 0x00]); // ttl, proto, checksum
        h.extend_from_slice(&src); // source
        h.extend_from_slice(&[10, 0, 0, 1]); // destination
        h
    }

    /// Minimal IPv6 header (40 bytes) with a given next-header and source.
    fn ipv6(next_header: u8, src: [u8; 16]) -> Vec<u8> {
        let mut h = vec![0x60, 0x00, 0x00, 0x00]; // v6, traffic class/flow = 0
        h.extend_from_slice(&[0x00, 0x00]); // payload length (ignored)
        h.push(next_header);
        h.push(0x40); // hop limit
        h.extend_from_slice(&src); // source
        h.extend_from_slice(&[0xff; 16]); // destination
        h
    }

    fn tcp(dst_port: u16, flags: u8) -> Vec<u8> {
        let mut h = Vec::new();
        h.extend_from_slice(&[0x30, 0x39]); // source port 12345
        h.extend_from_slice(&dst_port.to_be_bytes());
        h.extend_from_slice(&[0u8; 8]); // seq + ack
        h.push(0x50); // data offset = 5
        h.push(flags);
        h.extend_from_slice(&[0u8; 6]); // window, checksum, urgent
        h
    }

    fn udp(dst_port: u16) -> Vec<u8> {
        let mut h = Vec::new();
        h.extend_from_slice(&[0x30, 0x39]); // source port
        h.extend_from_slice(&dst_port.to_be_bytes());
        h.extend_from_slice(&[0x00, 0x08, 0x00, 0x00]); // length, checksum
        h
    }

    const SYN: u8 = 0x02;
    const SYN_ACK: u8 = 0x12;

    fn frame(parts: &[Vec<u8>]) -> Vec<u8> {
        parts.iter().flatten().copied().collect()
    }

    // --- tests --------------------------------------------------------------

    #[test]
    fn ipv4_tcp_syn_is_parsed() {
        let f = frame(&[
            eth(ETHERTYPE_IPV4),
            ipv4(IPPROTO_TCP, [10, 0, 0, 7]),
            tcp(7000, SYN),
        ]);
        let ev = parse_ethernet(&f, 42).unwrap();
        assert_eq!(ev.src, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)));
        assert_eq!(ev.port, 7000);
        assert_eq!(ev.proto, Proto::Tcp);
        assert_eq!(ev.at_ms, 42);
    }

    #[test]
    fn ipv4_tcp_syn_ack_is_ignored() {
        let f = frame(&[
            eth(ETHERTYPE_IPV4),
            ipv4(IPPROTO_TCP, [10, 0, 0, 7]),
            tcp(7000, SYN_ACK),
        ]);
        assert!(parse_ethernet(&f, 0).is_none());
    }

    #[test]
    fn ipv4_udp_is_parsed() {
        let f = frame(&[
            eth(ETHERTYPE_IPV4),
            ipv4(IPPROTO_UDP, [10, 0, 0, 8]),
            udp(8000),
        ]);
        let ev = parse_ethernet(&f, 1).unwrap();
        assert_eq!(ev.port, 8000);
        assert_eq!(ev.proto, Proto::Udp);
    }

    #[test]
    fn ipv6_tcp_syn_is_parsed() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let f = frame(&[eth(ETHERTYPE_IPV6), ipv6(IPPROTO_TCP, src), tcp(9000, SYN)]);
        let ev = parse_ethernet(&f, 7).unwrap();
        assert_eq!(ev.src, IpAddr::V6(Ipv6Addr::from(src)));
        assert_eq!(ev.port, 9000);
        assert_eq!(ev.proto, Proto::Tcp);
    }

    #[test]
    fn ipv6_with_hop_by_hop_extension_header() {
        // Hop-by-Hop header (next=TCP, len=0 → 8 bytes) before the TCP segment.
        let src = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let mut hbh = vec![IPPROTO_TCP, 0x00];
        hbh.extend_from_slice(&[0u8; 6]); // pad to 8 bytes
        let f = frame(&[eth(ETHERTYPE_IPV6), ipv6(0, src), hbh, tcp(443, SYN)]);
        let ev = parse_ethernet(&f, 0).unwrap();
        assert_eq!(ev.port, 443);
        assert_eq!(ev.src, IpAddr::V6(Ipv6Addr::from(src)));
    }

    #[test]
    fn single_vlan_tag_is_peeled() {
        let f = frame(&[
            eth(ETHERTYPE_VLAN),
            vlan_tag(0x0064, ETHERTYPE_IPV4), // vid 100
            ipv4(IPPROTO_TCP, [10, 0, 0, 9]),
            tcp(7000, SYN),
        ]);
        let ev = parse_ethernet(&f, 0).unwrap();
        assert_eq!(ev.port, 7000);
        assert_eq!(ev.src, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)));
    }

    #[test]
    fn stacked_qinq_tags_are_peeled() {
        let f = frame(&[
            eth(ETHERTYPE_QINQ),
            vlan_tag(0x0064, ETHERTYPE_VLAN), // outer service tag
            vlan_tag(0x000a, ETHERTYPE_IPV4), // inner customer tag
            ipv4(IPPROTO_UDP, [10, 0, 0, 10]),
            udp(5353),
        ]);
        let ev = parse_ethernet(&f, 0).unwrap();
        assert_eq!(ev.port, 5353);
        assert_eq!(ev.proto, Proto::Udp);
    }

    #[test]
    fn ipv4_non_initial_fragment_is_ignored() {
        let mut ip = ipv4(IPPROTO_TCP, [10, 0, 0, 7]);
        // Fragment offset = 1 (in the low 13 bits of bytes 6..8).
        ip[6] = 0x00;
        ip[7] = 0x01;
        let f = frame(&[eth(ETHERTYPE_IPV4), ip, tcp(7000, SYN)]);
        assert!(parse_ethernet(&f, 0).is_none());
    }

    #[test]
    fn non_ip_ethertype_is_ignored() {
        let f = frame(&[eth(0x0806)]); // ARP
        assert!(parse_ethernet(&f, 0).is_none());
    }

    #[test]
    fn truncated_frames_are_ignored() {
        assert!(parse_ethernet(&[0u8; 4], 0).is_none()); // shorter than Ethernet
        let short_l4 = frame(&[
            eth(ETHERTYPE_IPV4),
            ipv4(IPPROTO_TCP, [10, 0, 0, 7]),
            vec![0u8; 4],
        ]);
        assert!(parse_ethernet(&short_l4, 0).is_none()); // TCP header cut off
    }
}
