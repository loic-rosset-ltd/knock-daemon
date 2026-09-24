//! Pure link-layer → [`Captured`] parsing, shared by every capture backend.
//!
//! Every backend (libpcap, AF_PACKET, …) hands raw bytes; this module turns an
//! Ethernet frame into a normalised event, or `None` if it isn't relevant.
//! It understands Ethernet II, 802.1Q / 802.1ad VLAN tags (including stacked
//! QinQ), IPv4 and IPv6 (skipping a bounded chain of extension headers), and
//! pulls the destination port from TCP **SYN-without-ACK** segments and UDP
//! datagrams. It is pure — no clock, no I/O — so the whole thing is unit-tested
//! against hand-built frames without sockets or root.
//!
//! A UDP datagram whose destination port is in the caller's *SPA port set* is
//! decoded differently: its body is copied out into a [`SpaDatagram`] so the
//! daemon can verify it, along with the destination address (a multi-homed
//! server needs to know which of its addresses was addressed). Everything else
//! stays a [`PacketEvent`], which remains `Copy` and payload-free.
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

use super::{Captured, SpaDatagram};

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

/// Longest SPA body we copy out of a datagram. Mirrors
/// `spa::packet::MAX_PACKET_LEN`, deliberately restated rather than imported so
/// the parser stays independent of the SPA module (and of whether it is
/// compiled in at all). Anything longer cannot be a valid SPA packet, so we
/// truncate instead of letting a remote peer size our copy: the verifier
/// rejects the short read exactly as it would have rejected the long one.
const MAX_SPA_PAYLOAD_LEN: usize = 1400;

/// Parse one Ethernet frame into a [`Captured`] event, stamping it with `at_ms`
/// (the caller's logical/monotonic millisecond clock) and `at_unix` (seconds
/// since the UNIX epoch). Both clocks are *parameters*: this module never reads
/// one, so every path through it is testable without sleeping.
///
/// A UDP datagram whose destination port is in `spa_ports` becomes
/// [`Captured::Spa`] with its body copied out; everything else becomes
/// [`Captured::Knock`]. Returns `None` for anything that isn't an inbound TCP
/// SYN or UDP datagram we can read.
pub fn parse_ethernet(
    frame: &[u8],
    at_ms: u64,
    at_unix: u64,
    spa_ports: &[u16],
) -> Option<Captured> {
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
        ETHERTYPE_IPV4 => parse_ipv4(l3, at_ms, at_unix, spa_ports),
        ETHERTYPE_IPV6 => parse_ipv6(l3, at_ms, at_unix, spa_ports),
        _ => None,
    }
}

fn parse_ipv4(ip: &[u8], at_ms: u64, at_unix: u64, spa_ports: &[u16]) -> Option<Captured> {
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
    let dst = IpAddr::V4(Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]));
    parse_l4(
        protocol,
        src,
        dst,
        ip.get(ihl..)?,
        at_ms,
        at_unix,
        spa_ports,
    )
}

fn parse_ipv6(ip: &[u8], at_ms: u64, at_unix: u64, spa_ports: &[u16]) -> Option<Captured> {
    const IPV6_HDR_LEN: usize = 40;
    if ip.len() < IPV6_HDR_LEN || ip[0] >> 4 != 6 {
        return None;
    }
    let src = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&ip[8..24]).ok()?));
    let dst = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&ip[24..40]).ok()?));

    // Walk the next-header chain to the transport header. We can skip the
    // ordinary TLV option headers; anything exotic (AH/ESP) means it's not a
    // plain knock packet, so we bail.
    let mut next = ip[6];
    let mut off = IPV6_HDR_LEN;
    for _ in 0..MAX_IPV6_EXT_HEADERS {
        match next {
            IPPROTO_TCP | IPPROTO_UDP => {
                return parse_l4(next, src, dst, ip.get(off..)?, at_ms, at_unix, spa_ports)
            }
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

fn parse_l4(
    protocol: u8,
    src: IpAddr,
    dst: IpAddr,
    l4: &[u8],
    at_ms: u64,
    at_unix: u64,
    spa_ports: &[u16],
) -> Option<Captured> {
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
            (syn && !ack).then_some(Captured::Knock(PacketEvent {
                src,
                port,
                proto: Proto::Tcp,
                at_ms,
            }))
        }
        IPPROTO_UDP => {
            if l4.len() < 8 {
                return None;
            }
            let port = u16::from_be_bytes([l4[2], l4[3]]);
            // An SPA port is a payload port: the body is the whole point, so it
            // is copied out here — the capture buffer is reused by the next
            // recv, and the sink may outlive this frame. The UDP length field is
            // deliberately not trusted; the captured slice is what we actually
            // have, and a truncated datagram simply yields a short payload the
            // verifier will reject.
            if spa_ports.contains(&port) {
                let body = &l4[8..];
                let take = body.len().min(MAX_SPA_PAYLOAD_LEN);
                return Some(Captured::Spa(SpaDatagram {
                    src,
                    dst,
                    payload: body[..take].to_vec(),
                    at_ms,
                    at_unix,
                }));
            }
            Some(Captured::Knock(PacketEvent {
                src,
                port,
                proto: Proto::Udp,
                at_ms,
            }))
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

    /// The destination addresses baked into the `ipv4`/`ipv6` builders above.
    const DST_V4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const DST_V6: Ipv6Addr = Ipv6Addr::new(
        0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
    );

    /// The SPA port used throughout these tests.
    const SPA_PORT: u16 = 62201;

    fn frame(parts: &[Vec<u8>]) -> Vec<u8> {
        parts.iter().flatten().copied().collect()
    }

    // --- parse wrappers -----------------------------------------------------
    //
    // Most tests only care about one arm of `Captured`, and asserting the arm is
    // itself part of what they check — so unwrap it here and fail loudly on the
    // other one, rather than repeat a `match` in every test.

    /// Parse with no SPA ports configured: the pre-SPA behaviour.
    fn knock(frame: &[u8], at_ms: u64) -> Option<PacketEvent> {
        knock_with(frame, at_ms, &[])
    }

    /// Parse with an SPA port set, expecting a knock out the far side.
    fn knock_with(frame: &[u8], at_ms: u64, spa_ports: &[u16]) -> Option<PacketEvent> {
        match parse_ethernet(frame, at_ms, 0, spa_ports)? {
            Captured::Knock(ev) => Some(ev),
            Captured::Spa(d) => panic!("expected a knock, got SPA from {}", d.src),
        }
    }

    /// Parse with `SPA_PORT` configured, expecting an SPA datagram.
    fn spa(frame: &[u8], at_ms: u64, at_unix: u64) -> Option<SpaDatagram> {
        match parse_ethernet(frame, at_ms, at_unix, &[SPA_PORT])? {
            Captured::Spa(d) => Some(d),
            Captured::Knock(ev) => panic!("expected SPA, got a knock on :{}", ev.port),
        }
    }

    // --- tests --------------------------------------------------------------

    #[test]
    fn ipv4_tcp_syn_is_parsed() {
        let f = frame(&[
            eth(ETHERTYPE_IPV4),
            ipv4(IPPROTO_TCP, [10, 0, 0, 7]),
            tcp(7000, SYN),
        ]);
        let ev = knock(&f, 42).unwrap();
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
        assert!(knock(&f, 0).is_none());
    }

    #[test]
    fn ipv4_udp_is_parsed() {
        let f = frame(&[
            eth(ETHERTYPE_IPV4),
            ipv4(IPPROTO_UDP, [10, 0, 0, 8]),
            udp(8000),
        ]);
        let ev = knock(&f, 1).unwrap();
        assert_eq!(ev.port, 8000);
        assert_eq!(ev.proto, Proto::Udp);
    }

    #[test]
    fn ipv6_tcp_syn_is_parsed() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let f = frame(&[eth(ETHERTYPE_IPV6), ipv6(IPPROTO_TCP, src), tcp(9000, SYN)]);
        let ev = knock(&f, 7).unwrap();
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
        let ev = knock(&f, 0).unwrap();
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
        let ev = knock(&f, 0).unwrap();
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
        let ev = knock(&f, 0).unwrap();
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
        assert!(knock(&f, 0).is_none());
    }

    #[test]
    fn non_ip_ethertype_is_ignored() {
        let f = frame(&[eth(0x0806)]); // ARP
        assert!(knock(&f, 0).is_none());
    }

    // --- SPA datagrams ------------------------------------------------------

    #[test]
    fn spa_port_udp_yields_the_exact_payload() {
        let body = b"\x00\x01SPA-BODY\xff\xfe".to_vec();
        let f = frame(&[
            eth(ETHERTYPE_IPV4),
            ipv4(IPPROTO_UDP, [10, 0, 0, 11]),
            udp(SPA_PORT),
            body.clone(),
        ]);
        let d = spa(&f, 99, 1_700_000_000).unwrap();
        assert_eq!(d.payload, body);
        assert_eq!(d.src, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 11)));
        assert_eq!(d.at_ms, 99);
        // The two clocks are independent and both come from the caller.
        assert_eq!(d.at_unix, 1_700_000_000);
    }

    #[test]
    fn udp_on_a_non_spa_port_is_still_a_knock() {
        let f = frame(&[
            eth(ETHERTYPE_IPV4),
            ipv4(IPPROTO_UDP, [10, 0, 0, 8]),
            udp(8000),
            b"ignored".to_vec(),
        ]);
        let ev = knock_with(&f, 1, &[SPA_PORT]).unwrap();
        assert_eq!(ev.port, 8000);
        assert_eq!(ev.proto, Proto::Udp);
    }

    #[test]
    fn tcp_syn_is_unaffected_by_the_spa_port_set() {
        // Same port number as SPA, but TCP: SPA is UDP-only, so this stays a knock.
        let f = frame(&[
            eth(ETHERTYPE_IPV4),
            ipv4(IPPROTO_TCP, [10, 0, 0, 7]),
            tcp(SPA_PORT, SYN),
        ]);
        let ev = knock_with(&f, 42, &[SPA_PORT]).unwrap();
        assert_eq!(ev.port, SPA_PORT);
        assert_eq!(ev.proto, Proto::Tcp);
    }

    #[test]
    fn oversized_spa_payload_is_truncated_not_fatal() {
        // A peer can always send more than MAX_SPA_PAYLOAD_LEN; the copy must be
        // bounded by our constant, not by what they chose to send.
        let body: Vec<u8> = (0..MAX_SPA_PAYLOAD_LEN + 500).map(|i| i as u8).collect();
        let f = frame(&[
            eth(ETHERTYPE_IPV4),
            ipv4(IPPROTO_UDP, [10, 0, 0, 12]),
            udp(SPA_PORT),
            body.clone(),
        ]);
        let d = spa(&f, 0, 0).unwrap();
        assert_eq!(d.payload.len(), MAX_SPA_PAYLOAD_LEN);
        assert_eq!(d.payload[..], body[..MAX_SPA_PAYLOAD_LEN]);
    }

    #[test]
    fn udp_truncated_mid_header_is_ignored() {
        // Four bytes in: ports present, length/checksum cut off. There is no
        // payload offset to take, so this must be dropped rather than indexed.
        let f = frame(&[
            eth(ETHERTYPE_IPV4),
            ipv4(IPPROTO_UDP, [10, 0, 0, 13]),
            udp(SPA_PORT)[..4].to_vec(),
        ]);
        assert!(parse_ethernet(&f, 0, 0, &[SPA_PORT]).is_none());
    }

    #[test]
    fn zero_length_spa_payload_is_empty_not_a_panic() {
        // A header-only datagram: `l4[8..]` is the empty slice, not out of range.
        let f = frame(&[
            eth(ETHERTYPE_IPV4),
            ipv4(IPPROTO_UDP, [10, 0, 0, 14]),
            udp(SPA_PORT),
        ]);
        let d = spa(&f, 0, 0).unwrap();
        assert!(d.payload.is_empty());
    }

    #[test]
    fn vlan_and_qinq_tagged_spa_frames_are_parsed() {
        let body = b"tagged".to_vec();
        let tagged = frame(&[
            eth(ETHERTYPE_VLAN),
            vlan_tag(0x0064, ETHERTYPE_IPV4),
            ipv4(IPPROTO_UDP, [10, 0, 0, 15]),
            udp(SPA_PORT),
            body.clone(),
        ]);
        assert_eq!(spa(&tagged, 0, 0).unwrap().payload, body);

        let qinq = frame(&[
            eth(ETHERTYPE_QINQ),
            vlan_tag(0x0064, ETHERTYPE_VLAN),
            vlan_tag(0x000a, ETHERTYPE_IPV4),
            ipv4(IPPROTO_UDP, [10, 0, 0, 16]),
            udp(SPA_PORT),
            body.clone(),
        ]);
        assert_eq!(spa(&qinq, 0, 0).unwrap().payload, body);
    }

    #[test]
    fn ipv6_spa_frame_is_parsed_through_an_extension_header() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
        let body = b"v6-spa".to_vec();
        // Destination Options (60) header before the UDP datagram.
        let mut dst_opts = vec![IPPROTO_UDP, 0x00];
        dst_opts.extend_from_slice(&[0u8; 6]);
        let f = frame(&[
            eth(ETHERTYPE_IPV6),
            ipv6(60, src),
            dst_opts,
            udp(SPA_PORT),
            body.clone(),
        ]);
        let d = spa(&f, 3, 7).unwrap();
        assert_eq!(d.payload, body);
        assert_eq!(d.src, IpAddr::V6(Ipv6Addr::from(src)));
    }

    #[test]
    fn destination_address_is_extracted_for_both_families() {
        // A multi-homed server needs to know which of its addresses was hit, so
        // the destination must come from the IP header, not be inferred.
        let v4 = frame(&[
            eth(ETHERTYPE_IPV4),
            ipv4(IPPROTO_UDP, [10, 0, 0, 17]),
            udp(SPA_PORT),
        ]);
        assert_eq!(spa(&v4, 0, 0).unwrap().dst, IpAddr::V4(DST_V4));

        let src6 = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3];
        let v6 = frame(&[eth(ETHERTYPE_IPV6), ipv6(IPPROTO_UDP, src6), udp(SPA_PORT)]);
        assert_eq!(spa(&v6, 0, 0).unwrap().dst, IpAddr::V6(DST_V6));
    }

    #[test]
    fn truncated_frames_are_ignored() {
        assert!(knock(&[0u8; 4], 0).is_none()); // shorter than Ethernet
        let short_l4 = frame(&[
            eth(ETHERTYPE_IPV4),
            ipv4(IPPROTO_TCP, [10, 0, 0, 7]),
            vec![0u8; 4],
        ]);
        assert!(knock(&short_l4, 0).is_none()); // TCP header cut off
    }
}
