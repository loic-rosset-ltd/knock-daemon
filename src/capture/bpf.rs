//! Classic-BPF (cBPF) prefilter program builder for the `AF_PACKET` backend.
//!
//! The kernel runs this program on every frame before it is queued to our raw
//! socket (attached via `SO_ATTACH_FILTER`); frames it rejects are dropped in
//! the kernel and never copied to userspace. It is a pure *optimisation*: the
//! userspace decoder in [`super::parse`] (plus `AfPacketCapture::accepts`) is the
//! source of truth. The cardinal rule is therefore **no false negatives** — the
//! program must never drop a frame userspace would have accepted. It is allowed
//! to over-accept (pass frames userspace then rejects); it just must not
//! under-accept.
//!
//! That rule shapes the design:
//! - **Ethernet II IPv4/IPv6** are matched directly: protocol must be TCP or UDP
//!   and the L4 destination port must be one of the door ports. The TCP SYN flag
//!   is deliberately *not* checked here — userspace does that; cutting by port is
//!   already the big win and keeps the program simple.
//! - **In-payload VLAN/QinQ** (EtherType `0x8100`/`0x88a8`) shift the IP header by
//!   4/8 bytes, which cBPF can't chase cleanly, so those frames are *accepted*
//!   and left to the userspace VLAN peeling. (Hardware-offloaded VLAN tags are
//!   stripped into skb metadata, so such frames already arrive looking like plain
//!   IPv4/IPv6 and take the normal path — no special handling needed.)
//! - **IPv6 extension headers** move the L4 header past the fixed offset, so any
//!   IPv6 frame whose *first* next-header isn't directly TCP/UDP is accepted and
//!   left to the userspace next-header walk.
//!
//! The program is built without any platform types so it can be unit-tested with
//! a tiny cBPF interpreter on any host (see the tests); only the `setsockopt`
//! attach in [`super::afpacket`] is Linux-only. In a build that never compiles
//! the afpacket backend it has no caller, so suppress dead-code there rather than
//! gate the module (and its tests) out entirely.
#![cfg_attr(
    not(all(target_os = "linux", feature = "capture-afpacket")),
    allow(dead_code)
)]

/// One classic-BPF instruction. Layout-identical to `libc::sock_filter`
/// (`__u16, __u8, __u8, __u32`), so a `*const SockFilter` can be handed to
/// `SO_ATTACH_FILTER` as a `*const libc::sock_filter` (see `afpacket.rs`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

// cBPF opcode encodings (architecture-independent; `libc` re-exports the same
// values under Linux, but we define them here so this module builds everywhere).
const LD: u16 = 0x00; // load into A
const LDX: u16 = 0x01; // load into X
const JMP: u16 = 0x05; // conditional jump
const RET: u16 = 0x06; // return (verdict)
const H: u16 = 0x08; // halfword
const B: u16 = 0x10; // byte
const ABS: u16 = 0x20; // absolute offset
const IND: u16 = 0x40; // X-indexed offset
const MSH: u16 = 0xa0; // 4 * (frame[k] & 0xf) → X (IPv4 IHL → header length)
const JEQ: u16 = 0x10; // A == k
const K: u16 = 0x00; // immediate operand

/// Verdict snaplen meaning "accept the whole frame" (kernel caps to its length).
const ACCEPT: u32 = u32::MAX;

/// Cap on distinct door ports baked into the program. Keeps every (forward) jump
/// offset inside cBPF's 8-bit `jt`/`jf` range and the program far under
/// `BPF_MAXINSNS` (4096). With `n` ports the largest offset is `10 + 2n`, so 64
/// is comfortably safe; above it we skip the kernel filter and rely on userspace.
pub const MAX_FILTER_PORTS: usize = 64;

const fn stmt(code: u16, k: u32) -> SockFilter {
    SockFilter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

/// Build the cBPF prefilter accepting only TCP/UDP frames whose destination port
/// is one of `ports`. Returns `None` when no filter should be attached — an empty
/// port set (accept everything) or more than [`MAX_FILTER_PORTS`] ports — in which
/// case the caller leaves the socket unfiltered and relies on userspace.
pub fn build_filter(ports: &[u16]) -> Option<Vec<SockFilter>> {
    let n = ports.len();
    if n == 0 || n > MAX_FILTER_PORTS {
        return None;
    }

    // Absolute instruction indices of the program's labelled points. The layout
    // is fixed given `n`, so we can address jump targets arithmetically. The
    // tcp?/udp? checks jump to the *load* that fetches the port, not to the
    // compares — otherwise the port (and, for IPv4, the IHL) never gets loaded.
    //   0             ld ethertype
    //   1..=4         dispatch: IPv4 / IPv6 / 802.1Q / QinQ
    //   ipv4=5        ld ip-proto; tcp?; udp?
    //   v4_load=8     ldx ihl; ld port; then n port compares (start at 10)
    //   v6=10+n       ld next-header; tcp?; udp?
    //   v6_load=13+n  ld port; then n port compares (start at 14+n)
    //   accept / drop verdicts
    let ipv4 = 5usize;
    let v4_load = 8usize;
    let v6 = 10 + n;
    let v6_load = 13 + n;
    let accept = 14 + 2 * n;
    let drop = 15 + 2 * n;
    let total = 16 + 2 * n;

    // Relative offset from the instruction at `idx` to absolute `target`. Every
    // jump here is forward, so the distance is non-negative; it must fit in u8.
    let off = |target: usize, idx: usize| -> Option<u8> {
        u8::try_from(target.checked_sub(idx + 1)?).ok()
    };

    let mut p: Vec<SockFilter> = Vec::with_capacity(total);

    // --- dispatch on EtherType (offset 12) ---
    p.push(stmt(LD | H | ABS, 12));
    let i = p.len();
    p.push(jump(JMP | JEQ | K, 0x0800, off(ipv4, i)?, 0)); // IPv4
    let i = p.len();
    p.push(jump(JMP | JEQ | K, 0x86DD, off(v6, i)?, 0)); // IPv6
    let i = p.len();
    p.push(jump(JMP | JEQ | K, 0x8100, off(accept, i)?, 0)); // 802.1Q → accept (userspace peels)
    let i = p.len();
    p.push(jump(JMP | JEQ | K, 0x88A8, off(accept, i)?, off(drop, i)?)); // QinQ → accept, else drop

    // --- IPv4: protocol at byte 23 (14 + 9); dst port at 14 + 4*IHL + 2 ---
    p.push(stmt(LD | B | ABS, 23));
    let i = p.len();
    p.push(jump(JMP | JEQ | K, 6, off(v4_load, i)?, 0)); // TCP
    let i = p.len();
    p.push(jump(JMP | JEQ | K, 17, off(v4_load, i)?, off(drop, i)?)); // UDP, else drop
    p.push(stmt(LDX | B | MSH, 14)); // X = 4 * IHL
    p.push(stmt(LD | H | IND, 16)); // A = halfword at 14 + X + 2 = dst port
    push_port_compares(&mut p, ports, accept, drop, &off)?;

    // --- IPv6: next-header at byte 20 (14 + 6); dst port at 14 + 40 + 2 = 56 ---
    p.push(stmt(LD | B | ABS, 20));
    let i = p.len();
    p.push(jump(JMP | JEQ | K, 6, off(v6_load, i)?, 0)); // TCP
    let i = p.len();
    // UDP → port check; any other next-header means extension headers (or a
    // non-transport protocol), which we accept and let userspace resolve.
    p.push(jump(JMP | JEQ | K, 17, off(v6_load, i)?, off(accept, i)?));
    p.push(stmt(LD | H | ABS, 56));
    push_port_compares(&mut p, ports, accept, drop, &off)?;

    // --- verdicts ---
    p.push(stmt(RET | K, ACCEPT));
    p.push(stmt(RET | K, 0));

    debug_assert_eq!(p.len(), total);
    Some(p)
}

/// Emit one `A == port → accept` compare per door port. Each falls through to the
/// next compare; the last one jumps to `drop` when it doesn't match.
fn push_port_compares(
    p: &mut Vec<SockFilter>,
    ports: &[u16],
    accept: usize,
    drop: usize,
    off: &dyn Fn(usize, usize) -> Option<u8>,
) -> Option<()> {
    let n = ports.len();
    for (j, &port) in ports.iter().enumerate() {
        let i = p.len();
        let jf = if j + 1 == n { off(drop, i)? } else { 0 };
        p.push(jump(JMP | JEQ | K, port as u32, off(accept, i)?, jf));
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- a minimal cBPF interpreter, just the opcodes build_filter emits -------

    /// Run `prog` over `frame`, returning the verdict (snaplen; 0 = drop). Mirrors
    /// the kernel: an out-of-bounds packet read aborts the program to a drop.
    fn run(prog: &[SockFilter], frame: &[u8]) -> u32 {
        let load = |off: usize, size: u16| -> Option<u32> {
            match size {
                B => frame.get(off).map(|b| *b as u32),
                H => frame
                    .get(off..off + 2)
                    .map(|b| u16::from_be_bytes([b[0], b[1]]) as u32),
                _ => frame
                    .get(off..off + 4)
                    .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]])),
            }
        };

        let (mut a, mut x, mut pc) = (0u32, 0u32, 0usize);
        loop {
            let ins = prog[pc];
            let class = ins.code & 0x07;
            let size = ins.code & 0x18;
            let mode = ins.code & 0xe0;
            match class {
                RET => return ins.k,
                LD => {
                    let v = match mode {
                        ABS => load(ins.k as usize, size),
                        IND => load(x as usize + ins.k as usize, size),
                        _ => None,
                    };
                    match v {
                        Some(v) => a = v,
                        None => return 0,
                    }
                    pc += 1;
                }
                LDX => {
                    // Only BPF_LDX | BPF_B | BPF_MSH is emitted.
                    match frame.get(ins.k as usize) {
                        Some(b) => x = 4 * ((*b & 0x0f) as u32),
                        None => return 0,
                    }
                    pc += 1;
                }
                JMP => {
                    // Only BPF_JMP | BPF_JEQ | BPF_K is emitted.
                    let step = if a == ins.k { ins.jt } else { ins.jf } as usize;
                    pc += 1 + step;
                }
                _ => return 0,
            }
        }
    }

    // --- frame builders (mirroring capture::parse's test frames) --------------

    const ETH_IPV4: u16 = 0x0800;
    const ETH_IPV6: u16 = 0x86DD;
    const ETH_VLAN: u16 = 0x8100;
    const SYN: u8 = 0x02;

    fn eth(ethertype: u16) -> Vec<u8> {
        let mut f = vec![
            0x52, 0x54, 0, 0x11, 0x22, 0x33, 0x52, 0x54, 0, 0x44, 0x55, 0x66,
        ];
        f.extend_from_slice(&ethertype.to_be_bytes());
        f
    }

    /// IPv4 header with a given IHL (in 32-bit words; 5 = no options).
    fn ipv4(protocol: u8, ihl: u8) -> Vec<u8> {
        let mut h = vec![0x40 | (ihl & 0x0f), 0x00, 0x00, 0x00];
        h.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // id, flags+frag=0
        h.extend_from_slice(&[0x40, protocol, 0x00, 0x00]); // ttl, proto, checksum
        h.extend_from_slice(&[10, 0, 0, 7]); // source
        h.extend_from_slice(&[10, 0, 0, 1]); // destination
        h.resize(ihl as usize * 4, 0); // pad out any options
        h
    }

    fn ipv6(next_header: u8) -> Vec<u8> {
        let mut h = vec![0x60, 0x00, 0x00, 0x00, 0x00, 0x00, next_header, 0x40];
        h.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // src
        h.extend_from_slice(&[0xff; 16]); // dst
        h
    }

    fn tcp(dst_port: u16, flags: u8) -> Vec<u8> {
        let mut h = vec![0x30, 0x39]; // source port 12345
        h.extend_from_slice(&dst_port.to_be_bytes());
        h.extend_from_slice(&[0u8; 8]); // seq + ack
        h.push(0x50); // data offset 5
        h.push(flags);
        h.extend_from_slice(&[0u8; 6]);
        h
    }

    fn udp(dst_port: u16) -> Vec<u8> {
        let mut h = vec![0x30, 0x39];
        h.extend_from_slice(&dst_port.to_be_bytes());
        h.extend_from_slice(&[0x00, 0x08, 0x00, 0x00]);
        h
    }

    fn frame(parts: &[Vec<u8>]) -> Vec<u8> {
        parts.iter().flatten().copied().collect()
    }

    fn accepts(prog: &[SockFilter], frame: &[u8]) -> bool {
        run(prog, frame) != 0
    }

    // --- structural -----------------------------------------------------------

    #[test]
    fn empty_ports_means_no_filter() {
        assert!(build_filter(&[]).is_none());
    }

    #[test]
    fn too_many_ports_means_no_filter() {
        let ports: Vec<u16> = (1..=(MAX_FILTER_PORTS as u16 + 1)).collect();
        assert!(build_filter(&ports).is_none());
    }

    #[test]
    fn program_is_well_formed() {
        // Every forward jump must land within the program and end at a RET.
        let prog = build_filter(&[7000, 8000, 9000]).unwrap();
        assert_eq!(prog.len(), 16 + 2 * 3);
        for (idx, ins) in prog.iter().enumerate() {
            let max = (idx + 1 + ins.jt.max(ins.jf) as usize).max(idx + 1);
            assert!(max <= prog.len(), "jump out of bounds at {idx}");
        }
        let last = prog.len() - 1;
        assert_eq!(prog[last].code, RET | K);
        assert_eq!(prog[last].k, 0); // drop
        assert_eq!(prog[last - 1].k, ACCEPT); // accept
    }

    #[test]
    fn max_ports_offsets_stay_in_u8_range() {
        // The binding constraint: build must succeed at exactly the cap.
        let ports: Vec<u16> = (1..=MAX_FILTER_PORTS as u16).collect();
        assert!(build_filter(&ports).is_some());
    }

    // --- semantics ------------------------------------------------------------

    #[test]
    fn ipv4_tcp_syn_to_door_port_is_accepted() {
        let prog = build_filter(&[7000]).unwrap();
        let f = frame(&[eth(ETH_IPV4), ipv4(6, 5), tcp(7000, SYN)]);
        assert!(accepts(&prog, &f));
    }

    #[test]
    fn ipv4_tcp_to_non_door_port_is_dropped() {
        let prog = build_filter(&[7000]).unwrap();
        let f = frame(&[eth(ETH_IPV4), ipv4(6, 5), tcp(22, SYN)]);
        assert!(!accepts(&prog, &f));
    }

    #[test]
    fn ipv4_udp_to_door_port_is_accepted_other_dropped() {
        let prog = build_filter(&[5353, 7000]).unwrap();
        assert!(accepts(
            &prog,
            &frame(&[eth(ETH_IPV4), ipv4(17, 5), udp(5353)])
        ));
        assert!(!accepts(
            &prog,
            &frame(&[eth(ETH_IPV4), ipv4(17, 5), udp(1234)])
        ));
    }

    #[test]
    fn ipv4_options_are_handled_via_ihl() {
        // IHL = 6 (one 32-bit option word) shifts the L4 header by 4 bytes; the
        // MSH/IND load must follow it to still find the port.
        let prog = build_filter(&[7000]).unwrap();
        let f = frame(&[eth(ETH_IPV4), ipv4(6, 6), tcp(7000, SYN)]);
        assert!(accepts(&prog, &f));
    }

    #[test]
    fn ipv6_tcp_to_door_port_is_accepted_other_dropped() {
        let prog = build_filter(&[9000]).unwrap();
        assert!(accepts(
            &prog,
            &frame(&[eth(ETH_IPV6), ipv6(6), tcp(9000, SYN)])
        ));
        assert!(!accepts(
            &prog,
            &frame(&[eth(ETH_IPV6), ipv6(6), tcp(443, SYN)])
        ));
    }

    #[test]
    fn ipv6_with_extension_header_is_accepted_conservatively() {
        // next-header = Hop-by-Hop (0), not TCP/UDP: we can't walk the chain in
        // cBPF, so the frame is accepted regardless of the eventual port.
        let prog = build_filter(&[9000]).unwrap();
        let mut hbh = vec![6u8, 0x00];
        hbh.extend_from_slice(&[0u8; 6]);
        let f = frame(&[eth(ETH_IPV6), ipv6(0), hbh, tcp(443, SYN)]);
        assert!(accepts(&prog, &f), "ext-header frame must not be dropped");
    }

    #[test]
    fn in_payload_vlan_is_accepted_conservatively() {
        // An in-payload 802.1Q tag shifts the IP header; we accept and let
        // userspace peel it rather than risk a false negative.
        let prog = build_filter(&[7000]).unwrap();
        let mut f = eth(ETH_VLAN);
        f.extend_from_slice(&[0x00, 0x64]); // VLAN TCI (vid 100)
        f.extend_from_slice(&ETH_IPV4.to_be_bytes()); // inner ethertype
        f.extend(frame(&[ipv4(6, 5), tcp(7000, SYN)]));
        assert!(accepts(&prog, &f));
    }

    #[test]
    fn non_ip_frame_is_dropped() {
        let prog = build_filter(&[7000]).unwrap();
        assert!(!accepts(&prog, &eth(0x0806))); // ARP
    }

    #[test]
    fn truncated_frame_is_dropped_not_panicking() {
        let prog = build_filter(&[7000]).unwrap();
        // IPv4 ethertype but the L4 header is cut off: the indexed port load is
        // out of bounds, which the kernel (and our interpreter) treat as a drop.
        let f = frame(&[eth(ETH_IPV4), ipv4(6, 5), vec![0u8; 2]]);
        assert!(!accepts(&prog, &f));
    }
}
