//! Pure-Rust live capture over a Linux `AF_PACKET` raw socket (feature
//! `capture-afpacket`, Linux only).
//!
//! This drops the libpcap C dependency: we open `socket(AF_PACKET, SOCK_RAW,
//! ETH_P_ALL)`, optionally bind it to one interface, and read raw Ethernet
//! frames straight from the kernel. Frame decoding — Ethernet/VLAN/IPv4/IPv6/
//! TCP-SYN/UDP — is the shared, unit-tested [`super::parse`] code, so this file
//! is only the socket plumbing.
//!
//! A kernel-side cBPF prefilter (`SO_ATTACH_FILTER`, built in [`super::bpf`])
//! drops irrelevant frames before they are copied to userspace, so the recv loop
//! only wakes for plausible knocks. It is a pure optimisation built to never drop
//! a frame userspace would accept (it accepts in-payload VLAN and IPv6 with
//! extension headers rather than risk a false negative), so the userspace
//! [`AfPacketCapture::accepts`] check below stays as the source of truth and the
//! backstop if the filter can't be attached. The socket needs `CAP_NET_RAW` (see
//! the systemd unit in `packaging/`), so unit tests can't open it; the generated
//! filter program is unit-tested in `bpf`, and the root `ci/wire-test.sh` job
//! exercises the whole backend — attach, capture, and the `PACKET_STATISTICS`
//! sampling below — against a live kernel over `lo`.
//!
//! The recv loop also samples the kernel's `PACKET_STATISTICS` (`tp_packets` /
//! `tp_drops`) every [`STATS_POLL_INTERVAL`] and reports the deltas to an
//! optional [`KernelStatsSink`], surfacing how many frames the kernel delivered
//! vs. dropped. A `SO_RCVTIMEO` on the socket guarantees the loop wakes to sample
//! even while the prefilter is dropping every frame.

use std::ffi::CString;
use std::io::{Error, ErrorKind};
use std::mem;
use std::os::raw::c_void;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};

use crate::matcher::PacketEvent;

use super::{bpf, parse, Capture, KernelStatsSink};

/// EtherType passed to `socket()`; `ETH_P_ALL` delivers every frame.
const ETH_P_ALL: u16 = 0x0003;

/// How often to sample the kernel's `PACKET_STATISTICS` and how long a starved
/// `recv` blocks before it wakes to take that sample. The two are tied together:
/// when the prefilter is dropping everything, no frame ever wakes `recv`, so the
/// receive timeout is the only thing that lets us observe the drops.
const STATS_POLL_INTERVAL: Duration = Duration::from_millis(250);

// The cBPF builder emits its own [`bpf::SockFilter`] (so it stays platform-free
// and unit-testable); we hand the program to the kernel as `libc::sock_filter`.
// That cast is only sound if the two have identical layout — assert it here so a
// libc change can never silently corrupt the attached program.
const _: () = assert!(
    mem::size_of::<bpf::SockFilter>() == mem::size_of::<libc::sock_filter>()
        && mem::align_of::<bpf::SockFilter>() == mem::align_of::<libc::sock_filter>()
);

pub struct AfPacketCapture {
    interface: Option<String>,
    /// Sorted union of every door's ports; empty means "accept all".
    ports: Vec<u16>,
    /// Optional sink for kernel-side capture counters (PACKET_STATISTICS).
    kstats: Option<Arc<dyn KernelStatsSink>>,
    start: Instant,
}

impl AfPacketCapture {
    pub fn new(
        interface: Option<String>,
        ports: &[u16],
        kstats: Option<Arc<dyn KernelStatsSink>>,
    ) -> Self {
        let mut ports = ports.to_vec();
        ports.sort_unstable();
        ports.dedup();
        Self {
            interface,
            ports,
            kstats,
            start: Instant::now(),
        }
    }

    fn accepts(&self, port: u16) -> bool {
        self.ports.is_empty() || self.ports.binary_search(&port).is_ok()
    }

    /// Attach the kernel cBPF prefilter so irrelevant frames are dropped before
    /// they reach userspace. Best-effort: if there's no useful filter to build
    /// (no ports, or too many) or the kernel rejects it, we log and carry on —
    /// `accepts` still filters in userspace, so correctness never depends on it.
    ///
    /// Frames that arrived before the filter was attached bypass it, but those
    /// too are caught by the userspace check, so the brief startup window only
    /// costs a little extra work, never a wrong accept.
    fn attach_prefilter(&self, fd: i32) {
        let Some(mut prog) = bpf::build_filter(&self.ports) else {
            return;
        };
        let fprog = libc::sock_fprog {
            len: prog.len() as u16,
            // Layout-identical to libc::sock_filter (asserted above).
            filter: prog.as_mut_ptr() as *mut libc::sock_filter,
        };
        // SAFETY: setsockopt copies the program in during the call; `prog` and
        // `fprog` outlive it. The option/level/size are the documented contract.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ATTACH_FILTER,
                &fprog as *const libc::sock_fprog as *const c_void,
                mem::size_of::<libc::sock_fprog>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            tracing::warn!(
                error = %Error::last_os_error(),
                "attaching cBPF prefilter failed; relying on userspace filtering"
            );
        } else {
            tracing::debug!(instructions = prog.len(), "attached cBPF prefilter");
        }
    }

    /// Set a receive timeout so `recv` wakes every [`STATS_POLL_INTERVAL`] even
    /// with no traffic, letting the loop sample kernel stats while the prefilter
    /// is dropping every frame. Best-effort — only relevant when reporting stats.
    fn set_poll_timeout(&self, fd: i32) {
        if self.kstats.is_none() {
            return;
        }
        let tv = libc::timeval {
            tv_sec: STATS_POLL_INTERVAL.as_secs() as libc::time_t,
            tv_usec: STATS_POLL_INTERVAL.subsec_micros() as libc::suseconds_t,
        };
        // SAFETY: SO_RCVTIMEO takes a `struct timeval` of the size we pass.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const libc::timeval as *const c_void,
                mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            tracing::warn!(
                error = %Error::last_os_error(),
                "setting recv timeout failed; kernel stats will only update on traffic"
            );
        }
    }

    /// If a sink is configured and at least [`STATS_POLL_INTERVAL`] has passed,
    /// read-and-reset the kernel's `PACKET_STATISTICS` and report the delta.
    fn maybe_poll_stats(&self, fd: i32, last_poll: &mut Instant) {
        let Some(sink) = &self.kstats else { return };
        if last_poll.elapsed() < STATS_POLL_INTERVAL {
            return;
        }
        let (packets, drops) = poll_kernel_stats(fd);
        if packets != 0 || drops != 0 {
            sink.add_kernel_stats(packets, drops);
        }
        *last_poll = Instant::now();
    }
}

/// Read and reset the socket's `PACKET_STATISTICS`, returning the `(tp_packets,
/// tp_drops)` delta since the previous read. Per `packet(7)`, `tp_packets` is the
/// total that passed the filter (including the `tp_drops` shed for a full buffer),
/// and reading resets both — so each call yields only what accrued since the last
/// one. Best-effort: on error returns `(0, 0)`, dropping a single sample rather
/// than failing the capture.
fn poll_kernel_stats(fd: i32) -> (u64, u64) {
    // SAFETY: `tpacket_stats` is a plain-old-data struct; zeroing it is valid.
    let mut stats: libc::tpacket_stats = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<libc::tpacket_stats>() as libc::socklen_t;
    // SAFETY: getsockopt writes at most `len` bytes into `stats` and updates
    // `len`; PACKET_STATISTICS at SOL_PACKET is the documented contract.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_PACKET,
            libc::PACKET_STATISTICS,
            &mut stats as *mut libc::tpacket_stats as *mut c_void,
            &mut len,
        )
    };
    if rc < 0 {
        (0, 0)
    } else {
        (stats.tp_packets as u64, stats.tp_drops as u64)
    }
}

/// Owns the raw socket fd and closes it on drop.
struct Socket(i32);

impl Drop for Socket {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a valid fd we opened and no longer use.
        unsafe { libc::close(self.0) };
    }
}

impl Capture for AfPacketCapture {
    fn run(&mut self, sink: &mut dyn FnMut(PacketEvent)) -> Result<()> {
        // SAFETY: plain socket(2); we check the return value.
        let fd =
            unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, (ETH_P_ALL.to_be()) as i32) };
        if fd < 0 {
            return Err(anyhow!(Error::last_os_error()))
                .context("opening AF_PACKET socket (need CAP_NET_RAW / root)");
        }
        let socket = Socket(fd);

        // Resolve the interface index (0 = all interfaces).
        let ifindex = match &self.interface {
            Some(name) => {
                let cname = CString::new(name.as_str()).context("interface name")?;
                // SAFETY: cname is a valid NUL-terminated string.
                let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
                if idx == 0 {
                    bail!("interface {name:?} not found");
                }
                idx as i32
            }
            None => 0,
        };

        // Bind to the interface/protocol.
        // SAFETY: zeroed sockaddr_ll is a valid all-interfaces binding.
        let mut sll: libc::sockaddr_ll = unsafe { mem::zeroed() };
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = ETH_P_ALL.to_be();
        sll.sll_ifindex = ifindex;
        // SAFETY: bind with a correctly sized sockaddr_ll.
        let rc = unsafe {
            libc::bind(
                socket.0,
                &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(anyhow!(Error::last_os_error())).context("binding AF_PACKET socket");
        }

        self.attach_prefilter(socket.0);
        self.set_poll_timeout(socket.0);

        let mut buf = [0u8; 65536];
        let mut last_poll = Instant::now();
        loop {
            // SAFETY: recv into a buffer we own, bounded by its length.
            let n = unsafe { libc::recv(socket.0, buf.as_mut_ptr() as *mut c_void, buf.len(), 0) };
            if n < 0 {
                let err = Error::last_os_error();
                match err.kind() {
                    ErrorKind::Interrupted => continue,
                    // SO_RCVTIMEO fired with no frame ready: not an error — fall
                    // through to the periodic stats poll, then block again.
                    ErrorKind::WouldBlock | ErrorKind::TimedOut => {}
                    _ => return Err(anyhow!(err)).context("recv on AF_PACKET socket"),
                }
            } else {
                let at_ms = self.start.elapsed().as_millis() as u64;
                if let Some(ev) = parse::parse_ethernet(&buf[..n as usize], at_ms) {
                    if self.accepts(ev.port) {
                        sink(ev);
                    }
                }
            }
            self.maybe_poll_stats(socket.0, &mut last_poll);
        }
    }
}
