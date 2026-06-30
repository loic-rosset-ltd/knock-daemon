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
//! the systemd unit in `packaging/`); it is therefore, like the pcap backend, not
//! exercised in CI, but the generated filter program is unit-tested in `bpf`.

use std::ffi::CString;
use std::io::{Error, ErrorKind};
use std::mem;
use std::os::raw::c_void;
use std::time::Instant;

use anyhow::{anyhow, bail, Context, Result};

use crate::matcher::PacketEvent;

use super::{bpf, parse, Capture};

/// EtherType passed to `socket()`; `ETH_P_ALL` delivers every frame.
const ETH_P_ALL: u16 = 0x0003;

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
    start: Instant,
}

impl AfPacketCapture {
    pub fn new(interface: Option<String>, ports: &[u16]) -> Self {
        let mut ports = ports.to_vec();
        ports.sort_unstable();
        ports.dedup();
        Self {
            interface,
            ports,
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

        let mut buf = [0u8; 65536];
        loop {
            // SAFETY: recv into a buffer we own, bounded by its length.
            let n = unsafe { libc::recv(socket.0, buf.as_mut_ptr() as *mut c_void, buf.len(), 0) };
            if n < 0 {
                let err = Error::last_os_error();
                if err.kind() == ErrorKind::Interrupted {
                    continue;
                }
                return Err(anyhow!(err)).context("recv on AF_PACKET socket");
            }
            let at_ms = self.start.elapsed().as_millis() as u64;
            if let Some(ev) = parse::parse_ethernet(&buf[..n as usize], at_ms) {
                if self.accepts(ev.port) {
                    sink(ev);
                }
            }
        }
    }
}
