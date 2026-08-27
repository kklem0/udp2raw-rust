//! Linux socket layer.

pub mod addr;
pub mod bpf;
pub mod lower_level;
pub mod raw;

use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};

pub use crate::types::{Syscalls, cpu_has_lse};

static SINGLE_SYSCALLS: AtomicBool = AtomicBool::new(false);

/// Select the syscall flavour for the whole process (call once at startup); returns the
/// resolved choice.
pub fn set_syscalls(mode: Syscalls) -> Syscalls {
    let r = mode.resolve();
    SINGLE_SYSCALLS.store(r == Syscalls::Single, Ordering::Relaxed);
    r
}

fn single_syscalls() -> bool {
    SINGLE_SYSCALLS.load(Ordering::Relaxed)
}

/// A reusable `recvmmsg` batch: `n` buffers plus one source address per message.
/// `A` is the sockaddr type to fill (`libc::sockaddr_ll` for AF_PACKET, `sockaddr_storage`
/// for UDP).
pub struct RecvBatch<A: Copy> {
    pub bufs: Vec<Vec<u8>>,
    pub lens: Vec<usize>,
    pub addrs: Vec<A>,
    iovs: Vec<libc::iovec>,
    msgs: Vec<libc::mmsghdr>,
}

impl<A: Copy> Default for RecvBatch<A> {
    fn default() -> Self {
        RecvBatch { bufs: Vec::new(), lens: Vec::new(), addrs: Vec::new(), iovs: Vec::new(), msgs: Vec::new() }
    }
}

impl<A: Copy> RecvBatch<A> {
    pub fn new(n: usize, buf_size: usize) -> Self {
        // SAFETY: A is a plain C sockaddr struct; all-zero is a valid value.
        let zero: A = unsafe { std::mem::zeroed() };
        RecvBatch {
            bufs: (0..n).map(|_| vec![0u8; buf_size]).collect(),
            lens: vec![0; n],
            addrs: vec![zero; n],
            iovs: (0..n).map(|_| libc::iovec { iov_base: std::ptr::null_mut(), iov_len: 0 }).collect(),
            msgs: (0..n).map(|_| unsafe { std::mem::zeroed() }).collect(),
        }
    }

    pub fn capacity(&self) -> usize {
        self.bufs.len()
    }

    /// Receive up to `capacity()` datagrams without blocking; returns how many arrived
    /// (0 when the socket is empty). `lens[i]` is the received length of `bufs[i]`
    /// (truncated to the buffer size, like `recvfrom`).
    pub fn recv(&mut self, fd: RawFd) -> io::Result<usize> {
        let n = self.bufs.len();
        if n == 0 {
            return Ok(0);
        }
        if single_syscalls() {
            return self.recv_single(fd);
        }
        for i in 0..n {
            self.iovs[i].iov_base = self.bufs[i].as_mut_ptr() as *mut libc::c_void;
            self.iovs[i].iov_len = self.bufs[i].len();
            let h = &mut self.msgs[i].msg_hdr;
            h.msg_name = &mut self.addrs[i] as *mut A as *mut libc::c_void;
            h.msg_namelen = std::mem::size_of::<A>() as libc::socklen_t;
            h.msg_iov = &mut self.iovs[i];
            h.msg_iovlen = 1;
            h.msg_control = std::ptr::null_mut();
            h.msg_controllen = 0;
            h.msg_flags = 0;
            self.msgs[i].msg_len = 0;
        }
        let r = unsafe { libc::recvmmsg(fd, self.msgs.as_mut_ptr(), n as libc::c_uint, libc::MSG_DONTWAIT, std::ptr::null_mut()) };
        if r < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::Interrupted {
                return Ok(0);
            }
            return Err(e);
        }
        for i in 0..r as usize {
            self.lens[i] = self.msgs[i].msg_len as usize;
        }
        Ok(r as usize)
    }

    /// Same contract as [`recv`](Self::recv) with one `recvfrom` per datagram: stops at the
    /// first `EAGAIN` (or, after at least one datagram, at any error, which the next call
    /// reports again).
    fn recv_single(&mut self, fd: RawFd) -> io::Result<usize> {
        let n = self.bufs.len();
        let mut got = 0usize;
        while got < n {
            let mut alen = std::mem::size_of::<A>() as libc::socklen_t;
            let buf = &mut self.bufs[got];
            let r = unsafe {
                libc::recvfrom(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), libc::MSG_DONTWAIT, &mut self.addrs[got] as *mut A as *mut libc::sockaddr, &mut alen)
            };
            if r < 0 {
                let e = io::Error::last_os_error();
                if got > 0 || e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::Interrupted {
                    break;
                }
                return Err(e);
            }
            self.lens[got] = r as usize;
            got += 1;
        }
        Ok(got)
    }
}

/// Destination of an outgoing packet.
#[derive(Clone, Copy)]
pub enum TxDst {
    /// Raw IP packet (header included) to this host via an `IPPROTO_RAW` socket.
    Ip(IpAddr),
    /// UDP datagram to this peer.
    Sock(SocketAddr),
    /// Layer-2 frame (`--lower-level`).
    L2(libc::sockaddr_ll),
}

/// One queued outgoing packet: the bytes are `buf[off..]`.
pub struct TxPacket {
    pub buf: Vec<u8>,
    pub off: usize,
    pub dst: TxDst,
}

/// Scratch space reused across `sendmmsg` calls.
#[derive(Default)]
pub struct SendScratch {
    addrs: Vec<libc::sockaddr_storage>,
    iovs: Vec<libc::iovec>,
    msgs: Vec<libc::mmsghdr>,
}

pub const SEND_CHUNK: usize = 64;

impl SendScratch {
    fn ensure(&mut self, n: usize) {
        if self.addrs.len() < n {
            self.addrs.resize_with(n, || unsafe { std::mem::zeroed() });
            self.iovs.resize_with(n, || libc::iovec { iov_base: std::ptr::null_mut(), iov_len: 0 });
            self.msgs.resize_with(n, || unsafe { std::mem::zeroed() });
        }
    }
}

/// Fill `out` with the sockaddr for `dst`; returns its length.
fn fill_addr(dst: &TxDst, out: &mut libc::sockaddr_storage) -> libc::socklen_t {
    match *dst {
        TxDst::Ip(ip) => {
            let (sa, l) = addr::to_sockaddr(SocketAddr::new(ip, 0));
            *out = sa;
            l
        }
        TxDst::Sock(a) => {
            let (sa, l) = addr::to_sockaddr(a);
            *out = sa;
            l
        }
        TxDst::L2(ll) => {
            unsafe {
                std::ptr::copy_nonoverlapping(&ll as *const _ as *const u8, out as *mut _ as *mut u8, std::mem::size_of::<libc::sockaddr_ll>());
            }
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t
        }
    }
}

/// Send all packets: one `sendmmsg` per chunk of [`SEND_CHUNK`], or one `sendto` per packet
/// (see [`Syscalls`]). A packet the kernel refuses is skipped (UDP semantics); a full socket
/// buffer drops the rest of the chunk. Returns how many were accepted.
pub fn send_batch(fd: RawFd, pkts: &[TxPacket], sc: &mut SendScratch) -> usize {
    if single_syscalls() {
        return send_single(fd, pkts, sc);
    }
    let mut accepted = 0usize;
    for chunk in pkts.chunks(SEND_CHUNK) {
        let n = chunk.len();
        sc.ensure(n);
        for (i, p) in chunk.iter().enumerate() {
            let alen = fill_addr(&p.dst, &mut sc.addrs[i]);
            sc.iovs[i].iov_base = p.buf[p.off..].as_ptr() as *mut libc::c_void;
            sc.iovs[i].iov_len = p.buf.len() - p.off;
            let h = &mut sc.msgs[i].msg_hdr;
            h.msg_name = &mut sc.addrs[i] as *mut _ as *mut libc::c_void;
            h.msg_namelen = alen;
            h.msg_iov = &mut sc.iovs[i];
            h.msg_iovlen = 1;
            h.msg_control = std::ptr::null_mut();
            h.msg_controllen = 0;
            h.msg_flags = 0;
            sc.msgs[i].msg_len = 0;
        }
        let mut done = 0usize;
        while done < n {
            let r = unsafe { libc::sendmmsg(fd, sc.msgs.as_mut_ptr().add(done), (n - done) as libc::c_uint, libc::MSG_DONTWAIT) };
            if r < 0 {
                let e = io::Error::last_os_error();
                match e.kind() {
                    io::ErrorKind::Interrupted => continue,
                    // socket buffer full: the rest of this chunk is dropped
                    io::ErrorKind::WouldBlock => break,
                    _ => {
                        log::trace!("sendmmsg failed: {e}");
                        done += 1; // skip the offending message, keep going
                        continue;
                    }
                }
            }
            done += r as usize;
            accepted += r as usize;
        }
    }
    accepted
}

fn send_single(fd: RawFd, pkts: &[TxPacket], sc: &mut SendScratch) -> usize {
    sc.ensure(1);
    let mut accepted = 0usize;
    for p in pkts {
        let alen = fill_addr(&p.dst, &mut sc.addrs[0]);
        let data = &p.buf[p.off..];
        loop {
            let r = unsafe { libc::sendto(fd, data.as_ptr() as *const libc::c_void, data.len(), libc::MSG_DONTWAIT, &sc.addrs[0] as *const _ as *const libc::sockaddr, alen) };
            if r >= 0 {
                accepted += 1;
                break;
            }
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock => return accepted,
                _ => {
                    log::trace!("sendto failed: {e}");
                    break;
                }
            }
        }
    }
    accepted
}

/// A non-blocking UDP socket connected to `remote`, with the configured buffer sizes
/// (`address_t::new_connected_udp_fd`).
pub fn new_connected_udp(remote: SocketAddr, buf_size: usize, force: bool) -> io::Result<UdpSocket> {
    let bind: SocketAddr = if remote.is_ipv6() { "[::]:0".parse().unwrap() } else { "0.0.0.0:0".parse().unwrap() };
    let s = UdpSocket::bind(bind)?;
    s.set_nonblocking(true)?;
    addr::set_buf_size(s.as_raw_fd(), buf_size, force)?;
    s.connect(remote)?;
    Ok(s)
}

/// The client's listening UDP socket.
pub fn bind_udp_listener(local: SocketAddr, buf_size: usize, force: bool) -> io::Result<UdpSocket> {
    let s = UdpSocket::bind(local)?;
    addr::set_buf_size(s.as_raw_fd(), buf_size, force)?;
    s.set_nonblocking(true)?;
    Ok(s)
}
