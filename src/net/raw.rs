//! The two raw sockets: an `AF_PACKET/SOCK_DGRAM` receiver with a BPF filter and an
//! `IPPROTO_RAW` (or `AF_PACKET` when `--lower-level`) sender — `init_raw_socket`,
//! `init_filter`, `send_raw_packet`, `pre_recv_raw_packet`.

use super::addr::{bind_to_device, if_nametoindex, set_nonblocking, setsockopt_int, to_sockaddr};
use super::bpf;
use crate::config::Config;
use crate::types::RawMode;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::RawFd;

pub struct RawSockets {
    pub send_fd: RawFd,
    pub recv_fd: RawFd,
    pub is_v6: bool,
    pub lower_level: bool,
}

impl RawSockets {
    pub fn open(cfg: &Config) -> io::Result<RawSockets> {
        let is_v6 = cfg.raw_is_v6();
        let family = if is_v6 { libc::AF_INET6 } else { libc::AF_INET };
        let lower_level = cfg.lower_level.is_some();
        let eth_p = if is_v6 { libc::ETH_P_IPV6 } else { libc::ETH_P_IP };

        let send_fd = if !lower_level {
            unsafe { libc::socket(family, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::IPPROTO_RAW) }
        } else {
            unsafe { libc::socket(libc::PF_PACKET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, (libc::ETH_P_IP as u16).to_be() as libc::c_int) }
        };
        if send_fd < 0 {
            return Err(io::Error::other(format!("Failed to create raw_send_fd: {}", io::Error::last_os_error())));
        }
        // send-only socket: no receive buffer needed
        let _ = setsockopt_int(send_fd, libc::SOL_SOCKET, libc::SO_RCVBUF, 0);
        let sndbuf_opt = if cfg.force_socket_buf { libc::SO_SNDBUFFORCE } else { libc::SO_SNDBUF };
        setsockopt_int(send_fd, libc::SOL_SOCKET, sndbuf_opt, cfg.socket_buf_size as libc::c_int)
            .map_err(|e| io::Error::new(e.kind(), format!("SO_SNDBUF fail socket_buf_size={} errno={}", cfg.socket_buf_size, e)))?;

        let recv_fd = unsafe { libc::socket(libc::PF_PACKET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, (eth_p as u16).to_be() as libc::c_int) };
        if recv_fd < 0 {
            return Err(io::Error::other(format!("Failed to create raw_recv_fd: {}", io::Error::last_os_error())));
        }
        let rcvbuf_opt = if cfg.force_socket_buf { libc::SO_RCVBUFFORCE } else { libc::SO_RCVBUF };
        setsockopt_int(recv_fd, libc::SOL_SOCKET, rcvbuf_opt, cfg.socket_buf_size as libc::c_int)
            .map_err(|e| io::Error::new(e.kind(), format!("SO_RCVBUF fail socket_buf_size={} errno={}", cfg.socket_buf_size, e)))?;

        let s = RawSockets { send_fd, recv_fd, is_v6, lower_level };
        // --underlay-dev: the sender's route lookups stay on the native interface, and the
        // receiver filters only that interface unless --dev says otherwise
        if let Some(dev) = &cfg.underlay_dev {
            if !lower_level {
                bind_to_device(send_fd, dev).map_err(|e| io::Error::new(e.kind(), format!("bind raw sender to underlay [{dev}] failed: {e}")))?;
                log::info!("raw sender bound to underlay device {dev}");
            }
        }
        match (&cfg.dev, &cfg.underlay_dev) {
            (Some(dev), _) => s.bind_dev(dev)?,
            (None, Some(dev)) => s.bind_dev(dev)?,
            (None, None) => {}
        }
        set_nonblocking(send_fd)?;
        set_nonblocking(recv_fd)?;
        Ok(s)
    }

    /// `--dev`: bind the receive socket to one interface so the BPF filter does not run on
    /// every packet of every interface (loopback traffic between the local app and udp2raw!).
    fn bind_dev(&self, dev: &str) -> io::Result<()> {
        let index = if_nametoindex(dev).map_err(|e| io::Error::new(e.kind(), format!("bind to dev [{dev}] failed: {e}")))?;
        log::info!("ifname:{dev}  ifindex:{index}");
        let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = ((if self.is_v6 { libc::ETH_P_IPV6 } else { libc::ETH_P_IP }) as u16).to_be();
        sll.sll_ifindex = index;
        let r = unsafe { libc::bind(self.recv_fd, &sll as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t) };
        if r != 0 {
            return Err(io::Error::other(format!("bind to dev [{dev}] failed: {}", io::Error::last_os_error())));
        }
        Ok(())
    }

    /// Attach (replacing any previous) the kernel filter for `port` — `init_filter`.
    pub fn attach_filter(&self, raw_mode: RawMode, port: u16, disabled: bool) -> io::Result<()> {
        if disabled {
            return Ok(());
        }
        let mut prog: Vec<libc::sock_filter> = bpf::program(raw_mode, self.is_v6, port)
            .into_iter()
            .map(|i| libc::sock_filter { code: i.code, jt: i.jt, jf: i.jf, k: i.k })
            .collect();
        let dummy: libc::c_int = 0;
        unsafe {
            // in case a filter is already attached
            libc::setsockopt(self.recv_fd, libc::SOL_SOCKET, libc::SO_DETACH_FILTER, &dummy as *const _ as *const libc::c_void, std::mem::size_of::<libc::c_int>() as libc::socklen_t);
        }
        let fprog = libc::sock_fprog { len: prog.len() as libc::c_ushort, filter: prog.as_mut_ptr() };
        let r = unsafe { libc::setsockopt(self.recv_fd, libc::SOL_SOCKET, libc::SO_ATTACH_FILTER, &fprog as *const _ as *const libc::c_void, std::mem::size_of::<libc::sock_fprog>() as libc::socklen_t) };
        if r != 0 {
            return Err(io::Error::other(format!("error set fiter: {}", io::Error::last_os_error())));
        }
        Ok(())
    }

    /// Send a complete IP packet (header included) to `dst` via the IPPROTO_RAW socket.
    pub fn send_ip(&self, packet: &[u8], dst: IpAddr) -> io::Result<()> {
        let (sa, len) = to_sockaddr(SocketAddr::new(dst, 0));
        let r = unsafe { libc::sendto(self.send_fd, packet.as_ptr() as *const libc::c_void, packet.len(), 0, &sa as *const _ as *const libc::sockaddr, len) };
        if r < 0 {
            let e = io::Error::last_os_error();
            log::trace!("sendto failed: {e}");
            return Err(e);
        }
        Ok(())
    }

    /// Send a complete IP packet at layer 2 (`--lower-level`).
    pub fn send_l2(&self, packet: &[u8], addr: &libc::sockaddr_ll) -> io::Result<()> {
        let r = unsafe { libc::sendto(self.send_fd, packet.as_ptr() as *const libc::c_void, packet.len(), 0, addr as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t) };
        if r < 0 {
            let e = io::Error::last_os_error();
            log::trace!("sendto (l2) failed: {e}");
            return Err(e);
        }
        Ok(())
    }

    /// Receive up to a batch of packets (IP header first) with their link-layer sources.
    pub fn recv_batch(&self, b: &mut super::RecvBatch<libc::sockaddr_ll>) -> io::Result<usize> {
        b.recv(self.recv_fd)
    }

    /// Receive one packet (IP header first) and the link-layer source (for `--lower-level auto`).
    /// Returns `Ok(None)` when the socket has no more packets (EAGAIN).
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<Option<(usize, libc::sockaddr_ll)>> {
        let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
        let r = unsafe { libc::recvfrom(self.recv_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0, &mut sll as *mut _ as *mut libc::sockaddr, &mut len) };
        if r < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::Interrupted {
                return Ok(None);
            }
            return Err(e);
        }
        Ok(Some((r as usize, sll)))
    }
}

impl Drop for RawSockets {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.send_fd);
            libc::close(self.recv_fd);
        }
    }
}

/// Build the `sockaddr_ll` used for `--lower-level` sends.
pub fn make_sockaddr_ll(ifindex: i32, dest_mac: &[u8; 6]) -> libc::sockaddr_ll {
    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_ifindex = ifindex;
    sll.sll_halen = 6;
    sll.sll_protocol = (libc::ETH_P_IP as u16).to_be();
    sll.sll_addr[..6].copy_from_slice(dest_mac);
    sll
}

/// `handle_lower_level` (auto): reply to the link-layer address the packet came from.
pub fn reply_sockaddr_ll(recv: &libc::sockaddr_ll) -> libc::sockaddr_ll {
    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sll.sll_family = recv.sll_family;
    sll.sll_ifindex = recv.sll_ifindex;
    sll.sll_protocol = recv.sll_protocol;
    sll.sll_halen = recv.sll_halen;
    sll.sll_addr = recv.sll_addr;
    sll
}
