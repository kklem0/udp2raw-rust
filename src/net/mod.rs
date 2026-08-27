//! Linux socket layer.

pub mod addr;
pub mod bpf;
pub mod lower_level;
pub mod raw;

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;

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
