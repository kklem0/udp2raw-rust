//! sockaddr conversions, interface lookups, and the "reserve a port" helpers.

use crate::types::RawMode;
use crate::util::fast_random_u32;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd, RawFd};

/// Convert a `SocketAddr` into a `sockaddr_storage` + length for libc calls.
pub fn to_sockaddr(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match addr {
        SocketAddr::V4(a) => {
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: a.port().to_be(),
                sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(a.ip().octets()) },
                sin_zero: [0; 8],
            };
            unsafe { std::ptr::copy_nonoverlapping(&sin as *const _ as *const u8, &mut storage as *mut _ as *mut u8, std::mem::size_of::<libc::sockaddr_in>()) };
            (storage, std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t)
        }
        SocketAddr::V6(a) => {
            let sin6 = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: a.port().to_be(),
                sin6_flowinfo: a.flowinfo(),
                sin6_addr: libc::in6_addr { s6_addr: a.ip().octets() },
                sin6_scope_id: a.scope_id(),
            };
            unsafe { std::ptr::copy_nonoverlapping(&sin6 as *const _ as *const u8, &mut storage as *mut _ as *mut u8, std::mem::size_of::<libc::sockaddr_in6>()) };
            (storage, std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t)
        }
    }
}

/// Convert a `sockaddr_storage` back to a `SocketAddr`.
pub fn from_sockaddr(storage: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            let sin: &libc::sockaddr_in = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes()), u16::from_be(sin.sin_port))))
        }
        libc::AF_INET6 => {
            let sin6: &libc::sockaddr_in6 = unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
            Some(SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(sin6.sin6_addr.s6_addr), u16::from_be(sin6.sin6_port), sin6.sin6_flowinfo, sin6.sin6_scope_id)))
        }
        _ => None,
    }
}

pub fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub fn setsockopt_int(fd: RawFd, level: libc::c_int, name: libc::c_int, value: libc::c_int) -> io::Result<()> {
    let r = unsafe { libc::setsockopt(fd, level, name, &value as *const _ as *const libc::c_void, std::mem::size_of::<libc::c_int>() as libc::socklen_t) };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// `set_buf_size`: SO_SNDBUF/SO_RCVBUF, or the FORCE variants (needs CAP_NET_ADMIN).
pub fn set_buf_size(fd: RawFd, size: usize, force: bool) -> io::Result<()> {
    let v = size as libc::c_int;
    if force {
        setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_SNDBUFFORCE, v)?;
        setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUFFORCE, v)?;
    } else {
        setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_SNDBUF, v)?;
        setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, v)?;
    }
    Ok(())
}

/// The source address the kernel would use to reach `remote` (connect a UDP socket, read
/// back its local address) — `get_src_adress2`.
pub fn get_src_addr(remote: SocketAddr) -> io::Result<IpAddr> {
    get_src_addr_dev(remote, None)
}

/// The source address the kernel picks for `remote`, optionally as seen from `dev`
/// (`SO_BINDTODEVICE` on the probe socket, like the raw sender with `--underlay-dev`).
pub fn get_src_addr_dev(remote: SocketAddr, dev: Option<&str>) -> io::Result<IpAddr> {
    let bind: SocketAddr = if remote.is_ipv6() { "[::]:0".parse().unwrap() } else { "0.0.0.0:0".parse().unwrap() };
    let s = std::net::UdpSocket::bind(bind)?;
    if let Some(dev) = dev {
        bind_to_device(s.as_raw_fd(), dev)?;
    }
    s.connect(remote)?;
    Ok(s.local_addr()?.ip())
}

/// `SO_BINDTODEVICE`: route lookups and packets of this socket stay on `dev`.
pub fn bind_to_device(fd: RawFd, dev: &str) -> io::Result<()> {
    let bytes = dev.as_bytes();
    if bytes.is_empty() || bytes.len() >= libc::IFNAMSIZ {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("bad interface name {dev}")));
    }
    let r = unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_BINDTODEVICE, bytes.as_ptr() as *const libc::c_void, bytes.len() as libc::socklen_t) };
    if r != 0 {
        let e = io::Error::last_os_error();
        return Err(io::Error::new(e.kind(), format!("SO_BINDTODEVICE {dev}: {e}")));
    }
    Ok(())
}

pub fn if_nametoindex(name: &str) -> io::Result<i32> {
    let c = std::ffi::CString::new(name).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad interface name"))?;
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(idx as i32)
    }
}

/// Whether the interface uses ARP (tun/ppp interfaces are NOARP → zero destination MAC).
pub fn interface_has_arp(name: &str) -> io::Result<bool> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let bytes = name.as_bytes();
    if bytes.len() >= ifr.ifr_name.len() {
        unsafe { libc::close(fd) };
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "interface name is too long"));
    }
    for (i, b) in bytes.iter().enumerate() {
        ifr.ifr_name[i] = *b as libc::c_char;
    }
    // `libc::Ioctl` is `c_ulong` for glibc targets but `c_int` for musl. Let the
    // function signature infer the request type so this stays portable across both.
    let r = unsafe { libc::ioctl(fd, libc::SIOCGIFFLAGS as _, &mut ifr) };
    let err = io::Error::last_os_error();
    unsafe { libc::close(fd) };
    if r < 0 {
        return Err(err);
    }
    let flags = unsafe { ifr.ifr_ifru.ifru_flags } as libc::c_int;
    Ok(flags & libc::IFF_NOARP == 0)
}

/// Create the "dummy" socket that reserves `addr` so no other program takes the port
/// (SOCK_STREAM + listen for faketcp, SOCK_DGRAM otherwise) — `try_to_list_and_bind2`.
pub fn bind_reserve(addr: SocketAddr, raw_mode: RawMode, easy_faketcp: bool) -> io::Result<RawFd> {
    let family = if addr.is_ipv6() { libc::AF_INET6 } else { libc::AF_INET };
    let ty = if raw_mode == RawMode::FakeTcp { libc::SOCK_STREAM } else { libc::SOCK_DGRAM };
    let fd = unsafe { libc::socket(family, ty | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let (sa, len) = to_sockaddr(addr);
    if unsafe { libc::bind(fd, &sa as *const _ as *const libc::sockaddr, len) } != 0 {
        let e = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(e);
    }
    if raw_mode == RawMode::FakeTcp && !easy_faketcp && unsafe { libc::listen(fd, libc::SOMAXCONN) } != 0 {
        let e = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(e);
    }
    Ok(fd)
}

/// Pick a random free port in 10000..65535 and reserve it — `client_bind_to_a_new_port2`.
/// Closes `old_fd` (the previous reservation) first.
pub fn bind_new_random_port(ip: IpAddr, raw_mode: RawMode, easy_faketcp: bool, old_fd: Option<RawFd>) -> io::Result<(RawFd, u16)> {
    if let Some(fd) = old_fd {
        unsafe { libc::close(fd) };
    }
    for _ in 0..1000 {
        let port = 10000 + (fast_random_u32() % (65535 - 10000)) as u16;
        match bind_reserve(SocketAddr::new(ip, port), raw_mode, easy_faketcp) {
            Ok(fd) => return Ok((fd, port)),
            Err(e) => log::debug!("bind fail: {e}"),
        }
    }
    Err(io::Error::new(io::ErrorKind::AddrInUse, "bind port fail"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sockaddr_roundtrip() {
        for s in ["1.2.3.4:5", "[fe80::1%3]:6", "[::1]:7"] {
            let a: SocketAddr = s.parse().unwrap();
            let (st, _) = to_sockaddr(a);
            assert_eq!(from_sockaddr(&st), Some(a));
        }
    }
}
