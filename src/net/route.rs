//! Host routes for a relay address over the native underlay (`--underlay-dev`), talked to the
//! kernel directly over rtnetlink — no `ip` binary involved.
//!
//! Boxes that send everything through a VPN keep literal `/32` escape routes for the relay's
//! address; a freshly resolved address has none, and `SO_BINDTODEVICE` on the raw socket
//! only pins the interface — with no route for the destination through it the kernel
//! answers ENETUNREACH. So when the client adopts an address it installs
//! `<addr>/32 via <underlay gateway> dev <underlay>` (on-link when no gateway is known),
//! tagged with protocol [`RTPROT_UDP2RAW`] so that only routes this program added are ever
//! deleted again. Operator routes for the same address (other protocol/metric) coexist.

use std::io;
use std::net::Ipv4Addr;
use std::os::fd::RawFd;

/// `rtm_protocol` of the routes this program installs (a value no other daemon uses).
pub const RTPROT_UDP2RAW: u8 = 235;
/// Metric of the installed host routes (below the usual operator `/32` at 10).
pub const ROUTE_METRIC: u32 = 5;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RouteInfo {
    pub gateway: Option<Ipv4Addr>,
    pub oif: Option<u32>,
    pub prefsrc: Option<Ipv4Addr>,
}

const NLMSG_HDRLEN: usize = 16;
const RTMSG_LEN: usize = 12;

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Append one rtattr (header + payload, padded to 4 bytes).
fn push_attr(buf: &mut Vec<u8>, kind: u16, data: &[u8]) {
    let len = 4 + data.len();
    buf.extend_from_slice(&(len as u16).to_ne_bytes());
    buf.extend_from_slice(&kind.to_ne_bytes());
    buf.extend_from_slice(data);
    buf.resize(buf.len() + (align4(len) - len), 0);
}

/// `struct rtmsg`: family, dst_len, src_len, tos, table, protocol, scope, type, flags.
fn rtmsg(dst_len: u8, table: u8, protocol: u8, scope: u8, rtype: u8) -> [u8; RTMSG_LEN] {
    let mut m = [0u8; RTMSG_LEN];
    m[0] = libc::AF_INET as u8;
    m[1] = dst_len;
    m[4] = table;
    m[5] = protocol;
    m[6] = scope;
    m[7] = rtype;
    m
}

/// A complete netlink message: header + rtmsg + attributes.
fn message(msg_type: u16, flags: u16, seq: u32, body: &[u8]) -> Vec<u8> {
    let len = NLMSG_HDRLEN + body.len();
    let mut m = Vec::with_capacity(len);
    m.extend_from_slice(&(len as u32).to_ne_bytes());
    m.extend_from_slice(&msg_type.to_ne_bytes());
    m.extend_from_slice(&flags.to_ne_bytes());
    m.extend_from_slice(&seq.to_ne_bytes());
    m.extend_from_slice(&0u32.to_ne_bytes()); // pid: kernel fills the sender's port id
    m.extend_from_slice(body);
    m
}

struct Netlink {
    fd: RawFd,
    seq: u32,
}

impl Netlink {
    fn open() -> io::Result<Netlink> {
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_ROUTE) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        sa.nl_family = libc::AF_NETLINK as u16;
        if unsafe { libc::bind(fd, &sa as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t) } != 0 {
            let e = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(e);
        }
        let tv = libc::timeval { tv_sec: 2, tv_usec: 0 };
        unsafe {
            libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv as *const _ as *const libc::c_void, std::mem::size_of::<libc::timeval>() as libc::socklen_t);
        }
        Ok(Netlink { fd, seq: (std::process::id() << 8) | 1 })
    }

    /// Send one request and return the payloads of the RTM replies for it. An NLMSG_ERROR
    /// with a non-zero code becomes an `io::Error`; a zero code is the ACK.
    fn request(&mut self, msg_type: u16, flags: u16, body: &[u8]) -> io::Result<Vec<Vec<u8>>> {
        self.seq = self.seq.wrapping_add(1);
        let seq = self.seq;
        let msg = message(msg_type, flags | libc::NLM_F_REQUEST as u16, seq, body);
        let sent = unsafe { libc::send(self.fd, msg.as_ptr() as *const libc::c_void, msg.len(), 0) };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut replies = Vec::new();
        let mut buf = vec![0u8; 16384];
        loop {
            let n = unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut off = 0usize;
            let n = n as usize;
            while off + NLMSG_HDRLEN <= n {
                let len = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
                let ty = u16::from_ne_bytes(buf[off + 4..off + 6].try_into().unwrap());
                let flags = u16::from_ne_bytes(buf[off + 6..off + 8].try_into().unwrap());
                let rseq = u32::from_ne_bytes(buf[off + 8..off + 12].try_into().unwrap());
                if len < NLMSG_HDRLEN || off + len > n {
                    return Err(io::Error::other("netlink: truncated message"));
                }
                if rseq == seq {
                    let payload = &buf[off + NLMSG_HDRLEN..off + len];
                    match ty {
                        x if x == libc::NLMSG_ERROR as u16 => {
                            if payload.len() < 4 {
                                return Err(io::Error::other("netlink: short error message"));
                            }
                            let code = i32::from_ne_bytes(payload[..4].try_into().unwrap());
                            if code != 0 {
                                return Err(io::Error::from_raw_os_error(-code));
                            }
                            return Ok(replies); // ACK
                        }
                        x if x == libc::NLMSG_DONE as u16 => return Ok(replies),
                        _ => {
                            replies.push(payload.to_vec());
                            if flags & libc::NLM_F_MULTI as u16 == 0 {
                                return Ok(replies);
                            }
                        }
                    }
                }
                off += align4(len);
            }
        }
    }
}

impl Drop for Netlink {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

/// Parse an RTM_NEWROUTE payload (rtmsg + attributes) into the fields we use.
fn parse_route(payload: &[u8]) -> io::Result<RouteInfo> {
    if payload.len() < RTMSG_LEN {
        return Err(io::Error::other("netlink: short rtmsg"));
    }
    let mut info = RouteInfo::default();
    let mut off = RTMSG_LEN;
    while off + 4 <= payload.len() {
        let len = u16::from_ne_bytes(payload[off..off + 2].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes(payload[off + 2..off + 4].try_into().unwrap());
        if len < 4 || off + len > payload.len() {
            return Err(io::Error::other("netlink: bad rtattr"));
        }
        let data = &payload[off + 4..off + len];
        match kind {
            libc::RTA_GATEWAY if data.len() == 4 => info.gateway = Some(Ipv4Addr::new(data[0], data[1], data[2], data[3])),
            libc::RTA_PREFSRC if data.len() == 4 => info.prefsrc = Some(Ipv4Addr::new(data[0], data[1], data[2], data[3])),
            libc::RTA_OIF if data.len() == 4 => info.oif = Some(u32::from_ne_bytes(data.try_into().unwrap())),
            _ => {}
        }
        off += align4(len);
    }
    Ok(info)
}

/// What the kernel would use to reach `dst` (optionally restricted to interface `oif`).
pub fn get_route(dst: Ipv4Addr, oif: Option<u32>) -> io::Result<RouteInfo> {
    let mut body = rtmsg(32, 0, 0, 0, 0).to_vec();
    push_attr(&mut body, libc::RTA_DST, &dst.octets());
    if let Some(i) = oif {
        push_attr(&mut body, libc::RTA_OIF, &i.to_ne_bytes());
    }
    let mut nl = Netlink::open()?;
    let replies = nl.request(libc::RTM_GETROUTE, 0, &body)?;
    match replies.first() {
        Some(p) => parse_route(p),
        None => Err(io::Error::other("netlink: no route in reply")),
    }
}

/// Install (or replace) `dst/32 [via gateway] dev oif [src prefsrc] metric ROUTE_METRIC
/// proto RTPROT_UDP2RAW` in the main table.
pub fn replace_host_route(dst: Ipv4Addr, gateway: Option<Ipv4Addr>, oif: u32, prefsrc: Option<Ipv4Addr>) -> io::Result<()> {
    let scope = if gateway.is_some() { libc::RT_SCOPE_UNIVERSE } else { libc::RT_SCOPE_LINK };
    let mut body = rtmsg(32, libc::RT_TABLE_MAIN, RTPROT_UDP2RAW, scope, libc::RTN_UNICAST).to_vec();
    push_attr(&mut body, libc::RTA_DST, &dst.octets());
    push_attr(&mut body, libc::RTA_OIF, &oif.to_ne_bytes());
    if let Some(gw) = gateway {
        push_attr(&mut body, libc::RTA_GATEWAY, &gw.octets());
    }
    if let Some(src) = prefsrc {
        push_attr(&mut body, libc::RTA_PREFSRC, &src.octets());
    }
    push_attr(&mut body, libc::RTA_PRIORITY, &ROUTE_METRIC.to_ne_bytes());
    let mut nl = Netlink::open()?;
    let flags = (libc::NLM_F_ACK | libc::NLM_F_CREATE | libc::NLM_F_REPLACE) as u16;
    nl.request(libc::RTM_NEWROUTE, flags, &body).map(|_| ())
}

/// Remove the host route for `dst` on `oif` that this program installed (matched by
/// protocol and metric, so operator routes survive). Missing routes are not an error.
pub fn delete_host_route(dst: Ipv4Addr, oif: u32) -> io::Result<()> {
    let mut body = rtmsg(32, libc::RT_TABLE_MAIN, RTPROT_UDP2RAW, libc::RT_SCOPE_NOWHERE, libc::RTN_UNICAST).to_vec();
    push_attr(&mut body, libc::RTA_DST, &dst.octets());
    push_attr(&mut body, libc::RTA_OIF, &oif.to_ne_bytes());
    push_attr(&mut body, libc::RTA_PRIORITY, &ROUTE_METRIC.to_ne_bytes());
    let mut nl = Netlink::open()?;
    match nl.request(libc::RTM_DELROUTE, libc::NLM_F_ACK as u16, &body) {
        Ok(_) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::ESRCH) || e.raw_os_error() == Some(libc::ENOENT) => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_layout() {
        let body = rtmsg(32, libc::RT_TABLE_MAIN, RTPROT_UDP2RAW, libc::RT_SCOPE_UNIVERSE, libc::RTN_UNICAST);
        assert_eq!(body[0], libc::AF_INET as u8);
        assert_eq!(body[1], 32);
        assert_eq!(body[4], 254);
        assert_eq!(body[5], RTPROT_UDP2RAW);
        let mut b = body.to_vec();
        push_attr(&mut b, libc::RTA_DST, &[10, 99, 1, 20]);
        push_attr(&mut b, libc::RTA_OIF, &7u32.to_ne_bytes());
        push_attr(&mut b, libc::RTA_PRIORITY, &ROUTE_METRIC.to_ne_bytes());
        // three 8-byte attributes after the 12-byte rtmsg
        assert_eq!(b.len(), RTMSG_LEN + 3 * 8);
        let m = message(libc::RTM_NEWROUTE, libc::NLM_F_ACK as u16, 9, &b);
        assert_eq!(m.len(), NLMSG_HDRLEN + b.len());
        assert_eq!(u32::from_ne_bytes(m[0..4].try_into().unwrap()) as usize, m.len());
        assert_eq!(u16::from_ne_bytes(m[4..6].try_into().unwrap()), libc::RTM_NEWROUTE);
        assert_eq!(u32::from_ne_bytes(m[8..12].try_into().unwrap()), 9);
        // odd-length attribute payloads are padded
        let mut c = Vec::new();
        push_attr(&mut c, 99, &[1, 2, 3]);
        assert_eq!(c.len(), 8);
        assert_eq!(&c[..2], &7u16.to_ne_bytes());
        // parse back what the kernel would send
        let info = parse_route(&b).unwrap();
        assert_eq!(info.oif, Some(7));
        assert_eq!(info.gateway, None);
        let mut with_gw = body.to_vec();
        push_attr(&mut with_gw, libc::RTA_GATEWAY, &[10, 99, 0, 2]);
        push_attr(&mut with_gw, libc::RTA_PREFSRC, &[10, 99, 0, 1]);
        let info = parse_route(&with_gw).unwrap();
        assert_eq!(info.gateway, Some(Ipv4Addr::new(10, 99, 0, 2)));
        assert_eq!(info.prefsrc, Some(Ipv4Addr::new(10, 99, 0, 1)));
        assert!(parse_route(&[0u8; 5]).is_err());
    }
}
