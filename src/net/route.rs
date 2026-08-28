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
/// Owned routes use the high half of the metric space. A more-specific `/32` still wins
/// over a VPN default route, while a conventional operator `/32` remains preferred.
const OWNED_METRIC_BIT: u32 = 1 << 31;

/// Derive the first exact route metric owned by one client process. The client uses
/// create-exclusive netlink requests and advances the metric if another process happened
/// to choose the same value.
pub fn owned_metric(owner: u32) -> u32 {
    OWNED_METRIC_BIT | (owner & !OWNED_METRIC_BIT)
}

/// The next metric in the udp2raw-owned half of the metric space.
pub fn next_owned_metric(metric: u32) -> u32 {
    OWNED_METRIC_BIT | (metric.wrapping_add(1) & !OWNED_METRIC_BIT)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RouteInfo {
    pub family: u8,
    pub destination: Option<Ipv4Addr>,
    pub gateway: Option<Ipv4Addr>,
    pub oif: Option<u32>,
    pub prefsrc: Option<Ipv4Addr>,
    pub metric: Option<u32>,
    pub dst_len: u8,
    pub table: u8,
    pub protocol: u8,
    pub route_type: u8,
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
                        x if x == libc::NLMSG_DONE as u16 => {
                            if flags & libc::NLM_F_DUMP_INTR as u16 != 0 {
                                return Err(io::Error::new(
                                    io::ErrorKind::Interrupted,
                                    "netlink: route dump was interrupted",
                                ));
                            }
                            if payload.len() >= 4 {
                                let code = i32::from_ne_bytes(payload[..4].try_into().unwrap());
                                if code != 0 {
                                    let errno = code.checked_neg().filter(|e| *e > 0).unwrap_or(libc::EIO);
                                    return Err(io::Error::from_raw_os_error(errno));
                                }
                            }
                            return Ok(replies);
                        }
                        x if x == libc::NLMSG_OVERRUN as u16 => {
                            return Err(io::Error::other("netlink: route dump overrun"));
                        }
                        x if x == libc::NLMSG_NOOP as u16 => {}
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
    let mut info = RouteInfo {
        family: payload[0],
        dst_len: payload[1],
        table: payload[4],
        protocol: payload[5],
        route_type: payload[7],
        ..RouteInfo::default()
    };
    let mut off = RTMSG_LEN;
    while off + 4 <= payload.len() {
        let len = u16::from_ne_bytes(payload[off..off + 2].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes(payload[off + 2..off + 4].try_into().unwrap());
        if len < 4 || off + len > payload.len() {
            return Err(io::Error::other("netlink: bad rtattr"));
        }
        let data = &payload[off + 4..off + len];
        match kind {
            libc::RTA_DST if data.len() == 4 => {
                info.destination = Some(Ipv4Addr::new(data[0], data[1], data[2], data[3]));
            }
            libc::RTA_GATEWAY if data.len() == 4 => info.gateway = Some(Ipv4Addr::new(data[0], data[1], data[2], data[3])),
            libc::RTA_PREFSRC if data.len() == 4 => info.prefsrc = Some(Ipv4Addr::new(data[0], data[1], data[2], data[3])),
            libc::RTA_OIF if data.len() == 4 => info.oif = Some(u32::from_ne_bytes(data.try_into().unwrap())),
            libc::RTA_PRIORITY if data.len() == 4 => info.metric = Some(u32::from_ne_bytes(data.try_into().unwrap())),
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

fn owned_route_dump_body() -> Vec<u8> {
    // A dump is required rather than an ordinary lookup: RTM_GETROUTE for one destination
    // returns only the route the kernel would select, which may be an operator or peer route
    // and cannot prove whether our exact metric still exists after a lost delete ACK.
    rtmsg(0, libc::RT_TABLE_MAIN, 0, 0, 0).to_vec()
}

fn owned_host_route_matches(
    info: &RouteInfo,
    dst: Ipv4Addr,
    gateway: Option<Ipv4Addr>,
    oif: u32,
    prefsrc: Option<Ipv4Addr>,
    metric: u32,
) -> bool {
    info.family == libc::AF_INET as u8
        && info.destination == Some(dst)
        && info.dst_len == 32
        && info.table == libc::RT_TABLE_MAIN
        && info.protocol == RTPROT_UDP2RAW
        && info.route_type == libc::RTN_UNICAST
        && info.gateway == gateway
        && info.oif == Some(oif)
        && info.prefsrc == prefsrc
        && info.metric == Some(metric)
}

fn owned_host_route_in_payloads(
    payloads: &[Vec<u8>],
    dst: Ipv4Addr,
    gateway: Option<Ipv4Addr>,
    oif: u32,
    prefsrc: Option<Ipv4Addr>,
    metric: u32,
) -> io::Result<bool> {
    for payload in payloads {
        let info = parse_route(payload)?;
        if owned_host_route_matches(&info, dst, gateway, oif, prefsrc, metric) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether this process's exact protocol-235 host route is currently present.
///
/// This dumps the IPv4 main table and requires every ownership and native-path field to
/// match. In particular, a selected operator route, another client's route for the same
/// `/32`, or a route with the same metric on a different gateway/interface cannot satisfy
/// reconciliation after an uncertain delete result.
pub fn owned_host_route_exists(
    dst: Ipv4Addr,
    gateway: Option<Ipv4Addr>,
    oif: u32,
    prefsrc: Option<Ipv4Addr>,
    metric: u32,
) -> io::Result<bool> {
    let mut nl = Netlink::open()?;
    let replies = nl.request(
        libc::RTM_GETROUTE,
        libc::NLM_F_DUMP as u16,
        &owned_route_dump_body(),
    )?;
    owned_host_route_in_payloads(&replies, dst, gateway, oif, prefsrc, metric)
}

fn host_route_body(
    dst: Ipv4Addr,
    gateway: Option<Ipv4Addr>,
    oif: u32,
    prefsrc: Option<Ipv4Addr>,
    metric: u32,
    scope: u8,
) -> Vec<u8> {
    let mut body = rtmsg(32, libc::RT_TABLE_MAIN, RTPROT_UDP2RAW, scope, libc::RTN_UNICAST).to_vec();
    push_attr(&mut body, libc::RTA_DST, &dst.octets());
    push_attr(&mut body, libc::RTA_OIF, &oif.to_ne_bytes());
    if let Some(gw) = gateway {
        push_attr(&mut body, libc::RTA_GATEWAY, &gw.octets());
    }
    if let Some(src) = prefsrc {
        push_attr(&mut body, libc::RTA_PREFSRC, &src.octets());
    }
    push_attr(&mut body, libc::RTA_PRIORITY, &metric.to_ne_bytes());
    body
}

/// Create one process-owned `dst/32 [via gateway] dev oif [src prefsrc] metric metric
/// proto RTPROT_UDP2RAW` route in the main table. `NLM_F_EXCL` is intentional: a second
/// client must never replace a route owned by the first one (or an operator route).
pub fn create_host_route(
    dst: Ipv4Addr,
    gateway: Option<Ipv4Addr>,
    oif: u32,
    prefsrc: Option<Ipv4Addr>,
    metric: u32,
) -> io::Result<()> {
    let scope = if gateway.is_some() { libc::RT_SCOPE_UNIVERSE } else { libc::RT_SCOPE_LINK };
    let body = host_route_body(dst, gateway, oif, prefsrc, metric, scope);
    let mut nl = Netlink::open()?;
    let flags = (libc::NLM_F_ACK | libc::NLM_F_CREATE | libc::NLM_F_EXCL) as u16;
    nl.request(libc::RTM_NEWROUTE, flags, &body).map(|_| ())
}

/// Remove the host route for `dst` on `oif` that this program installed (matched by
/// protocol, exact per-process metric, interface and gateway, so operator and peer-client
/// routes survive). Missing routes are not an error.
pub fn delete_host_route(dst: Ipv4Addr, gateway: Option<Ipv4Addr>, oif: u32, metric: u32) -> io::Result<()> {
    let body = host_route_body(dst, gateway, oif, None, metric, libc::RT_SCOPE_NOWHERE);
    // RTA_PREFSRC is route information rather than route identity. Omitting it makes cleanup
    // work across kernel-normalized replies without weakening the exact metric ownership.
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
        let metric = owned_metric(0x1234);
        let mut b = body.to_vec();
        push_attr(&mut b, libc::RTA_DST, &[10, 99, 1, 20]);
        push_attr(&mut b, libc::RTA_OIF, &7u32.to_ne_bytes());
        push_attr(&mut b, libc::RTA_PRIORITY, &metric.to_ne_bytes());
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
        assert_eq!(info.family, libc::AF_INET as u8);
        assert_eq!(info.destination, Some(Ipv4Addr::new(10, 99, 1, 20)));
        assert_eq!(info.oif, Some(7));
        assert_eq!(info.metric, Some(metric));
        assert_eq!(info.dst_len, 32);
        assert_eq!(info.table, libc::RT_TABLE_MAIN);
        assert_eq!(info.protocol, RTPROT_UDP2RAW);
        assert_eq!(info.route_type, libc::RTN_UNICAST);
        assert_eq!(info.gateway, None);
        let mut with_gw = body.to_vec();
        push_attr(&mut with_gw, libc::RTA_GATEWAY, &[10, 99, 0, 2]);
        push_attr(&mut with_gw, libc::RTA_PREFSRC, &[10, 99, 0, 1]);
        let info = parse_route(&with_gw).unwrap();
        assert_eq!(info.gateway, Some(Ipv4Addr::new(10, 99, 0, 2)));
        assert_eq!(info.prefsrc, Some(Ipv4Addr::new(10, 99, 0, 1)));
        assert!(parse_route(&[0u8; 5]).is_err());
    }

    #[test]
    fn owned_metrics_are_distinct_and_stay_in_the_reserved_half() {
        let a = owned_metric(7);
        let b = next_owned_metric(a);
        assert_ne!(a, b);
        assert_ne!(a & OWNED_METRIC_BIT, 0);
        assert_ne!(b & OWNED_METRIC_BIT, 0);
    }

    #[test]
    fn create_and_delete_bodies_keep_exact_owned_identity() {
        let dst = Ipv4Addr::new(47, 243, 1, 2);
        let gateway = Some(Ipv4Addr::new(192, 0, 2, 1));
        let prefsrc = Some(Ipv4Addr::new(192, 0, 2, 9));
        let metric = owned_metric(99);
        let create = host_route_body(dst, gateway, 11, prefsrc, metric, libc::RT_SCOPE_UNIVERSE);
        let delete = host_route_body(dst, gateway, 11, None, metric, libc::RT_SCOPE_NOWHERE);
        let created = parse_route(&create).unwrap();
        let deleted = parse_route(&delete).unwrap();

        assert_eq!(created.destination, Some(dst));
        assert_eq!(created.gateway, gateway);
        assert_eq!(created.oif, Some(11));
        assert_eq!(created.prefsrc, prefsrc);
        assert_eq!(created.metric, Some(metric));
        assert_eq!(created.protocol, RTPROT_UDP2RAW);
        assert_eq!(deleted.destination, created.destination);
        assert_eq!(deleted.gateway, created.gateway);
        assert_eq!(deleted.oif, created.oif);
        assert_eq!(deleted.metric, created.metric);
        assert_eq!(deleted.protocol, created.protocol);

        let create_flags = (libc::NLM_F_ACK | libc::NLM_F_CREATE | libc::NLM_F_EXCL) as u16;
        assert_ne!(create_flags & libc::NLM_F_EXCL as u16, 0);
        assert_eq!(create_flags & libc::NLM_F_REPLACE as u16, 0);
    }

    #[test]
    fn owned_route_dump_request_is_main_table_ipv4_multipart() {
        let body = owned_route_dump_body();
        let parsed = parse_route(&body).unwrap();
        assert_eq!(parsed.family, libc::AF_INET as u8);
        assert_eq!(parsed.dst_len, 0);
        assert_eq!(parsed.table, libc::RT_TABLE_MAIN);
        assert_eq!(parsed.protocol, 0);
        assert_eq!(parsed.route_type, 0);
        assert_eq!(parsed.destination, None);

        let flags = libc::NLM_F_REQUEST as u16 | libc::NLM_F_DUMP as u16;
        let request = message(libc::RTM_GETROUTE, flags, 17, &body);
        assert_eq!(u16::from_ne_bytes(request[4..6].try_into().unwrap()), libc::RTM_GETROUTE);
        assert_eq!(u16::from_ne_bytes(request[6..8].try_into().unwrap()), flags);
        assert_ne!(flags & libc::NLM_F_ROOT as u16, 0);
        assert_ne!(flags & libc::NLM_F_MATCH as u16, 0);
    }

    #[test]
    fn owned_route_match_requires_every_identity_and_path_field() {
        let dst = Ipv4Addr::new(47, 243, 1, 2);
        let gateway = Some(Ipv4Addr::new(192, 0, 2, 1));
        let prefsrc = Some(Ipv4Addr::new(192, 0, 2, 9));
        let metric = owned_metric(99);
        let exact = parse_route(&host_route_body(
            dst,
            gateway,
            11,
            prefsrc,
            metric,
            libc::RT_SCOPE_UNIVERSE,
        ))
        .unwrap();
        assert!(owned_host_route_matches(&exact, dst, gateway, 11, prefsrc, metric));

        let mut changed = exact;
        changed.family = libc::AF_INET6 as u8;
        assert!(!owned_host_route_matches(&changed, dst, gateway, 11, prefsrc, metric));
        changed = exact;
        changed.destination = Some(Ipv4Addr::new(47, 243, 1, 3));
        assert!(!owned_host_route_matches(&changed, dst, gateway, 11, prefsrc, metric));
        changed = exact;
        changed.dst_len = 24;
        assert!(!owned_host_route_matches(&changed, dst, gateway, 11, prefsrc, metric));
        changed = exact;
        changed.table = libc::RT_TABLE_LOCAL;
        assert!(!owned_host_route_matches(&changed, dst, gateway, 11, prefsrc, metric));
        changed = exact;
        changed.protocol = libc::RTPROT_STATIC;
        assert!(!owned_host_route_matches(&changed, dst, gateway, 11, prefsrc, metric));
        changed = exact;
        changed.route_type = libc::RTN_BLACKHOLE;
        assert!(!owned_host_route_matches(&changed, dst, gateway, 11, prefsrc, metric));
        changed = exact;
        changed.gateway = Some(Ipv4Addr::new(192, 0, 2, 2));
        assert!(!owned_host_route_matches(&changed, dst, gateway, 11, prefsrc, metric));
        changed = exact;
        changed.oif = Some(12);
        assert!(!owned_host_route_matches(&changed, dst, gateway, 11, prefsrc, metric));
        changed = exact;
        changed.prefsrc = Some(Ipv4Addr::new(192, 0, 2, 10));
        assert!(!owned_host_route_matches(&changed, dst, gateway, 11, prefsrc, metric));
        changed = exact;
        changed.metric = Some(next_owned_metric(metric));
        assert!(!owned_host_route_matches(&changed, dst, gateway, 11, prefsrc, metric));
    }

    #[test]
    fn owned_route_dump_ignores_operator_and_peer_routes() {
        let dst = Ipv4Addr::new(47, 243, 9, 9);
        let gateway = Some(Ipv4Addr::new(192, 0, 2, 1));
        let prefsrc = Some(Ipv4Addr::new(192, 0, 2, 9));
        let metric = owned_metric(0x101);
        let peer = host_route_body(
            dst,
            gateway,
            7,
            prefsrc,
            next_owned_metric(metric),
            libc::RT_SCOPE_UNIVERSE,
        );
        let mut operator = host_route_body(
            dst,
            gateway,
            7,
            prefsrc,
            metric,
            libc::RT_SCOPE_UNIVERSE,
        );
        operator[5] = libc::RTPROT_STATIC;
        assert!(!owned_host_route_in_payloads(
            &[peer.clone(), operator.clone()],
            dst,
            gateway,
            7,
            prefsrc,
            metric,
        )
        .unwrap());

        let exact = host_route_body(
            dst,
            gateway,
            7,
            prefsrc,
            metric,
            libc::RT_SCOPE_UNIVERSE,
        );
        assert!(owned_host_route_in_payloads(
            &[peer, operator, exact],
            dst,
            gateway,
            7,
            prefsrc,
            metric,
        )
        .unwrap());
        assert!(owned_host_route_in_payloads(
            &[vec![0u8; 5]],
            dst,
            gateway,
            7,
            prefsrc,
            metric,
        )
        .is_err());
    }

    #[test]
    fn two_clients_sharing_a_prefix_have_independent_delete_keys() {
        let dst = Ipv4Addr::new(47, 243, 9, 9);
        let gateway = Some(Ipv4Addr::new(192, 0, 2, 1));
        let metric_a = owned_metric(0x101);
        let metric_b = owned_metric(0x202);
        assert_ne!(metric_a, metric_b);

        let route_a = parse_route(&host_route_body(
            dst,
            gateway,
            7,
            None,
            metric_a,
            libc::RT_SCOPE_UNIVERSE,
        ))
        .unwrap();
        let route_b = parse_route(&host_route_body(
            dst,
            gateway,
            7,
            None,
            metric_b,
            libc::RT_SCOPE_UNIVERSE,
        ))
        .unwrap();
        assert_eq!(route_a.destination, route_b.destination);
        assert_eq!(route_a.gateway, route_b.gateway);
        assert_eq!(route_a.oif, route_b.oif);
        assert_ne!(route_a.metric, route_b.metric);

        // Deleting A names A's exact metric and cannot select B's otherwise-identical route.
        let delete_a = parse_route(&host_route_body(
            dst,
            gateway,
            7,
            None,
            metric_a,
            libc::RT_SCOPE_NOWHERE,
        ))
        .unwrap();
        assert_eq!(delete_a.metric, route_a.metric);
        assert_ne!(delete_a.metric, route_b.metric);
    }
}
