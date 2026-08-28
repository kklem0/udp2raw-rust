//! A small, explicit-resolver DNS client for the client's `-r hostname:port` endpoint.
//!
//! Only the servers given with `--dns-server` are asked (never `/etc/resolv.conf`, never an
//! external program), in the configured order; the first server that returns a usable
//! answer wins. Queries are `A`/`IN` only: `AAAA` is not requested and any other record type
//! in an answer is ignored. Each query uses a random ID and a fresh socket with a random
//! source port; a reply must echo the ID and the question before it is looked at, and a
//! truncated UDP reply is retried over TCP. Message encoding and decoding come from
//! `hickory-proto`, so no hand-written parser touches untrusted bytes.
//!
//! The optional `device` binds the query sockets with `SO_BINDTODEVICE` (Linux) so that the
//! lookup itself travels the native underlay and not a tunnel that may be the reason for the
//! lookup.

use crate::util::secure_random_u32;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

/// TTLs below this are raised to it: a zero or tiny TTL must not turn every reconnect
/// cycle into a query.
pub const TTL_MIN_SECS: u32 = 10;
/// TTLs above this are lowered to it so a stale record is noticed within the hour.
pub const TTL_MAX_SECS: u32 = 3600;
/// CNAME hops followed inside one answer before giving up.
pub const MAX_CNAME_HOPS: usize = 8;
/// Largest DNS message accepted over TCP (the protocol maximum).
const MAX_TCP_MESSAGE: usize = 65535;

#[derive(Clone, Debug)]
pub struct DnsConfig {
    /// Servers in the order they are tried.
    pub servers: Vec<SocketAddr>,
    /// Interface the query sockets are bound to (`--underlay-dev`).
    pub device: Option<String>,
    /// Per-server, per-transport timeout.
    pub timeout: Duration,
}

/// A validated positive answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsAnswer {
    /// Distinct addresses in the order the server listed them.
    pub addrs: Vec<Ipv4Addr>,
    /// Smallest TTL of the records used, clamped to `TTL_MIN_SECS..=TTL_MAX_SECS`.
    pub ttl: u32,
    /// The same TTL before clamping (for logs).
    pub raw_ttl: u32,
    pub server: SocketAddr,
    /// CNAME chain that led to the addresses, if any.
    pub cnames: Vec<String>,
    pub via_tcp: bool,
}

#[derive(Debug)]
pub enum DnsError {
    /// The name does not exist (authoritative NXDOMAIN).
    NxDomain,
    /// The name exists but has no `A` record.
    NoData,
    /// Any other error response code.
    Rcode(ResponseCode),
    /// No matching reply within the timeout.
    Timeout,
    /// The reply could not be decoded or did not describe our question.
    Malformed(String),
    Io(io::Error),
    InvalidName(String),
    NoServers,
    /// Every server failed; one entry per server in the order tried.
    AllFailed(Vec<(SocketAddr, DnsError)>),
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsError::NxDomain => write!(f, "NXDOMAIN"),
            DnsError::NoData => write!(f, "no A record (NODATA)"),
            DnsError::Rcode(rc) => write!(f, "response code {rc}"),
            DnsError::Timeout => write!(f, "timeout"),
            DnsError::Malformed(s) => write!(f, "malformed reply: {s}"),
            DnsError::Io(e) => write!(f, "io: {e}"),
            DnsError::InvalidName(s) => write!(f, "invalid name: {s}"),
            DnsError::NoServers => write!(f, "no --dns-server configured"),
            DnsError::AllFailed(v) => {
                write!(f, "all {} servers failed:", v.len())?;
                for (s, e) in v {
                    write!(f, " [{s}: {e}]")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for DnsError {}

impl From<io::Error> for DnsError {
    fn from(e: io::Error) -> Self {
        if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut {
            DnsError::Timeout
        } else {
            DnsError::Io(e)
        }
    }
}

/// Something that answers `A` queries — the real resolver, or a fake one in tests.
pub trait Resolve: Send + Sync {
    fn resolve_a(&self, name: &str) -> Result<DnsAnswer, DnsError>;
}

/// The real resolver over `DnsConfig`.
pub struct Resolver {
    pub cfg: DnsConfig,
}

impl Resolve for Resolver {
    fn resolve_a(&self, name: &str) -> Result<DnsAnswer, DnsError> {
        resolve_a(&self.cfg, name)
    }
}

/// Query every configured server in order until one returns a usable `A` answer.
pub fn resolve_a(cfg: &DnsConfig, name: &str) -> Result<DnsAnswer, DnsError> {
    if cfg.servers.is_empty() {
        return Err(DnsError::NoServers);
    }
    let qname = parse_name(name)?;
    let mut failures = Vec::new();
    for &server in &cfg.servers {
        match query_server(cfg, server, &qname) {
            Ok(a) => return Ok(a),
            Err(e) => {
                log::warn!("dns: {name} @{server}: {e}");
                failures.push((server, e));
            }
        }
    }
    Err(DnsError::AllFailed(failures))
}

/// The absolute (FQDN) form of a hostname, as hickory needs it.
pub fn parse_name(name: &str) -> Result<Name, DnsError> {
    let mut n = Name::from_ascii(name).map_err(|e| DnsError::InvalidName(format!("{name}: {e}")))?;
    n.set_fqdn(true);
    Ok(n)
}

fn build_query(id: u16, qname: &Name) -> Message {
    let mut m = Message::new();
    m.set_id(id).set_message_type(MessageType::Query).set_op_code(OpCode::Query).set_recursion_desired(true);
    m.add_query(Query::query(qname.clone(), RecordType::A));
    m
}

fn query_server(cfg: &DnsConfig, server: SocketAddr, qname: &Name) -> Result<DnsAnswer, DnsError> {
    let id = (secure_random_u32() & 0xffff) as u16;
    let wire = build_query(id, qname).to_vec().map_err(|e| DnsError::Malformed(format!("encode: {e}")))?;
    let reply = udp_exchange(cfg, server, &wire, id, qname)?;
    if reply.truncated() {
        log::debug!("dns: truncated udp reply from {server}, retrying over tcp");
        let reply = tcp_exchange(cfg, server, &wire, id, qname)?;
        return interpret(&reply, qname, server, true);
    }
    interpret(&reply, qname, server, false)
}

/// Does `m` look like the reply to our query? (ID and the question section must match.)
fn is_our_reply(m: &Message, id: u16, qname: &Name) -> bool {
    m.id() == id
        && m.message_type() == MessageType::Response
        && m.queries().len() == 1
        && m.queries()[0].name() == qname
        && m.queries()[0].query_type() == RecordType::A
        && m.queries()[0].query_class() == DNSClass::IN
}

fn udp_exchange(cfg: &DnsConfig, server: SocketAddr, wire: &[u8], id: u16, qname: &Name) -> Result<Message, DnsError> {
    let bind: SocketAddr = if server.is_ipv6() { "[::]:0".parse().unwrap() } else { "0.0.0.0:0".parse().unwrap() };
    let sock = UdpSocket::bind(bind)?;
    if let Some(dev) = &cfg.device {
        bind_device(&sock, dev)?;
    }
    sock.connect(server)?;
    sock.send(wire)?;
    let deadline = Instant::now() + cfg.timeout;
    let mut buf = [0u8; 4096];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(DnsError::Timeout);
        }
        sock.set_read_timeout(Some(left))?;
        let n = match sock.recv(&mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => return Err(DnsError::Timeout),
            Err(e) => return Err(DnsError::Io(e)),
        };
        match Message::from_vec(&buf[..n]) {
            Ok(m) if is_our_reply(&m, id, qname) => return Ok(m),
            Ok(_) => log::debug!("dns: ignoring reply from {server} that does not match our query"),
            Err(e) => log::debug!("dns: ignoring undecodable datagram from {server}: {e}"),
        }
    }
}

fn tcp_exchange(cfg: &DnsConfig, server: SocketAddr, wire: &[u8], id: u16, qname: &Name) -> Result<Message, DnsError> {
    let mut stream = tcp_connect(server, cfg.device.as_deref(), cfg.timeout)?;
    stream.set_read_timeout(Some(cfg.timeout))?;
    stream.set_write_timeout(Some(cfg.timeout))?;
    let len = u16::try_from(wire.len()).map_err(|_| DnsError::Malformed("query too long for tcp".into()))?;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(wire)?;
    let mut lenbuf = [0u8; 2];
    stream.read_exact(&mut lenbuf)?;
    let rlen = u16::from_be_bytes(lenbuf) as usize;
    if rlen == 0 || rlen > MAX_TCP_MESSAGE {
        return Err(DnsError::Malformed(format!("tcp length {rlen}")));
    }
    let mut body = vec![0u8; rlen];
    stream.read_exact(&mut body)?;
    let m = Message::from_vec(&body).map_err(|e| DnsError::Malformed(format!("tcp reply: {e}")))?;
    if !is_our_reply(&m, id, qname) {
        return Err(DnsError::Malformed("tcp reply does not match our query".into()));
    }
    Ok(m)
}

/// Turn a validated reply into addresses, following CNAMEs inside the answer section.
fn interpret(m: &Message, qname: &Name, server: SocketAddr, via_tcp: bool) -> Result<DnsAnswer, DnsError> {
    if m.op_code() != OpCode::Query {
        return Err(DnsError::Malformed(format!("opcode {:?}", m.op_code())));
    }
    match m.response_code() {
        ResponseCode::NoError => {}
        ResponseCode::NXDomain => return Err(DnsError::NxDomain),
        rc => return Err(DnsError::Rcode(rc)),
    }
    let answers = m.answers();
    let mut name = qname.clone();
    let mut cnames = Vec::new();
    loop {
        let mut addrs: Vec<Ipv4Addr> = Vec::new();
        let mut ttl = u32::MAX;
        for r in answers.iter().filter(|r| r.name() == &name) {
            if let RData::A(a) = r.data() {
                if !addrs.contains(&a.0) {
                    addrs.push(a.0);
                }
                ttl = ttl.min(r.ttl());
            }
        }
        if !addrs.is_empty() {
            let raw_ttl = ttl;
            return Ok(DnsAnswer { addrs, ttl: raw_ttl.clamp(TTL_MIN_SECS, TTL_MAX_SECS), raw_ttl, server, cnames, via_tcp });
        }
        let cname = answers.iter().filter(|r| r.name() == &name).find_map(|r| match r.data() {
            RData::CNAME(c) => Some(c.0.clone()),
            _ => None,
        });
        match cname {
            Some(target) => {
                if cnames.len() >= MAX_CNAME_HOPS {
                    return Err(DnsError::Malformed("cname chain too long".into()));
                }
                if target == name || cnames.iter().any(|c| c.eq_ignore_ascii_case(&target.to_ascii())) {
                    return Err(DnsError::Malformed("cname loop".into()));
                }
                cnames.push(target.to_ascii());
                name = target;
            }
            None => return Err(DnsError::NoData),
        }
    }
}

#[cfg(target_os = "linux")]
fn bind_device_fd(fd: std::os::fd::RawFd, dev: &str) -> io::Result<()> {
    let bytes = dev.as_bytes();
    if bytes.is_empty() || bytes.len() >= libc::IFNAMSIZ {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad interface name"));
    }
    let r = unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_BINDTODEVICE, bytes.as_ptr() as *const libc::c_void, bytes.len() as libc::socklen_t) };
    if r != 0 {
        return Err(io::Error::new(io::Error::last_os_error().kind(), format!("SO_BINDTODEVICE {dev}: {}", io::Error::last_os_error())));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn bind_device(sock: &UdpSocket, dev: &str) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    bind_device_fd(sock.as_raw_fd(), dev)
}

#[cfg(not(target_os = "linux"))]
fn bind_device(_sock: &UdpSocket, dev: &str) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, format!("binding to device {dev} is only supported on linux")))
}

/// A TCP connection with a connect timeout, bound to `dev` first when requested.
#[cfg(target_os = "linux")]
fn tcp_connect(server: SocketAddr, dev: Option<&str>, timeout: Duration) -> io::Result<TcpStream> {
    use std::os::fd::FromRawFd;
    let family = if server.is_ipv6() { libc::AF_INET6 } else { libc::AF_INET };
    let fd = unsafe { libc::socket(family, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // the stream owns the fd from here on, so every early return closes it
    let stream = unsafe { TcpStream::from_raw_fd(fd) };
    if let Some(dev) = dev {
        bind_device_fd(fd, dev)?;
    }
    let tv = libc::timeval { tv_sec: timeout.as_secs() as libc::time_t, tv_usec: timeout.subsec_micros() as libc::suseconds_t };
    for opt in [libc::SO_SNDTIMEO, libc::SO_RCVTIMEO] {
        let r = unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, opt, &tv as *const _ as *const libc::c_void, std::mem::size_of::<libc::timeval>() as libc::socklen_t) };
        if r != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    let (sa, len) = crate::net::addr::to_sockaddr(server);
    // SO_SNDTIMEO bounds a blocking connect() on Linux
    let r = unsafe { libc::connect(fd, &sa as *const _ as *const libc::sockaddr, len) };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stream)
}

#[cfg(not(target_os = "linux"))]
fn tcp_connect(server: SocketAddr, dev: Option<&str>, timeout: Duration) -> io::Result<TcpStream> {
    if let Some(dev) = dev {
        return Err(io::Error::new(io::ErrorKind::Unsupported, format!("binding to device {dev} is only supported on linux")));
    }
    TcpStream::connect_timeout(&server, timeout)
}

/// Build a reply for tests and tooling: `NoError` with the given answer records, or an
/// error code with none.
pub fn build_reply(query: &Message, rcode: ResponseCode, answers: Vec<hickory_proto::rr::Record>, truncated: bool) -> Message {
    let mut m = Message::new();
    m.set_id(query.id()).set_message_type(MessageType::Response).set_op_code(OpCode::Query).set_recursion_desired(true).set_recursion_available(true).set_response_code(rcode).set_truncated(truncated);
    for q in query.queries() {
        m.add_query(q.clone());
    }
    for a in answers {
        m.add_answer(a);
    }
    m
}

/// Is this an address a relay could legitimately have? Unspecified, loopback, link-local,
/// multicast, broadcast, reserved and documentation ranges are never accepted; RFC 1918 and
/// CGNAT space only with `allow_private`.
pub fn check_endpoint_ip(ip: Ipv4Addr, allow_private: bool) -> Result<(), &'static str> {
    let o = ip.octets();
    if ip.is_unspecified() || o[0] == 0 {
        return Err("unspecified/this-network");
    }
    if ip.is_loopback() {
        return Err("loopback");
    }
    if ip.is_link_local() {
        return Err("link-local");
    }
    if ip.is_multicast() {
        return Err("multicast");
    }
    if ip.is_broadcast() || o[0] >= 240 {
        return Err("broadcast/reserved");
    }
    if ip.is_documentation() || (o[0] == 198 && (o[1] == 18 || o[1] == 19)) {
        return Err("documentation/benchmark range");
    }
    let private = ip.is_private();
    let cgnat = o[0] == 100 && (64..=127).contains(&o[1]);
    if (private || cgnat) && !allow_private {
        return Err(if cgnat { "CGNAT range (use --allow-private-endpoint)" } else { "private range (use --allow-private-endpoint)" });
    }
    Ok(())
}

/// `IpAddr` convenience for callers holding a socket address.
pub fn check_endpoint(addr: IpAddr, allow_private: bool) -> Result<(), &'static str> {
    match addr {
        IpAddr::V4(v4) => check_endpoint_ip(v4, allow_private),
        IpAddr::V6(_) => Err("ipv6 endpoints are not resolved (AAAA ignored)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::Record;
    use hickory_proto::rr::rdata::{A, CNAME};
    use std::sync::{Arc, Mutex};
    use std::thread;

    fn a(name: &str, ttl: u32, ip: [u8; 4]) -> Record {
        Record::from_rdata(parse_name(name).unwrap(), ttl, RData::A(A(Ipv4Addr::from(ip))))
    }
    fn cname(name: &str, ttl: u32, target: &str) -> Record {
        Record::from_rdata(parse_name(name).unwrap(), ttl, RData::CNAME(CNAME(parse_name(target).unwrap())))
    }

    /// What a stub server does with each query.
    #[derive(Clone)]
    enum Behaviour {
        Answer(Vec<Record>),
        Rcode(ResponseCode),
        /// Reply with TC set and no answers over UDP; the TCP listener gives the real answer.
        Truncate(Vec<Record>),
        Silent,
        Garbage,
        WrongId(Vec<Record>),
        WrongQuestion(Vec<Record>),
    }

    struct Stub {
        addr: SocketAddr,
        queries: Arc<Mutex<u32>>,
    }

    /// A UDP (+TCP) stub resolver on 127.0.0.1 that serves one behaviour.
    fn stub(b: Behaviour) -> Stub {
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = udp.local_addr().unwrap();
        let tcp = std::net::TcpListener::bind(addr).unwrap();
        let queries = Arc::new(Mutex::new(0u32));
        let q1 = queries.clone();
        let b1 = b.clone();
        thread::spawn(move || {
            let mut buf = [0u8; 1024];
            while let Ok((n, from)) = udp.recv_from(&mut buf) {
                *q1.lock().unwrap() += 1;
                let q = Message::from_vec(&buf[..n]).unwrap();
                let reply = match &b1 {
                    Behaviour::Answer(recs) => build_reply(&q, ResponseCode::NoError, recs.clone(), false).to_vec().unwrap(),
                    Behaviour::Rcode(rc) => build_reply(&q, *rc, vec![], false).to_vec().unwrap(),
                    Behaviour::Truncate(_) => build_reply(&q, ResponseCode::NoError, vec![], true).to_vec().unwrap(),
                    Behaviour::Silent => continue,
                    Behaviour::Garbage => vec![0xff; 17],
                    Behaviour::WrongId(recs) => {
                        let mut m = build_reply(&q, ResponseCode::NoError, recs.clone(), false);
                        m.set_id(q.id().wrapping_add(1));
                        m.to_vec().unwrap()
                    }
                    Behaviour::WrongQuestion(recs) => {
                        let mut m = build_reply(&q, ResponseCode::NoError, recs.clone(), false);
                        m.queries_mut()[0].set_name(parse_name("other.example.").unwrap());
                        m.to_vec().unwrap()
                    }
                };
                let _ = udp.send_to(&reply, from);
            }
        });
        let q2 = queries.clone();
        thread::spawn(move || {
            for stream in tcp.incoming().flatten() {
                let mut s = stream;
                let mut lb = [0u8; 2];
                if s.read_exact(&mut lb).is_err() {
                    continue;
                }
                let mut body = vec![0u8; u16::from_be_bytes(lb) as usize];
                if s.read_exact(&mut body).is_err() {
                    continue;
                }
                *q2.lock().unwrap() += 1;
                let q = Message::from_vec(&body).unwrap();
                let reply = match &b {
                    Behaviour::Truncate(recs) | Behaviour::Answer(recs) => build_reply(&q, ResponseCode::NoError, recs.clone(), false).to_vec().unwrap(),
                    _ => build_reply(&q, ResponseCode::ServFail, vec![], false).to_vec().unwrap(),
                };
                let _ = s.write_all(&(reply.len() as u16).to_be_bytes());
                let _ = s.write_all(&reply);
            }
        });
        Stub { addr, queries }
    }

    fn cfg(servers: &[&Stub]) -> DnsConfig {
        DnsConfig { servers: servers.iter().map(|s| s.addr).collect(), device: None, timeout: Duration::from_millis(400) }
    }

    #[test]
    fn single_answer() {
        let s = stub(Behaviour::Answer(vec![a("relay.example.", 60, [203, 0, 113, 10])]));
        let ans = resolve_a(&cfg(&[&s]), "relay.example").unwrap();
        assert_eq!(ans.addrs, vec![Ipv4Addr::new(203, 0, 113, 10)]);
        assert_eq!(ans.ttl, 60);
        assert!(!ans.via_tcp);
        assert!(ans.cnames.is_empty());
    }

    #[test]
    fn multiple_duplicate_and_reordered_answers() {
        let recs = vec![a("relay.example.", 60, [203, 0, 113, 20]), a("relay.example.", 60, [203, 0, 113, 10]), a("relay.example.", 30, [203, 0, 113, 20])];
        let s = stub(Behaviour::Answer(recs));
        let ans = resolve_a(&cfg(&[&s]), "RELAY.example").unwrap();
        // distinct, server order preserved, smallest ttl
        assert_eq!(ans.addrs, vec![Ipv4Addr::new(203, 0, 113, 20), Ipv4Addr::new(203, 0, 113, 10)]);
        assert_eq!(ans.ttl, 30);
    }

    #[test]
    fn cname_chain_and_loop() {
        let recs = vec![cname("relay.example.", 300, "edge.example."), cname("edge.example.", 120, "final.example."), a("final.example.", 45, [203, 0, 113, 7])];
        let s = stub(Behaviour::Answer(recs));
        let ans = resolve_a(&cfg(&[&s]), "relay.example").unwrap();
        assert_eq!(ans.addrs, vec![Ipv4Addr::new(203, 0, 113, 7)]);
        assert_eq!(ans.cnames, vec!["edge.example.", "final.example."]);
        assert_eq!(ans.ttl, 45);
        let s2 = stub(Behaviour::Answer(vec![cname("relay.example.", 300, "edge.example."), cname("edge.example.", 300, "relay.example.")]));
        assert!(matches!(resolve_a(&cfg(&[&s2]), "relay.example"), Err(DnsError::AllFailed(ref v)) if matches!(v[0].1, DnsError::Malformed(_))));
    }

    #[test]
    fn ttl_clamps() {
        for (raw, want) in [(0u32, TTL_MIN_SECS), (3, TTL_MIN_SECS), (600, 600), (7 * 86400, TTL_MAX_SECS), (u32::MAX, TTL_MAX_SECS)] {
            let s = stub(Behaviour::Answer(vec![a("relay.example.", raw, [203, 0, 113, 1])]));
            let ans = resolve_a(&cfg(&[&s]), "relay.example").unwrap();
            assert_eq!(ans.ttl, want, "raw ttl {raw}");
            assert_eq!(ans.raw_ttl, raw);
        }
    }

    #[test]
    fn negative_answers_and_failures() {
        let nx = stub(Behaviour::Rcode(ResponseCode::NXDomain));
        assert!(matches!(resolve_a(&cfg(&[&nx]), "relay.example"), Err(DnsError::AllFailed(ref v)) if matches!(v[0].1, DnsError::NxDomain)));
        let nodata = stub(Behaviour::Answer(vec![cname("relay.example.", 60, "gone.example.")]));
        assert!(matches!(resolve_a(&cfg(&[&nodata]), "relay.example"), Err(DnsError::AllFailed(ref v)) if matches!(v[0].1, DnsError::NoData)));
        let sf = stub(Behaviour::Rcode(ResponseCode::ServFail));
        assert!(matches!(resolve_a(&cfg(&[&sf]), "relay.example"), Err(DnsError::AllFailed(ref v)) if matches!(v[0].1, DnsError::Rcode(ResponseCode::ServFail))));
        let silent = stub(Behaviour::Silent);
        let t = Instant::now();
        assert!(matches!(resolve_a(&cfg(&[&silent]), "relay.example"), Err(DnsError::AllFailed(ref v)) if matches!(v[0].1, DnsError::Timeout)));
        assert!(t.elapsed() < Duration::from_secs(2));
        let garbage = stub(Behaviour::Garbage);
        assert!(matches!(resolve_a(&cfg(&[&garbage]), "relay.example"), Err(DnsError::AllFailed(ref v)) if matches!(v[0].1, DnsError::Timeout)));
        let wrong_id = stub(Behaviour::WrongId(vec![a("relay.example.", 60, [203, 0, 113, 9])]));
        assert!(matches!(resolve_a(&cfg(&[&wrong_id]), "relay.example"), Err(DnsError::AllFailed(ref v)) if matches!(v[0].1, DnsError::Timeout)));
        let wrong_q = stub(Behaviour::WrongQuestion(vec![a("relay.example.", 60, [203, 0, 113, 9])]));
        assert!(matches!(resolve_a(&cfg(&[&wrong_q]), "relay.example"), Err(DnsError::AllFailed(ref v)) if matches!(v[0].1, DnsError::Timeout)));
        assert!(matches!(resolve_a(&DnsConfig { servers: vec![], device: None, timeout: Duration::from_millis(100) }, "relay.example"), Err(DnsError::NoServers)));
        assert!(matches!(resolve_a(&cfg(&[&nx]), "not a name!"), Err(DnsError::InvalidName(_))));
    }

    #[test]
    fn truncated_udp_falls_back_to_tcp() {
        let s = stub(Behaviour::Truncate(vec![a("relay.example.", 60, [203, 0, 113, 3])]));
        let ans = resolve_a(&cfg(&[&s]), "relay.example").unwrap();
        assert_eq!(ans.addrs, vec![Ipv4Addr::new(203, 0, 113, 3)]);
        assert!(ans.via_tcp);
        assert_eq!(*s.queries.lock().unwrap(), 2);
    }

    #[test]
    fn servers_in_order_and_disagreement() {
        let s1 = stub(Behaviour::Answer(vec![a("relay.example.", 60, [203, 0, 113, 1])]));
        let s2 = stub(Behaviour::Answer(vec![a("relay.example.", 60, [203, 0, 113, 2])]));
        // the first server that answers wins, the second is not even asked
        let ans = resolve_a(&cfg(&[&s1, &s2]), "relay.example").unwrap();
        assert_eq!(ans.addrs, vec![Ipv4Addr::new(203, 0, 113, 1)]);
        assert_eq!(ans.server, s1.addr);
        assert_eq!(*s2.queries.lock().unwrap(), 0);
        // a failing first server hands over to the second
        let dead = stub(Behaviour::Rcode(ResponseCode::ServFail));
        let ans = resolve_a(&cfg(&[&dead, &s2]), "relay.example").unwrap();
        assert_eq!(ans.addrs, vec![Ipv4Addr::new(203, 0, 113, 2)]);
        assert_eq!(ans.server, s2.addr);
    }

    #[test]
    fn endpoint_safety() {
        for bad in ["0.0.0.0", "0.1.2.3", "127.0.0.1", "169.254.1.1", "224.0.0.1", "255.255.255.255", "240.0.0.1", "192.0.2.1", "198.51.100.1", "203.0.113.1", "198.18.0.1"] {
            assert!(check_endpoint_ip(bad.parse().unwrap(), true).is_err(), "{bad}");
        }
        for private in ["10.0.0.1", "172.16.0.1", "192.168.1.1", "100.64.0.1", "100.127.255.1"] {
            let ip: Ipv4Addr = private.parse().unwrap();
            assert!(check_endpoint_ip(ip, false).is_err(), "{private}");
            assert!(check_endpoint_ip(ip, true).is_ok(), "{private}");
        }
        assert!(check_endpoint_ip("47.243.1.1".parse().unwrap(), false).is_ok());
        assert!(check_endpoint("2001:db8::1".parse().unwrap(), true).is_err());
    }
}
