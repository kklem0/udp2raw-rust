//! The client's relay endpoint: what was configured (`-r ip:port` or `-r host:port`), which
//! address is in use right now, and when to re-resolve and switch.
//!
//! Rules (see README "Hostname endpoints"):
//! * A literal address never resolves anything and behaves exactly as before.
//! * A hostname is resolved through the explicit `--dns-server`s at startup and at the start
//!   of a reconnect cycle when the cached answer's TTL has expired or a refresh was forced
//!   (`reconnect` on the fifo). Failed queries back off exponentially with jitter.
//! * An answer only produces *candidates*. The current address stays first; the rest are
//!   sorted numerically, so a reordered answer changes nothing. A different address is used
//!   only at a reconnect boundary: immediately when DNS no longer lists the current one, or
//!   after a failed handshake cycle when the answer holds several addresses.
//! * An address becomes last-known-good (and lands in the cache file) only after the
//!   udp2raw handshake authenticated it. Resolver errors never erase it.

use crate::dns::{DnsError, Resolve, check_endpoint_ip};
use crate::util::fast_random_u32;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EndpointSpec {
    Literal(SocketAddr),
    Hostname { name: String, port: u16 },
}

impl EndpointSpec {
    /// `ip:port`, `[ipv6]:port` or `hostname:port`.
    pub fn parse(s: &str) -> Result<EndpointSpec, String> {
        if let Ok(a) = s.parse::<SocketAddr>() {
            return Ok(EndpointSpec::Literal(a));
        }
        let (host, port) = s.rsplit_once(':').ok_or_else(|| format!("{s}: expected host:port"))?;
        let port: u16 = port.parse().map_err(|_| format!("{s}: invalid port"))?;
        if port == 0 {
            return Err(format!("{s}: invalid port"));
        }
        validate_hostname(host)?;
        Ok(EndpointSpec::Hostname { name: host.trim_end_matches('.').to_ascii_lowercase(), port })
    }

    pub fn port(&self) -> u16 {
        match self {
            EndpointSpec::Literal(a) => a.port(),
            EndpointSpec::Hostname { port, .. } => *port,
        }
    }

    pub fn is_dynamic(&self) -> bool {
        matches!(self, EndpointSpec::Hostname { .. })
    }

    pub fn hostname(&self) -> Option<&str> {
        match self {
            EndpointSpec::Hostname { name, .. } => Some(name),
            EndpointSpec::Literal(_) => None,
        }
    }
}

impl fmt::Display for EndpointSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EndpointSpec::Literal(a) => write!(f, "{a}"),
            EndpointSpec::Hostname { name, port } => write!(f, "{name}:{port}"),
        }
    }
}

/// RFC 1123 host name syntax; the last label must not be all digits (that is an address).
pub fn validate_hostname(name: &str) -> Result<(), String> {
    let n = name.strip_suffix('.').unwrap_or(name);
    if n.is_empty() || n.len() > 253 {
        return Err(format!("{name}: hostname must be 1..253 characters"));
    }
    let labels: Vec<&str> = n.split('.').collect();
    for l in &labels {
        if l.is_empty() || l.len() > 63 {
            return Err(format!("{name}: labels must be 1..63 characters"));
        }
        if !l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(format!("{name}: only letters, digits and '-' are allowed"));
        }
        if l.starts_with('-') || l.ends_with('-') {
            return Err(format!("{name}: a label cannot start or end with '-'"));
        }
    }
    if labels.last().map(|l| l.bytes().all(|b| b.is_ascii_digit())).unwrap_or(false) {
        return Err(format!("{name}: not a hostname (numeric top-level label)"));
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct EndpointOptions {
    /// Accept RFC 1918 / CGNAT answers.
    pub allow_private: bool,
    /// Where the last authenticated address is remembered across restarts.
    pub cache_file: Option<PathBuf>,
    /// A literal to fall back to when neither DNS nor the cache can provide an address.
    pub bootstrap: Option<Ipv4Addr>,
    pub backoff_min_ms: u64,
    pub backoff_max_ms: u64,
}

impl Default for EndpointOptions {
    fn default() -> Self {
        EndpointOptions { allow_private: false, cache_file: None, bootstrap: None, backoff_min_ms: 2_000, backoff_max_ms: 60_000 }
    }
}

/// Bounded exponential backoff with ±25 % jitter for failed queries.
#[derive(Clone, Debug)]
pub struct Backoff {
    failures: u32,
    not_before_ms: u64,
    min_ms: u64,
    max_ms: u64,
}

impl Backoff {
    pub fn new(min_ms: u64, max_ms: u64) -> Backoff {
        Backoff { failures: 0, not_before_ms: 0, min_ms: min_ms.max(1), max_ms: max_ms.max(min_ms.max(1)) }
    }

    pub fn ready(&self, now_ms: u64) -> bool {
        now_ms >= self.not_before_ms
    }

    pub fn failures(&self) -> u32 {
        self.failures
    }

    /// Record a failure; returns the delay before the next attempt is allowed.
    pub fn on_failure(&mut self, now_ms: u64) -> u64 {
        let base = self.min_ms.saturating_mul(1u64 << self.failures.min(20)).min(self.max_ms);
        // jitter in [-25 %, +25 %]
        let jitter_span = base / 2;
        let jitter = if jitter_span == 0 { 0 } else { (fast_random_u32() as u64) % (jitter_span + 1) };
        let delay = (base - base / 4 + jitter).clamp(self.min_ms.min(self.max_ms), self.max_ms.saturating_add(self.max_ms / 4));
        self.failures = self.failures.saturating_add(1);
        self.not_before_ms = now_ms.saturating_add(delay);
        delay
    }

    pub fn on_success(&mut self) {
        self.failures = 0;
        self.not_before_ms = 0;
    }
}

/// Why the client is (re)starting a connection attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CycleReason {
    /// First attempt of the process.
    Startup,
    /// A handshake cycle on the current address timed out.
    AttemptFailed,
    /// An established session lost its heartbeats.
    SessionLost,
    /// `reconnect` on the fifo: planned cutover, re-resolve regardless of TTL and backoff.
    Forced,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Switch {
    pub from: SocketAddr,
    pub to: SocketAddr,
    pub why: String,
}

pub struct EndpointController {
    spec: EndpointSpec,
    opts: EndpointOptions,
    resolver: Box<dyn Resolve>,
    current: SocketAddr,
    current_authenticated: bool,
    last_good: Option<Ipv4Addr>,
    /// Ordered candidates from the last usable answer: current first, rest numeric.
    candidates: Vec<Ipv4Addr>,
    expires_at_ms: Option<u64>,
    backoff: Backoff,
    force_refresh: bool,
    queries: u64,
}

impl EndpointController {
    /// Decide the first address. DNS first; if that fails, the cache file; if that fails,
    /// `--bootstrap-addr`. A literal `-r` never queries.
    pub fn bootstrap(spec: EndpointSpec, resolver: Box<dyn Resolve>, opts: EndpointOptions, now_ms: u64) -> Result<EndpointController, String> {
        let port = spec.port();
        let mut c = EndpointController {
            spec: spec.clone(),
            opts,
            resolver,
            current: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
            current_authenticated: false,
            last_good: None,
            candidates: Vec::new(),
            expires_at_ms: None,
            backoff: Backoff::new(2_000, 60_000),
            force_refresh: false,
            queries: 0,
        };
        c.backoff = Backoff::new(c.opts.backoff_min_ms, c.opts.backoff_max_ms);
        let name = match &spec {
            EndpointSpec::Literal(a) => {
                c.current = *a;
                c.candidates = match a.ip() {
                    IpAddr::V4(v4) => vec![v4],
                    IpAddr::V6(_) => Vec::new(),
                };
                return Ok(c);
            }
            EndpointSpec::Hostname { name, .. } => name.clone(),
        };
        let cached = c.opts.cache_file.as_deref().and_then(|p| match load_cache(p, &name, port) {
            Ok(Some(ip)) => {
                log::info!("endpoint: cache {} has last-known-good {ip} for {name}:{port}", p.display());
                Some(ip)
            }
            Ok(None) => None,
            Err(e) => {
                log::warn!("endpoint: cache {} unreadable: {e}", p.display());
                None
            }
        });
        c.last_good = cached;
        let queried = c.query(now_ms);
        let chosen = if queried && !c.candidates.is_empty() {
            // continuity first: the address that worked last time, if DNS still lists it
            let pick = cached.filter(|ip| c.candidates.contains(ip)).unwrap_or(c.candidates[0]);
            log::info!("endpoint: {name}:{port} -> {pick} (dns; candidates {:?})", c.candidates);
            pick
        } else if let Some(ip) = cached {
            log::warn!("endpoint: dns unavailable, starting with last-known-good {ip} from the cache");
            ip
        } else if let Some(ip) = c.opts.bootstrap {
            log::warn!("endpoint: dns unavailable and no cache, starting with --bootstrap-addr {ip}");
            ip
        } else {
            return Err(format!("cannot resolve {name}:{port} and no cached or bootstrap address is available"));
        };
        c.current = SocketAddr::new(IpAddr::V4(chosen), port);
        c.order_candidates();
        Ok(c)
    }

    pub fn spec(&self) -> &EndpointSpec {
        &self.spec
    }

    pub fn current(&self) -> SocketAddr {
        self.current
    }

    pub fn last_good(&self) -> Option<Ipv4Addr> {
        self.last_good
    }

    pub fn is_dynamic(&self) -> bool {
        self.spec.is_dynamic()
    }

    pub fn candidates(&self) -> &[Ipv4Addr] {
        &self.candidates
    }

    /// Number of DNS queries sent so far (tests, logs).
    pub fn queries(&self) -> u64 {
        self.queries
    }

    /// `reconnect` on the fifo: the next cycle re-resolves regardless of TTL and backoff.
    pub fn request_refresh(&mut self, why: &str) {
        if self.is_dynamic() {
            log::info!("endpoint: refresh requested ({why})");
            self.force_refresh = true;
            self.backoff.on_success();
        }
    }

    /// Called by the client when it starts a connection attempt from the idle state.
    /// Refreshes the candidates when due and returns the address change to apply, if any.
    pub fn on_cycle(&mut self, now_ms: u64, reason: CycleReason) -> Option<Switch> {
        if !self.is_dynamic() {
            return None;
        }
        let expired = self.expires_at_ms.is_none_or(|t| now_ms >= t);
        let due = self.force_refresh || expired || self.candidates.is_empty();
        if due {
            if self.backoff.ready(now_ms) {
                self.force_refresh = false;
                self.query(now_ms);
            } else {
                log::debug!("endpoint: dns query deferred by backoff ({} failures)", self.backoff.failures());
            }
        }
        self.select(reason)
    }

    /// The udp2raw handshake on the current address succeeded: it is now last-known-good.
    /// Returns the previous last-known-good address when it differs (resources for it can go).
    pub fn on_authenticated(&mut self) -> Option<Ipv4Addr> {
        self.current_authenticated = true;
        let IpAddr::V4(cur) = self.current.ip() else { return None };
        let prev = self.last_good;
        if prev != Some(cur) {
            self.last_good = Some(cur);
            if let (Some(p), Some(name)) = (self.opts.cache_file.as_deref(), self.spec.hostname()) {
                match save_cache(p, name, self.spec.port(), cur) {
                    Ok(()) => log::info!("endpoint: {cur} is now last-known-good (saved to {})", p.display()),
                    Err(e) => log::warn!("endpoint: {cur} is now last-known-good but the cache {} could not be written: {e}", p.display()),
                }
            } else {
                log::info!("endpoint: {cur} is now last-known-good");
            }
            self.order_candidates();
        }
        prev.filter(|p| *p != cur)
    }

    pub fn current_authenticated(&self) -> bool {
        self.current_authenticated
    }

    /// One DNS round trip; updates candidates and TTL on success, backoff on failure.
    /// Returns whether a usable answer arrived.
    fn query(&mut self, now_ms: u64) -> bool {
        let Some(name) = self.spec.hostname().map(str::to_string) else { return false };
        self.queries += 1;
        match self.resolver.resolve_a(&name) {
            Ok(ans) => {
                self.expires_at_ms = Some(now_ms + u64::from(ans.ttl) * 1000);
                let mut safe = Vec::new();
                for ip in &ans.addrs {
                    match check_endpoint_ip(*ip, self.opts.allow_private) {
                        Ok(()) => {
                            if !safe.contains(ip) {
                                safe.push(*ip);
                            }
                        }
                        Err(why) => log::warn!("endpoint: rejecting {ip} from dns for {name}: {why}"),
                    }
                }
                log::info!(
                    "endpoint: dns {name} @{}{} -> {:?} ttl {}s (raw {}s){}; usable {:?}",
                    ans.server,
                    if ans.via_tcp { " (tcp)" } else { "" },
                    ans.addrs,
                    ans.ttl,
                    ans.raw_ttl,
                    if ans.cnames.is_empty() { String::new() } else { format!(" via {}", ans.cnames.join(" -> ")) },
                    safe
                );
                if safe.is_empty() {
                    // A reply we could read but with no usable address (all filtered out, or a
                    // NODATA-shaped positive): rate-limit it like a failure so a resolver that
                    // only ever returns rejected addresses cannot drive a per-cycle query loop.
                    let delay = self.backoff.on_failure(now_ms);
                    log::warn!("endpoint: dns answer for {name} had no usable address; keeping the previous candidates, next query in {:.1}s", delay as f64 / 1000.0);
                    return false;
                }
                self.backoff.on_success();
                if safe != self.candidates_unordered() {
                    log::info!("endpoint: candidates for {name} changed: {:?} -> {:?}", self.candidates, safe);
                }
                self.candidates = safe;
                self.order_candidates();
                true
            }
            Err(e) => {
                let delay = self.backoff.on_failure(now_ms);
                match e {
                    DnsError::AllFailed(_) | DnsError::Timeout | DnsError::Io(_) => log::warn!("endpoint: dns {name} failed: {e}; keeping {} , next query in {:.1}s", self.current, delay as f64 / 1000.0),
                    _ => log::warn!("endpoint: dns {name}: {e}; keeping {} , next query in {:.1}s", self.current, delay as f64 / 1000.0),
                }
                false
            }
        }
    }

    fn candidates_unordered(&self) -> Vec<Ipv4Addr> {
        let mut v = self.candidates.clone();
        v.sort_by_key(|ip| u32::from(*ip));
        v
    }

    /// Current first, then last-known-good, then the rest by numeric value: the order never
    /// depends on how the server listed the records.
    fn order_candidates(&mut self) {
        let cur = match self.current.ip() {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        };
        let mut rest: Vec<Ipv4Addr> = self.candidates.iter().copied().filter(|ip| Some(*ip) != cur && Some(*ip) != self.last_good).collect();
        rest.sort_by_key(|ip| u32::from(*ip));
        rest.dedup();
        let mut ordered = Vec::with_capacity(self.candidates.len());
        if let Some(c) = cur.filter(|c| self.candidates.contains(c)) {
            ordered.push(c);
        }
        if let Some(g) = self.last_good.filter(|g| self.candidates.contains(g) && Some(*g) != cur) {
            ordered.push(g);
        }
        ordered.extend(rest);
        self.candidates = ordered;
    }

    fn select(&mut self, reason: CycleReason) -> Option<Switch> {
        if self.candidates.is_empty() {
            return None;
        }
        let cur = match self.current.ip() {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => return None,
        };
        let target = match self.candidates.iter().position(|ip| *ip == cur) {
            None => (self.candidates[0], format!("dns no longer lists {cur}")),
            Some(idx) => {
                if reason == CycleReason::AttemptFailed && self.candidates.len() > 1 {
                    let next = self.candidates[(idx + 1) % self.candidates.len()];
                    (next, format!("handshake with {cur} failed, trying the next candidate"))
                } else {
                    return None;
                }
            }
        };
        if target.0 == cur {
            return None;
        }
        let from = self.current;
        self.current = SocketAddr::new(IpAddr::V4(target.0), self.spec.port());
        self.current_authenticated = false;
        self.order_candidates();
        log::warn!("endpoint: switching {} -> {} ({}; reason {:?})", from, self.current, target.1, reason);
        Some(Switch { from, to: self.current, why: target.1 })
    }
}

/// The cache file: a few `key=value` lines, written atomically with mode 0600.
pub fn load_cache(path: &Path, host: &str, port: u16) -> io::Result<Option<Ipv4Addr>> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let (mut h, mut p, mut a) = (None, None, None);
    for line in text.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("host=") {
            h = Some(v.trim().to_ascii_lowercase());
        } else if let Some(v) = line.strip_prefix("port=") {
            p = v.trim().parse::<u16>().ok();
        } else if let Some(v) = line.strip_prefix("addr=") {
            a = v.trim().parse::<Ipv4Addr>().ok();
        }
    }
    if h.as_deref() != Some(&host.to_ascii_lowercase()) || p != Some(port) {
        return Ok(None); // written for another endpoint
    }
    Ok(a)
}

pub fn save_cache(path: &Path, host: &str, port: u16, addr: Ipv4Addr) -> io::Result<()> {
    use std::io::Write;
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir)?;
        }
    }
    let saved = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let body = format!("# udp2raw endpoint cache: the last address whose handshake succeeded\nhost={host}\nport={port}\naddr={addr}\nsaved={saved}\n");
    // append (not replace-extension: a dotted hostname filename would be mangled) a suffix,
    // keeping the temp file in the same directory so the rename is atomic
    let mut tmp_name = path.file_name().map(|f| f.to_os_string()).unwrap_or_else(|| std::ffi::OsString::from("endpoint"));
    tmp_name.push(format!(".tmp.{}", std::process::id()));
    let tmp = path.with_file_name(tmp_name);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    f.write_all(body.as_bytes())?;
    f.sync_all()?;
    drop(f);
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::DnsAnswer;
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Mock {
        answers: Mutex<VecDeque<Result<Vec<Ipv4Addr>, &'static str>>>,
        ttl: u32,
        calls: AtomicU64,
    }

    impl Mock {
        fn new(script: Vec<Result<Vec<Ipv4Addr>, &'static str>>, ttl: u32) -> Box<Mock> {
            Box::new(Mock { answers: Mutex::new(script.into()), ttl, calls: AtomicU64::new(0) })
        }
    }

    impl Resolve for Mock {
        fn resolve_a(&self, _name: &str) -> Result<DnsAnswer, DnsError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let mut q = self.answers.lock().unwrap();
            let item = if q.len() > 1 { q.pop_front().unwrap() } else { q.front().cloned().unwrap_or(Err("empty")) };
            match item {
                Ok(addrs) => Ok(DnsAnswer { addrs, ttl: self.ttl.clamp(10, 3600), raw_ttl: self.ttl, server: "127.0.0.1:53".parse().unwrap(), cnames: vec![], via_tcp: false }),
                Err("nx") => Err(DnsError::NxDomain),
                Err(_) => Err(DnsError::Timeout),
            }
        }
    }

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }
    fn host() -> EndpointSpec {
        EndpointSpec::parse("relay.example.com:8443").unwrap()
    }
    fn opts() -> EndpointOptions {
        EndpointOptions { allow_private: false, cache_file: None, bootstrap: None, backoff_min_ms: 2_000, backoff_max_ms: 60_000 }
    }

    #[test]
    fn spec_parsing() {
        assert_eq!(EndpointSpec::parse("1.2.3.4:8443").unwrap(), EndpointSpec::Literal("1.2.3.4:8443".parse().unwrap()));
        assert_eq!(EndpointSpec::parse("[2001:db8::1]:8443").unwrap(), EndpointSpec::Literal("[2001:db8::1]:8443".parse().unwrap()));
        assert_eq!(EndpointSpec::parse("Relay.Example.COM.:8443").unwrap(), EndpointSpec::Hostname { name: "relay.example.com".into(), port: 8443 });
        assert_eq!(EndpointSpec::parse("relay:8443").unwrap().to_string(), "relay:8443");
        for bad in ["relay.example.com", "relay.example.com:0", "relay.example.com:70000", ":8443", "-bad.example:1", "bad-.example:1", "a..b:1", "1.2.3:1", "under_score.example:1", "x y:1"] {
            assert!(EndpointSpec::parse(bad).is_err(), "{bad}");
        }
        let long = format!("{}.example:1", "a".repeat(64));
        assert!(EndpointSpec::parse(&long).is_err());
    }

    #[test]
    fn literal_never_queries() {
        let m = Mock::new(vec![Ok(vec![ip("203.0.113.9")])], 60);
        let mut c = EndpointController::bootstrap(EndpointSpec::parse("47.243.1.1:8443").unwrap(), m, opts(), 0).unwrap();
        assert_eq!(c.current().to_string(), "47.243.1.1:8443");
        assert!(c.on_cycle(1_000_000, CycleReason::AttemptFailed).is_none());
        assert!(c.on_cycle(2_000_000, CycleReason::Forced).is_none());
        assert_eq!(c.queries(), 0);
    }

    #[test]
    fn startup_prefers_dns_then_cache_then_bootstrap() {
        let dir = std::env::temp_dir().join(format!("udp2raw-ep-{}", std::process::id()));
        let cache = dir.join("cache");
        let _ = std::fs::remove_dir_all(&dir);
        // dns ok
        let m = Mock::new(vec![Ok(vec![ip("47.243.1.2"), ip("47.243.1.1")])], 60);
        let o = EndpointOptions { cache_file: Some(cache.clone()), ..opts() };
        let mut c = EndpointController::bootstrap(host(), m, o.clone(), 0).unwrap();
        // no history: the numerically first candidate, whatever order the server used
        assert_eq!(c.current().ip(), IpAddr::V4(ip("47.243.1.1")));
        assert_eq!(c.candidates(), &[ip("47.243.1.1"), ip("47.243.1.2")]);
        assert!(!cache.exists(), "cache must not be written before authentication");
        assert_eq!(c.on_authenticated(), None);
        assert!(cache.exists());
        assert_eq!(load_cache(&cache, "relay.example.com", 8443).unwrap(), Some(ip("47.243.1.1")));
        assert_eq!(load_cache(&cache, "other.example.com", 8443).unwrap(), None);
        assert_eq!(load_cache(&cache, "relay.example.com", 1).unwrap(), None);
        // dns now lists a numerically earlier address as well: continuity with the cache wins
        let m = Mock::new(vec![Ok(vec![ip("47.243.1.0"), ip("47.243.1.1")])], 60);
        let c = EndpointController::bootstrap(host(), m, o.clone(), 0).unwrap();
        assert_eq!(c.current().ip(), IpAddr::V4(ip("47.243.1.1")));
        assert_eq!(c.candidates(), &[ip("47.243.1.1"), ip("47.243.1.0")]);
        // dns down: cache
        let m = Mock::new(vec![Err("timeout")], 60);
        let c = EndpointController::bootstrap(host(), m, o.clone(), 0).unwrap();
        assert_eq!(c.current().ip(), IpAddr::V4(ip("47.243.1.1")));
        // dns down, no cache: bootstrap literal
        let _ = std::fs::remove_dir_all(&dir);
        let m = Mock::new(vec![Err("timeout")], 60);
        let c = EndpointController::bootstrap(host(), m, EndpointOptions { bootstrap: Some(ip("47.243.9.9")), ..opts() }, 0).unwrap();
        assert_eq!(c.current().ip(), IpAddr::V4(ip("47.243.9.9")));
        // nothing at all
        let m = Mock::new(vec![Err("nx")], 60);
        assert!(EndpointController::bootstrap(host(), m, opts(), 0).is_err());
    }

    #[test]
    fn failed_attempt_switches_to_new_dns_address_and_dns_failure_keeps_current() {
        let m = Mock::new(vec![Ok(vec![ip("47.243.1.1")]), Ok(vec![ip("47.243.1.1")]), Ok(vec![ip("47.243.2.2")]), Err("timeout")], 30);
        let mut c = EndpointController::bootstrap(host(), m, opts(), 0).unwrap();
        c.on_authenticated();
        // session lost while the TTL is fresh: no query, no switch
        assert!(c.on_cycle(5_000, CycleReason::SessionLost).is_none());
        assert_eq!(c.queries(), 1);
        // TTL expired, DNS still says the same: no switch even after a failed attempt (single candidate)
        assert!(c.on_cycle(31_000, CycleReason::AttemptFailed).is_none());
        assert_eq!(c.queries(), 2);
        // next expiry: DNS moved -> switch immediately, not yet last-known-good
        let sw = c.on_cycle(62_000, CycleReason::AttemptFailed).unwrap();
        assert_eq!(sw.from.ip(), IpAddr::V4(ip("47.243.1.1")));
        assert_eq!(sw.to.ip(), IpAddr::V4(ip("47.243.2.2")));
        assert_eq!(c.last_good(), Some(ip("47.243.1.1")));
        assert!(!c.current_authenticated());
        // resolver dies: current stays, last-good untouched
        assert!(c.on_cycle(100_000, CycleReason::AttemptFailed).is_none());
        assert_eq!(c.current().ip(), IpAddr::V4(ip("47.243.2.2")));
        assert_eq!(c.last_good(), Some(ip("47.243.1.1")));
        // handshake succeeds on the new one: it becomes last-known-good and the old one is released
        assert_eq!(c.on_authenticated(), Some(ip("47.243.1.1")));
        assert_eq!(c.last_good(), Some(ip("47.243.2.2")));
    }

    #[test]
    fn forced_refresh_switches_even_when_healthy_and_fresh() {
        let m = Mock::new(vec![Ok(vec![ip("47.243.1.1")]), Ok(vec![ip("47.243.2.2")])], 3600);
        let mut c = EndpointController::bootstrap(host(), m, opts(), 0).unwrap();
        c.on_authenticated();
        assert!(c.on_cycle(1_000, CycleReason::SessionLost).is_none()); // TTL fresh: not even a query
        assert_eq!(c.queries(), 1);
        c.request_refresh("fifo reconnect");
        let sw = c.on_cycle(2_000, CycleReason::Forced).unwrap();
        assert_eq!(sw.to.ip(), IpAddr::V4(ip("47.243.2.2")));
        assert_eq!(c.queries(), 2);
    }

    #[test]
    fn reordered_and_duplicate_answers_do_not_rotate_but_failure_does_deterministically() {
        let m = Mock::new(vec![Ok(vec![ip("47.243.1.1"), ip("47.243.1.2")]), Ok(vec![ip("47.243.1.2"), ip("47.243.1.1"), ip("47.243.1.2")]), Ok(vec![ip("47.243.1.1"), ip("47.243.1.2")])], 10);
        let mut c = EndpointController::bootstrap(host(), m, opts(), 0).unwrap();
        assert_eq!(c.current().ip(), IpAddr::V4(ip("47.243.1.1")));
        c.on_authenticated();
        // session lost with a reordered answer: same set, current stays
        assert!(c.on_cycle(11_000, CycleReason::SessionLost).is_none());
        assert_eq!(c.candidates(), &[ip("47.243.1.1"), ip("47.243.1.2")]);
        // a failed handshake cycle rotates to the other candidate, deterministically
        let sw = c.on_cycle(22_000, CycleReason::AttemptFailed).unwrap();
        assert_eq!(sw.to.ip(), IpAddr::V4(ip("47.243.1.2")));
        assert_eq!(c.candidates(), &[ip("47.243.1.2"), ip("47.243.1.1")]);
        // and back if that fails too (answer unchanged)
        let sw = c.on_cycle(33_000, CycleReason::AttemptFailed).unwrap();
        assert_eq!(sw.to.ip(), IpAddr::V4(ip("47.243.1.1")));
    }

    #[test]
    fn unsafe_answers_are_rejected_unless_allowed() {
        let m = Mock::new(vec![Ok(vec![ip("127.0.0.1"), ip("10.0.0.5"), ip("47.243.1.1")])], 60);
        let c = EndpointController::bootstrap(host(), m, opts(), 0).unwrap();
        assert_eq!(c.candidates(), &[ip("47.243.1.1")]);
        let m = Mock::new(vec![Ok(vec![ip("127.0.0.1"), ip("10.0.0.5"), ip("47.243.1.1")])], 60);
        let c = EndpointController::bootstrap(host(), m, EndpointOptions { allow_private: true, ..opts() }, 0).unwrap();
        assert_eq!(c.candidates(), &[ip("10.0.0.5"), ip("47.243.1.1")]);
        // an answer with only unsafe addresses keeps the previous candidates
        let m = Mock::new(vec![Ok(vec![ip("47.243.1.1")]), Ok(vec![ip("169.254.1.1")])], 10);
        let mut c = EndpointController::bootstrap(host(), m, opts(), 0).unwrap();
        assert!(c.on_cycle(11_000, CycleReason::AttemptFailed).is_none());
        assert_eq!(c.candidates(), &[ip("47.243.1.1")]);
    }

    #[test]
    fn persistent_unsafe_answers_do_not_loop() {
        // DNS keeps returning only loopback while we run on a --bootstrap-addr: candidates stay
        // empty, but the queries must be backoff-limited, not one per reconnect cycle.
        let m = Mock::new(vec![Ok(vec![ip("127.0.0.1")])], 30);
        let o = EndpointOptions { bootstrap: Some(ip("47.243.1.1")), ..opts() };
        let mut c = EndpointController::bootstrap(host(), m, o, 0).unwrap();
        assert_eq!(c.current().ip(), IpAddr::V4(ip("47.243.1.1")));
        assert!(c.candidates().is_empty());
        let mut t = 0;
        while t < 600_000 {
            t += 5_000;
            assert!(c.on_cycle(t, CycleReason::AttemptFailed).is_none());
        }
        assert!(c.queries() >= 8 && c.queries() <= 20, "queries {}", c.queries());
        assert_eq!(c.current().ip(), IpAddr::V4(ip("47.243.1.1")));
    }

    #[test]
    fn backoff_bounds_query_rate_during_an_outage() {
        let m = Mock::new(vec![Err("timeout")], 30);
        let o = EndpointOptions { bootstrap: Some(ip("47.243.1.1")), ..opts() };
        let mut c = EndpointController::bootstrap(host(), m, o, 0).unwrap();
        assert_eq!(c.queries(), 1);
        // a reconnect cycle every 5 s for 10 minutes: far fewer queries than cycles
        let mut cycles = 0;
        let mut t = 0;
        while t < 600_000 {
            t += 5_000;
            cycles += 1;
            assert!(c.on_cycle(t, CycleReason::AttemptFailed).is_none());
        }
        assert_eq!(cycles, 120);
        assert!(c.queries() >= 8 && c.queries() <= 20, "queries {}", c.queries());
        assert_eq!(c.current().ip(), IpAddr::V4(ip("47.243.1.1")));
    }

    #[test]
    fn backoff_growth_and_jitter() {
        let mut b = Backoff::new(2_000, 60_000);
        let mut last = 0;
        for i in 0..12 {
            let d = b.on_failure(0);
            let base = (2_000u64 << i).min(60_000);
            assert!(d >= base - base / 4 && d <= base + base / 4, "attempt {i}: {d} vs base {base}");
            assert!(d >= last / 2, "must not shrink much: {d} after {last}");
            last = d;
            assert!(!b.ready(d - 1));
            assert!(b.ready(d));
        }
        b.on_success();
        assert!(b.ready(0));
        assert_eq!(b.failures(), 0);
    }
}
