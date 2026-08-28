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
//! * Last-good rollback is opt-in. The cache supplies startup history, while authenticated
//!   runtime activity supplies independent live freshness. A working committed endpoint is
//!   never torn down by a periodic DNS probe.
//! * A newly authenticated address remains probationary. The previous committed address and
//!   native resources survive until sustained authenticated payload traffic plus an explicit
//!   FIFO promotion, or until rollback.
//! * Old-address probes are pre-charged to crash-safe per-answer and global limits.

use crate::consts::{CLIENT_HANDSHAKE_TIMEOUT_MS, TIMER_INTERVAL_MS};
use crate::dns::{DnsError, Resolve, check_endpoint_ip};
use crate::util::fast_random_u32;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::dns::MAX_ENDPOINT_CANDIDATES;

const CACHE_MAX_BYTES: usize = 4096;
const STATE_MAX_BYTES: usize = 16 * 1024;
const MAX_BUDGET_ENTRIES: usize = 16;
const MAX_PERSISTED_COOLDOWN_SECS: u64 = 86_400;
pub const MIN_PROMOTION_DATA_PACKETS: u32 = 3;

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
        Ok(EndpointSpec::Hostname {
            name: host.trim_end_matches('.').to_ascii_lowercase(),
            port,
        })
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
    pub last_good_fallback: LastGoodFallbackPolicy,
}

impl Default for EndpointOptions {
    fn default() -> Self {
        EndpointOptions {
            allow_private: false,
            cache_file: None,
            bootstrap: None,
            backoff_min_ms: 2_000,
            backoff_max_ms: 60_000,
            last_good_fallback: LastGoodFallbackPolicy::default(),
        }
    }
}

/// Opt-in limits for retrying a committed-good address that newer DNS excludes.
///
/// Unattended probes are durably charged before they start. An authenticated recovery stays
/// in service until it fails; migration to a replacement requires an attended cutover and
/// explicit promotion after probation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LastGoodFallbackPolicy {
    pub enabled: bool,
    pub after_failures: u32,
    pub max_attempts: u32,
    pub cooldown_ms: u64,
    pub max_age_ms: u64,
    pub global_capacity: u32,
    pub global_refill_ms: u64,
    pub preferred_round_timeout_ms: u64,
    pub probation_ms: u64,
    pub rollback_window_ms: u64,
}

impl Default for LastGoodFallbackPolicy {
    fn default() -> Self {
        LastGoodFallbackPolicy {
            enabled: false,
            after_failures: 3,
            max_attempts: 2,
            cooldown_ms: 300_000,
            max_age_ms: 86_400_000,
            global_capacity: 4,
            global_refill_ms: 900_000,
            preferred_round_timeout_ms: 30_000,
            probation_ms: 30_000,
            rollback_window_ms: 300_000,
        }
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
        Backoff {
            failures: 0,
            not_before_ms: 0,
            min_ms: min_ms.max(1),
            max_ms: max_ms.max(min_ms.max(1)),
        }
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
    /// A probationary candidate did not earn promotion before its rollback deadline.
    ProbationExpired,
    /// An operator or external health collector explicitly requested rollback.
    OperatorRollback,
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
    /// Durable rollback point. The cache always describes this address, never a candidate
    /// that has merely completed one handshake.
    committed_good: Option<Ipv4Addr>,
    /// Startup-cache freshness is wall-clock-derived and never substitutes for live health.
    cache_fresh_until_ms: Option<u64>,
    /// Last accepted authenticated packet while the committed endpoint was current. This is
    /// refreshed continuously and is frozen only while another endpoint is being tried.
    committed_runtime_activity_ms: Option<u64>,
    /// Ordered candidates from the last usable answer: current first, rest numeric.
    candidates: Vec<Ipv4Addr>,
    expires_at_ms: Option<u64>,
    backoff: Backoff,
    force_refresh: bool,
    queries: u64,
    /// Failed handshake cycles on DNS-preferred candidates since the last authentication.
    preferred_failures: u32,
    /// Absolute deadline and attempt count for the current bounded preferred-candidate round.
    preferred_round_deadline_ms: Option<u64>,
    preferred_attempts: u32,
    /// FIFO `reconnect` is an attended, single-candidate interruption with direct rollback.
    attended_cutover: bool,
    probation: Option<Probation>,
    fallback_state: FallbackState,
    fallback_state_path: Option<PathBuf>,
    fallback_state_usable: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Probation {
    candidate: Ipv4Addr,
    rollback: Ipv4Addr,
    authenticated_at_ms: u64,
    /// Only an attended FIFO cutover from the currently healthy committed endpoint may
    /// return directly without consuming the persisted blind old-address probe budget.
    direct_return: bool,
    /// None preserves the historical cache/resources without scheduling a destructive
    /// rollback to an endpoint whose freshness proof has already expired.
    rollback_at_ms: Option<u64>,
    rollback_authorized: bool,
    first_data_ms: Option<u64>,
    last_data_ms: Option<u64>,
    data_packets: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BudgetEntry {
    candidate: Ipv4Addr,
    dns_set: Vec<Ipv4Addr>,
    charged: u32,
    not_before_unix_secs: u64,
    last_used_unix_secs: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FallbackState {
    global_tokens: u32,
    global_updated_unix_secs: u64,
    entries: Vec<BudgetEntry>,
}

impl FallbackState {
    fn new(capacity: u32, wall_now: u64) -> Self {
        Self {
            global_tokens: capacity,
            global_updated_unix_secs: wall_now,
            entries: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PromotionResult {
    Promoted { previous: Ipv4Addr },
    NotProbationary,
    WrongCandidate,
    NotActive,
    RollbackExpired,
    StaleEvidence { idle_ms: u64 },
    InsufficientEvidence { packets: u32, span_ms: u64 },
    PersistenceFailed(String),
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
            committed_good: None,
            cache_fresh_until_ms: None,
            committed_runtime_activity_ms: None,
            candidates: Vec::new(),
            expires_at_ms: None,
            backoff: Backoff::new(2_000, 60_000),
            force_refresh: false,
            queries: 0,
            preferred_failures: 0,
            preferred_round_deadline_ms: None,
            preferred_attempts: 0,
            attended_cutover: false,
            probation: None,
            fallback_state: FallbackState::new(0, unix_now_secs()),
            fallback_state_path: None,
            fallback_state_usable: true,
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
        if let Some(ip) = c.opts.bootstrap {
            check_endpoint_ip(ip, c.opts.allow_private)
                .map_err(|why| format!("unsafe --bootstrap-addr {ip}: {why}"))?;
        }
        let cached = c.opts.cache_file.as_deref().and_then(|p| match load_cache_entry(p, &name, port, c.opts.allow_private) {
            Ok(Some(entry)) => {
                log::info!("endpoint: cache {} has last-known-good {} for {name}:{port}", p.display(), entry.addr);
                Some(entry)
            }
            Ok(None) => None,
            Err(e) => {
                log::warn!("endpoint: cache {} unreadable: {e}", p.display());
                None
            }
        });
        let wall_now = unix_now_secs();
        c.committed_good = cached.map(|entry| entry.addr);
        c.cache_fresh_until_ms = cached.and_then(|entry| c.cached_fresh_until(entry, now_ms, wall_now));
        if cached.is_some() && c.cache_fresh_until_ms.is_none() {
            log::warn!(
                "endpoint: cached last-known-good is too old or has no trustworthy saved timestamp; it may bootstrap an outage but will not be used as a DNS fallback until it authenticates again"
            );
        }
        if c.opts.last_good_fallback.enabled {
            c.fallback_state_path = c.opts.cache_file.as_deref().map(fallback_state_path);
            c.fallback_state = FallbackState::new(c.opts.last_good_fallback.global_capacity, wall_now);
            if let Some(p) = c.fallback_state_path.as_deref() {
                // Opening the durable lock also creates and validates a previously absent
                // owner-only state directory. A first installation must not be mistaken for
                // corrupt state and lose fallback for the lifetime of this process.
                let lock_path = fallback_state_lock_path(p);
                let loaded = crate::secure_file::with_owner_only_lock(&lock_path, || {
                    load_fallback_state(
                        p,
                        &name,
                        port,
                        c.opts.last_good_fallback.global_capacity,
                        c.opts.allow_private,
                        wall_now,
                    )
                });
                match loaded {
                    Ok(Some(s)) => c.fallback_state = s,
                    Ok(None) => {}
                    Err(e) => {
                        c.fallback_state_usable = false;
                        log::warn!(
                            "endpoint: persisted fallback limits {} are unsafe or unreadable: {e}; old-address probes are disabled fail-closed",
                            p.display()
                        );
                    }
                }
            }
        }
        c.start_preferred_round(now_ms);
        let queried = c.query(now_ms);
        let chosen = if queried && !c.candidates.is_empty() {
            // continuity first: the address that worked last time, if DNS still lists it
            let pick = c.committed_good.filter(|ip| c.candidates.contains(ip)).unwrap_or(c.candidates[0]);
            log::info!("endpoint: {name}:{port} -> {pick} (dns; candidates {:?})", c.candidates);
            pick
        } else if let Some(ip) = c.committed_good {
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
        self.committed_good
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

    pub fn retained_addresses(&self) -> Vec<Ipv4Addr> {
        let mut out = Vec::with_capacity(2);
        if let IpAddr::V4(cur) = self.current.ip() {
            out.push(cur);
        }
        if let Some(good) = self.committed_good {
            if !out.contains(&good) {
                out.push(good);
            }
        }
        out
    }

    pub fn is_probationary(&self) -> bool {
        self.probation.is_some()
    }

    pub fn probation_rollback_due(&mut self, now_ms: u64) -> bool {
        self.probation_rollback_due_at(now_ms, unix_now_secs())
    }

    fn probation_rollback_due_at(&mut self, now_ms: u64, wall_now: u64) -> bool {
        let IpAddr::V4(cur) = self.current.ip() else {
            return false;
        };
        let Some((rollback, direct_return, already_authorized)) = self
            .probation
            .as_ref()
            .filter(|p| p.candidate == cur)
            .filter(|p| p.rollback_at_ms.is_some_and(|deadline| now_ms >= deadline))
            .map(|p| (p.rollback, p.direct_return, p.rollback_authorized))
        else {
            return false;
        };
        if self.committed_fresh(now_ms, cur) != Some(rollback) {
            return false;
        }
        if already_authorized {
            return true;
        }
        if !direct_return && !self.charge_fallback(wall_now, rollback) {
            log::warn!(
                "endpoint: probation rollback to {rollback} denied by persisted old-address probe limits; keeping live candidate {cur}"
            );
            return false;
        }
        if let Some(p) = self
            .probation
            .as_mut()
            .filter(|p| p.candidate == cur && p.rollback == rollback)
        {
            // Preserve the charged eligibility decision across the short Idle transition.
            // The next timer may run just after the freshness horizon that was valid here.
            p.rollback_authorized = true;
            return true;
        }
        false
    }

    pub fn authorize_operator_rollback(&mut self, expected: Ipv4Addr, now_ms: u64) -> bool {
        self.authorize_operator_rollback_at(expected, now_ms, unix_now_secs())
    }

    fn authorize_operator_rollback_at(&mut self, expected: Ipv4Addr, now_ms: u64, wall_now: u64) -> bool {
        let IpAddr::V4(cur) = self.current.ip() else {
            return false;
        };
        let Some((rollback, direct_return, already_authorized)) = self
            .probation
            .as_ref()
            .filter(|p| cur == expected && p.candidate == expected)
            .map(|p| (p.rollback, p.direct_return, p.rollback_authorized))
        else {
            return false;
        };
        if self.committed_fresh(now_ms, cur) != Some(rollback) {
            return false;
        }
        if !already_authorized && !direct_return && !self.charge_fallback(wall_now, rollback) {
            log::warn!(
                "endpoint: operator rollback to {rollback} denied because its durable old-address probe could not be pre-charged"
            );
            return false;
        }
        if let Some(p) = self
            .probation
            .as_mut()
            .filter(|p| p.candidate == expected && p.rollback == rollback)
        {
            p.rollback_authorized = true;
            return true;
        }
        false
    }

    /// Mark the active transport down even when the next cycle will retry the same address.
    pub fn on_session_ended(&mut self) {
        self.current_authenticated = false;
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
        self.on_cycle_with_clock(now_ms, reason, unix_now_secs(), || {
            (crate::util::now_ms(), unix_now_secs())
        })
    }

    #[cfg(test)]
    fn on_cycle_at(&mut self, now_ms: u64, reason: CycleReason, wall_now: u64) -> Option<Switch> {
        self.on_cycle_with_clock(now_ms, reason, wall_now, || (now_ms, wall_now))
    }

    #[cfg(test)]
    fn on_cycle_after_query_at(&mut self, now_ms: u64, after_query_ms: u64, reason: CycleReason, wall_now: u64) -> Option<Switch> {
        self.on_cycle_with_clock(now_ms, reason, wall_now, || (after_query_ms, wall_now))
    }

    fn on_cycle_with_clock<F>(&mut self, now_ms: u64, reason: CycleReason, wall_now: u64, mut after_query: F) -> Option<Switch>
    where
        F: FnMut() -> (u64, u64),
    {
        if !self.is_dynamic() {
            return None;
        }
        let expired = self.expires_at_ms.is_none_or(|t| now_ms >= t);
        let due = self.force_refresh || expired || self.candidates.is_empty();
        let mut query_succeeded = None;
        let mut decision_now_ms = now_ms;
        let mut decision_wall_now = wall_now;
        if due {
            if matches!(reason, CycleReason::Forced | CycleReason::SessionLost | CycleReason::AttemptFailed) {
                self.start_preferred_round(now_ms);
            }
            if self.backoff.ready(now_ms) {
                self.force_refresh = false;
                query_succeeded = Some(self.query(now_ms));
            } else {
                log::debug!("endpoint: dns query deferred by backoff ({} failures)", self.backoff.failures());
            }
            // Resolver I/O is synchronous in the first safe version. Never evaluate the
            // preferred-round deadline using the stale timestamp from before that I/O.
            (decision_now_ms, decision_wall_now) = after_query();
        }
        self.select(decision_now_ms, decision_wall_now, reason, query_succeeded)
    }

    /// A handshake authenticates the active transport. With rollback enabled, a different
    /// endpoint becomes probationary and cannot rewrite the committed cache yet.
    pub fn on_authenticated(&mut self) -> Option<Ipv4Addr> {
        self.on_authenticated_at(crate::util::now_ms())
    }

    /// Deterministic form used by the state-machine tests.
    fn on_authenticated_at(&mut self, now_ms: u64) -> Option<Ipv4Addr> {
        self.current_authenticated = true;
        let IpAddr::V4(cur) = self.current.ip() else {
            return None;
        };
        self.preferred_failures = 0;
        self.preferred_attempts = 0;
        self.preferred_round_deadline_ms = None;
        let prev = self.committed_good;
        if !self.opts.last_good_fallback.enabled || prev.is_none() || prev == Some(cur) {
            self.committed_good = Some(cur);
            self.committed_runtime_activity_ms = Some(now_ms);
            self.cache_fresh_until_ms = None;
            self.probation = None;
            self.attended_cutover = false;
            self.persist_committed(cur, prev != Some(cur));
            self.order_candidates();
            return prev.filter(|old| *old != cur);
        }
        let rollback = prev.expect("checked above");
        let direct_return = self.attended_cutover;
        let freshness_deadline = self
            .committed_health_deadline(now_ms)
            .map(|(_, deadline)| deadline)
            .map(|deadline| deadline.min(now_ms.saturating_add(self.opts.last_good_fallback.rollback_window_ms)));
        let rollback_grace_ms = 2 * TIMER_INTERVAL_MS;
        let required_rollback_horizon_ms = now_ms
            .saturating_add(self.opts.last_good_fallback.probation_ms)
            .saturating_add(rollback_grace_ms);
        let rollback_at_ms = freshness_deadline
            .filter(|deadline| *deadline >= required_rollback_horizon_ms)
            .map(|deadline| deadline.saturating_sub(rollback_grace_ms));
        self.probation = Some(Probation {
            candidate: cur,
            rollback,
            authenticated_at_ms: now_ms,
            direct_return,
            rollback_at_ms,
            rollback_authorized: false,
            first_data_ms: None,
            last_data_ms: None,
            data_packets: 0,
        });
        self.attended_cutover = false;
        if let (Some(due), Some(fresh_until)) = (rollback_at_ms, freshness_deadline) {
            log::warn!(
                "endpoint: {cur} authenticated but remains probationary; committed-good {rollback} and its cache/route are preserved (rollback due {due}ms, freshness through {fresh_until}ms monotonic)"
            );
        } else {
            log::warn!(
                "endpoint: {cur} authenticated but remains probationary; committed-good {rollback} stays cached/preserved, but its remaining freshness cannot safely schedule an automatic probation rollback"
            );
        }
        self.order_candidates();
        None
    }

    /// Record an accepted authenticated safer packet. Heartbeats maintain the runtime
    /// freshness of a committed endpoint; only real inbound DATA counts toward promotion.
    pub fn on_authenticated_activity(&mut self, now_ms: u64, is_data: bool) {
        let IpAddr::V4(cur) = self.current.ip() else { return };
        if self.current_authenticated && self.committed_good == Some(cur) {
            self.committed_runtime_activity_ms = Some(now_ms);
        }
        if !is_data {
            return;
        }
        let probation_ms = self.opts.last_good_fallback.probation_ms;
        let Some(p) = self.probation.as_mut().filter(|p| p.candidate == cur) else { return };
        let max_gap = probation_ms.clamp(1, 5_000);
        if p.last_data_ms.is_some_and(|last| now_ms.saturating_sub(last) > max_gap) {
            p.first_data_ms = None;
            p.data_packets = 0;
        }
        p.first_data_ms.get_or_insert(now_ms);
        p.last_data_ms = Some(now_ms);
        p.data_packets = p.data_packets.saturating_add(1);
    }

    pub fn promote_candidate(&mut self, expected: Ipv4Addr, now_ms: u64) -> PromotionResult {
        let Some(p) = self.probation.as_ref() else { return PromotionResult::NotProbationary };
        if p.candidate != expected {
            return PromotionResult::WrongCandidate;
        }
        if self.current.ip() != IpAddr::V4(expected) || !self.current_authenticated {
            return PromotionResult::NotActive;
        }
        if p.rollback_at_ms.is_some_and(|deadline| {
            now_ms >= deadline || self.committed_fresh(now_ms, expected) != Some(p.rollback)
        }) {
            return PromotionResult::RollbackExpired;
        }
        let span_ms = p.last_data_ms.zip(p.first_data_ms).map_or(0, |(last, first)| last.saturating_sub(first));
        if p.data_packets < MIN_PROMOTION_DATA_PACKETS || span_ms < self.opts.last_good_fallback.probation_ms {
            return PromotionResult::InsufficientEvidence { packets: p.data_packets, span_ms };
        }
        let max_gap = self.opts.last_good_fallback.probation_ms.clamp(1, 5_000);
        let idle_ms = p.last_data_ms.map_or(u64::MAX, |last| now_ms.saturating_sub(last));
        if idle_ms > max_gap {
            return PromotionResult::StaleEvidence { idle_ms };
        }
        let previous = p.rollback;
        if let (Some(path), Some(name)) = (self.opts.cache_file.as_deref(), self.spec.hostname()) {
            if let Err(e) = save_cache_with_policy(path, name, self.spec.port(), expected, self.opts.allow_private) {
                return PromotionResult::PersistenceFailed(e.to_string());
            }
        }
        self.committed_good = Some(expected);
        self.committed_runtime_activity_ms = Some(now_ms);
        self.cache_fresh_until_ms = None;
        self.probation = None;
        self.attended_cutover = false;
        log::warn!("endpoint: probationary {expected} promoted to committed-good after explicit FIFO authority and sustained authenticated DATA; previous {previous} may be released");
        self.order_candidates();
        PromotionResult::Promoted { previous }
    }

    pub fn current_authenticated(&self) -> bool {
        self.current_authenticated
    }

    fn persist_committed(&self, cur: Ipv4Addr, changed: bool) {
        if let (Some(p), Some(name)) = (self.opts.cache_file.as_deref(), self.spec.hostname()) {
            match save_cache_with_policy(p, name, self.spec.port(), cur, self.opts.allow_private) {
                Ok(()) if changed => log::info!("endpoint: {cur} is now committed-good (saved to {})", p.display()),
                Ok(()) => log::debug!("endpoint: refreshed committed-good timestamp for {cur} in {}", p.display()),
                Err(e) => log::warn!("endpoint: {cur} authenticated but committed cache {} could not be written: {e}", p.display()),
            }
        } else if changed {
            log::info!("endpoint: {cur} is now committed-good");
        }
    }

    fn cached_fresh_until(&self, entry: CacheEntry, now_ms: u64, wall_now: u64) -> Option<u64> {
        let saved = entry.saved_unix_secs?;
        let max_age = self.opts.last_good_fallback.max_age_ms;
        if !self.opts.last_good_fallback.enabled || saved > wall_now.saturating_add(300) {
            return None;
        }
        let age_ms = wall_now.saturating_sub(saved).saturating_mul(1000);
        (age_ms < max_age).then(|| now_ms.saturating_add(max_age - age_ms))
    }

    fn committed_health_deadline(&self, now_ms: u64) -> Option<(Ipv4Addr, u64)> {
        if !self.opts.last_good_fallback.enabled {
            return None;
        }
        let committed = self.committed_good?;
        let runtime_deadline = self
            .committed_runtime_activity_ms
            .map(|last| last.saturating_add(self.opts.last_good_fallback.rollback_window_ms))
            .filter(|deadline| now_ms <= *deadline);
        let cache_deadline = self.cache_fresh_until_ms.filter(|deadline| now_ms <= *deadline);
        runtime_deadline
            .into_iter()
            .chain(cache_deadline)
            .max()
            .map(|deadline| (committed, deadline))
    }

    fn committed_fresh(&self, now_ms: u64, cur: Ipv4Addr) -> Option<Ipv4Addr> {
        self.committed_health_deadline(now_ms)
            .and_then(|(committed, _)| (committed != cur).then_some(committed))
    }

    fn start_preferred_round(&mut self, now_ms: u64) {
        if self.opts.last_good_fallback.enabled && self.preferred_round_deadline_ms.is_none() {
            self.preferred_round_deadline_ms = Some(now_ms.saturating_add(self.opts.last_good_fallback.preferred_round_timeout_ms));
            self.preferred_attempts = 0;
        }
    }

    fn round_expired(&self, now_ms: u64) -> bool {
        self.preferred_round_deadline_ms.is_some_and(|deadline| now_ms >= deadline)
    }

    fn canonical_candidates(&self) -> Vec<Ipv4Addr> {
        let mut out = self.candidates.clone();
        out.sort_by_key(|ip| u32::from(*ip));
        out.dedup();
        out.truncate(MAX_ENDPOINT_CANDIDATES);
        out
    }

    fn next_dns_candidate(&self, cur: Ipv4Addr) -> Option<Ipv4Addr> {
        let set = self.canonical_candidates();
        if set.is_empty() {
            return None;
        }
        let next = set.iter().position(|ip| *ip == cur).map_or(0, |idx| (idx + 1) % set.len());
        Some(set[next])
    }

    fn charge_fallback(&mut self, wall_now: u64, candidate: Ipv4Addr) -> bool {
        // A corrupt or unsafe budget file disables unattended old-address probes. Only an
        // attended FIFO cutover from the just-working committed endpoint may take its
        // endpoint-qualified direct-return path without calling this function.
        if !self.fallback_state_usable {
            return false;
        }
        let Some(path) = self.fallback_state_path.clone() else { return false };
        let Some(name) = self.spec.hostname().map(str::to_string) else { return false };
        let port = self.spec.port();
        let policy = self.opts.last_good_fallback.clone();
        let allow_private = self.opts.allow_private;
        let dns_set = self.canonical_candidates();
        let lock_path = fallback_state_lock_path(&path);
        let result = crate::secure_file::with_owner_only_lock(&lock_path, || {
            // The lock protects the stable pathname, so reload after acquiring it. Never
            // charge from a controller's possibly stale startup snapshot.
            let current = load_fallback_state(
                &path,
                &name,
                port,
                policy.global_capacity,
                allow_private,
                wall_now,
            )?
                .unwrap_or_else(|| FallbackState::new(policy.global_capacity, wall_now));
            let Some(next) = precharge_fallback_state(current, &policy, wall_now, candidate, &dns_set) else {
                return Ok(None);
            };
            let body = serialize_fallback_state(&name, port, &next);
            crate::secure_file::atomic_write_owner_only(&path, body.as_bytes())?;
            Ok(Some(next))
        });
        match result {
            Ok(Some(next)) => {
                self.fallback_state = next;
                true
            }
            Ok(None) => false,
            Err(e) => {
                self.fallback_state_usable = false;
                log::warn!("endpoint: refusing old-address probe because its locked durable pre-charge failed: {e}");
                false
            }
        }
    }

    /// One DNS round trip; updates candidates and TTL on success, backoff on failure.
    /// Returns whether a usable answer arrived.
    fn query(&mut self, now_ms: u64) -> bool {
        let Some(name) = self.spec.hostname().map(str::to_string) else {
            return false;
        };
        self.queries += 1;
        match self.resolver.resolve_a(&name) {
            Ok(ans) => {
                let mut safe = Vec::new();
                for ip in &ans.addrs {
                    match check_endpoint_ip(*ip, self.opts.allow_private) {
                        Ok(()) => {
                            if !safe.contains(ip) {
                                safe.push(*ip);
                            }
                        }
                        Err(why) => {
                            log::warn!("endpoint: rejecting {ip} from dns for {name}: {why}")
                        }
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
                    log::warn!(
                        "endpoint: dns answer for {name} had no usable address; keeping the previous candidates, next query in {:.1}s",
                        delay as f64 / 1000.0
                    );
                    return false;
                }
                self.backoff.on_success();
                self.expires_at_ms = Some(now_ms.saturating_add(u64::from(ans.ttl).saturating_mul(1000)));
                safe.sort_by_key(|ip| u32::from(*ip));
                safe.dedup();
                if safe.len() > MAX_ENDPOINT_CANDIDATES {
                    log::warn!(
                        "endpoint: dns returned {} usable addresses; deterministically keeping the lowest {}",
                        safe.len(),
                        MAX_ENDPOINT_CANDIDATES
                    );
                    safe.truncate(MAX_ENDPOINT_CANDIDATES);
                }
                let previous = self.candidates_unordered();
                if safe != previous {
                    log::info!("endpoint: candidates for {name} changed: {:?} -> {:?}", previous, safe);
                    self.preferred_failures = 0;
                    self.preferred_attempts = 0;
                }
                self.candidates = safe;
                self.order_candidates();
                true
            }
            Err(e) => {
                let delay = self.backoff.on_failure(now_ms);
                match e {
                    DnsError::AllFailed(_) | DnsError::Timeout | DnsError::Io(_) => {
                        log::warn!("endpoint: dns {name} failed: {e}; keeping {} , next query in {:.1}s", self.current, delay as f64 / 1000.0)
                    }
                    _ => log::warn!("endpoint: dns {name}: {e}; keeping {} , next query in {:.1}s", self.current, delay as f64 / 1000.0),
                }
                false
            }
        }
    }

    fn candidates_unordered(&self) -> Vec<Ipv4Addr> {
        self.canonical_candidates()
    }

    /// Current first, then last-known-good, then the rest by numeric value: the order never
    /// depends on how the server listed the records.
    fn order_candidates(&mut self) {
        let cur = match self.current.ip() {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        };
        let mut rest: Vec<Ipv4Addr> = self.candidates.iter().copied().filter(|ip| Some(*ip) != cur && Some(*ip) != self.committed_good).collect();
        rest.sort_by_key(|ip| u32::from(*ip));
        rest.dedup();
        let mut ordered = Vec::with_capacity(self.candidates.len());
        if let Some(c) = cur.filter(|c| self.candidates.contains(c)) {
            ordered.push(c);
        }
        if let Some(g) = self.committed_good.filter(|g| self.candidates.contains(g) && Some(*g) != cur) {
            ordered.push(g);
        }
        ordered.extend(rest);
        ordered.truncate(MAX_ENDPOINT_CANDIDATES);
        self.candidates = ordered;
    }

    fn switch_to(&mut self, target: Ipv4Addr, reason: CycleReason, why: String) -> Option<Switch> {
        let IpAddr::V4(cur) = self.current.ip() else { return None };
        if target == cur {
            return None;
        }
        let from = self.current;
        self.current = SocketAddr::new(IpAddr::V4(target), self.spec.port());
        self.current_authenticated = false;
        self.order_candidates();
        log::warn!("endpoint: switching {} -> {} ({why}; reason {:?})", from, self.current, reason);
        Some(Switch { from, to: self.current, why })
    }

    fn select(&mut self, now_ms: u64, wall_now: u64, reason: CycleReason, query_succeeded: Option<bool>) -> Option<Switch> {
        let IpAddr::V4(cur) = self.current.ip() else { return None };

        if matches!(reason, CycleReason::ProbationExpired | CycleReason::OperatorRollback) {
            let p = self.probation.as_ref()?;
            if !p.rollback_authorized {
                log::warn!("endpoint: rollback was requested without a fresh endpoint-qualified authorization");
                return None;
            }
            let rollback = p.rollback;
            self.probation = None;
            self.attended_cutover = false;
            return self.switch_to(rollback, reason, format!("rolling back to preserved committed-good {rollback}"));
        }

        if reason == CycleReason::Forced {
            if self.round_expired(now_ms) {
                log::warn!("endpoint: attended cutover cancelled because the preferred-candidate round deadline elapsed during resolution");
                self.preferred_round_deadline_ms = None;
                return None;
            }
            if query_succeeded != Some(true) || self.candidates.is_empty() {
                log::warn!("endpoint: attended FIFO cutover got no fresh usable DNS answer; reconnecting the current endpoint without changing it");
                return None;
            }
            let target = self.canonical_candidates()[0];
            if target != cur {
                self.start_preferred_round(now_ms);
                if self.opts.last_good_fallback.enabled && self.committed_good == Some(cur) {
                    let round_deadline = self.preferred_round_deadline_ms.unwrap_or(now_ms);
                    let required_through = round_deadline
                        .saturating_add(CLIENT_HANDSHAKE_TIMEOUT_MS)
                        .saturating_add(self.opts.last_good_fallback.probation_ms)
                        .saturating_add(2 * TIMER_INTERVAL_MS);
                    if self
                        .committed_health_deadline(now_ms)
                        .is_none_or(|(_, fresh_through)| fresh_through < required_through)
                    {
                        log::warn!(
                            "endpoint: attended cutover to {target} refused because committed-good {cur} cannot remain rollback-eligible through {required_through}ms"
                        );
                        return None;
                    }
                }
                self.attended_cutover = self.opts.last_good_fallback.enabled && self.committed_good == Some(cur);
                return self.switch_to(target, reason, format!("attended FIFO cutover to DNS-preferred {target}"));
            }
            return None;
        }

        if reason == CycleReason::AttemptFailed {
            if let Some((rollback, direct_return)) = self
                .probation
                .as_ref()
                .filter(|p| p.candidate == cur)
                .map(|p| (p.rollback, p.direct_return))
            {
                if self.committed_fresh(now_ms, cur) == Some(rollback)
                    && (direct_return || self.charge_fallback(wall_now, rollback))
                {
                    self.probation = None;
                    return self.switch_to(rollback, reason, format!("probationary {cur} failed; returning directly to committed-good {rollback}"));
                }
            }
            if self.attended_cutover {
                if let Some(rollback) = self.committed_fresh(now_ms, cur) {
                    self.attended_cutover = false;
                    return self.switch_to(rollback, reason, format!("attended candidate {cur} failed; returning directly to preserved {rollback}"));
                }
            }
            if self.committed_good == Some(cur) {
                if self.round_expired(now_ms) {
                    log::warn!(
                        "endpoint: preferred-candidate round expired while retrying committed-good {cur}; refusing to extend it with another candidate handshake"
                    );
                    self.preferred_round_deadline_ms = None;
                    self.preferred_attempts = 0;
                    return None;
                }
                self.start_preferred_round(now_ms);
                if let Some(next) = self.next_dns_candidate(cur).filter(|next| *next != cur) {
                    return self.switch_to(next, reason, format!("committed endpoint {cur} failed; trying bounded DNS candidate {next}"));
                }
                return None;
            }

            self.start_preferred_round(now_ms);
            self.preferred_failures = self.preferred_failures.saturating_add(1);
            self.preferred_attempts = self.preferred_attempts.saturating_add(1);
            let candidate_count = self.canonical_candidates().len().max(1);
            let fallback_due = self.round_expired(now_ms)
                || (self.preferred_failures >= self.opts.last_good_fallback.after_failures
                    && self.preferred_attempts as usize >= candidate_count);
            if fallback_due {
                if let Some(good) = self.committed_fresh(now_ms, cur) {
                    if self.charge_fallback(wall_now, good) {
                        self.preferred_round_deadline_ms = None;
                        return self.switch_to(good, reason, format!("preferred round failed; pre-charged rollback probe of committed-good {good}"));
                    }
                }
            }
            if !self.round_expired(now_ms) {
                if let Some(next) = self.next_dns_candidate(cur).filter(|next| *next != cur) {
                    return self.switch_to(next, reason, format!("handshake with {cur} failed; trying next bounded DNS candidate {next}"));
                }
            } else {
                // End this bounded round even when persistent limits deny the old-address
                // probe. A later reconnect may start another bounded DNS round instead of
                // pinning all future attempts to one poisoned candidate.
                self.preferred_round_deadline_ms = None;
                self.preferred_attempts = 0;
            }
            return None;
        }

        if reason == CycleReason::SessionLost {
            if let Some((rollback, direct_return)) = self
                .probation
                .as_ref()
                .filter(|p| p.candidate == cur)
                .map(|p| (p.rollback, p.direct_return))
            {
                if self.committed_fresh(now_ms, cur) == Some(rollback)
                    && (direct_return || self.charge_fallback(wall_now, rollback))
                {
                    self.probation = None;
                    return self.switch_to(rollback, reason, format!("probationary session {cur} was lost; returning to {rollback}"));
                }
            }
            if self.committed_good == Some(cur) && !self.candidates.contains(&cur) {
                self.start_preferred_round(now_ms);
                if let Some(target) = self.canonical_candidates().first().copied() {
                    return self.switch_to(target, reason, format!("failed committed endpoint {cur} is no longer in DNS"));
                }
            }
        }
        None
    }
}

fn precharge_fallback_state(
    mut next: FallbackState,
    policy: &LastGoodFallbackPolicy,
    wall_now: u64,
    candidate: Ipv4Addr,
    dns_set: &[Ipv4Addr],
) -> Option<FallbackState> {
    let refill_secs = policy.global_refill_ms.saturating_add(999) / 1000;
    if wall_now >= next.global_updated_unix_secs && refill_secs > 0 {
        let elapsed = wall_now - next.global_updated_unix_secs;
        let elapsed_intervals = elapsed / refill_secs;
        if elapsed_intervals > 0 {
            let minted = elapsed_intervals.min(u64::from(u32::MAX)) as u32;
            next.global_tokens = next.global_tokens.saturating_add(minted).min(policy.global_capacity);
            // Consume every elapsed interval even when the bucket saturates. Otherwise a
            // long-idle state keeps a refill backlog that restarts can replay repeatedly.
            next.global_updated_unix_secs = next
                .global_updated_unix_secs
                .saturating_add(elapsed_intervals.saturating_mul(refill_secs));
        }
    }
    if next.global_tokens == 0 {
        log::warn!("endpoint: persisted global old-address probe bucket is empty");
        return None;
    }
    let pos = next
        .entries
        .iter()
        .position(|entry| entry.candidate == candidate && entry.dns_set == dns_set);
    let cooldown_secs = policy.cooldown_ms.saturating_add(999) / 1000;
    if let Some(pos) = pos {
        let entry = &next.entries[pos];
        if entry.charged >= policy.max_attempts || wall_now < entry.not_before_unix_secs {
            return None;
        }
        let entry = &mut next.entries[pos];
        entry.charged = entry.charged.saturating_add(1);
        entry.not_before_unix_secs = wall_now.saturating_add(cooldown_secs);
        entry.last_used_unix_secs = wall_now;
    } else {
        if next.entries.len() >= MAX_BUDGET_ENTRIES {
            log::warn!(
                "endpoint: persisted old-address budget table is full; refusing a new DNS-set key rather than evicting charged history"
            );
            return None;
        }
        next.entries.push(BudgetEntry {
            candidate,
            dns_set: dns_set.to_vec(),
            charged: 1,
            not_before_unix_secs: wall_now.saturating_add(cooldown_secs),
            last_used_unix_secs: wall_now,
        });
    }
    next.global_tokens -= 1;
    next.entries.sort_by_key(|entry| std::cmp::Reverse(entry.last_used_unix_secs));
    Some(next)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CacheEntry {
    addr: Ipv4Addr,
    saved_unix_secs: Option<u64>,
}

/// The cache file: a few `key=value` lines, written atomically with mode 0600.
/// Old files without `saved=` remain valid for startup compatibility, but cannot prove
/// freshness for the last-good fallback until the address authenticates in this process.
fn load_cache_entry(path: &Path, host: &str, port: u16, allow_private: bool) -> io::Result<Option<CacheEntry>> {
    let Some(bytes) = crate::secure_file::read_owner_only(path, CACHE_MAX_BYTES)? else {
        return Ok(None);
    };
    let text = std::str::from_utf8(&bytes).map_err(|_| invalid_cache(path, "not UTF-8"))?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    if text.contains('\r') || text.is_empty() {
        return Err(invalid_cache(path, "empty or non-canonical line endings"));
    }
    let mut lines: Vec<&str> = text.split('\n').collect();
    if lines.first() == Some(&"# udp2raw endpoint cache: the last address whose handshake succeeded") {
        lines.remove(0);
    }
    if !(lines.len() == 3 || lines.len() == 4) {
        return Err(invalid_cache(path, "expected exactly host, port, addr and optional saved fields"));
    }
    let h = strict_field(path, lines[0], "host")?;
    let p = strict_field(path, lines[1], "port")?;
    let a = strict_field(path, lines[2], "addr")?;
    if h != host || validate_hostname(h).is_err() {
        return Ok(None);
    }
    let parsed_port = p.parse::<u16>().map_err(|_| invalid_cache(path, "invalid port"))?;
    if parsed_port.to_string() != p || parsed_port != port {
        return Ok(None);
    }
    let addr = a.parse::<Ipv4Addr>().map_err(|_| invalid_cache(path, "invalid IPv4 address"))?;
    if addr.to_string() != a {
        return Err(invalid_cache(path, "non-canonical IPv4 address"));
    }
    check_endpoint_ip(addr, allow_private).map_err(|why| invalid_cache(path, format!("unsafe endpoint address: {why}")))?;
    let saved_unix_secs = if lines.len() == 4 {
        let value = strict_field(path, lines[3], "saved")?;
        let saved = value.parse::<u64>().map_err(|_| invalid_cache(path, "invalid saved timestamp"))?;
        if saved.to_string() != value {
            return Err(invalid_cache(path, "non-canonical saved timestamp"));
        }
        Some(saved)
    } else {
        None
    };
    Ok(Some(CacheEntry { addr, saved_unix_secs }))
}

pub fn load_cache(path: &Path, host: &str, port: u16) -> io::Result<Option<Ipv4Addr>> {
    Ok(load_cache_entry(path, host, port, false)?.map(|entry| entry.addr))
}

pub fn save_cache(path: &Path, host: &str, port: u16, addr: Ipv4Addr) -> io::Result<()> {
    save_cache_with_policy(path, host, port, addr, false)
}

fn save_cache_with_policy(path: &Path, host: &str, port: u16, addr: Ipv4Addr, allow_private: bool) -> io::Result<()> {
    validate_hostname(host).map_err(|why| invalid_cache(path, why))?;
    if host != host.trim_end_matches('.').to_ascii_lowercase() {
        return Err(invalid_cache(path, "hostname is not canonical lowercase without a trailing dot"));
    }
    if port == 0 {
        return Err(invalid_cache(path, "port is zero"));
    }
    check_endpoint_ip(addr, allow_private).map_err(|why| invalid_cache(path, format!("unsafe endpoint address: {why}")))?;
    let saved = unix_now_secs();
    let body = format!("# udp2raw endpoint cache: the last address whose handshake succeeded\nhost={host}\nport={port}\naddr={addr}\nsaved={saved}\n");
    crate::secure_file::atomic_write_owner_only(path, body.as_bytes())
}

fn unix_now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn invalid_cache(path: &Path, why: impl fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("invalid endpoint state {}: {why}", path.display()))
}

fn strict_field<'a>(path: &Path, line: &'a str, name: &str) -> io::Result<&'a str> {
    let prefix = format!("{name}=");
    let value = line.strip_prefix(&prefix).ok_or_else(|| invalid_cache(path, format!("expected {name}= field")))?;
    if value.is_empty() || value.trim() != value || value.contains('=') {
        return Err(invalid_cache(path, format!("non-canonical {name} field")));
    }
    Ok(value)
}

fn fallback_state_path(cache: &Path) -> PathBuf {
    let mut file = cache.file_name().map_or_else(|| std::ffi::OsString::from("endpoint"), |name| name.to_os_string());
    file.push(".fallback-state");
    cache.with_file_name(file)
}

fn fallback_state_lock_path(state: &Path) -> PathBuf {
    let mut file = state
        .file_name()
        .map_or_else(|| std::ffi::OsString::from("fallback-state"), |name| name.to_os_string());
    file.push(".lock");
    state.with_file_name(file)
}

fn serialize_fallback_state(host: &str, port: u16, state: &FallbackState) -> String {
    let mut body = format!(
        "# udp2raw fallback state v1\nversion=1\nhost={host}\nport={port}\nglobal_tokens={}\nglobal_updated={}\n",
        state.global_tokens, state.global_updated_unix_secs
    );
    for entry in &state.entries {
        let set = entry.dns_set.iter().map(ToString::to_string).collect::<Vec<_>>().join(",");
        body.push_str(&format!(
            "entry={}|{}|{}|{}|{}\n",
            entry.candidate, entry.charged, entry.not_before_unix_secs, entry.last_used_unix_secs, set
        ));
    }
    body
}

fn load_fallback_state(
    path: &Path,
    host: &str,
    port: u16,
    capacity: u32,
    allow_private: bool,
    wall_now: u64,
) -> io::Result<Option<FallbackState>> {
    let Some(bytes) = crate::secure_file::read_owner_only(path, STATE_MAX_BYTES)? else {
        return Ok(None);
    };
    let text = std::str::from_utf8(&bytes).map_err(|_| invalid_cache(path, "fallback state is not UTF-8"))?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    if text.contains('\r') || text.is_empty() {
        return Err(invalid_cache(path, "empty fallback state or non-canonical line endings"));
    }
    let lines: Vec<&str> = text.split('\n').collect();
    if lines.len() < 6 || lines.len() > 6 + MAX_BUDGET_ENTRIES {
        return Err(invalid_cache(path, "fallback state has an invalid number of fields"));
    }
    if lines[0] != "# udp2raw fallback state v1" || strict_field(path, lines[1], "version")? != "1" {
        return Err(invalid_cache(path, "unsupported fallback state version"));
    }
    if strict_field(path, lines[2], "host")? != host || strict_field(path, lines[3], "port")? != port.to_string() {
        return Err(invalid_cache(path, "fallback state endpoint identity mismatch"));
    }
    let global_tokens = parse_state_u32(path, strict_field(path, lines[4], "global_tokens")?, "global token count")?;
    if global_tokens > capacity {
        return Err(invalid_cache(path, "global token count exceeds configured capacity"));
    }
    let global_updated_unix_secs = parse_state_u64(path, strict_field(path, lines[5], "global_updated")?, "global update timestamp")?;
    if global_updated_unix_secs > wall_now.saturating_add(300) {
        return Err(invalid_cache(path, "global update timestamp is implausibly far in the future"));
    }
    let mut entries = Vec::new();
    for line in &lines[6..] {
        let raw = strict_field(path, line, "entry")?;
        let fields: Vec<&str> = raw.split('|').collect();
        if fields.len() != 5 {
            return Err(invalid_cache(path, "invalid fallback budget entry"));
        }
        let candidate = parse_state_ip(path, fields[0], allow_private)?;
        let charged = parse_state_u32(path, fields[1], "charged count")?;
        let not_before_unix_secs = parse_state_u64(path, fields[2], "cooldown timestamp")?;
        let last_used_unix_secs = parse_state_u64(path, fields[3], "last-used timestamp")?;
        if charged == 0 {
            return Err(invalid_cache(path, "zero-charge entry"));
        }
        if last_used_unix_secs > wall_now.saturating_add(300) {
            return Err(invalid_cache(path, "last-used timestamp is implausibly far in the future"));
        }
        if not_before_unix_secs < last_used_unix_secs
            || not_before_unix_secs.saturating_sub(last_used_unix_secs) > MAX_PERSISTED_COOLDOWN_SECS
        {
            return Err(invalid_cache(path, "invalid cooldown/last-used timestamp relation"));
        }
        let mut dns_set = Vec::new();
        for value in fields[4].split(',') {
            dns_set.push(parse_state_ip(path, value, allow_private)?);
        }
        let mut canonical = dns_set.clone();
        canonical.sort_by_key(|ip| u32::from(*ip));
        canonical.dedup();
        if dns_set != canonical || dns_set.is_empty() || dns_set.len() > MAX_ENDPOINT_CANDIDATES {
            return Err(invalid_cache(path, "non-canonical DNS set in fallback state"));
        }
        if entries.iter().any(|e: &BudgetEntry| e.candidate == candidate && e.dns_set == dns_set) {
            return Err(invalid_cache(path, "duplicate fallback budget entry"));
        }
        entries.push(BudgetEntry {
            candidate,
            dns_set,
            charged,
            not_before_unix_secs,
            last_used_unix_secs,
        });
    }
    Ok(Some(FallbackState {
        global_tokens,
        global_updated_unix_secs,
        entries,
    }))
}

fn parse_state_ip(path: &Path, value: &str, allow_private: bool) -> io::Result<Ipv4Addr> {
    let ip = value.parse::<Ipv4Addr>().map_err(|_| invalid_cache(path, "invalid state IPv4 address"))?;
    if ip.to_string() != value {
        return Err(invalid_cache(path, "non-canonical state IPv4 address"));
    }
    check_endpoint_ip(ip, allow_private).map_err(|why| invalid_cache(path, format!("unsafe state address: {why}")))?;
    Ok(ip)
}

fn parse_state_u32(path: &Path, value: &str, field: &str) -> io::Result<u32> {
    let parsed = value.parse::<u32>().map_err(|_| invalid_cache(path, format!("invalid {field}")))?;
    if parsed.to_string() != value {
        return Err(invalid_cache(path, format!("non-canonical {field}")));
    }
    Ok(parsed)
}

fn parse_state_u64(path: &Path, value: &str, field: &str) -> io::Result<u64> {
    let parsed = value.parse::<u64>().map_err(|_| invalid_cache(path, format!("invalid {field}")))?;
    if parsed.to_string() != value {
        return Err(invalid_cache(path, format!("non-canonical {field}")));
    }
    Ok(parsed)
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
            Box::new(Mock {
                answers: Mutex::new(script.into()),
                ttl,
                calls: AtomicU64::new(0),
            })
        }
    }

    impl Resolve for Mock {
        fn resolve_a(&self, _name: &str) -> Result<DnsAnswer, DnsError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let mut q = self.answers.lock().unwrap();
            let item = if q.len() > 1 { q.pop_front().unwrap() } else { q.front().cloned().unwrap_or(Err("empty")) };
            match item {
                Ok(addrs) => Ok(DnsAnswer {
                    addrs,
                    ttl: self.ttl.clamp(10, 3600),
                    raw_ttl: self.ttl,
                    server: "127.0.0.1:53".parse().unwrap(),
                    cnames: vec![],
                    via_tcp: false,
                }),
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
        EndpointOptions {
            allow_private: false,
            cache_file: None,
            bootstrap: None,
            backoff_min_ms: 2_000,
            backoff_max_ms: 60_000,
            last_good_fallback: LastGoodFallbackPolicy::default(),
        }
    }
    fn fallback_opts(cache_file: PathBuf) -> EndpointOptions {
        EndpointOptions {
            cache_file: Some(cache_file),
            last_good_fallback: LastGoodFallbackPolicy {
                enabled: true,
                after_failures: 2,
                max_attempts: 2,
                cooldown_ms: 1_000,
                max_age_ms: 60_000,
                global_capacity: 3,
                global_refill_ms: 60_000,
                preferred_round_timeout_ms: 10_000,
                probation_ms: 2_000,
                rollback_window_ms: 20_000,
            },
            ..opts()
        }
    }
    fn fresh_cache(path: &Path, addr: Ipv4Addr) {
        save_cache(path, "relay.example.com", 8443, addr).unwrap();
    }

    #[test]
    fn spec_parsing() {
        assert_eq!(EndpointSpec::parse("1.2.3.4:8443").unwrap(), EndpointSpec::Literal("1.2.3.4:8443".parse().unwrap()));
        assert_eq!(EndpointSpec::parse("[2001:db8::1]:8443").unwrap(), EndpointSpec::Literal("[2001:db8::1]:8443".parse().unwrap()));
        assert_eq!(
            EndpointSpec::parse("Relay.Example.COM.:8443").unwrap(),
            EndpointSpec::Hostname {
                name: "relay.example.com".into(),
                port: 8443
            }
        );
        assert_eq!(EndpointSpec::parse("relay:8443").unwrap().to_string(), "relay:8443");
        for bad in [
            "relay.example.com",
            "relay.example.com:0",
            "relay.example.com:70000",
            ":8443",
            "-bad.example:1",
            "bad-.example:1",
            "a..b:1",
            "1.2.3:1",
            "under_score.example:1",
            "x y:1",
        ] {
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
        let o = EndpointOptions {
            cache_file: Some(cache.clone()),
            ..opts()
        };
        let mut c = EndpointController::bootstrap(host(), m, o.clone(), 0).unwrap();
        // no history: the numerically first candidate, whatever order the server used
        assert_eq!(c.current().ip(), IpAddr::V4(ip("47.243.1.1")));
        assert_eq!(c.candidates(), &[ip("47.243.1.1"), ip("47.243.1.2")]);
        assert!(!cache.exists(), "cache must not be written before authentication");
        assert_eq!(c.on_authenticated_at(0), None);
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
        let c = EndpointController::bootstrap(
            host(),
            m,
            EndpointOptions {
                bootstrap: Some(ip("47.243.9.9")),
                ..opts()
            },
            0,
        )
        .unwrap();
        assert_eq!(c.current().ip(), IpAddr::V4(ip("47.243.9.9")));
        // nothing at all
        let m = Mock::new(vec![Err("nx")], 60);
        assert!(EndpointController::bootstrap(host(), m, opts(), 0).is_err());
        // Programmatic callers cannot bypass the endpoint-address policy with bootstrap.
        let m = Mock::new(vec![Err("timeout")], 60);
        assert!(EndpointController::bootstrap(
            host(),
            m,
            EndpointOptions {
                bootstrap: Some(ip("127.0.0.1")),
                ..opts()
            },
            0,
        )
        .is_err());
        let m = Mock::new(vec![Err("timeout")], 60);
        let c = EndpointController::bootstrap(
            host(),
            m,
            EndpointOptions {
                allow_private: true,
                bootstrap: Some(ip("10.0.0.1")),
                ..opts()
            },
            0,
        )
        .unwrap();
        assert_eq!(c.current().ip(), IpAddr::V4(ip("10.0.0.1")));
    }

    #[test]
    fn failed_attempt_switches_to_new_dns_address_and_dns_failure_keeps_current() {
        let m = Mock::new(vec![Ok(vec![ip("47.243.1.1")]), Ok(vec![ip("47.243.1.1")]), Ok(vec![ip("47.243.2.2")]), Err("timeout")], 30);
        let mut c = EndpointController::bootstrap(host(), m, opts(), 0).unwrap();
        c.on_authenticated_at(1_000);
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
        assert_eq!(c.on_authenticated_at(101_000), Some(ip("47.243.1.1")));
        assert_eq!(c.last_good(), Some(ip("47.243.2.2")));
    }

    #[test]
    fn forced_refresh_switches_even_when_healthy_and_fresh() {
        let m = Mock::new(vec![Ok(vec![ip("47.243.1.1")]), Ok(vec![ip("47.243.2.2")])], 3600);
        let mut c = EndpointController::bootstrap(host(), m, opts(), 0).unwrap();
        c.on_authenticated_at(1_000);
        assert!(c.on_cycle(1_000, CycleReason::SessionLost).is_none()); // TTL fresh: not even a query
        assert_eq!(c.queries(), 1);
        c.request_refresh("fifo reconnect");
        let sw = c.on_cycle(2_000, CycleReason::Forced).unwrap();
        assert_eq!(sw.to.ip(), IpAddr::V4(ip("47.243.2.2")));
        assert_eq!(c.queries(), 2);
    }

    #[test]
    fn reordered_and_duplicate_answers_do_not_rotate_but_failure_does_deterministically() {
        let m = Mock::new(
            vec![
                Ok(vec![ip("47.243.1.1"), ip("47.243.1.2")]),
                Ok(vec![ip("47.243.1.2"), ip("47.243.1.1"), ip("47.243.1.2")]),
                Ok(vec![ip("47.243.1.1"), ip("47.243.1.2")]),
            ],
            10,
        );
        let mut c = EndpointController::bootstrap(host(), m, opts(), 0).unwrap();
        assert_eq!(c.current().ip(), IpAddr::V4(ip("47.243.1.1")));
        c.on_authenticated_at(1_000);
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
        let o = EndpointOptions {
            bootstrap: Some(ip("47.243.1.1")),
            ..opts()
        };
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
        let o = EndpointOptions {
            bootstrap: Some(ip("47.243.1.1")),
            ..opts()
        };
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
