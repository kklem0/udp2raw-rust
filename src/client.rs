//! Client event loop (`client.cpp`): one raw connection to the server, many local UDP peers
//! multiplexed as convs.

use crate::config::{Config, LowerLevel};
use crate::conn::{self, ConnInfo};
use crate::consts::*;
use crate::conv::ConvManager;
use crate::crypto::Crypto;
use crate::faketcp::{RawCtx, RecvMeta};
use crate::endpoint::{CycleReason, EndpointController, Switch};
use crate::fifo;
use crate::iptables::{self, Iptables};
use crate::net::route;
use crate::net::{self, addr, raw::RawSockets, send_batch, RecvBatch, SendScratch, TxDst, TxPacket};
use crate::pipeline::{Done, Job, JobKey, Pipeline};
use crate::types::RawMode;
use crate::util::{now_ms, secure_random_u32, secure_random_u32_nz, BufPool};
use crate::wire;
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

const TOK_RAW: Token = Token(0);
const TOK_UDP: Token = Token(1);
const TOK_PIPE: Token = Token(2);
const TOK_FIFO: Token = Token(3);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Idle,
    TcpHandshake,
    TcpHandshakeDummy,
    Handshake1,
    Handshake2,
    Ready,
}

/// The native interface for relay traffic (`--underlay-dev`) and what a host route through
/// it needs.
struct Underlay {
    dev: String,
    ifindex: u32,
    gateway: Option<std::net::Ipv4Addr>,
    prefsrc: Option<std::net::Ipv4Addr>,
}

impl Underlay {
    fn detect(dev: &str, gateway: Option<std::net::Ipv4Addr>, remote: SocketAddr) -> io::Result<Underlay> {
        let ifindex = addr::if_nametoindex(dev).map_err(|e| io::Error::new(e.kind(), format!("--underlay-dev {dev}: {e}")))? as u32;
        let mut u = Underlay { dev: dev.to_string(), ifindex, gateway, prefsrc: None };
        if let IpAddr::V4(v4) = remote.ip() {
            // learn the next hop from the route the box already has for the bootstrap address
            let learned = match route::get_route(v4, Some(ifindex)) {
                Ok(r) => Some(r),
                Err(e) => match route::get_route(v4, None) {
                    Ok(r) if r.oif == Some(ifindex) => Some(r),
                    Ok(r) => {
                        log::warn!("underlay {dev}: the route to {v4} uses ifindex {:?}, not {ifindex} ({e})", r.oif);
                        None
                    }
                    Err(e2) => {
                        log::warn!("underlay {dev}: no route to {v4} via {dev} ({e}) nor otherwise ({e2})");
                        None
                    }
                },
            };
            if let Some(r) = learned {
                if u.gateway.is_none() {
                    u.gateway = r.gateway;
                }
                u.prefsrc = r.prefsrc;
            }
        }
        if u.gateway.is_none() {
            log::warn!("underlay {dev}: no gateway known, relay host routes will be on-link (set --underlay-gateway if the relay is not on this link)");
        }
        log::info!("underlay: dev {dev} ifindex {ifindex} gateway {} prefsrc {}", u.gateway.map_or("none".to_string(), |g| g.to_string()), u.prefsrc.map_or("auto".to_string(), |p| p.to_string()));
        Ok(u)
    }
}

/// Kernel state this process installed for one relay address.
struct Installed {
    addr: SocketAddr,
    route: bool,
    rule: Option<String>,
}

struct Client {
    cfg: Config,
    crypto: Arc<Crypto>,
    ctx: RawCtx,
    udp: UdpSocket,
    pipeline: Pipeline,
    info: ConnInfo,
    state: State,
    convs: ConvManager<SocketAddr>,
    bind_fd: Option<RawFd>,
    const_id: u32,
    fail_time_counter: u32,
    /// Bumped whenever the connection restarts; in-flight pipeline jobs from before are ignored.
    generation: u64,
    raw_batch: RecvBatch<libc::sockaddr_ll>,
    udp_batch: RecvBatch<libc::sockaddr_storage>,
    /// Decrypted datagrams for local peers, sent with one `sendmmsg` per round.
    udp_tx: Vec<TxPacket>,
    udp_scratch: SendScratch,
    pool: BufPool,
    hb_buf: Vec<u8>,
    /// The relay address in use; a hostname `-r` may change it at a reconnect boundary.
    remote: SocketAddr,
    endpoint: EndpointController,
    ipt: Option<Arc<Iptables>>,
    underlay: Option<Underlay>,
    installed: Vec<Installed>,
    /// Why the next attempt from `Idle` starts (set wherever `go_idle` is called).
    cycle_reason: CycleReason,
    exit_flag: &'static AtomicBool,
    /// Edge-triggered sources that still had data when the per-round budget ran out.
    udp_pending: bool,
    raw_pending: bool,
}

/// Packets taken from one socket per event-loop round before giving the other sockets,
/// the pipeline completions and the timer a turn (bounds latency and memory under overload).
const DRAIN_BUDGET: usize = 64;
/// Datagrams per `recvmmsg`.
const RX_BATCH: usize = 32;

pub fn run(cfg: Config, crypto: Arc<Crypto>, const_id: u32, exit_flag: &'static AtomicBool, endpoint: EndpointController, ipt: Option<Arc<Iptables>>) -> io::Result<()> {
    let remote = endpoint.current();
    let underlay = match &cfg.underlay_dev {
        Some(dev) => Some(Underlay::detect(dev, cfg.underlay_gateway, remote)?),
        None => None,
    };
    let sockets = RawSockets::open(&cfg)?;
    let ctx = RawCtx::new(&cfg, sockets);
    let raw_mode = cfg.raw_mode;
    let is_v6 = cfg.raw_is_v6();
    let mut info = ConnInfo::new(raw_mode, is_v6, cfg.disable_anti_replay);
    info.my_id = secure_random_u32_nz();

    // --lower-level: where to send layer-2 frames
    if let Some(ll) = &cfg.lower_level {
        let (if_name, mac) = match ll {
            LowerLevel::Manual { if_name, dest_mac } => {
                log::info!("we are running at lower-level (manual) mode");
                (if_name.clone(), *dest_mac)
            }
            LowerLevel::Auto => {
                let IpAddr::V4(remote_v4) = remote.ip() else {
                    return Err(io::Error::new(io::ErrorKind::Unsupported, "--lower-level auto only supports ipv4"));
                };
                let (dest_ip, if_name, mac) = loop {
                    match net::lower_level::find_lower_level_info(remote_v4) {
                        Ok(x) => break x,
                        Err(e) if cfg.retry_on_error => {
                            log::warn!("auto detect lower-level info failed for {remote_v4}: {e}, retry in 10 seconds");
                            std::thread::sleep(Duration::from_secs(10));
                        }
                        Err(e) => return Err(io::Error::other(format!("auto detect lower-level info failed for {remote_v4}: {e}, specific it manually"))),
                    }
                };
                log::info!("we are running at lower-level (auto) mode,{dest_ip} {if_name} {}", fmt_mac(&mac));
                log::warn!("make sure this is correct:   if_name=<{if_name}>  dest_mac_adress=<{}>", fmt_mac(&mac));
                (if_name, mac)
            }
        };
        let idx = addr::if_nametoindex(&if_name)?;
        log::info!("ifname:{if_name}  ifindex:{idx}");
        info.raw.send_info.addr_ll = net::raw::make_sockaddr_ll(idx, &mac);
    }

    info.raw.send_info.dst_ip = remote.ip();
    info.raw.send_info.dst_port = remote.port();

    let udp = net::bind_udp_listener(cfg.local_addr, cfg.socket_buf_size, cfg.force_socket_buf).map_err(|e| io::Error::new(e.kind(), format!("socket bind error: {e}")))?;
    let pipeline = Pipeline::new(cfg.threads, crypto.clone(), cfg.fix_gro)?;
    log::info!("crypto threads: {}", pipeline.threads());
    let hb_buf = vec![0u8; cfg.hb_len];

    let mut c = Client {
        cfg,
        crypto,
        ctx,
        udp,
        pipeline,
        info,
        state: State::Idle,
        convs: ConvManager::new(),
        bind_fd: None,
        const_id,
        fail_time_counter: 0,
        generation: 1,
        raw_batch: RecvBatch::new(RX_BATCH, HUGE_DATA_LEN + 1),
        udp_batch: RecvBatch::new(RX_BATCH, MAX_DATA_LEN + 1),
        udp_tx: Vec::with_capacity(64),
        udp_scratch: SendScratch::default(),
        pool: BufPool::new(2048, 2048),
        hb_buf,
        remote,
        endpoint,
        ipt,
        underlay,
        installed: Vec::new(),
        cycle_reason: CycleReason::Startup,
        exit_flag,
        udp_pending: false,
        raw_pending: false,
    };
    c.record_initial_endpoint();
    let r = c.event_loop();
    c.release_all();
    r
}

fn fmt_mac(m: &[u8; 6]) -> String {
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2], m[3], m[4], m[5])
}

impl Client {
    fn event_loop(&mut self) -> io::Result<()> {
        let mut poll = Poll::new()?;
        poll.registry().register(&mut SourceFd(&self.ctx.sockets.recv_fd), TOK_RAW, Interest::READABLE)?;
        poll.registry().register(&mut SourceFd(&self.udp.as_raw_fd()), TOK_UDP, Interest::READABLE)?;
        if self.pipeline.threads() > 0 {
            poll.registry().register(&mut SourceFd(&self.pipeline.wake_fd()), TOK_PIPE, Interest::READABLE)?;
        }
        let fifo_fd = match &self.cfg.fifo {
            Some(path) => {
                let fd = fifo::create_fifo(path)?;
                poll.registry().register(&mut SourceFd(&fd), TOK_FIFO, Interest::READABLE)?;
                log::info!("fifo_file={path}");
                Some(fd)
            }
            None => None,
        };
        let mut events = Events::with_capacity(256);
        let mut last_timer = 0u64;
        loop {
            if self.exit_flag.load(Ordering::Relaxed) {
                log::info!("exiting");
                return Ok(());
            }
            let now = now_ms();
            let elapsed = now.saturating_sub(last_timer);
            // Only a socket we stopped draining early needs an immediate re-poll; pipeline
            // completions wake us through the eventfd, so never spin on them.
            let timeout = if self.udp_pending || self.raw_pending {
                Duration::ZERO
            } else {
                Duration::from_millis(TIMER_INTERVAL_MS.saturating_sub(elapsed).max(1))
            };
            match poll.poll(&mut events, Some(timeout)) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
            for ev in events.iter() {
                match ev.token() {
                    TOK_UDP => self.udp_pending = true,
                    TOK_RAW => self.raw_pending = true,
                    TOK_PIPE => {}
                    TOK_FIFO => {
                        if let Some(fd) = fifo_fd {
                            self.on_fifo(fd);
                        }
                    }
                    _ => {}
                }
            }
            if self.raw_pending {
                self.raw_pending = self.on_raw_readable();
            }
            if self.udp_pending {
                self.udp_pending = self.on_udp_readable();
            }
            self.collect();
            let now = now_ms();
            if now.saturating_sub(last_timer) >= TIMER_INTERVAL_MS {
                last_timer = now;
                self.on_timer();
                self.collect();
            }
            self.ctx.flush_tx();
            self.flush_udp_tx();
        }
    }

    fn flush_udp_tx(&mut self) {
        if self.udp_tx.is_empty() {
            return;
        }
        let n = self.udp_tx.len();
        let accepted = send_batch(self.udp.as_raw_fd(), &self.udp_tx, &mut self.udp_scratch);
        if accepted < n {
            log::debug!("udp send: {} of {} datagrams not accepted", n - accepted, n);
        }
        for p in self.udp_tx.drain(..) {
            self.pool.recycle(p.buf);
        }
    }

    fn collect(&mut self) {
        // take the pipeline out to satisfy the borrow checker while we mutate self
        let mut done = Vec::new();
        self.pipeline.collect(|d| done.push(d));
        for d in done {
            self.on_done(d);
        }
    }

    fn key(&self) -> JobKey {
        JobKey { slot: 0, generation: self.generation }
    }

    fn go_idle(&mut self, reason: CycleReason, why: &str) {
        self.cycle_reason = reason;
        self.state = State::Idle;
        self.info.my_id = secure_random_u32_nz();
        self.generation += 1;
        log::info!("state back to client_idle{why}");
    }

    // ---------------------------------------------------------------- UDP side (local peers)

    /// Returns true if the socket may still hold data (budget exhausted).
    fn on_udp_readable(&mut self) -> bool {
        let mut rounds = 0;
        loop {
            let mut b = std::mem::take(&mut self.udp_batch);
            let n = match b.recv(self.udp.as_raw_fd()) {
                Ok(n) => n,
                Err(e) => {
                    log::debug!("recv_from error,{e}");
                    0
                }
            };
            for i in 0..n {
                let len = b.lens[i];
                if let Some(peer) = addr::from_sockaddr(&b.addrs[i]) {
                    self.on_udp_packet(&b.bufs[i][..len], peer);
                }
            }
            let cap = b.capacity();
            self.udp_batch = b;
            rounds += 1;
            if n < cap {
                return false;
            }
            if rounds * cap >= DRAIN_BUDGET {
                return true;
            }
        }
    }

    fn on_udp_packet(&mut self, data: &[u8], peer: SocketAddr) {
        if data.len() == MAX_DATA_LEN + 1 {
            log::warn!("huge packet, data_len > {MAX_DATA_LEN},dropped");
            return;
        }
        if data.len() >= self.cfg.mtu_warn {
            log::warn!("huge packet,data len={} (>={}).strongly suggested to set a smaller mtu at upper level,to get rid of this warn", data.len(), self.cfg.mtu_warn);
        }
        let now = now_ms();
        let conv = match self.convs.find_conv_by_data(&peer) {
            Some(c) => c,
            None => {
                if self.convs.len() >= MAX_CONV_NUM {
                    log::warn!("ignored new udp connect bc max_conv_num exceed");
                    return;
                }
                let c = self.convs.new_conv();
                self.convs.insert(c, peer, now);
                log::info!("new packet from {peer},conv_id={c:x}");
                c
            }
        };
        self.convs.update_active_time(conv, now);
        if self.state == State::Ready {
            let mut plain = self.pool.take();
            conn::prepare_safer_data_into(&mut self.info, conv, data, &mut plain);
            let key = self.key();
            self.pipeline.submit(Job::Encrypt { key, plain });
        }
    }

    // ---------------------------------------------------------------- raw side (server)

    /// Returns true if the socket may still hold data (budget exhausted).
    fn on_raw_readable(&mut self) -> bool {
        let mut rounds = 0;
        loop {
            let mut b = std::mem::take(&mut self.raw_batch);
            let n = match self.ctx.sockets.recv_batch(&mut b) {
                Ok(n) => n,
                Err(e) => {
                    log::debug!("raw recv error: {e}");
                    0
                }
            };
            for i in 0..n {
                let len = b.lens[i];
                self.on_raw_packet(&b.bufs[i], len, &b.addrs[i]);
            }
            let cap = b.capacity();
            self.raw_batch = b;
            rounds += 1;
            if n < cap {
                return false;
            }
            if rounds * cap >= DRAIN_BUDGET {
                return true;
            }
        }
    }

    fn on_raw_packet(&mut self, buf: &[u8], mut len: usize, ll: &libc::sockaddr_ll) {
        if len == HUGE_DATA_LEN + 1 {
            if !self.cfg.fix_gro {
                log::warn!("huge packet, data_len {len} > {HUGE_DATA_LEN},dropped");
                return;
            }
            len = HUGE_DATA_LEN;
        }
        if len > MAX_DATA_LEN && !self.cfg.fix_gro {
            log::warn!("huge packet, data_len {len} > {MAX_DATA_LEN}(max_data_len) dropped, maybe you need to turn down mtu at upper level, or you may take a look at --fix-gro");
            return;
        }
        let send_dst = (self.info.raw.send_info.dst_ip, self.info.raw.send_info.dst_port);
        match self.state {
            State::Idle => {}
            State::TcpHandshake | State::TcpHandshakeDummy => {
                let Some(data) = self.ctx.parse_recv(&mut self.info.raw, &buf[..len], ll) else { return };
                let data_len = data.len();
                let r = self.info.raw.recv_info;
                if data_len > MAX_DATA_LEN {
                    log::debug!("data_len={data_len} >= max_data_len+1,ignored");
                    return;
                }
                if (r.src_ip, r.src_port) != send_dst {
                    log::debug!("unexpected adress {} {} {} {}", r.src_ip, send_dst.0, r.src_port, send_dst.1);
                    return;
                }
                if data_len == 0 && r.syn && r.ack {
                    if self.state == State::TcpHandshake {
                        if r.ack_seq != self.info.raw.send_info.seq.wrapping_add(1) {
                            log::debug!("seq ack_seq mis match");
                            return;
                        }
                        log::info!("state changed from client_tcp_handshake to client_handshake1");
                    } else {
                        self.info.raw.send_info.seq = r.ack_seq.wrapping_sub(1);
                        log::info!("state changed from client_tcp_dummy to client_handshake1");
                    }
                    self.state = State::Handshake1;
                    self.info.last_state_time = now_ms();
                    self.info.last_hb_sent_time = 0;
                    self.on_timer();
                } else {
                    log::debug!("unexpected packet type,expected:syn ack");
                }
            }
            State::Handshake1 => {
                let Some(data) = self.ctx.parse_recv(&mut self.info.raw, &buf[..len], ll) else {
                    log::debug!("recv_bare failed!");
                    return;
                };
                let r = self.info.raw.recv_info;
                if self.cfg.raw_mode == RawMode::FakeTcp && (r.syn || !r.ack) {
                    log::debug!("unexpect packet type recv_info.syn={} recv_info.ack={}", r.syn, r.ack);
                    return;
                }
                let Some(payload) = conn::parse_bare(&self.crypto, data) else {
                    log::debug!("recv_bare failed!");
                    return;
                };
                if (r.src_ip, r.src_port) != send_dst {
                    log::debug!("unexpected adress {} {} {} {}", r.src_ip, send_dst.0, r.src_port, send_dst.1);
                    return;
                }
                let Some((tmp_oppsite_id, tmp_my_id, _tmp_oppsite_const_id)) = wire::parse_handshake(&payload) else {
                    log::debug!("too short to be a handshake");
                    return;
                };
                if tmp_my_id != self.info.my_id {
                    log::debug!("tmp_my_id doesnt match");
                    return;
                }
                if self.cfg.raw_mode == RawMode::FakeTcp && (r.ack_seq != self.info.raw.send_info.seq || r.seq != self.info.raw.send_info.ack_seq) {
                    log::debug!("seq ack_seq mis match");
                    return;
                }
                self.info.oppsite_id = tmp_oppsite_id;
                log::info!("changed state from to client_handshake1 to client_handshake2,my_id is {:x},oppsite id is {:x}", self.info.my_id, self.info.oppsite_id);
                self.state = State::Handshake2;
                self.info.last_state_time = now_ms();
                self.info.last_hb_sent_time = 0;
                self.on_timer();
            }
            State::Handshake2 | State::Ready => {
                let Some(data) = self.ctx.parse_recv(&mut self.info.raw, &buf[..len], ll) else { return };
                let r = self.info.raw.recv_info;
                if (r.src_ip, r.src_port) != send_dst {
                    log::warn!("unexpected adress {} {} {} {},this shouldnt happen.", r.src_ip, send_dst.0, r.src_port, send_dst.1);
                    return;
                }
                let meta = RecvMeta::from_recv(&r);
                let mut wire_bytes = self.pool.take();
                wire_bytes.extend_from_slice(data);
                let key = self.key();
                self.pipeline.submit(Job::Decrypt { key, wire: wire_bytes, meta });
            }
        }
    }

    // ---------------------------------------------------------------- pipeline completions

    fn on_done(&mut self, d: Done) {
        match d {
            Done::Encrypted { key, wire } => {
                let Some(w) = wire else { return };
                if key.generation == self.generation && self.state == State::Ready {
                    if let Err(e) = conn::transmit_safer(&mut self.ctx, &mut self.info.raw, &w) {
                        log::trace!("send failed: {e}");
                    }
                }
                self.pool.recycle(w);
            }
            Done::Decrypted { key, plains, meta } => {
                if key.generation != self.generation || !matches!(self.state, State::Handshake2 | State::Ready) {
                    for p in plains {
                        self.pool.recycle(p);
                    }
                    return;
                }
                if plains.is_empty() {
                    log::debug!("recv_safer failed!");
                    return;
                }
                let mut any = false;
                for p in plains {
                    match conn::accept_safer_offset(&mut self.info, &p, self.cfg.hb_mode) {
                        Some((ptype, off)) => {
                            any = true;
                            self.on_safer_packet(ptype, p, off);
                        }
                        None => self.pool.recycle(p),
                    }
                }
                if any {
                    self.ctx.after_recv(&mut self.info.raw, &meta);
                }
            }
        }
    }

    /// `plain[off..]` is the packet payload; the buffer is recycled or queued for sending.
    fn on_safer_packet(&mut self, ptype: u8, plain: Vec<u8>, off: usize) {
        if self.state == State::Handshake2 {
            log::info!("changed state from to client_handshake2 to client_ready");
            self.state = State::Ready;
            self.info.last_hb_sent_time = 0;
            self.on_endpoint_authenticated();
            self.info.last_hb_recv_time = now_ms();
            self.info.last_oppsite_roller_time = self.info.last_hb_recv_time;
            self.on_timer();
        }
        if ptype == TYPE_HEARTBEAT {
            log::debug!("[hb]heart beat received,oppsite_roller={}", self.info.oppsite_roller);
            self.info.last_hb_recv_time = now_ms();
            self.pool.recycle(plain);
            return;
        }
        if ptype == TYPE_DATA {
            let Some((conv, data)) = wire::parse_data_payload(&plain[off..]) else {
                log::warn!("unknown packet,this shouldnt happen.");
                self.pool.recycle(plain);
                return;
            };
            log::trace!("received a data from fake tcp,len:{}", data.len());
            if self.cfg.hb_mode == 0 {
                self.info.last_hb_recv_time = now_ms();
            }
            if !self.convs.is_conv_used(conv) {
                log::info!("unknow conv {conv},ignore");
                self.pool.recycle(plain);
                return;
            }
            self.convs.update_active_time(conv, now_ms());
            let peer = *self.convs.find_data_by_conv(conv).unwrap();
            self.udp_tx.push(TxPacket { buf: plain, off: off + 4, dst: TxDst::Sock(peer) });
            if self.udp_tx.len() >= 64 {
                self.flush_udp_tx();
            }
            return;
        }
        self.pool.recycle(plain);
    }

    // ---------------------------------------------------------------- timer / state machine

    fn on_timer(&mut self) {
        let now = now_ms();
        for (conv, _) in self.convs.clear_inactive(now) {
            log::info!("conv {conv:x} cleared");
        }
        log::trace!("timer! roller my {},oppsite {},{}", self.info.my_roller, self.info.oppsite_roller, self.info.last_oppsite_roller_time);

        if self.info.raw.disabled {
            self.go_idle(CycleReason::AttemptFailed, "");
        }
        if self.state == State::Idle {
            self.info.raw.rst_received = 0;
            self.info.raw.disabled = false;
            self.fail_time_counter += 1;
            self.info.anti_replay.re_init();
            self.info.my_id = secure_random_u32_nz();
            self.generation += 1;

            // a hostname -r: re-resolve when due and adopt a new relay address before the attempt
            let reason = std::mem::replace(&mut self.cycle_reason, CycleReason::AttemptFailed);
            if let Some(sw) = self.endpoint.on_cycle(now, reason) {
                self.apply_switch(&sw);
            }
            // make sure the address we are about to use has its DROP rule (retries a rule
            // whose install failed on an earlier cycle; a no-op once it is in place)
            let cur = self.remote;
            self.ensure_installed(cur);

            let src_ip = match self.cfg.source_ip {
                Some(ip) => ip,
                None => match addr::get_src_addr_dev(self.remote, self.underlay.as_ref().map(|u| u.dev.as_str())) {
                    Ok(ip) => {
                        log::info!("source_addr is now {ip}");
                        ip
                    }
                    Err(e) => {
                        log::warn!("get_src_adress() failed: {e}");
                        return;
                    }
                },
            };
            self.info.raw.send_info.src_ip = src_ip;
            let port = match self.cfg.source_port {
                Some(p) => p,
                None => match addr::bind_new_random_port(src_ip, self.cfg.raw_mode, self.cfg.easy_faketcp, self.bind_fd.take()) {
                    Ok((fd, port)) => {
                        self.bind_fd = Some(fd);
                        port
                    }
                    Err(e) => {
                        log::error!("bind port fail: {e}");
                        self.exit_flag.store(true, Ordering::Relaxed);
                        return;
                    }
                },
            };
            self.info.raw.send_info.src_port = port;
            if self.cfg.raw_mode == RawMode::Icmp {
                self.info.raw.send_info.dst_port = port;
            }
            log::info!("using port {port}");
            if let Err(e) = self.ctx.set_filter(port) {
                log::error!("{e}");
                self.exit_flag.store(true, Ordering::Relaxed);
                return;
            }
            match self.cfg.raw_mode {
                RawMode::Icmp | RawMode::Udp => {
                    self.state = State::Handshake1;
                    log::info!("state changed from client_idle to client_pre_handshake");
                }
                RawMode::FakeTcp => {
                    if self.cfg.easy_faketcp {
                        if let Some(fd) = self.bind_fd {
                            let _ = addr::set_nonblocking(fd);
                            let (sa, len) = addr::to_sockaddr(self.remote);
                            let ret = unsafe { libc::connect(fd, &sa as *const _ as *const libc::sockaddr, len) };
                            log::debug!("ret={ret},errno={}, {fd} {}", io::Error::last_os_error(), self.remote);
                        }
                        self.state = State::TcpHandshakeDummy;
                        log::info!("state changed from client_idle to client_tcp_handshake_dummy");
                    } else {
                        self.state = State::TcpHandshake;
                        log::info!("state changed from client_idle to client_tcp_handshake");
                    }
                }
            }
            self.info.last_state_time = now;
            self.info.last_hb_sent_time = 0;
            // fall through
        }
        match self.state {
            State::Idle => {}
            State::TcpHandshake => {
                if now - self.info.last_state_time > CLIENT_HANDSHAKE_TIMEOUT_MS {
                    self.go_idle(CycleReason::AttemptFailed, " from client_tcp_handshake");
                } else if now - self.info.last_hb_sent_time > CLIENT_RETRY_INTERVAL_MS {
                    if self.info.last_hb_sent_time == 0 {
                        let s = &mut self.info.raw.send_info;
                        s.psh = false;
                        s.syn = true;
                        s.ack = false;
                        s.ts_ack = 0;
                        s.seq = secure_random_u32();
                        s.ack_seq = secure_random_u32();
                    }
                    let _ = self.ctx.send_raw(&mut self.info.raw, &[]);
                    self.info.last_hb_sent_time = now;
                    log::info!("(re)sent tcp syn");
                }
            }
            State::TcpHandshakeDummy => {
                if now - self.info.last_state_time > CLIENT_HANDSHAKE_TIMEOUT_MS {
                    self.go_idle(CycleReason::AttemptFailed, " from client_tcp_handshake_dummy");
                }
            }
            State::Handshake1 => {
                if now - self.info.last_state_time > CLIENT_HANDSHAKE_TIMEOUT_MS {
                    self.go_idle(CycleReason::AttemptFailed, " from client_handshake1");
                } else if now - self.info.last_hb_sent_time > CLIENT_RETRY_INTERVAL_MS {
                    if self.cfg.raw_mode == RawMode::FakeTcp {
                        if self.info.last_hb_sent_time == 0 {
                            let r = self.info.raw.recv_info;
                            let s = &mut self.info.raw.send_info;
                            s.seq = s.seq.wrapping_add(1);
                            s.ack_seq = r.seq.wrapping_add(1);
                            s.ts_ack = r.ts;
                            self.info.raw.reserved_send_seq = s.seq;
                        }
                        let s = &mut self.info.raw.send_info;
                        s.seq = self.info.raw.reserved_send_seq;
                        s.psh = false;
                        s.syn = false;
                        s.ack = true;
                        if !self.cfg.easy_faketcp {
                            let _ = self.ctx.send_raw(&mut self.info.raw, &[]);
                        }
                        let _ = conn::send_handshake(&mut self.ctx, &self.crypto, &mut self.info.raw, self.info.my_id, 0, self.const_id);
                        let dl = self.info.raw.send_info.data_len as u32;
                        self.info.raw.send_info.seq = self.info.raw.send_info.seq.wrapping_add(dl);
                    } else {
                        let _ = conn::send_handshake(&mut self.ctx, &self.crypto, &mut self.info.raw, self.info.my_id, 0, self.const_id);
                        if self.cfg.raw_mode == RawMode::Icmp {
                            self.info.raw.send_info.icmp_seq = self.info.raw.send_info.icmp_seq.wrapping_add(1);
                        }
                    }
                    self.info.last_hb_sent_time = now;
                    log::info!("(re)sent handshake1");
                }
            }
            State::Handshake2 => {
                if now - self.info.last_state_time > CLIENT_HANDSHAKE_TIMEOUT_MS {
                    self.go_idle(CycleReason::AttemptFailed, " from client_handshake2");
                } else if now - self.info.last_hb_sent_time > CLIENT_RETRY_INTERVAL_MS {
                    if self.cfg.raw_mode == RawMode::FakeTcp {
                        if self.info.last_hb_sent_time == 0 {
                            let r = self.info.raw.recv_info;
                            let s = &mut self.info.raw.send_info;
                            s.ack_seq = r.seq.wrapping_add(r.data_len as u32);
                            s.ts_ack = r.ts;
                            self.info.raw.reserved_send_seq = s.seq;
                        }
                        self.info.raw.send_info.seq = self.info.raw.reserved_send_seq;
                        let _ = conn::send_handshake(&mut self.ctx, &self.crypto, &mut self.info.raw, self.info.my_id, self.info.oppsite_id, self.const_id);
                        let dl = self.info.raw.send_info.data_len as u32;
                        self.info.raw.send_info.seq = self.info.raw.send_info.seq.wrapping_add(dl);
                    } else {
                        let _ = conn::send_handshake(&mut self.ctx, &self.crypto, &mut self.info.raw, self.info.my_id, self.info.oppsite_id, self.const_id);
                        if self.cfg.raw_mode == RawMode::Icmp {
                            self.info.raw.send_info.icmp_seq = self.info.raw.send_info.icmp_seq.wrapping_add(1);
                        }
                    }
                    self.info.last_hb_sent_time = now;
                    log::info!("(re)sent handshake2");
                }
            }
            State::Ready => {
                self.fail_time_counter = 0;
                if now - self.info.last_hb_recv_time > CLIENT_CONN_TIMEOUT_MS {
                    self.go_idle(CycleReason::SessionLost, " from  client_ready bc of server-->client direction timeout");
                    return;
                }
                if now - self.info.last_oppsite_roller_time > CLIENT_CONN_UPLINK_TIMEOUT_MS {
                    self.go_idle(CycleReason::SessionLost, " from  client_ready bc of client-->server direction timeout");
                    return;
                }
                if now - self.info.last_hb_sent_time < HEARTBEAT_INTERVAL_MS {
                    return;
                }
                log::debug!("heartbeat sent <{:x},{:x}>", self.info.oppsite_id, self.info.my_id);
                let mut plain = self.pool.take();
                let hb: &[u8] = if self.cfg.hb_mode == 0 { &[] } else { &self.hb_buf };
                conn::prepare_safer_into(&mut self.info, TYPE_HEARTBEAT, hb, &mut plain);
                let key = self.key();
                self.pipeline.submit(Job::Encrypt { key, plain });
                self.info.last_hb_sent_time = now;
            }
        }
    }

    // ---------------------------------------------------------------- relay endpoint (hostname -r)

    fn pattern_for(&self, addr: SocketAddr) -> String {
        iptables::pattern_for(&self.cfg, addr)
    }

    /// Kernel state for the address we start with: its `-a` rule came from `Iptables::init`,
    /// its host route (with `--underlay-dev`) is installed here.
    fn record_initial_endpoint(&mut self) {
        let addr = self.remote;
        let rule = self.ipt.as_ref().map(|_| self.pattern_for(addr));
        let route = self.install_route(addr);
        self.installed.push(Installed { addr, route, rule });
    }

    fn install_route(&self, addr: SocketAddr) -> bool {
        let (Some(u), IpAddr::V4(v4)) = (&self.underlay, addr.ip()) else { return false };
        match route::replace_host_route(v4, u.gateway, u.ifindex, u.prefsrc) {
            Ok(()) => {
                log::info!("route: {v4}/32 {}dev {} metric {} proto {}", u.gateway.map_or(String::new(), |g| format!("via {g} ")), u.dev, route::ROUTE_METRIC, route::RTPROT_UDP2RAW);
                true
            }
            Err(e) => {
                log::warn!("route: could not install {v4}/32 {}dev {}: {e}", u.gateway.map_or(String::new(), |g| format!("via {g} ")), u.dev);
                false
            }
        }
    }

    /// Rule and route for `addr`, installed before the first packet goes there.
    /// Rule and route for `addr`, installed before the first packet goes there. Idempotent
    /// and self-healing: if a previous `add_pattern` failed (iptables was busy) the entry is
    /// kept with `rule = None` and the rule is retried on the next call, so the DROP rule for
    /// the address in use is (re)established every reconnect cycle even without a switch.
    fn ensure_installed(&mut self, addr: SocketAddr) {
        let pos = self.installed.iter().position(|i| i.addr == addr);
        if let Some(p) = pos {
            if self.installed[p].rule.is_some() || self.ipt.is_none() {
                return; // already fully installed (or no -a: nothing to add)
            }
        }
        let rule = match self.ipt.clone() {
            Some(ipt) => {
                let pat = self.pattern_for(addr);
                match ipt.add_pattern(&pat) {
                    Ok(()) => Some(pat),
                    Err(e) => {
                        log::warn!("{e}");
                        None
                    }
                }
            }
            None => None,
        };
        match pos {
            Some(p) => self.installed[p].rule = rule,
            None => {
                let route = self.install_route(addr);
                self.installed.push(Installed { addr, route, rule });
            }
        }
    }

    fn release(&mut self, addr: SocketAddr) {
        let Some(pos) = self.installed.iter().position(|i| i.addr == addr) else { return };
        let ent = self.installed.remove(pos);
        if let (Some(ipt), Some(p)) = (&self.ipt, &ent.rule) {
            ipt.del_pattern(p);
        }
        if ent.route {
            if let (Some(u), IpAddr::V4(v4)) = (&self.underlay, addr.ip()) {
                match route::delete_host_route(v4, u.ifindex) {
                    Ok(()) => log::info!("route: removed {v4}/32 dev {}", u.dev),
                    Err(e) => log::warn!("route: could not remove {v4}/32 dev {}: {e}", u.dev),
                }
            }
        }
    }

    /// Drop the kernel state of every address not in `keep`.
    fn release_except(&mut self, keep: &[SocketAddr]) {
        let stale: Vec<SocketAddr> = self.installed.iter().map(|i| i.addr).filter(|a| !keep.contains(a)).collect();
        for a in stale {
            self.release(a);
        }
    }

    fn release_all(&mut self) {
        self.release_except(&[]);
    }

    /// Switch the relay address at a reconnect boundary: roll back a candidate that never
    /// authenticated, keep the last-known-good address's rule and route until the new one
    /// authenticates, install the new address's rule and route, then retarget the raw sender.
    fn apply_switch(&mut self, sw: &Switch) {
        let port = sw.to.port();
        let mut keep = vec![sw.to];
        if let Some(g) = self.endpoint.last_good() {
            keep.push(SocketAddr::new(IpAddr::V4(g), port));
        }
        self.release_except(&keep);
        self.ensure_installed(sw.to);
        self.remote = sw.to;
        self.info.raw.send_info.dst_ip = sw.to.ip();
        self.info.raw.send_info.dst_port = sw.to.port();
        if matches!(self.cfg.lower_level, Some(LowerLevel::Auto)) {
            if let IpAddr::V4(v4) = sw.to.ip() {
                match net::lower_level::find_lower_level_info(v4) {
                    Ok((dest_ip, if_name, mac)) => match addr::if_nametoindex(&if_name) {
                        Ok(idx) => {
                            self.info.raw.send_info.addr_ll = net::raw::make_sockaddr_ll(idx, &mac);
                            log::info!("lower-level (auto) now {dest_ip} {if_name} {}", fmt_mac(&mac));
                        }
                        Err(e) => log::warn!("lower-level: {if_name}: {e}"),
                    },
                    Err(e) => log::warn!("lower-level auto re-detect for {v4} failed: {e}; keeping the previous link-layer destination"),
                }
            }
        }
        log::warn!("endpoint: relay is now {} (was {}; {})", sw.to, sw.from, sw.why);
    }

    /// The handshake with the current address succeeded: it becomes last-known-good and the
    /// kernel state of every other address goes.
    fn on_endpoint_authenticated(&mut self) {
        if !self.endpoint.is_dynamic() {
            return;
        }
        let _ = self.endpoint.on_authenticated();
        let cur = self.remote;
        self.release_except(&[cur]);
    }

    fn on_fifo(&mut self, fd: RawFd) {
        if let Some(cmd) = fifo::read_command(fd) {
            log::info!("got data from fifo,s=[{cmd}]");
            if cmd == "reconnect" {
                log::info!("received command: reconnect");
                self.endpoint.request_refresh("fifo reconnect");
                self.go_idle(CycleReason::Forced, " (fifo reconnect)");
            } else {
                log::info!("unknown command");
            }
        }
    }
}
