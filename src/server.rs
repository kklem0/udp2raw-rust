//! Server event loop (`server.cpp`): many raw connections (one per client address), each
//! multiplexing convs onto its own connected UDP sockets towards `-r`.

use crate::config::{Config, LowerLevel};
use crate::conn::{self, ConnInfo};
use crate::consts::*;
use crate::conv::ConvManager;
use crate::crypto::Crypto;
use crate::faketcp::{RawCtx, RawInfo, RecvMeta};
use crate::fifo;
use crate::net::{self, addr, raw::RawSockets};
use crate::pipeline::{Done, Job, JobKey, Pipeline};
use crate::types::RawMode;
use crate::util::{now_ms, secure_random_u32_nz};
use crate::wire;
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, UdpSocket};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

const TOK_RAW: Token = Token(0);
const TOK_PIPE: Token = Token(1);
const TOK_FIFO: Token = Token(2);
const TOK_SOCK_BASE: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Idle,
    Handshake1,
    Ready,
}

struct ConvSock {
    sock: UdpSocket,
    conn_slot: usize,
    conv: u32,
}

struct ServerConn {
    info: ConnInfo,
    state: State,
    /// conv → index into `Server::socks`
    convs: ConvManager<usize>,
    generation: u64,
    addr: (IpAddr, u16),
}

struct Server {
    cfg: Config,
    crypto: Arc<Crypto>,
    ctx: RawCtx,
    poll: Poll,
    pipeline: Pipeline,
    conns: Vec<Option<ServerConn>>,
    free_conns: Vec<usize>,
    by_addr: HashMap<(IpAddr, u16), usize>,
    by_const_id: HashMap<u32, usize>,
    ready_num: usize,
    socks: Vec<Option<ConvSock>>,
    free_socks: Vec<usize>,
    clear_cursor: usize,
    last_conn_clear: u64,
    next_generation: u64,
    const_id: u32,
    manual_ll: Option<libc::sockaddr_ll>,
    _bind_fd: RawFd,
    recv_buf: Vec<u8>,
    udp_buf: Vec<u8>,
    hb_buf: Vec<u8>,
    exit_flag: &'static AtomicBool,
    /// Edge-triggered sources that still had data when the per-round budget ran out.
    raw_pending: bool,
    socks_pending: Vec<usize>,
}

/// Packets taken from one socket per event-loop round before the other sockets, the
/// pipeline completions and the timer get a turn (bounds latency and memory under overload).
const DRAIN_BUDGET: usize = 64;

pub fn run(cfg: Config, crypto: Arc<Crypto>, const_id: u32, exit_flag: &'static AtomicBool) -> io::Result<()> {
    let sockets = RawSockets::open(&cfg)?;
    let mut ctx = RawCtx::new(&cfg, sockets);

    let manual_ll = match &cfg.lower_level {
        Some(LowerLevel::Manual { if_name, dest_mac }) => {
            let idx = addr::if_nametoindex(if_name)?;
            log::info!("ifname:{if_name}  ifindex:{idx}");
            log::info!("we are running at lower-level (manual) mode");
            Some(net::raw::make_sockaddr_ll(idx, dest_mac))
        }
        Some(LowerLevel::Auto) => {
            log::info!("we are running at lower-level (auto) mode");
            None
        }
        None => None,
    };

    // reserve the port so nothing else binds it (and, for faketcp, let the kernel own the
    // listening socket so easy-faketcp clients get their SYN-ACK)
    let bind_fd = addr::bind_reserve(cfg.local_addr, cfg.raw_mode, false).map_err(|e| io::Error::new(e.kind(), format!("bind fail: {e}")))?;
    ctx.set_filter(cfg.local_addr.port())?;

    let poll = Poll::new()?;
    let pipeline = Pipeline::new(cfg.threads, crypto.clone(), cfg.fix_gro)?;
    log::info!("crypto threads: {}", pipeline.threads());
    let hb_buf = vec![0u8; cfg.hb_len];
    log::info!("now listening at {}", cfg.local_addr);

    let mut s = Server {
        cfg,
        crypto,
        ctx,
        poll,
        pipeline,
        conns: Vec::new(),
        free_conns: Vec::new(),
        by_addr: HashMap::new(),
        by_const_id: HashMap::new(),
        ready_num: 0,
        socks: Vec::new(),
        free_socks: Vec::new(),
        clear_cursor: 0,
        last_conn_clear: 0,
        next_generation: 1,
        const_id,
        manual_ll,
        _bind_fd: bind_fd,
        recv_buf: vec![0u8; HUGE_BUF_LEN],
        udp_buf: vec![0u8; BUF_LEN],
        hb_buf,
        exit_flag,
        raw_pending: false,
        socks_pending: Vec::new(),
    };
    s.event_loop()
}

fn addr_str(a: &(IpAddr, u16)) -> String {
    match a.0 {
        IpAddr::V4(ip) => format!("{ip}:{}", a.1),
        IpAddr::V6(ip) => format!("[{ip}]:{}", a.1),
    }
}

impl Server {
    fn event_loop(&mut self) -> io::Result<()> {
        self.poll.registry().register(&mut SourceFd(&self.ctx.sockets.recv_fd), TOK_RAW, Interest::READABLE)?;
        if self.pipeline.threads() > 0 {
            self.poll.registry().register(&mut SourceFd(&self.pipeline.wake_fd()), TOK_PIPE, Interest::READABLE)?;
        }
        let fifo_fd = match &self.cfg.fifo {
            Some(path) => {
                let fd = fifo::create_fifo(path)?;
                self.poll.registry().register(&mut SourceFd(&fd), TOK_FIFO, Interest::READABLE)?;
                log::info!("fifo_file={path}");
                Some(fd)
            }
            None => None,
        };
        let mut events = Events::with_capacity(1024);
        let mut last_timer = 0u64;
        loop {
            if self.exit_flag.load(Ordering::Relaxed) {
                log::info!("exiting");
                return Ok(());
            }
            let now = now_ms();
            let elapsed = now.saturating_sub(last_timer);
            let timeout = if self.raw_pending || !self.socks_pending.is_empty() || self.pipeline.in_flight() > 0 {
                Duration::ZERO
            } else {
                Duration::from_millis(TIMER_INTERVAL_MS.saturating_sub(elapsed).max(1))
            };
            match self.poll.poll(&mut events, Some(timeout)) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
            for ev in events.iter() {
                match ev.token() {
                    TOK_RAW => self.raw_pending = true,
                    TOK_PIPE => {}
                    TOK_FIFO => {
                        if let Some(fd) = fifo_fd {
                            if let Some(cmd) = fifo::read_command(fd) {
                                log::info!("got data from fifo,s=[{cmd}]");
                                log::info!("unknown command");
                            }
                        }
                    }
                    Token(t) if t >= TOK_SOCK_BASE => {
                        let sidx = t - TOK_SOCK_BASE;
                        if !self.socks_pending.contains(&sidx) {
                            self.socks_pending.push(sidx);
                        }
                    }
                    _ => {}
                }
            }
            if self.raw_pending {
                self.raw_pending = self.on_raw_readable();
            }
            let pending = std::mem::take(&mut self.socks_pending);
            for sidx in pending {
                if self.on_sock_readable(sidx) {
                    self.socks_pending.push(sidx);
                }
            }
            self.collect();
            let now = now_ms();
            if now.saturating_sub(last_timer) >= TIMER_INTERVAL_MS {
                last_timer = now;
                self.on_timer();
                self.collect();
            }
        }
    }

    fn collect(&mut self) {
        let mut done = Vec::new();
        self.pipeline.collect(|d| done.push(d));
        for d in done {
            self.on_done(d);
        }
    }

    // ---------------------------------------------------------------- slot management

    fn alloc_conn(&mut self, conn: ServerConn) -> usize {
        if let Some(i) = self.free_conns.pop() {
            self.conns[i] = Some(conn);
            i
        } else {
            self.conns.push(Some(conn));
            self.conns.len() - 1
        }
    }

    fn live_conns(&self) -> usize {
        self.conns.len() - self.free_conns.len()
    }

    fn conn(&mut self, slot: usize) -> &mut ServerConn {
        self.conns[slot].as_mut().expect("conn slot")
    }

    fn close_sock(&mut self, sidx: usize) {
        if let Some(cs) = self.socks[sidx].take() {
            let _ = self.poll.registry().deregister(&mut SourceFd(&cs.sock.as_raw_fd()));
            drop(cs);
            self.free_socks.push(sidx);
        }
    }

    fn erase_conn(&mut self, slot: usize) {
        let Some(mut c) = self.conns[slot].take() else { return };
        if c.state == State::Ready {
            self.ready_num -= 1;
            self.by_const_id.remove(&c.info.oppsite_const_id);
        }
        for sidx in c.convs.clear() {
            self.close_sock(sidx);
        }
        self.by_addr.remove(&c.addr);
        self.free_conns.push(slot);
    }

    fn key(&self, slot: usize) -> JobKey {
        JobKey { slot, generation: self.conns[slot].as_ref().map_or(0, |c| c.generation) }
    }

    fn fill_lower_level(&self, raw: &mut RawInfo) {
        if !self.ctx.lower_level {
            return;
        }
        raw.send_info.addr_ll = match self.manual_ll {
            Some(ll) => ll,
            None => net::raw::reply_sockaddr_ll(&raw.recv_info.addr_ll),
        };
    }

    // ---------------------------------------------------------------- raw side (clients)

    /// Returns true if the socket may still hold data (budget exhausted).
    fn on_raw_readable(&mut self) -> bool {
        for _ in 0..DRAIN_BUDGET {
            let mut buf = std::mem::take(&mut self.recv_buf);
            let r = self.ctx.sockets.recv(&mut buf[..HUGE_DATA_LEN + 1]);
            match r {
                Ok(Some((len, ll))) => {
                    self.on_raw_packet(&mut buf, len, &ll);
                    self.recv_buf = buf;
                }
                Ok(None) => {
                    self.recv_buf = buf;
                    return false;
                }
                Err(e) => {
                    log::debug!("raw recv error: {e}");
                    self.recv_buf = buf;
                    return false;
                }
            }
        }
        true
    }

    fn on_raw_packet(&mut self, buf: &mut [u8], mut len: usize, ll: &libc::sockaddr_ll) {
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
        let buf = &buf[..len];
        let Some(peek) = self.ctx.peek(buf) else {
            log::trace!("peek_raw failed");
            return;
        };
        let addr = (peek.src_ip, peek.src_port);
        let ip_port = addr_str(&addr);
        let slot_opt = self.by_addr.get(&addr).copied();
        let raw_mode = self.cfg.raw_mode;
        let is_v6 = self.ctx.is_v6;

        if raw_mode == RawMode::FakeTcp && peek.syn {
            let not_ready = slot_opt.is_none_or(|s| self.conns[s].as_ref().is_none_or(|c| c.state != State::Ready));
            if not_ready {
                // reply to any syn before the connection is ready
                let mut tmp = RawInfo::new(raw_mode, is_v6);
                let Some(data) = self.ctx.parse_recv(&mut tmp, buf, ll) else { return };
                let data_len = data.len();
                if data_len > MAX_DATA_LEN {
                    log::debug!("data_len={data_len} >= max_data_len+1,ignored");
                    return;
                }
                if self.cfg.easy_faketcp {
                    return; // the kernel's listening socket answers
                }
                let r = tmp.recv_info;
                tmp.send_info.src_ip = r.dst_ip;
                tmp.send_info.src_port = r.dst_port;
                tmp.send_info.dst_port = r.src_port;
                tmp.send_info.dst_ip = r.src_ip;
                self.fill_lower_level(&mut tmp);
                if data_len == 0 && r.syn && !r.ack {
                    tmp.send_info.ack_seq = r.seq.wrapping_add(1);
                    tmp.send_info.psh = false;
                    tmp.send_info.syn = true;
                    tmp.send_info.ack = true;
                    tmp.send_info.ts_ack = r.ts;
                    log::info!("[{ip_port}]received syn,sent syn ack back");
                    let _ = self.ctx.send_raw(&mut tmp, &[]);
                }
            }
            return;
        }

        let Some(slot) = slot_opt else {
            // a brand-new address: must be an initial handshake
            if self.live_conns() >= MAX_HANDSHAKE_CONN_NUM {
                log::info!("[{ip_port}]reached max_handshake_conn_num,ignored new handshake");
                return;
            }
            let mut tmp = RawInfo::new(raw_mode, is_v6);
            if raw_mode == RawMode::Icmp {
                tmp.send_info.dst_port = addr.1;
                tmp.send_info.src_port = addr.1;
            }
            let Some(data) = self.ctx.parse_recv(&mut tmp, buf, ll) else { return };
            let r = tmp.recv_info;
            if raw_mode == RawMode::FakeTcp && (r.syn || !r.ack) {
                log::debug!("unexpect packet type recv_info.syn={} recv_info.ack={}", r.syn, r.ack);
                return;
            }
            let Some(payload) = conn::parse_bare(&self.crypto, data) else { return };
            let Some((_, zero, _)) = wire::parse_handshake(&payload) else {
                log::debug!("[{ip_port}]too short to be a handshake");
                return;
            };
            if zero != 0 {
                log::debug!("[{ip_port}]not a invalid initial handshake");
                return;
            }
            log::info!("[{ip_port}]got packet from a new ip");
            let mut info = ConnInfo::new(raw_mode, is_v6, self.cfg.disable_anti_replay);
            info.raw = tmp;
            info.raw.send_info.src_ip = r.dst_ip;
            info.raw.send_info.src_port = r.dst_port;
            info.raw.send_info.dst_port = r.src_port;
            info.raw.send_info.dst_ip = r.src_ip;
            self.fill_lower_level(&mut info.raw);
            info.my_id = secure_random_u32_nz();
            info.last_state_time = now_ms();
            let generation = self.next_generation;
            self.next_generation += 1;
            let slot = self.alloc_conn(ServerConn { info, state: State::Handshake1, convs: ConvManager::new(), generation, addr });
            self.by_addr.insert(addr, slot);
            log::info!("[{ip_port}]created new conn,state: server_handshake1,my_id is {:x}", self.conn(slot).info.my_id);
            self.on_handshake1(slot, &payload);
            return;
        };

        let state = self.conn(slot).state;
        match state {
            State::Handshake1 => {
                let c = self.conns[slot].as_mut().unwrap();
                let Some(data) = self.ctx.parse_recv(&mut c.info.raw, buf, ll) else { return };
                let r = c.info.raw.recv_info;
                if raw_mode == RawMode::FakeTcp && (r.syn || !r.ack) {
                    log::debug!("unexpect packet type recv_info.syn={} recv_info.ack={}", r.syn, r.ack);
                    return;
                }
                let Some(payload) = conn::parse_bare(&self.crypto, data) else { return };
                self.on_handshake1(slot, &payload);
            }
            State::Ready => {
                let c = self.conns[slot].as_mut().unwrap();
                let Some(data) = self.ctx.parse_recv(&mut c.info.raw, buf, ll) else { return };
                let meta = RecvMeta::from_recv(&c.info.raw.recv_info);
                let wire_bytes = data.to_vec();
                let key = self.key(slot);
                self.pipeline.submit(Job::Decrypt { key, wire: wire_bytes, meta });
            }
            State::Idle => {}
        }
    }

    /// `server_on_raw_recv_handshake1`
    fn on_handshake1(&mut self, slot: usize, payload: &[u8]) {
        let raw_mode = self.cfg.raw_mode;
        let const_id = self.const_id;
        let c = self.conns[slot].as_mut().unwrap();
        let ip_port = addr_str(&c.addr);
        let Some((tmp_oppsite_id, tmp_my_id, tmp_oppsite_const_id)) = wire::parse_handshake(payload) else {
            log::debug!("[{ip_port}] data_len={} too short to be a handshake", payload.len());
            return;
        };
        let sync_seq = |raw: &mut RawInfo| {
            if raw_mode == RawMode::FakeTcp {
                let r = raw.recv_info;
                raw.send_info.seq = r.ack_seq;
                raw.send_info.ack_seq = r.seq.wrapping_add(r.data_len as u32);
                raw.send_info.ts_ack = r.ts;
            }
            if raw_mode == RawMode::Icmp {
                raw.send_info.icmp_seq = raw.recv_info.icmp_seq;
            }
        };
        if tmp_my_id == 0 {
            // received the initial handshake (again)
            sync_seq(&mut c.info.raw);
            let my_id = c.info.my_id;
            let _ = conn::send_handshake(&mut self.ctx, &self.crypto, &mut c.info.raw, my_id, tmp_oppsite_id, const_id);
            log::info!("[{ip_port}]changed state to server_handshake1,my_id is {my_id:x}");
        } else if tmp_my_id == c.info.my_id {
            c.info.oppsite_id = tmp_oppsite_id;
            sync_seq(&mut c.info.raw);
            self.pre_ready(slot, tmp_oppsite_const_id);
        } else {
            log::debug!("[{ip_port}]invalid my_id {tmp_my_id:x},my_id is {:x}", c.info.my_id);
        }
    }

    /// `server_on_raw_recv_pre_ready`: go ready, or recover an existing connection.
    fn pre_ready(&mut self, slot: usize, tmp_oppsite_const_id: u32) {
        let now = now_ms();
        let ip_port = addr_str(&self.conn(slot).addr);
        {
            let c = self.conn(slot);
            log::info!("[{ip_port}]received handshake oppsite_id:{:x}  my_id:{:x}", c.info.oppsite_id, c.info.my_id);
        }
        log::info!("[{ip_port}]oppsite const_id:{tmp_oppsite_const_id:x}");
        match self.by_const_id.get(&tmp_oppsite_const_id).copied() {
            None => {
                if self.ready_num >= MAX_READY_CONN_NUM {
                    log::info!("[{ip_port}]max_ready_conn_num,cant turn to ready");
                    self.conn(slot).state = State::Idle;
                    return;
                }
                {
                    let c = self.conn(slot);
                    c.state = State::Ready;
                    c.info.oppsite_const_id = tmp_oppsite_const_id;
                    c.info.last_hb_recv_time = now;
                    c.info.last_hb_sent_time = now;
                    c.info.anti_replay.re_init();
                }
                self.ready_num += 1;
                self.by_const_id.insert(tmp_oppsite_const_id, slot);
                self.send_heartbeat(slot);
                log::info!("[{ip_port}]changed state to server_ready");
            }
            Some(ori_slot) => {
                if ori_slot == slot {
                    log::error!("[{ip_port}]const_id already maps to this connection, this shouldnt happen");
                    return;
                }
                let ori_ready = self.conn(ori_slot).state == State::Ready;
                if !ori_ready {
                    log::error!("[{ip_port}]this should never happen: recovered connection is not ready");
                    let c = self.conn(slot);
                    c.state = State::Idle;
                    c.info.oppsite_const_id = 0;
                    return;
                }
                let new_lst = self.conn(slot).info.last_state_time;
                let ori_lst = self.conn(ori_slot).info.last_state_time;
                if new_lst < ori_lst {
                    log::info!("[{ip_port}]conn_info.last_state_time<ori_conn_info.last_state_time. ignored new handshake");
                    let c = self.conn(slot);
                    c.state = State::Idle;
                    c.info.oppsite_const_id = 0;
                    return;
                }
                // swap the address bindings: the established connection object takes over
                // the new address; the fresh object inherits the old address and goes idle.
                let addr_new = self.conn(slot).addr;
                let addr_old = self.conn(ori_slot).addr;
                self.by_addr.insert(addr_new, ori_slot);
                self.by_addr.insert(addr_old, slot);
                self.conn(slot).addr = addr_old;
                self.conn(ori_slot).addr = addr_new;
                log::info!("[{ip_port}]grabbed a connection");

                let (a, b) = if slot < ori_slot { self.conns.split_at_mut(ori_slot) } else { self.conns.split_at_mut(slot) };
                let (new_c, ori_c) = if slot < ori_slot { (a[slot].as_mut().unwrap(), b[0].as_mut().unwrap()) } else { (b[0].as_mut().unwrap(), a[ori_slot].as_mut().unwrap()) };
                ori_c.info.recover_from(&new_c.info);
                ori_c.generation = self.next_generation;
                self.next_generation += 1;
                new_c.state = State::Idle;
                new_c.info.oppsite_const_id = 0;
                self.send_heartbeat(ori_slot);
                self.conn(ori_slot).info.last_hb_recv_time = now;
            }
        }
    }

    fn send_heartbeat(&mut self, slot: usize) {
        let hb: &[u8] = if self.cfg.hb_mode == 0 { &[] } else { &self.hb_buf };
        let plain = conn::prepare_safer(&mut self.conns[slot].as_mut().unwrap().info, TYPE_HEARTBEAT, hb);
        let key = self.key(slot);
        self.pipeline.submit(Job::Encrypt { key, plain });
    }

    // ---------------------------------------------------------------- pipeline completions

    fn valid_ready(&self, key: JobKey) -> bool {
        match self.conns.get(key.slot).and_then(|c| c.as_ref()) {
            Some(c) => c.generation == key.generation && c.state == State::Ready,
            None => false,
        }
    }

    fn on_done(&mut self, d: Done) {
        match d {
            Done::Encrypted { key, wire } => {
                if !self.valid_ready(key) {
                    return;
                }
                if let Some(w) = wire {
                    let c = self.conns[key.slot].as_mut().unwrap();
                    if let Err(e) = conn::transmit_safer(&mut self.ctx, &mut c.info.raw, &w) {
                        log::trace!("send failed: {e}");
                    }
                }
            }
            Done::Decrypted { key, plains, meta } => {
                if !self.valid_ready(key) {
                    return;
                }
                if plains.is_empty() {
                    log::debug!("recv_safer failed!");
                    return;
                }
                let mut any = false;
                for p in plains {
                    let c = self.conns[key.slot].as_mut().unwrap();
                    if let Some((ptype, payload)) = conn::accept_safer(&mut c.info, &p, self.cfg.hb_mode) {
                        any = true;
                        self.on_ready_packet(key.slot, ptype, &payload);
                    }
                }
                if any {
                    let c = self.conns[key.slot].as_mut().unwrap();
                    self.ctx.after_recv(&mut c.info.raw, &meta);
                }
            }
        }
    }

    /// `server_on_raw_recv_ready`
    fn on_ready_packet(&mut self, slot: usize, ptype: u8, payload: &[u8]) {
        let now = now_ms();
        let ip_port = addr_str(&self.conn(slot).addr);
        if ptype == TYPE_HEARTBEAT {
            log::debug!("[{ip_port}][hb]received hb");
            self.conn(slot).info.last_hb_recv_time = now;
            return;
        }
        if ptype != TYPE_DATA {
            return;
        }
        let Some((conv, data)) = wire::parse_data_payload(payload) else { return };
        if self.cfg.hb_mode == 0 {
            self.conn(slot).info.last_hb_recv_time = now;
        }
        log::trace!("conv:{conv}");
        if !self.conn(slot).convs.is_conv_used(conv) {
            if self.conn(slot).convs.len() >= MAX_CONV_NUM {
                log::warn!("[{ip_port}]ignored new conv {conv:x} connect bc max_conv_num exceed");
                return;
            }
            let sock = match net::new_connected_udp(self.cfg.remote_addr, self.cfg.socket_buf_size, self.cfg.force_socket_buf) {
                Ok(s) => s,
                Err(e) => {
                    log::warn!("[{ip_port}]new_connected_udp_fd() failed: {e}");
                    return;
                }
            };
            let fd = sock.as_raw_fd();
            let sidx = if let Some(i) = self.free_socks.pop() {
                self.socks[i] = Some(ConvSock { sock, conn_slot: slot, conv });
                i
            } else {
                self.socks.push(Some(ConvSock { sock, conn_slot: slot, conv }));
                self.socks.len() - 1
            };
            if let Err(e) = self.poll.registry().register(&mut SourceFd(&fd), Token(TOK_SOCK_BASE + sidx), Interest::READABLE) {
                log::warn!("[{ip_port}]add udp_fd error: {e}");
                self.close_sock(sidx);
                return;
            }
            self.conn(slot).convs.insert(conv, sidx, now);
            log::info!("[{ip_port}]new conv conv_id={conv:x}, assigned fd={fd}");
        }
        let sidx = *self.conn(slot).convs.find_data_by_conv(conv).unwrap();
        self.conn(slot).convs.update_active_time(conv, now);
        log::trace!("[{ip_port}]received a data from fake tcp,len:{}", data.len());
        if let Some(cs) = self.socks[sidx].as_ref() {
            if let Err(e) = cs.sock.send(data) {
                log::warn!("send returned error {e}");
            }
        }
    }

    // ---------------------------------------------------------------- UDP side (towards -r)

    /// Returns true if the socket may still hold data (budget exhausted).
    fn on_sock_readable(&mut self, sidx: usize) -> bool {
        for _ in 0..DRAIN_BUDGET {
            let Some(cs) = self.socks[sidx].as_ref() else { return false };
            let (conn_slot, conv) = (cs.conn_slot, cs.conv);
            let mut buf = std::mem::take(&mut self.udp_buf);
            let r = cs.sock.recv(&mut buf[..MAX_DATA_LEN + 1]);
            let n = match r {
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    self.udp_buf = buf;
                    return false;
                }
                Err(e) => {
                    log::debug!("udp fd,recv_len<0 continue,{e}");
                    self.udp_buf = buf;
                    return false;
                }
            };
            self.on_sock_packet(conn_slot, conv, &buf[..n]);
            self.udp_buf = buf;
        }
        true
    }

    fn on_sock_packet(&mut self, slot: usize, conv: u32, data: &[u8]) {
        if data.len() == MAX_DATA_LEN + 1 {
            log::warn!("huge packet, data_len > {MAX_DATA_LEN},dropped");
            return;
        }
        if data.len() >= self.cfg.mtu_warn {
            log::warn!("huge packet,data len={} (>={}).strongly suggested to set a smaller mtu at upper level,to get rid of this warn", data.len(), self.cfg.mtu_warn);
        }
        let Some(c) = self.conns[slot].as_mut() else { return };
        if c.state != State::Ready {
            log::error!("conn state is not server_ready, this shouldnt happen");
            return;
        }
        let payload = wire::build_data_payload(conv, data);
        let plain = conn::prepare_safer(&mut c.info, TYPE_DATA, &payload);
        let key = self.key(slot);
        self.pipeline.submit(Job::Encrypt { key, plain });
    }

    // ---------------------------------------------------------------- timers

    fn on_timer(&mut self) {
        let now = now_ms();
        self.clear_inactive_conns(now);
        for slot in 0..self.conns.len() {
            let Some(c) = self.conns[slot].as_mut() else { continue };
            if c.state != State::Ready {
                continue;
            }
            let ip_port = addr_str(&c.addr);
            let expired = c.convs.clear_inactive(now);
            for (conv, sidx) in expired {
                self.close_sock(sidx);
                log::info!("[{ip_port}]conv {conv:x} cleared");
            }
            let c = self.conns[slot].as_mut().unwrap();
            if now - c.info.last_hb_sent_time < HEARTBEAT_INTERVAL_MS {
                continue;
            }
            self.send_heartbeat(slot);
            let c = self.conns[slot].as_mut().unwrap();
            c.info.last_hb_sent_time = now;
            log::debug!("heart beat sent<{:x},{:x}>", c.info.my_id, c.info.oppsite_id);
        }
    }

    /// `conn_manager_t::clear_inactive0`: inspect a bounded number of connections per pass.
    fn clear_inactive_conns(&mut self, now: u64) {
        if now.saturating_sub(self.last_conn_clear) <= CONN_CLEAR_INTERVAL_MS {
            return;
        }
        self.last_conn_clear = now;
        let size = self.live_conns();
        if size == 0 {
            return;
        }
        let num_to_clean = (size / CONN_CLEAR_RATIO + CONN_CLEAR_MIN).min(size);
        let mut cnt = 0;
        let mut visited = 0;
        while cnt < num_to_clean && visited < self.conns.len() {
            if self.clear_cursor >= self.conns.len() {
                self.clear_cursor = 0;
            }
            let slot = self.clear_cursor;
            self.clear_cursor += 1;
            visited += 1;
            let Some(c) = self.conns[slot].as_ref() else { continue };
            cnt += 1;
            let keep = if c.state == State::Ready {
                now - c.info.last_hb_recv_time <= SERVER_CONN_TIMEOUT_MS || !c.convs.is_empty()
            } else {
                now - c.info.last_state_time <= SERVER_HANDSHAKE_TIMEOUT_MS
            };
            if !keep {
                log::info!("[{}]inactive conn cleared", addr_str(&c.addr));
                self.erase_conn(slot);
            }
        }
    }
}
