//! Raw-packet send/receive glue for the three raw modes, and the FakeTCP seq/ack
//! emulation (`packet_info_t`, `raw_info_t`, `send_raw0`, `recv_raw0`, `after_send_raw0`,
//! `after_recv_raw0`, `peek_raw`).

use crate::config::Config;
use crate::consts::{MAX_DATA_LEN, RECEIVE_WINDOW_LOWER_BOUND, RECEIVE_WINDOW_RANDOM_RANGE, WSCALE};
use crate::net::raw::RawSockets;
use crate::net::{send_batch, SendScratch, TxDst, TxPacket};
use crate::packet::ip::{self, IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_TCP, IPPROTO_UDP};
use crate::packet::{icmp, tcp, udp};
use crate::types::RawMode;
use crate::util::{fast_random_u32, larger_than_u16, larger_than_u32, now_ms, secure_random_u32};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Copy)]
pub struct PacketInfo {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub syn: bool,
    pub ack: bool,
    pub psh: bool,
    pub rst: bool,
    pub seq: u32,
    pub ack_seq: u32,
    pub ack_seq_counter: u32,
    pub ts: u32,
    pub ts_ack: u32,
    pub has_ts: bool,
    pub icmp_seq: u16,
    pub data_len: usize,
    /// Link-layer address for `--lower-level` (send: destination, recv: source).
    pub addr_ll: libc::sockaddr_ll,
}

impl PacketInfo {
    pub fn new(raw_mode: RawMode, is_v6: bool) -> PacketInfo {
        let unspec = if is_v6 { IpAddr::V6(Ipv6Addr::UNSPECIFIED) } else { IpAddr::V4(Ipv4Addr::UNSPECIFIED) };
        let mut p = PacketInfo {
            src_ip: unspec,
            dst_ip: unspec,
            src_port: 0,
            dst_port: 0,
            syn: false,
            ack: false,
            psh: false,
            rst: false,
            seq: 0,
            ack_seq: 0,
            ack_seq_counter: 0,
            ts: 0,
            ts_ack: 0,
            has_ts: false,
            icmp_seq: 0,
            data_len: 0,
            addr_ll: unsafe { std::mem::zeroed() },
        };
        if raw_mode == RawMode::FakeTcp {
            p.ack_seq = secure_random_u32();
            p.seq = secure_random_u32();
            p.ack = true;
        }
        p
    }
}

#[derive(Clone, Copy)]
pub struct RawInfo {
    pub send_info: PacketInfo,
    pub recv_info: PacketInfo,
    pub reserved_send_seq: u32,
    pub rst_received: i32,
    pub disabled: bool,
}

impl RawInfo {
    pub fn new(raw_mode: RawMode, is_v6: bool) -> RawInfo {
        RawInfo { send_info: PacketInfo::new(raw_mode, is_v6), recv_info: PacketInfo::new(raw_mode, is_v6), reserved_send_seq: 0, rst_received: 0, disabled: false }
    }
}

/// Snapshot of the receive-side fields that `after_recv` consumes, taken when the packet
/// headers were parsed so the pipeline can apply it later in order.
#[derive(Clone, Copy, Debug, Default)]
pub struct RecvMeta {
    pub syn: bool,
    pub ack: bool,
    pub seq: u32,
    pub data_len: usize,
    pub has_ts: bool,
    pub ts: u32,
    pub icmp_seq: u16,
}

impl RecvMeta {
    pub fn from_recv(r: &PacketInfo) -> RecvMeta {
        RecvMeta { syn: r.syn, ack: r.ack, seq: r.seq, data_len: r.data_len, has_ts: r.has_ts, ts: r.ts, icmp_seq: r.icmp_seq }
    }
}

/// What the server needs to route an incoming raw packet before parsing it fully.
#[derive(Clone, Copy, Debug)]
pub struct PeekInfo {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub syn: bool,
}

/// Owner of the raw sockets and the per-process raw-mode settings (main thread only).
pub struct RawCtx {
    pub sockets: RawSockets,
    pub raw_mode: RawMode,
    pub is_v6: bool,
    pub is_client: bool,
    pub seq_mode: i32,
    pub ttl: u8,
    pub random_drop: u32,
    pub filter_port: u16,
    /// Server: the `-l` ip when it is not unspecified; packets to other addresses are dropped.
    pub bind_addr: Option<IpAddr>,
    pub lower_level: bool,
    pub easy_faketcp: bool,
    pub disable_bpf: bool,
    pub max_rst_to_show: i32,
    pub max_rst_allowed: i32,
    ip_id_counter: u16,
    seg_buf: Vec<u8>,
    /// Packets built by `send_raw`, sent with one `sendmmsg` per [`flush_tx`](Self::flush_tx).
    tx_queue: Vec<TxPacket>,
    tx_pool: Vec<Vec<u8>>,
    scratch: SendScratch,
    pub tx_dropped: u64,
}

/// Flush automatically once this many packets are queued.
const TX_QUEUE_FLUSH: usize = 64;

impl RawCtx {
    pub fn new(cfg: &Config, sockets: RawSockets) -> RawCtx {
        let bind_addr = if !cfg.is_client() && !cfg.local_addr.ip().is_unspecified() { Some(cfg.local_addr.ip()) } else { None };
        RawCtx {
            sockets,
            raw_mode: cfg.raw_mode,
            is_v6: cfg.raw_is_v6(),
            is_client: cfg.is_client(),
            seq_mode: cfg.seq_mode,
            ttl: cfg.ttl,
            random_drop: cfg.random_drop,
            filter_port: 0,
            bind_addr,
            lower_level: cfg.lower_level.is_some(),
            easy_faketcp: cfg.easy_faketcp,
            disable_bpf: cfg.disable_bpf,
            max_rst_to_show: cfg.max_rst_to_show,
            max_rst_allowed: cfg.max_rst_allowed,
            ip_id_counter: (secure_random_u32() % 65535) as u16,
            seg_buf: Vec::with_capacity(2048),
            tx_queue: Vec::with_capacity(TX_QUEUE_FLUSH),
            tx_pool: Vec::new(),
            scratch: SendScratch::default(),
            tx_dropped: 0,
        }
    }

    /// Hand every queued packet to the kernel (one `sendmmsg`). Call once per event-loop round.
    pub fn flush_tx(&mut self) {
        if self.tx_queue.is_empty() {
            return;
        }
        let accepted = send_batch(self.sockets.send_fd, &self.tx_queue, &mut self.scratch);
        let n = self.tx_queue.len();
        if accepted < n {
            self.tx_dropped += (n - accepted) as u64;
            log::trace!("raw send: {} of {} packets dropped by the kernel", n - accepted, n);
        }
        for p in self.tx_queue.drain(..) {
            if self.tx_pool.len() < 256 {
                self.tx_pool.push(p.buf);
            }
        }
    }

    pub fn pending_tx(&self) -> usize {
        self.tx_queue.len()
    }

    /// `init_filter`: remember the port (tcp/udp) and attach the kernel filter.
    pub fn set_filter(&mut self, port: u16) -> io::Result<()> {
        if matches!(self.raw_mode, RawMode::FakeTcp | RawMode::Udp) {
            self.filter_port = port;
        }
        self.sockets.attach_filter(self.raw_mode, port, self.disable_bpf)
    }

    /// `send_raw0`: build transport + IP headers around `payload` and queue it for
    /// [`flush_tx`](Self::flush_tx). Sets `send_info.data_len` for FakeTCP (used by `after_send`).
    pub fn send_raw(&mut self, raw: &mut RawInfo, payload: &[u8]) -> io::Result<()> {
        if self.random_drop != 0 && fast_random_u32() % 10000 < self.random_drop {
            return Ok(());
        }
        if raw.disabled {
            log::debug!("[{},{}]connection disabled, no packet will be sent", raw.recv_info.src_ip, raw.recv_info.src_port);
            return Ok(());
        }
        let s = &raw.send_info;
        log::trace!("send_raw : from {} {}  to {} {}", s.src_ip, s.src_port, s.dst_ip, s.dst_port);
        self.seg_buf.clear();
        let protocol = match self.raw_mode {
            RawMode::FakeTcp => {
                let window = (RECEIVE_WINDOW_LOWER_BOUND + fast_random_u32() % RECEIVE_WINDOW_RANDOM_RANGE) as u16;
                let p = tcp::TcpSendParams {
                    src_port: s.src_port,
                    dst_port: s.dst_port,
                    seq: s.seq,
                    ack_seq: s.ack_seq,
                    syn: s.syn,
                    ack: s.ack,
                    psh: s.psh,
                    window,
                    ts: now_ms() as u32,
                    ts_ack: s.ts_ack,
                };
                tcp::build_tcp(&mut self.seg_buf, s.src_ip, s.dst_ip, &p, payload);
                IPPROTO_TCP
            }
            RawMode::Udp => {
                if udp::build_udp(&mut self.seg_buf, s.src_ip, s.dst_ip, s.src_port, s.dst_port, payload).is_none() {
                    log::debug!("invalid len");
                    return Ok(());
                }
                IPPROTO_UDP
            }
            RawMode::Icmp => {
                icmp::build_icmp(&mut self.seg_buf, s.src_ip, s.dst_ip, self.is_client, s.src_port, s.icmp_seq, payload);
                if self.is_v6 { IPPROTO_ICMPV6 } else { IPPROTO_ICMP }
            }
        };
        let mut pkt = self.tx_pool.pop().unwrap_or_else(|| Vec::with_capacity(2048));
        pkt.clear();
        let id = self.ip_id_counter;
        self.ip_id_counter = self.ip_id_counter.wrapping_add(1);
        ip::build_ip_header(&mut pkt, s.src_ip, s.dst_ip, protocol, self.ttl, id, self.seg_buf.len());
        pkt.extend_from_slice(&self.seg_buf);
        let dst = if self.lower_level { TxDst::L2(s.addr_ll) } else { TxDst::Ip(s.dst_ip) };
        self.tx_queue.push(TxPacket { buf: pkt, off: 0, dst });
        if self.raw_mode == RawMode::FakeTcp {
            raw.send_info.data_len = payload.len();
        }
        if self.tx_queue.len() >= TX_QUEUE_FLUSH {
            self.flush_tx();
        }
        Ok(())
    }

    /// `after_send_raw0`: advance the FakeTCP sequence number per `--seq-mode`.
    pub fn after_send(&self, raw: &mut RawInfo) {
        match self.raw_mode {
            RawMode::FakeTcp => {
                let data_len = raw.send_info.data_len as u32;
                if !raw.send_info.syn && raw.send_info.ack && data_len != 0 {
                    match self.seq_mode {
                        0 => {}
                        1 => raw.send_info.seq = raw.send_info.seq.wrapping_add(data_len),
                        2 => {
                            if fast_random_u32() % 5 == 3 {
                                raw.send_info.seq = raw.send_info.seq.wrapping_add(data_len);
                            }
                        }
                        _ => {
                            // 3 and 4: simulate an almost real seq/ack procedure
                            raw.send_info.seq = raw.send_info.seq.wrapping_add(data_len);
                            let window_size: u32 = if self.seq_mode == 3 { RECEIVE_WINDOW_LOWER_BOUND << (WSCALE as u32) } else { RECEIVE_WINDOW_LOWER_BOUND };
                            if larger_than_u32(raw.send_info.seq.wrapping_add(MAX_DATA_LEN as u32), raw.recv_info.ack_seq.wrapping_add(window_size)) {
                                raw.send_info.seq = raw.recv_info.ack_seq;
                            }
                            if raw.recv_info.ack_seq_counter >= 3 {
                                // simulate tcp fast re-transmit
                                raw.recv_info.ack_seq_counter = 0;
                                raw.send_info.seq = raw.recv_info.ack_seq;
                            }
                            if larger_than_u32(raw.recv_info.ack_seq, raw.send_info.seq) {
                                raw.send_info.seq = raw.recv_info.ack_seq;
                            }
                        }
                    }
                }
            }
            RawMode::Icmp => {
                if self.is_client {
                    raw.send_info.icmp_seq = raw.send_info.icmp_seq.wrapping_add(1);
                }
            }
            RawMode::Udp => {}
        }
    }

    /// `after_recv_raw0`, using a snapshot of the received headers.
    pub fn after_recv(&self, raw: &mut RawInfo, m: &RecvMeta) {
        match self.raw_mode {
            RawMode::FakeTcp => {
                if m.has_ts {
                    raw.send_info.ts_ack = m.ts;
                }
                if !m.syn && m.ack && m.data_len != 0 {
                    let end = m.seq.wrapping_add(m.data_len as u32);
                    if self.seq_mode <= 2 {
                        if larger_than_u32(end, raw.send_info.ack_seq) {
                            raw.send_info.ack_seq = end;
                        }
                    } else if m.seq == raw.send_info.ack_seq {
                        // we don't remember tcp segments; this is the simplest way
                        raw.send_info.ack_seq = end;
                    }
                }
            }
            RawMode::Icmp => {
                if !self.is_client && larger_than_u16(m.icmp_seq, raw.send_info.icmp_seq) {
                    raw.send_info.icmp_seq = m.icmp_seq;
                }
            }
            RawMode::Udp => {}
        }
    }

    /// `peek_raw`: cheap header-only look at a received packet (no checksum).
    pub fn peek(&self, buf: &[u8]) -> Option<PeekInfo> {
        let ip = ip::parse_ip(buf, self.is_v6, false)?;
        let payload = ip.payload(buf);
        match self.raw_mode {
            RawMode::FakeTcp => {
                if ip.protocol != IPPROTO_TCP || payload.len() < tcp::TCP_MIN_HEADER {
                    return None;
                }
                Some(PeekInfo { src_ip: ip.src, src_port: u16::from_be_bytes([payload[0], payload[1]]), syn: payload[13] & 0x02 != 0 })
            }
            RawMode::Udp => {
                if ip.protocol != IPPROTO_UDP || payload.len() < udp::UDP_HEADER_LEN {
                    return None;
                }
                Some(PeekInfo { src_ip: ip.src, src_port: u16::from_be_bytes([payload[0], payload[1]]), syn: false })
            }
            RawMode::Icmp => {
                let want = if self.is_v6 { IPPROTO_ICMPV6 } else { IPPROTO_ICMP };
                if ip.protocol != want || payload.len() < icmp::ICMP_HEADER_LEN {
                    return None;
                }
                Some(PeekInfo { src_ip: ip.src, src_port: u16::from_be_bytes([payload[4], payload[5]]), syn: false })
            }
        }
    }

    /// `recv_raw0`: validate headers, fill `raw.recv_info`, return the transport payload.
    pub fn parse_recv<'a>(&self, raw: &mut RawInfo, buf: &'a [u8], ll: &libc::sockaddr_ll) -> Option<&'a [u8]> {
        let ip = ip::parse_ip(buf, self.is_v6, true)?;
        if self.lower_level {
            raw.recv_info.addr_ll = *ll;
        }
        if let Some(b) = self.bind_addr {
            if ip.dst != b {
                log::trace!("bind adress doenst match {} {}, dropped", ip.dst, b);
                return None;
            }
        }
        let r = &mut raw.recv_info;
        r.src_ip = ip.src;
        r.dst_ip = ip.dst;
        let payload = ip.payload(buf);
        match self.raw_mode {
            RawMode::FakeTcp => {
                if ip.protocol != IPPROTO_TCP {
                    return None;
                }
                let (t, data) = tcp::parse_tcp(payload, ip.src, ip.dst)?;
                if t.dst_port != self.filter_port {
                    return None;
                }
                if !t.csum_ok {
                    log::debug!("tcp checksum failed, ignored");
                }
                r.has_ts = t.has_ts;
                r.ts = t.ts;
                r.ts_ack = t.ts_ack;
                r.ack = t.ack;
                r.syn = t.syn;
                r.rst = t.rst;
                r.psh = t.psh;
                r.src_port = t.src_port;
                r.dst_port = t.dst_port;
                r.seq = t.seq;
                let last_ack_seq = r.ack_seq;
                r.ack_seq = t.ack_seq;
                if r.ack_seq == last_ack_seq {
                    r.ack_seq_counter += 1;
                } else {
                    r.ack_seq_counter = 0;
                }
                if t.rst {
                    raw.rst_received += 1;
                    let cnt = raw.rst_received;
                    let who = format!("[{},{}]", ip.src, t.src_port);
                    if self.max_rst_to_show > 0 {
                        if cnt < self.max_rst_to_show {
                            log::warn!("{who}rst==1,cnt={cnt}");
                        } else if cnt == self.max_rst_to_show {
                            log::warn!("{who}rst==1,cnt={cnt} >=max_rst_to_show, this log will be muted for current connection");
                        } else {
                            log::debug!("{who}rst==1,cnt={cnt}");
                        }
                    } else if self.max_rst_to_show == 0 {
                        log::debug!("{who}rst==1,cnt={cnt}");
                    } else {
                        log::warn!("{who}rst==1,cnt={cnt}");
                    }
                    if self.max_rst_allowed >= 0 && cnt == self.max_rst_allowed + 1 {
                        log::warn!("{who}connection disabled because of rst_received={cnt} > max_rst_allow={}", self.max_rst_allowed);
                        raw.disabled = true;
                    }
                }
                raw.recv_info.data_len = data.len();
                Some(data)
            }
            RawMode::Udp => {
                if ip.protocol != IPPROTO_UDP {
                    return None;
                }
                let (sp, dp, data) = udp::parse_udp(payload, ip.src, ip.dst)?;
                if dp != self.filter_port {
                    return None;
                }
                r.src_port = sp;
                r.dst_port = dp;
                r.data_len = data.len();
                Some(data)
            }
            RawMode::Icmp => {
                let want = if self.is_v6 { IPPROTO_ICMPV6 } else { IPPROTO_ICMP };
                if ip.protocol != want {
                    return None;
                }
                let (h, data) = icmp::parse_icmp(payload, ip.src, ip.dst, self.is_client)?;
                if h.id != raw.send_info.src_port {
                    log::debug!("icmp id mis-match,ignored");
                    return None;
                }
                let r = &mut raw.recv_info;
                r.src_port = h.id;
                r.dst_port = h.id;
                r.icmp_seq = h.seq;
                r.data_len = data.len();
                Some(data)
            }
        }
    }
}
