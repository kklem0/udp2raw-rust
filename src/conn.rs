//! Per-connection state shared by client and server, and the bare/safer packet helpers
//! (`conn_info_t`, `send_bare`, `recv_bare`, `send_handshake`, `send_safer`,
//! `reserved_parse_safer`, `recv_safer_multi`).

use crate::anti_replay::AntiReplay;
use crate::consts::{MAX_DATA_LEN, TYPE_DATA, TYPE_HEARTBEAT};
use crate::crypto::Crypto;
use crate::faketcp::{RawCtx, RawInfo, RecvMeta};
use crate::types::RawMode;
use crate::util::{now_ms, secure_random_u64};
use crate::wire;
use std::io;

pub struct ConnInfo {
    pub raw: RawInfo,
    pub last_state_time: u64,
    /// The client re-uses this as the retry timer during handshakes.
    pub last_hb_sent_time: u64,
    pub last_hb_recv_time: u64,
    pub my_id: u32,
    pub oppsite_id: u32,
    pub oppsite_const_id: u32,
    pub my_roller: u8,
    pub oppsite_roller: u8,
    pub last_oppsite_roller_time: u64,
    pub anti_replay: AntiReplay,
}

impl ConnInfo {
    pub fn new(raw_mode: RawMode, is_v6: bool, disable_anti_replay: bool) -> ConnInfo {
        ConnInfo {
            raw: RawInfo::new(raw_mode, is_v6),
            last_state_time: 0,
            last_hb_sent_time: 0,
            last_hb_recv_time: 0,
            my_id: 0,
            oppsite_id: 0,
            oppsite_const_id: 0,
            my_roller: 0,
            oppsite_roller: 0,
            last_oppsite_roller_time: 0,
            anti_replay: AntiReplay::new(disable_anti_replay),
        }
    }

    /// `conn_info_t::recover`: take over the raw connection of `other` (server-side
    /// reconnect of a client with the same const_id).
    pub fn recover_from(&mut self, other: &ConnInfo) {
        self.raw = other.raw;
        self.raw.rst_received = 0;
        self.raw.disabled = false;
        self.last_state_time = other.last_state_time;
        self.last_hb_recv_time = other.last_hb_recv_time;
        self.last_hb_sent_time = other.last_hb_sent_time;
        self.my_id = other.my_id;
        self.oppsite_id = other.oppsite_id;
        self.anti_replay.re_init();
        self.my_roller = 0;
        self.oppsite_roller = 0;
        self.last_oppsite_roller_time = 0;
    }
}

/// `send_bare`: encrypt a handshake payload with random nonces and send it (no anti-replay,
/// no `after_send` — the handshake code manages the FakeTCP sequence numbers itself).
pub fn send_bare(ctx: &mut RawCtx, crypto: &Crypto, raw: &mut RawInfo, payload: &[u8]) -> io::Result<()> {
    let plain = wire::build_bare(secure_random_u64(), secure_random_u64(), payload);
    let Some(wire_bytes) = crypto.encrypt(&plain) else {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "encrypt failed"));
    };
    ctx.send_raw(raw, &wire_bytes)
}

/// `send_handshake`: three ids as a bare packet.
pub fn send_handshake(ctx: &mut RawCtx, crypto: &Crypto, raw: &mut RawInfo, id1: u32, id2: u32, id3: u32) -> io::Result<()> {
    send_bare(ctx, crypto, raw, &wire::build_handshake(id1, id2, id3))
}

/// The decrypt half of `recv_bare`: returns the handshake payload.
pub fn parse_bare(crypto: &Crypto, data: &[u8]) -> Option<Vec<u8>> {
    if data.len() > MAX_DATA_LEN {
        log::debug!("data_len={} >= max_data_len+1,ignored", data.len());
        return None;
    }
    let plain = crypto.decrypt(data)?;
    let payload = wire::parse_bare(&plain)?;
    Some(payload.to_vec())
}

/// Build the plaintext of a safer packet, consuming one send sequence number.
pub fn prepare_safer(info: &mut ConnInfo, ptype: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(wire::SAFER_HEADER_LEN + payload.len());
    prepare_safer_into(info, ptype, payload, &mut v);
    v
}

/// [`prepare_safer`] into a caller-provided (pooled) buffer.
pub fn prepare_safer_into(info: &mut ConnInfo, ptype: u8, payload: &[u8], out: &mut Vec<u8>) {
    let h = wire::SaferHeader { my_id: info.my_id, oppsite_id: info.oppsite_id, seq: info.anti_replay.next_seq_for_send(), ptype, roller: info.my_roller };
    wire::build_safer_into(&h, payload, out);
}

/// [`prepare_safer_into`] for a data packet: `header || conv || datagram`, no intermediate copy.
pub fn prepare_safer_data_into(info: &mut ConnInfo, conv: u32, data: &[u8], out: &mut Vec<u8>) {
    prepare_safer_into(info, TYPE_DATA, &[], out);
    out.extend_from_slice(&conv.to_be_bytes());
    out.extend_from_slice(data);
}

/// Encrypt (and `--fix-gro` wrap) a prepared safer plaintext. Pure; runs on workers.
pub fn encrypt_safer(crypto: &Crypto, plain: &[u8], fix_gro: bool) -> Option<Vec<u8>> {
    encrypt_safer_vec(crypto, plain.to_vec(), fix_gro)
}

/// In-place variant of [`encrypt_safer`]: the plaintext buffer becomes the wire bytes.
pub fn encrypt_safer_vec(crypto: &Crypto, plain: Vec<u8>, fix_gro: bool) -> Option<Vec<u8>> {
    let mut enc = crypto.encrypt_vec(plain)?;
    if fix_gro {
        wire::gro_wrap_in_place(crypto, &mut enc);
    }
    Some(enc)
}

/// Send an encrypted safer packet and advance the FakeTCP state.
pub fn transmit_safer(ctx: &mut RawCtx, raw: &mut RawInfo, wire_bytes: &[u8]) -> io::Result<()> {
    ctx.send_raw(raw, wire_bytes)?;
    ctx.after_send(raw);
    Ok(())
}

/// Inline `send_safer` (used when no worker pool is configured).
pub fn send_safer(ctx: &mut RawCtx, crypto: &Crypto, info: &mut ConnInfo, ptype: u8, payload: &[u8], fix_gro: bool) -> io::Result<()> {
    if ptype != TYPE_HEARTBEAT && ptype != TYPE_DATA {
        log::warn!("first byte is not h or d  ,{ptype:x}");
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad type"));
    }
    let plain = prepare_safer(info, ptype, payload);
    let Some(w) = encrypt_safer(crypto, &plain, fix_gro) else {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "encrypt failed"));
    };
    transmit_safer(ctx, &mut info.raw, &w)
}

/// Decrypt (and `--fix-gro` split) a received raw payload into safer plaintexts. Pure;
/// runs on workers. The buffer is modified in place by the GRO deobfuscation.
pub fn decrypt_safer(crypto: &Crypto, data: &mut [u8], fix_gro: bool) -> Vec<Vec<u8>> {
    if !fix_gro {
        return decrypt_safer_vec(crypto, data.to_vec(), fix_gro);
    }
    decrypt_safer_gro(crypto, data)
}

/// Owned-buffer variant of [`decrypt_safer`]: without `--fix-gro` the wire buffer itself
/// becomes the plaintext (no allocation).
pub fn decrypt_safer_vec(crypto: &Crypto, mut wire: Vec<u8>, fix_gro: bool) -> Vec<Vec<u8>> {
    if !fix_gro {
        return crypto.decrypt_vec(wire).into_iter().collect();
    }
    decrypt_safer_gro(crypto, &mut wire)
}

fn decrypt_safer_gro(crypto: &Crypto, data: &mut [u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let parts = wire::gro_unwrap(crypto, data);
    let cnt = parts.len();
    for (off, len) in parts {
        match crypto.decrypt(&data[off..off + len]) {
            Some(p) => out.push(p),
            None => log::debug!("parse failed, offset= {off},single_len={len}"),
        }
    }
    if cnt > 1 {
        log::debug!("got a suspected gro packet, {} packets recovered, recv_len={}, loop_cnt={}", out.len(), data.len(), cnt);
    }
    out
}

/// The stateful half of `reserved_parse_safer`: id check, anti-replay, type/roller
/// bookkeeping. Returns (type, payload). Must run on the connection's owner thread.
pub fn accept_safer(info: &mut ConnInfo, plain: &[u8], hb_mode: i32) -> Option<(u8, Vec<u8>)> {
    let (ptype, off) = accept_safer_offset(info, plain, hb_mode)?;
    Some((ptype, plain[off..].to_vec()))
}

/// [`accept_safer`] without copying: returns (type, offset of the payload in `plain`).
pub fn accept_safer_offset(info: &mut ConnInfo, plain: &[u8], hb_mode: i32) -> Option<(u8, usize)> {
    let ids = wire::parse_safer_ids(plain)?;
    if ids.oppsite_id != info.oppsite_id || ids.my_id != info.my_id {
        log::debug!("id and oppsite_id verification failed {:x} {:x} {:x} {:x}", ids.oppsite_id, info.oppsite_id, ids.my_id, info.my_id);
        return None;
    }
    if !info.anti_replay.is_valid(ids.seq) {
        log::debug!("dropped replay packet");
        return None;
    }
    let (ptype, roller, payload) = wire::parse_safer_body(plain)?;
    if roller != info.oppsite_roller {
        info.oppsite_roller = roller;
        info.last_oppsite_roller_time = now_ms();
    }
    if hb_mode == 0 || ptype == TYPE_HEARTBEAT {
        info.my_roller = info.my_roller.wrapping_add(1);
    }
    let _ = payload;
    Some((ptype, wire::SAFER_HEADER_LEN))
}

/// Inline `recv_safer_multi`: decrypt + accept + `after_recv`, all on the caller's thread.
pub fn recv_safer_inline(ctx: &RawCtx, crypto: &Crypto, info: &mut ConnInfo, data: &mut [u8], fix_gro: bool, hb_mode: i32, meta: &RecvMeta) -> Vec<(u8, Vec<u8>)> {
    let plains = decrypt_safer(crypto, data, fix_gro);
    let mut out = Vec::with_capacity(plains.len());
    for p in plains {
        if let Some(x) = accept_safer(info, &p, hb_mode) {
            out.push(x);
        }
    }
    if !out.is_empty() {
        ctx.after_recv(&mut info.raw, meta);
    }
    out
}
