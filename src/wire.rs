//! udp2raw application-layer framing.
//!
//! ```text
//! bare  (handshake, no anti-replay):  [iv u64][padding u64]['b'][payload]        → encrypt
//! safer (data / heartbeat):           [my_id u32][oppsite_id u32][seq u64][type u8][roller u8][payload] → encrypt
//! handshake payload:                  [id1 u32][id2 u32][id3 u32] (big-endian)
//! data payload ('d'):                 [conv u32][udp datagram]
//! --fix-gro wrapping (per packet):    [len u16][encrypted...] with the head obfuscated
//! ```

use crate::consts::{BARE_MARKER, MAX_DATA_LEN, TYPE_DATA, TYPE_HEARTBEAT};
use crate::crypto::Crypto;
use crate::util::{read_u16_be, read_u32_be, read_u64_be, write_u16_be};

pub const BARE_HEADER_LEN: usize = 8 + 8 + 1;
pub const SAFER_HEADER_LEN: usize = 4 + 4 + 8 + 1 + 1;
pub const HANDSHAKE_LEN: usize = 12;

/// Build the plaintext of a bare packet. `iv`/`padding` are random nonces (their byte
/// order is irrelevant; the C++ memcpy'd host-order u64s).
pub fn build_bare(iv: u64, padding: u64, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(BARE_HEADER_LEN + payload.len());
    v.extend_from_slice(&iv.to_ne_bytes());
    v.extend_from_slice(&padding.to_ne_bytes());
    v.push(BARE_MARKER);
    v.extend_from_slice(payload);
    v
}

/// Parse a decrypted bare packet, returning the payload.
pub fn parse_bare(plain: &[u8]) -> Option<&[u8]> {
    if plain.len() < BARE_HEADER_LEN {
        return None;
    }
    if plain[16] != BARE_MARKER {
        return None;
    }
    Some(&plain[BARE_HEADER_LEN..])
}

pub fn build_handshake(id1: u32, id2: u32, id3: u32) -> [u8; HANDSHAKE_LEN] {
    let mut b = [0u8; HANDSHAKE_LEN];
    b[..4].copy_from_slice(&id1.to_be_bytes());
    b[4..8].copy_from_slice(&id2.to_be_bytes());
    b[8..].copy_from_slice(&id3.to_be_bytes());
    b
}

pub fn parse_handshake(data: &[u8]) -> Option<(u32, u32, u32)> {
    if data.len() < HANDSHAKE_LEN {
        return None;
    }
    Some((read_u32_be(&data[0..]), read_u32_be(&data[4..]), read_u32_be(&data[8..])))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SaferHeader {
    pub my_id: u32,
    pub oppsite_id: u32,
    pub seq: u64,
    pub ptype: u8,
    pub roller: u8,
}

pub fn build_safer(h: &SaferHeader, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(SAFER_HEADER_LEN + payload.len());
    build_safer_into(h, payload, &mut v);
    v
}

/// Append the safer plaintext (`header || payload`) to `out` (which is cleared first).
pub fn build_safer_into(h: &SaferHeader, payload: &[u8], out: &mut Vec<u8>) {
    out.clear();
    out.extend_from_slice(&h.my_id.to_be_bytes());
    out.extend_from_slice(&h.oppsite_id.to_be_bytes());
    out.extend_from_slice(&h.seq.to_be_bytes());
    out.push(h.ptype);
    out.push(h.roller);
    out.extend_from_slice(payload);
}

/// The ids and sequence number of a decrypted safer packet. Split from
/// [`parse_safer_body`] so the caller can run the anti-replay check between the two,
/// in the same order as the C++ (`reserved_parse_safer`).
#[derive(Clone, Copy, Debug)]
pub struct SaferIds {
    pub oppsite_id: u32, // the sender's id ("h_oppsite_id" from our point of view)
    pub my_id: u32,
    pub seq: u64,
}

pub fn parse_safer_ids(plain: &[u8]) -> Option<SaferIds> {
    if plain.len() < 16 {
        return None;
    }
    Some(SaferIds {
        oppsite_id: read_u32_be(&plain[0..]),
        my_id: read_u32_be(&plain[4..]),
        seq: read_u64_be(&plain[8..]),
    })
}

/// Returns (type, roller, payload).
pub fn parse_safer_body(plain: &[u8]) -> Option<(u8, u8, &[u8])> {
    if plain.len() < SAFER_HEADER_LEN {
        return None;
    }
    let ptype = plain[16];
    if ptype != TYPE_HEARTBEAT && ptype != TYPE_DATA {
        return None;
    }
    Some((ptype, plain[17], &plain[SAFER_HEADER_LEN..]))
}

/// `[conv u32][data]` — the payload of a 'd' packet.
pub fn build_data_payload(conv: u32, data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + data.len());
    v.extend_from_slice(&conv.to_be_bytes());
    v.extend_from_slice(data);
    v
}

pub fn parse_data_payload(data: &[u8]) -> Option<(u32, &[u8])> {
    if data.len() < 4 {
        return None;
    }
    Some((read_u32_be(data), &data[4..]))
}

/// `--fix-gro` sender side: prefix the encrypted packet with its length and obfuscate the
/// head so a GRO-merged burst can be split again by the receiver.
pub fn gro_wrap(crypto: &Crypto, encrypted: &[u8]) -> Vec<u8> {
    let mut v = encrypted.to_vec();
    gro_wrap_in_place(crypto, &mut v);
    v
}

/// In-place variant of [`gro_wrap`].
pub fn gro_wrap_in_place(crypto: &Crypto, buf: &mut Vec<u8>) {
    let len = buf.len();
    buf.splice(0..0, [0u8, 0u8]);
    write_u16_be(&mut buf[..2], len as u16);
    if buf.len() >= 16 || !crypto.cipher_mode().is_aes() {
        crypto.gro_obfuscate_head(buf);
    }
}

/// `--fix-gro` receiver side: split a (possibly GRO-merged) buffer into the individual
/// encrypted packets. Deobfuscates heads in place; returns `(offset, len)` pairs.
pub fn gro_unwrap(crypto: &Crypto, buf: &mut [u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    let mut remaining = buf.len();
    while remaining >= 16 {
        crypto.gro_deobfuscate_head(&mut buf[pos..pos + 16]);
        let single_len = read_u16_be(&buf[pos..]) as usize;
        pos += 2;
        remaining -= 2;
        if single_len > remaining {
            log::debug!("illegal single_len {single_len}, recv_len {remaining} left, dropped");
            break;
        }
        if single_len > MAX_DATA_LEN {
            log::warn!("single_len {single_len} > {MAX_DATA_LEN}, maybe you need to turn down mtu at upper level");
            break;
        }
        out.push((pos, single_len));
        pos += single_len;
        remaining -= single_len;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{AuthMode, CipherMode, Keys};

    #[test]
    fn bare_layout() {
        let p = build_bare(0x0102030405060708, 0x1112131415161718, b"xyz");
        assert_eq!(p.len(), 20);
        assert_eq!(p[16], b'b');
        assert_eq!(parse_bare(&p).unwrap(), b"xyz");
        assert!(parse_bare(&p[..16]).is_none());
        let mut bad = p.clone();
        bad[16] = b'c';
        assert!(parse_bare(&bad).is_none());
    }

    #[test]
    fn handshake_layout() {
        let h = build_handshake(1, 0x01020304, 0xffffffff);
        assert_eq!(h, [0, 0, 0, 1, 1, 2, 3, 4, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(parse_handshake(&h), Some((1, 0x01020304, 0xffffffff)));
        assert!(parse_handshake(&h[..11]).is_none());
    }

    #[test]
    fn safer_layout() {
        let h = SaferHeader { my_id: 0xaabbccdd, oppsite_id: 0x11223344, seq: 0x0102030405060708, ptype: b'd', roller: 7 };
        let p = build_safer(&h, &[9, 9]);
        assert_eq!(&p[..4], &[0xaa, 0xbb, 0xcc, 0xdd]);
        assert_eq!(&p[4..8], &[0x11, 0x22, 0x33, 0x44]);
        assert_eq!(&p[8..16], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(p[16], b'd');
        assert_eq!(p[17], 7);
        let ids = parse_safer_ids(&p).unwrap();
        // receiver's view: first word is the sender's id
        assert_eq!(ids.oppsite_id, 0xaabbccdd);
        assert_eq!(ids.my_id, 0x11223344);
        assert_eq!(ids.seq, 0x0102030405060708);
        let (t, r, d) = parse_safer_body(&p).unwrap();
        assert_eq!((t, r, d), (b'd', 7, &[9u8, 9][..]));
        let mut bad = p.clone();
        bad[16] = b'x';
        assert!(parse_safer_body(&bad).is_none());
        assert!(parse_safer_body(&p[..17]).is_none());
        let payload = build_data_payload(5, b"ab");
        let (conv, data) = parse_data_payload(&payload).unwrap();
        assert_eq!((conv, data), (5, &b"ab"[..]));
    }

    #[test]
    fn gro_wrap_unwrap_merged_burst() {
        for cm in [CipherMode::Aes128Cbc, CipherMode::Xor, CipherMode::None, CipherMode::Aes128Cfb, CipherMode::ChaCha20Poly1305] {
            let c = Crypto::new(cm, AuthMode::Md5, false, Keys::derive("k", true));
            let s = Crypto::new(cm, AuthMode::Md5, false, Keys::derive("k", false));
            let pkts: Vec<Vec<u8>> = (0..3)
                .map(|i| {
                    let plain = build_safer(&SaferHeader { my_id: 1, oppsite_id: 2, seq: i, ptype: b'h', roller: 0 }, &vec![i as u8; 30 + i as usize * 17]);
                    c.encrypt(&plain).unwrap()
                })
                .collect();
            let mut merged = Vec::new();
            for p in &pkts {
                merged.extend_from_slice(&gro_wrap(&c, p));
            }
            let parts = gro_unwrap(&s, &mut merged);
            assert_eq!(parts.len(), 3);
            for (i, (off, len)) in parts.iter().enumerate() {
                assert_eq!(&merged[*off..*off + *len], &pkts[i][..]);
                assert!(s.decrypt(&merged[*off..*off + *len]).is_some());
            }
        }
    }
}
