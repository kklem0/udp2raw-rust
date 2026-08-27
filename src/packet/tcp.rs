//! FakeTCP segment build/parse — byte-identical option layout to `send_raw_tcp`.

use super::checksum;
use super::ip::{pseudo_header, IPPROTO_TCP};
use crate::consts::{SYN_MSS, WSCALE};
use crate::util::read_u32_be;
use std::net::IpAddr;

pub const TCP_MIN_HEADER: usize = 20;

#[derive(Clone, Copy, Debug, Default)]
pub struct TcpSendParams {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack_seq: u32,
    pub syn: bool,
    pub ack: bool,
    pub psh: bool,
    pub window: u16,
    pub ts: u32,
    pub ts_ack: u32,
}

/// Append a TCP header (+options) and `payload` to `out`, returning the segment length.
/// SYN segments carry MSS, SACK-permitted, timestamps and window scale (doff=10);
/// everything else carries NOP NOP timestamps (doff=8).
pub fn build_tcp(out: &mut Vec<u8>, src: IpAddr, dst: IpAddr, p: &TcpSendParams, payload: &[u8]) -> usize {
    let start = out.len();
    let doff: usize = if p.syn { 10 } else { 8 };
    let hlen = doff * 4;
    out.resize(start + hlen, 0);
    {
        let h = &mut out[start..];
        h[0..2].copy_from_slice(&p.src_port.to_be_bytes());
        h[2..4].copy_from_slice(&p.dst_port.to_be_bytes());
        h[4..8].copy_from_slice(&p.seq.to_be_bytes());
        h[8..12].copy_from_slice(&p.ack_seq.to_be_bytes());
        h[12] = (doff as u8) << 4;
        let mut flags = 0u8;
        if p.syn {
            flags |= 0x02;
        }
        if p.psh {
            flags |= 0x08;
        }
        if p.ack {
            flags |= 0x10;
        }
        h[13] = flags;
        h[14..16].copy_from_slice(&p.window.to_be_bytes());
        h[16] = 0;
        h[17] = 0; // checksum, filled below
        h[18] = 0;
        h[19] = 0;
        let mut i = TCP_MIN_HEADER;
        if p.syn {
            h[i] = 0x02; // MSS
            h[i + 1] = 0x04;
            h[i + 2..i + 4].copy_from_slice(&SYN_MSS.to_be_bytes());
            i += 4;
            h[i] = 0x04; // SACK permitted
            h[i + 1] = 0x02;
            i += 2;
            h[i] = 0x08; // timestamps
            h[i + 1] = 0x0a;
            h[i + 2..i + 6].copy_from_slice(&p.ts.to_be_bytes());
            h[i + 6..i + 10].copy_from_slice(&p.ts_ack.to_be_bytes());
            i += 10;
            h[i] = 0x01; // NOP
            h[i + 1] = 0x03; // window scale
            h[i + 2] = 0x03;
            h[i + 3] = WSCALE;
        } else {
            h[i] = 0x01;
            h[i + 1] = 0x01;
            h[i + 2] = 0x08;
            h[i + 3] = 0x0a;
            h[i + 4..i + 8].copy_from_slice(&p.ts.to_be_bytes());
            h[i + 8..i + 12].copy_from_slice(&p.ts_ack.to_be_bytes());
        }
    }
    out.extend_from_slice(payload);
    let seg_len = hlen + payload.len();
    let pseudo = pseudo_header(src, dst, IPPROTO_TCP, seg_len);
    let c = checksum::csum_with_pseudo(&pseudo, &out[start..]);
    out[start + 16..start + 18].copy_from_slice(&c.to_be_bytes());
    seg_len
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ParsedTcp {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack_seq: u32,
    pub syn: bool,
    pub ack: bool,
    pub psh: bool,
    pub rst: bool,
    pub has_ts: bool,
    pub ts: u32,
    pub ts_ack: u32,
    pub header_len: usize,
    /// True if the checksum verified (the C++ only logs a failure for TCP, it does not drop).
    pub csum_ok: bool,
}

/// Parse the TCP options between `opt` slice bounds; mirrors `parse_tcp_option`.
fn parse_options(opt: &[u8], out: &mut ParsedTcp) {
    out.has_ts = false;
    out.ts = 0;
    let mut i = 0usize;
    while i < opt.len() {
        match opt[i] {
            0 => return,
            1 => i += 1,
            8 => {
                if i + 1 >= opt.len() || opt[i + 1] != 10 || i + 10 > opt.len() {
                    return;
                }
                out.has_ts = true;
                out.ts = read_u32_be(&opt[i + 2..]);
                out.ts_ack = read_u32_be(&opt[i + 6..]);
                i += 10;
            }
            _ => {
                if i + 1 >= opt.len() {
                    return;
                }
                let len = opt[i + 1] as usize;
                if len <= 1 {
                    return;
                }
                i += len;
            }
        }
    }
}

/// Parse a TCP segment (`seg` = IP payload). Returns the header info and the payload.
pub fn parse_tcp(seg: &[u8], src: IpAddr, dst: IpAddr) -> Option<(ParsedTcp, &[u8])> {
    if seg.len() < TCP_MIN_HEADER {
        return None;
    }
    let hlen = ((seg[12] >> 4) as usize) * 4;
    if hlen == 0 || hlen > 60 || hlen > seg.len() {
        log::debug!("tcph error");
        return None;
    }
    let pseudo = pseudo_header(src, dst, IPPROTO_TCP, seg.len());
    let csum_ok = checksum::verify_with_pseudo(&pseudo, seg);
    let flags = seg[13];
    let mut t = ParsedTcp {
        src_port: u16::from_be_bytes([seg[0], seg[1]]),
        dst_port: u16::from_be_bytes([seg[2], seg[3]]),
        seq: read_u32_be(&seg[4..]),
        ack_seq: read_u32_be(&seg[8..]),
        syn: flags & 0x02 != 0,
        ack: flags & 0x10 != 0,
        psh: flags & 0x08 != 0,
        rst: flags & 0x04 != 0,
        header_len: hlen,
        csum_ok,
        ..Default::default()
    };
    parse_options(&seg[TCP_MIN_HEADER..hlen], &mut t);
    Some((t, &seg[hlen..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addrs() -> (IpAddr, IpAddr) {
        ("192.168.1.10".parse().unwrap(), "203.0.113.5".parse().unwrap())
    }

    #[test]
    fn syn_layout() {
        let (s, d) = addrs();
        let mut v = Vec::new();
        let p = TcpSendParams { src_port: 1234, dst_port: 443, seq: 1, ack_seq: 2, syn: true, ack: false, psh: false, window: 40960, ts: 0x11223344, ts_ack: 0 };
        let n = build_tcp(&mut v, s, d, &p, &[]);
        assert_eq!(n, 40);
        assert_eq!(v[12] >> 4, 10);
        assert_eq!(v[13], 0x02);
        assert_eq!(&v[20..24], &[0x02, 0x04, 0x05, 0xb4]);
        assert_eq!(&v[24..26], &[0x04, 0x02]);
        assert_eq!(&v[26..28], &[0x08, 0x0a]);
        assert_eq!(&v[28..32], &[0x11, 0x22, 0x33, 0x44]);
        assert_eq!(&v[36..40], &[0x01, 0x03, 0x03, WSCALE]);
        let (t, payload) = parse_tcp(&v, s, d).unwrap();
        assert!(t.csum_ok);
        assert!(t.syn && !t.ack);
        assert!(t.has_ts);
        assert_eq!(t.ts, 0x11223344);
        assert_eq!(payload.len(), 0);
    }

    #[test]
    fn data_layout_and_checksum() {
        let (s, d) = addrs();
        let mut v = Vec::new();
        let p = TcpSendParams { src_port: 5, dst_port: 6, seq: 100, ack_seq: 200, syn: false, ack: true, psh: true, window: 41000, ts: 7, ts_ack: 8 };
        let n = build_tcp(&mut v, s, d, &p, b"hello");
        assert_eq!(n, 32 + 5);
        assert_eq!(v[12] >> 4, 8);
        assert_eq!(v[13], 0x18);
        assert_eq!(&v[20..24], &[1, 1, 8, 10]);
        let (t, payload) = parse_tcp(&v, s, d).unwrap();
        assert!(t.csum_ok);
        assert_eq!(payload, b"hello");
        assert_eq!((t.seq, t.ack_seq, t.ts, t.ts_ack), (100, 200, 7, 8));
        assert!(t.ack && t.psh && !t.syn && !t.rst);
        v[30] ^= 0xff; // corrupt payload
        let (t2, _) = parse_tcp(&v, s, d).unwrap();
        assert!(!t2.csum_ok);
    }

    #[test]
    fn options_parser_handles_unknown_and_end() {
        let mut t = ParsedTcp::default();
        // unknown option kind 3 len 3, then NOP, then timestamps, then EOL
        let opt = [3u8, 3, 9, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0];
        parse_options(&opt, &mut t);
        assert!(t.has_ts);
        assert_eq!((t.ts, t.ts_ack), (1, 2));
        let mut t = ParsedTcp::default();
        parse_options(&[8, 9, 0], &mut t); // bad ts length
        assert!(!t.has_ts);
    }
}
