//! Raw ICMP mode: the client sends echo requests, the server sends echo replies. The
//! ICMP `id` carries the tunnel "port" and `seq` the ICMP sequence counter.

use super::checksum;
use super::ip::{pseudo_header, IPPROTO_ICMPV6};
use std::net::IpAddr;

pub const ICMP_HEADER_LEN: usize = 8;

pub fn echo_type(is_v6: bool, is_client: bool) -> u8 {
    match (is_v6, is_client) {
        (false, true) => 8,
        (false, false) => 0,
        (true, true) => 128,
        (true, false) => 129,
    }
}

pub fn build_icmp(out: &mut Vec<u8>, src: IpAddr, dst: IpAddr, is_client: bool, id: u16, seq: u16, payload: &[u8]) -> usize {
    let is_v6 = src.is_ipv6();
    let start = out.len();
    out.resize(start + ICMP_HEADER_LEN, 0);
    out[start] = echo_type(is_v6, is_client);
    out[start + 1] = 0;
    out[start + 4..start + 6].copy_from_slice(&id.to_be_bytes());
    out[start + 6..start + 8].copy_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(payload);
    let tot = ICMP_HEADER_LEN + payload.len();
    let c = if is_v6 {
        let pseudo = pseudo_header(src, dst, IPPROTO_ICMPV6, tot);
        checksum::csum_with_pseudo(&pseudo, &out[start..])
    } else {
        checksum::csum(&out[start..])
    };
    out[start + 2..start + 4].copy_from_slice(&c.to_be_bytes());
    tot
}

#[derive(Clone, Copy, Debug)]
pub struct ParsedIcmp {
    pub ptype: u8,
    pub id: u16,
    pub seq: u16,
}

/// Parse and validate an echo packet from the peer (`is_client` = our role).
pub fn parse_icmp(seg: &[u8], src: IpAddr, dst: IpAddr, is_client: bool) -> Option<(ParsedIcmp, &[u8])> {
    if seg.len() < ICMP_HEADER_LEN {
        log::debug!("too short to hold icmp header");
        return None;
    }
    let is_v6 = src.is_ipv6();
    let ptype = seg[0];
    if seg[1] != 0 {
        return None;
    }
    // we expect the peer's type: client receives replies, server receives requests
    if ptype != echo_type(is_v6, !is_client) {
        return None;
    }
    let ok = if is_v6 {
        let pseudo = pseudo_header(src, dst, IPPROTO_ICMPV6, seg.len());
        checksum::verify_with_pseudo(&pseudo, seg)
    } else {
        checksum::verify(seg)
    };
    if !ok {
        log::debug!("icmp checksum fail");
        return None;
    }
    Some((
        ParsedIcmp { ptype, id: u16::from_be_bytes([seg[4], seg[5]]), seq: u16::from_be_bytes([seg[6], seg[7]]) },
        &seg[ICMP_HEADER_LEN..],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_roundtrip_client_to_server() {
        let s: IpAddr = "10.0.0.1".parse().unwrap();
        let d: IpAddr = "10.0.0.2".parse().unwrap();
        let mut v = Vec::new();
        build_icmp(&mut v, s, d, true, 4321, 9, b"payload");
        assert_eq!(v[0], 8);
        let (p, payload) = parse_icmp(&v, s, d, false).unwrap();
        assert_eq!((p.id, p.seq, payload), (4321, 9, &b"payload"[..]));
        // a client must not accept its own request type
        assert!(parse_icmp(&v, s, d, true).is_none());
    }

    #[test]
    fn v6_roundtrip_server_to_client() {
        let s: IpAddr = "2001:db8::1".parse().unwrap();
        let d: IpAddr = "2001:db8::2".parse().unwrap();
        let mut v = Vec::new();
        build_icmp(&mut v, s, d, false, 7, 8, b"x");
        assert_eq!(v[0], 129);
        let (p, payload) = parse_icmp(&v, s, d, true).unwrap();
        assert_eq!((p.id, p.seq, payload), (7, 8, &b"x"[..]));
        v[8] ^= 1;
        assert!(parse_icmp(&v, s, d, true).is_none());
    }
}
