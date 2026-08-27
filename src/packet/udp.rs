//! Raw UDP mode datagram build/parse.

use super::checksum;
use super::ip::{pseudo_header, IPPROTO_UDP};
use std::net::IpAddr;

pub const UDP_HEADER_LEN: usize = 8;

pub fn build_udp(out: &mut Vec<u8>, src: IpAddr, dst: IpAddr, src_port: u16, dst_port: u16, payload: &[u8]) -> Option<usize> {
    let tot = UDP_HEADER_LEN + payload.len();
    if tot > 65535 {
        return None;
    }
    let start = out.len();
    out.resize(start + UDP_HEADER_LEN, 0);
    out[start..start + 2].copy_from_slice(&src_port.to_be_bytes());
    out[start + 2..start + 4].copy_from_slice(&dst_port.to_be_bytes());
    out[start + 4..start + 6].copy_from_slice(&(tot as u16).to_be_bytes());
    out.extend_from_slice(payload);
    let pseudo = pseudo_header(src, dst, IPPROTO_UDP, tot);
    let c = checksum::csum_with_pseudo(&pseudo, &out[start..]);
    out[start + 6..start + 8].copy_from_slice(&c.to_be_bytes());
    Some(tot)
}

/// Returns (src_port, dst_port, payload). Length and checksum are enforced like the C++.
pub fn parse_udp(seg: &[u8], src: IpAddr, dst: IpAddr) -> Option<(u16, u16, &[u8])> {
    if seg.len() < UDP_HEADER_LEN {
        log::debug!("too short to hold udpheader");
        return None;
    }
    let len = u16::from_be_bytes([seg[4], seg[5]]) as usize;
    if len != seg.len() {
        log::debug!("udp length error {} {}", len, seg.len());
        return None;
    }
    let pseudo = pseudo_header(src, dst, IPPROTO_UDP, seg.len());
    if !checksum::verify_with_pseudo(&pseudo, seg) {
        log::debug!("udp header error");
        return None;
    }
    Some((u16::from_be_bytes([seg[0], seg[1]]), u16::from_be_bytes([seg[2], seg[3]]), &seg[UDP_HEADER_LEN..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let s: IpAddr = "10.1.1.1".parse().unwrap();
        let d: IpAddr = "10.1.1.2".parse().unwrap();
        let mut v = Vec::new();
        assert_eq!(build_udp(&mut v, s, d, 1000, 2000, b"abc"), Some(11));
        let (sp, dp, payload) = parse_udp(&v, s, d).unwrap();
        assert_eq!((sp, dp, payload), (1000, 2000, &b"abc"[..]));
        v[9] ^= 1;
        assert!(parse_udp(&v, s, d).is_none());
    }
}
