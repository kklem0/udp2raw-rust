//! IPv4 / IPv6 header build and parse.

use super::checksum;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const IPV4_HEADER_LEN: usize = 20;
pub const IPV6_HEADER_LEN: usize = 40;

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_ICMPV6: u8 = 58;

/// Append an IP header for `payload_len` bytes of `protocol` to `out`.
/// The IPv4 checksum and total length are always filled in (the kernel overwrites them
/// for `IPPROTO_RAW` sockets anyway; `--lower-level` sends need them).
pub fn build_ip_header(out: &mut Vec<u8>, src: IpAddr, dst: IpAddr, protocol: u8, ttl: u8, id: u16, payload_len: usize) {
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let start = out.len();
            out.resize(start + IPV4_HEADER_LEN, 0);
            let h = &mut out[start..];
            h[0] = 0x45;
            h[1] = 0;
            let tot = (IPV4_HEADER_LEN + payload_len) as u16;
            h[2..4].copy_from_slice(&tot.to_be_bytes());
            h[4..6].copy_from_slice(&id.to_be_bytes());
            h[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
            h[8] = ttl;
            h[9] = protocol;
            h[10] = 0;
            h[11] = 0;
            h[12..16].copy_from_slice(&s.octets());
            h[16..20].copy_from_slice(&d.octets());
            let c = checksum::csum(&h[..IPV4_HEADER_LEN]);
            h[10..12].copy_from_slice(&c.to_be_bytes());
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let start = out.len();
            out.resize(start + IPV6_HEADER_LEN, 0);
            let h = &mut out[start..];
            h[0] = 0x60;
            h[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
            h[6] = protocol;
            h[7] = ttl;
            h[8..24].copy_from_slice(&s.octets());
            h[24..40].copy_from_slice(&d.octets());
        }
        _ => panic!("mixed address families"),
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ParsedIp {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub protocol: u8,
    pub header_len: usize,
    /// End of the IP packet inside the buffer (tot_len / payload_len bounded).
    pub total_len: usize,
}

impl ParsedIp {
    pub fn payload<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        &buf[self.header_len..self.total_len]
    }
}

/// Parse an IP header of the expected version. `verify_csum` mirrors the C++ which
/// validates the IPv4 header checksum only on the non-peek pass.
pub fn parse_ip(buf: &[u8], want_v6: bool, verify_csum: bool) -> Option<ParsedIp> {
    if buf.is_empty() {
        return None;
    }
    let version = buf[0] >> 4;
    if !want_v6 {
        if version != 4 {
            log::trace!("expect ipv4 packet, but got version {version}");
            return None;
        }
        if buf.len() < IPV4_HEADER_LEN {
            return None;
        }
        let ihl = ((buf[0] & 0x0f) as usize) * 4;
        if ihl < IPV4_HEADER_LEN || ihl > buf.len() {
            return None;
        }
        let tot_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        if buf.len() < tot_len || tot_len < ihl {
            log::debug!("incomplete packet");
            return None;
        }
        if verify_csum && !checksum::verify(&buf[..ihl]) {
            log::debug!("ip header checksum error");
            return None;
        }
        Some(ParsedIp {
            src: IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&buf[12..16]).unwrap())),
            dst: IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&buf[16..20]).unwrap())),
            protocol: buf[9],
            header_len: ihl,
            total_len: tot_len,
        })
    } else {
        if version != 6 {
            log::trace!("expect ipv6 packet, but got version {version}");
            return None;
        }
        if buf.len() < IPV6_HEADER_LEN {
            return None;
        }
        let payload_len = u16::from_be_bytes([buf[4], buf[5]]) as usize;
        let tot = IPV6_HEADER_LEN + payload_len;
        if buf.len() < tot {
            log::debug!("incomplete packet");
            return None;
        }
        Some(ParsedIp {
            src: IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&buf[8..24]).unwrap())),
            dst: IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&buf[24..40]).unwrap())),
            protocol: buf[6], // extension headers are not supported (same as the C++)
            header_len: IPV6_HEADER_LEN,
            total_len: tot,
        })
    }
}

/// Pseudo header for transport checksums.
pub fn pseudo_header(src: IpAddr, dst: IpAddr, protocol: u8, transport_len: usize) -> Vec<u8> {
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let mut p = Vec::with_capacity(12);
            p.extend_from_slice(&s.octets());
            p.extend_from_slice(&d.octets());
            p.push(0);
            p.push(protocol);
            p.extend_from_slice(&(transport_len as u16).to_be_bytes());
            p
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            // Same layout as the C++ pseudo_header6 struct: src, dst, u32 length, 3 zero bytes, next header.
            let mut p = Vec::with_capacity(40);
            p.extend_from_slice(&s.octets());
            p.extend_from_slice(&d.octets());
            // The C++ stores htons(len) into a u32 field: on little-endian that puts the
            // big-endian u16 in the first two bytes and zeros after; reproduce that byte layout.
            let be = (transport_len as u16).to_be_bytes();
            p.extend_from_slice(&[be[0], be[1], 0, 0]);
            p.extend_from_slice(&[0, 0, 0]);
            p.push(protocol);
            p
        }
        _ => panic!("mixed address families"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_build_parse_roundtrip() {
        let mut v = Vec::new();
        build_ip_header(&mut v, "10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap(), IPPROTO_TCP, 64, 0x1234, 8);
        v.extend_from_slice(&[0u8; 8]);
        let p = parse_ip(&v, false, true).unwrap();
        assert_eq!(p.src, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(p.dst, "10.0.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(p.protocol, IPPROTO_TCP);
        assert_eq!(p.header_len, 20);
        assert_eq!(p.total_len, 28);
        assert_eq!(p.payload(&v).len(), 8);
        assert_eq!(&v[6..8], &[0x40, 0x00]);
        // corrupt checksum
        v[10] ^= 1;
        assert!(parse_ip(&v, false, true).is_none());
        assert!(parse_ip(&v, false, false).is_some());
    }

    #[test]
    fn v6_build_parse_roundtrip() {
        let mut v = Vec::new();
        build_ip_header(&mut v, "fe80::1".parse().unwrap(), "fe80::2".parse().unwrap(), IPPROTO_UDP, 64, 0, 3);
        v.extend_from_slice(&[1, 2, 3]);
        let p = parse_ip(&v, true, true).unwrap();
        assert_eq!(p.src, "fe80::1".parse::<IpAddr>().unwrap());
        assert_eq!(p.protocol, IPPROTO_UDP);
        assert_eq!(p.payload(&v), &[1, 2, 3]);
        assert!(parse_ip(&v, false, true).is_none());
    }

    #[test]
    fn pseudo_header_layouts() {
        let p4 = pseudo_header("1.2.3.4".parse().unwrap(), "5.6.7.8".parse().unwrap(), IPPROTO_TCP, 0x1234);
        assert_eq!(p4, vec![1, 2, 3, 4, 5, 6, 7, 8, 0, 6, 0x12, 0x34]);
        let p6 = pseudo_header("::1".parse().unwrap(), "::2".parse().unwrap(), IPPROTO_TCP, 0x1234);
        assert_eq!(p6.len(), 40);
        assert_eq!(&p6[32..], &[0x12, 0x34, 0, 0, 0, 0, 0, 6]);
    }
}
