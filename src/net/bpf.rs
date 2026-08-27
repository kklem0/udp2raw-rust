//! Classic BPF programs attached to the AF_PACKET receive socket, copied verbatim from
//! `network.cpp`. They see the IP packet (SOCK_DGRAM strips the link header) and accept
//! only the tunnel's protocol / destination port.

use crate::types::RawMode;

#[derive(Clone, Copy)]
pub struct Insn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

const fn i(code: u16, jt: u8, jf: u8, k: u32) -> Insn {
    Insn { code, jt, jf, k }
}

/// ip and tcp and dst port <k at index 6>
const TCP4: [Insn; 9] = [
    i(0x30, 0, 0, 0x00000009),
    i(0x15, 0, 6, 0x00000006),
    i(0x28, 0, 0, 0x00000006),
    i(0x45, 4, 0, 0x00001fff),
    i(0xb1, 0, 0, 0x00000000),
    i(0x48, 0, 0, 0x00000002),
    i(0x15, 0, 1, 0x0000fffe),
    i(0x6, 0, 0, 0x0000ffff),
    i(0x6, 0, 0, 0x00000000),
];
const TCP4_PORT_INDEX: usize = 6;

/// ip6 and tcp and dst port <k at index 3> (no extension-header support, like the C++)
const TCP6: [Insn; 6] = [
    i(0x30, 0, 0, 0x00000006),
    i(0x15, 0, 3, 0x00000006),
    i(0x28, 0, 0, 0x0000002a),
    i(0x15, 0, 1, 0x0000fffe),
    i(0x6, 0, 0, 0x00040000),
    i(0x6, 0, 0, 0x00000000),
];
const TCP6_PORT_INDEX: usize = 3;

const UDP4: [Insn; 9] = [
    i(0x30, 0, 0, 0x00000009),
    i(0x15, 0, 6, 0x00000011),
    i(0x28, 0, 0, 0x00000006),
    i(0x45, 4, 0, 0x00001fff),
    i(0xb1, 0, 0, 0x00000000),
    i(0x48, 0, 0, 0x00000002),
    i(0x15, 0, 1, 0x0000fffe),
    i(0x6, 0, 0, 0x0000ffff),
    i(0x6, 0, 0, 0x00000000),
];
const UDP4_PORT_INDEX: usize = 6;

const UDP6: [Insn; 6] = [
    i(0x30, 0, 0, 0x00000006),
    i(0x15, 0, 3, 0x00000011),
    i(0x28, 0, 0, 0x0000002a),
    i(0x15, 0, 1, 0x0000fffe),
    i(0x6, 0, 0, 0x00040000),
    i(0x6, 0, 0, 0x00000000),
];
const UDP6_PORT_INDEX: usize = 3;

const ICMP4: [Insn; 4] = [
    i(0x30, 0, 0, 0x00000009),
    i(0x15, 0, 1, 0x00000001),
    i(0x6, 0, 0, 0x0000ffff),
    i(0x6, 0, 0, 0x00000000),
];

const ICMP6: [Insn; 7] = [
    i(0x30, 0, 0, 0x00000006),
    i(0x15, 3, 0, 0x0000003a),
    i(0x15, 0, 3, 0x0000002c),
    i(0x30, 0, 0, 0x00000028),
    i(0x15, 0, 1, 0x0000003a),
    i(0x6, 0, 0, 0x00040000),
    i(0x6, 0, 0, 0x00000000),
];

/// Build the filter program for the given mode/family/port.
pub fn program(raw_mode: RawMode, is_v6: bool, port: u16) -> Vec<Insn> {
    let (base, port_index): (&[Insn], Option<usize>) = match (raw_mode, is_v6) {
        (RawMode::FakeTcp, false) => (&TCP4, Some(TCP4_PORT_INDEX)),
        (RawMode::FakeTcp, true) => (&TCP6, Some(TCP6_PORT_INDEX)),
        (RawMode::Udp, false) => (&UDP4, Some(UDP4_PORT_INDEX)),
        (RawMode::Udp, true) => (&UDP6, Some(UDP6_PORT_INDEX)),
        (RawMode::Icmp, false) => (&ICMP4, None),
        (RawMode::Icmp, true) => (&ICMP6, None),
    };
    let mut v = base.to_vec();
    if let Some(idx) = port_index {
        v[idx].k = port as u32;
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_is_patched() {
        let p = program(RawMode::FakeTcp, false, 4096);
        assert_eq!(p[6].k, 4096);
        assert_eq!(p.len(), 9);
        let p = program(RawMode::Udp, true, 1);
        assert_eq!(p[3].k, 1);
        assert_eq!(program(RawMode::Icmp, false, 9).len(), 4);
    }
}
