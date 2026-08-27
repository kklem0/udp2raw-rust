//! Internet checksum (RFC 1071), computed over big-endian 16-bit words so the result can
//! be written straight into a header with `to_be_bytes`.

#[inline]
fn sum_words(mut acc: u32, data: &[u8]) -> u32 {
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        acc += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        acc += (*last as u32) << 8;
    }
    acc
}

#[inline]
fn fold(mut acc: u32) -> u16 {
    acc = (acc >> 16) + (acc & 0xffff);
    acc += acc >> 16;
    !(acc as u16)
}

/// Checksum of `data` alone (IPv4 header, ICMPv4).
pub fn csum(data: &[u8]) -> u16 {
    fold(sum_words(0, data))
}

/// Checksum of a pseudo header followed by `data` (TCP/UDP/ICMPv6). `pseudo.len()` must be even.
pub fn csum_with_pseudo(pseudo: &[u8], data: &[u8]) -> u16 {
    debug_assert!(pseudo.len() % 2 == 0);
    fold(sum_words(sum_words(0, pseudo), data))
}

/// Verify: a correct header checksums to zero.
pub fn verify(data: &[u8]) -> bool {
    csum(data) == 0
}

pub fn verify_with_pseudo(pseudo: &[u8], data: &[u8]) -> bool {
    csum_with_pseudo(pseudo, data) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc1071_example() {
        // Classic IPv4 header example (Wikipedia): checksum b861
        let hdr: [u8; 20] = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00,
            0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert_eq!(csum(&hdr), 0xb861);
        let mut with = hdr;
        with[10..12].copy_from_slice(&0xb861u16.to_be_bytes());
        assert!(verify(&with));
    }

    #[test]
    fn odd_length_and_cpp_unit_test_values() {
        // matches the C++ unit_test(): csum({1,2,3,4,5}) and csum({1})
        let a = csum(&[1, 2, 3, 4, 5]);
        let b = csum(&[1]);
        // The C++ returns host-order shorts 0xf9f6 and 0xfffe on little-endian; written to
        // memory those are the wire bytes f6 f9 and fe ff, i.e. what we compute directly.
        assert_eq!(a, 0xf6f9);
        assert_eq!(b, 0xfeff);
    }
}
