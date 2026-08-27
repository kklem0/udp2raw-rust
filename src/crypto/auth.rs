//! Authentication (integrity) modes: none, md5, crc32, simple, hmac_sha1.
//!
//! Tag layouts match the C++ exactly: the tag is appended after the data.

use super::kdf::{md5, HmacSha1};
use crate::util::ct_eq;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthMode {
    None,
    Md5,
    Crc32,
    Simple,
    HmacSha1,
}

impl AuthMode {
    pub fn parse(s: &str) -> Option<AuthMode> {
        match s {
            "none" => Some(AuthMode::None),
            "md5" => Some(AuthMode::Md5),
            "crc32" => Some(AuthMode::Crc32),
            "simple" => Some(AuthMode::Simple),
            "hmac_sha1" => Some(AuthMode::HmacSha1),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            AuthMode::None => "none",
            AuthMode::Md5 => "md5",
            AuthMode::Crc32 => "crc32",
            AuthMode::Simple => "simple",
            AuthMode::HmacSha1 => "hmac_sha1",
        }
    }

    pub fn tag_len(self) -> usize {
        match self {
            AuthMode::None => 0,
            AuthMode::Md5 => 16,
            AuthMode::Crc32 => 4,
            AuthMode::Simple => 8,
            AuthMode::HmacSha1 => 20,
        }
    }
}

/// djb2-variant + sdbm, 8 bytes, both words big-endian — the C++ `simple_hash`.
pub fn simple_hash(data: &[u8]) -> [u8; 8] {
    let mut hash: u32 = 5381;
    let mut hash2: u32 = 0;
    for &b in data {
        let c = b as u32;
        hash = ((hash << 5).wrapping_add(hash)) ^ c;
        hash2 = c
            .wrapping_add(hash2 << 6)
            .wrapping_add(hash2 << 16)
            .wrapping_sub(hash2);
    }
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&hash.to_be_bytes());
    out[4..].copy_from_slice(&hash2.to_be_bytes());
    out
}

/// Per-direction authenticator: holds the precomputed HMAC key state.
#[derive(Clone)]
pub struct Authenticator {
    mode: AuthMode,
    hmac: Option<HmacSha1>,
}

impl Authenticator {
    /// `hmac_key` is the 64-byte HKDF output; like the C++ only its first 20 bytes are used.
    pub fn new(mode: AuthMode, hmac_key: &[u8]) -> Self {
        let hmac = if mode == AuthMode::HmacSha1 {
            Some(HmacSha1::new(&hmac_key[..20]))
        } else {
            None
        };
        Authenticator { mode, hmac }
    }

    pub fn mode(&self) -> AuthMode {
        self.mode
    }

    /// Append the tag of `buf[..]` to `buf`.
    pub fn append_tag(&self, buf: &mut Vec<u8>) {
        match self.mode {
            AuthMode::None => {}
            AuthMode::Md5 => {
                let t = md5(buf);
                buf.extend_from_slice(&t);
            }
            AuthMode::Crc32 => {
                let c = crc32fast::hash(buf);
                buf.extend_from_slice(&c.to_be_bytes());
            }
            AuthMode::Simple => {
                let t = simple_hash(buf);
                buf.extend_from_slice(&t);
            }
            AuthMode::HmacSha1 => {
                let t = self.hmac.as_ref().unwrap().mac(buf);
                buf.extend_from_slice(&t);
            }
        }
    }

    /// Verify the trailing tag of `data`; on success return the payload length.
    pub fn verify(&self, data: &[u8]) -> Option<usize> {
        let tl = self.mode.tag_len();
        if data.len() < tl {
            return None;
        }
        let body = &data[..data.len() - tl];
        let tag = &data[data.len() - tl..];
        let ok = match self.mode {
            AuthMode::None => true,
            AuthMode::Md5 => ct_eq(&md5(body), tag),
            AuthMode::Crc32 => ct_eq(&crc32fast::hash(body).to_be_bytes(), tag),
            AuthMode::Simple => ct_eq(&simple_hash(body), tag),
            AuthMode::HmacSha1 => ct_eq(&self.hmac.as_ref().unwrap().mac(body), tag),
        };
        if ok {
            Some(body.len())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_roundtrip_all_modes() {
        for mode in [
            AuthMode::None,
            AuthMode::Md5,
            AuthMode::Crc32,
            AuthMode::Simple,
            AuthMode::HmacSha1,
        ] {
            let a = Authenticator::new(mode, &[7u8; 64]);
            let mut buf = b"hello world".to_vec();
            a.append_tag(&mut buf);
            assert_eq!(buf.len(), 11 + mode.tag_len());
            assert_eq!(a.verify(&buf), Some(11));
            if mode != AuthMode::None {
                buf[3] ^= 1;
                assert_eq!(a.verify(&buf), None);
            }
            assert_eq!(a.verify(&buf[..mode.tag_len().saturating_sub(1)]), if mode == AuthMode::None { Some(0) } else { None });
        }
    }

    #[test]
    fn crc32_is_ieee() {
        // "123456789" -> cbf43926 (standard CRC-32)
        assert_eq!(crc32fast::hash(b"123456789"), 0xcbf43926);
    }
}
