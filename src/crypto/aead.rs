//! ChaCha20-Poly1305 AEAD cipher mode (`--cipher-mode chacha20poly1305`).
//!
//! A udp2raw-rust extension that the C++ implementation does not understand — both ends
//! must run this port. It is the fast, authenticated choice for CPUs without AES
//! instructions (Raspberry Pi 4: ChaCha20 runs on NEON, Poly1305 in 64-bit integer code).
//!
//! Wire format per packet: `[nonce 12][ciphertext][tag 16]`. The udp2raw ids and the
//! anti-replay sequence number stay inside the plaintext as in every other mode;
//! `--auth-mode` is ignored because integrity comes from the AEAD tag. Keys are the
//! direction-specific HKDF outputs (`cipher_key_encrypt[..32]` to send,
//! `cipher_key_decrypt[..32]` to receive), like the hmac_sha1 mode.
//!
//! Nonces: `[random 32 bits per process][64-bit counter starting at a random value]`. They
//! never repeat within a process; across restarts (the keys are static, derived from the
//! password) a repeat needs both the 32-bit prefix and the 64-bit counter position to
//! coincide.

use crate::util::{secure_random_u32, secure_random_u64};
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use std::sync::atomic::{AtomicU64, Ordering};

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
/// Bytes added to a packet by this mode.
pub const OVERHEAD: usize = NONCE_LEN + TAG_LEN;

pub struct Aead {
    enc: ChaCha20Poly1305,
    dec: ChaCha20Poly1305,
    prefix: u32,
    counter: AtomicU64,
}

impl Aead {
    /// `enc_key`/`dec_key`: at least 32 bytes each.
    pub fn new(enc_key: &[u8], dec_key: &[u8]) -> Aead {
        Aead {
            enc: ChaCha20Poly1305::new_from_slice(&enc_key[..32]).expect("chacha20poly1305 key length"),
            dec: ChaCha20Poly1305::new_from_slice(&dec_key[..32]).expect("chacha20poly1305 key length"),
            prefix: secure_random_u32(),
            counter: AtomicU64::new(secure_random_u64()),
        }
    }

    fn next_nonce(&self) -> [u8; NONCE_LEN] {
        let c = self.counter.fetch_add(1, Ordering::Relaxed);
        let mut n = [0u8; NONCE_LEN];
        n[..4].copy_from_slice(&self.prefix.to_be_bytes());
        n[4..].copy_from_slice(&c.to_be_bytes());
        n
    }

    /// In place: the plaintext buffer becomes `nonce || ciphertext || tag`.
    pub fn encrypt_vec(&self, buf: Vec<u8>) -> Option<Vec<u8>> {
        self.encrypt_with_nonce(buf, self.next_nonce())
    }

    pub fn encrypt_with_nonce(&self, mut buf: Vec<u8>, nonce: [u8; NONCE_LEN]) -> Option<Vec<u8>> {
        self.enc.encrypt_in_place(&Nonce::from(nonce), b"", &mut buf).ok()?;
        buf.splice(0..0, nonce);
        Some(buf)
    }

    /// In place: `nonce || ciphertext || tag` becomes the plaintext, or `None` if the tag
    /// does not verify.
    pub fn decrypt_vec(&self, mut buf: Vec<u8>) -> Option<Vec<u8>> {
        if buf.len() < OVERHEAD {
            return None;
        }
        let nonce: [u8; NONCE_LEN] = buf[..NONCE_LEN].try_into().unwrap();
        buf.drain(..NONCE_LEN);
        self.dec.decrypt_in_place(&Nonce::from(nonce), b"", &mut buf).ok()?;
        Some(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{hex, unhex};

    /// RFC 8439 §2.8.2 (with its AAD, through the same crate calls we use).
    #[test]
    fn rfc8439_aead_vector() {
        let key = unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
        let nonce: [u8; 12] = unhex("070000004041424344454647").unwrap().try_into().unwrap();
        let aad = unhex("50515253c0c1c2c3c4c5c6c7").unwrap();
        let mut buf = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".to_vec();
        let c = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        c.encrypt_in_place(&Nonce::from(nonce), &aad, &mut buf).unwrap();
        assert_eq!(
            hex(&buf),
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691"
        );
    }

    #[test]
    fn roundtrip_tamper_and_unique_nonces() {
        let k1 = [1u8; 64];
        let k2 = [2u8; 64];
        let a = Aead::new(&k1, &k2); // sends with k1, receives with k2
        let b = Aead::new(&k2, &k1); // the peer
        for len in [0usize, 1, 15, 16, 17, 100, 1400, 1800 - OVERHEAD] {
            let msg: Vec<u8> = (0..len).map(|i| (i * 13) as u8).collect();
            let ct = a.encrypt_vec(msg.clone()).unwrap();
            assert_eq!(ct.len(), len + OVERHEAD);
            assert_eq!(b.decrypt_vec(ct.clone()).unwrap(), msg);
            assert!(a.decrypt_vec(ct.clone()).is_none(), "wrong direction key accepted");
            let mut bad = ct.clone();
            if !bad.is_empty() {
                let i = bad.len() / 2;
                bad[i] ^= 1;
                assert!(b.decrypt_vec(bad).is_none(), "tampered packet accepted");
            }
        }
        assert!(b.decrypt_vec(vec![0u8; OVERHEAD - 1]).is_none());
        let n1 = a.next_nonce();
        let n2 = a.next_nonce();
        assert_ne!(n1, n2);
        assert_eq!(n1[..4], n2[..4]);
    }
}
