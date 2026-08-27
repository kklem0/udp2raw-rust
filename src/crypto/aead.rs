//! ChaCha20-Poly1305 AEAD cipher mode (`--cipher-mode chacha20poly1305`).
//!
//! A udp2raw-rust extension that the C++ implementation does not understand — both ends
//! must run this port. It is the fast, authenticated choice for CPUs without AES
//! instructions (Raspberry Pi 4: ChaCha20 runs on NEON, Poly1305 in 64-bit integer code).
//!
//! Wire format per packet: `[nonce 24][ciphertext][tag 16]` — XChaCha20-Poly1305 with a
//! fresh random 192-bit nonce per packet, so the whole payload is indistinguishable from
//! random bytes: no counter and no per-process constant on the wire for a pattern matcher
//! to key on (`--fix-gro` only masks the two length bytes in this mode). The udp2raw ids
//! and the anti-replay sequence number stay inside the plaintext as in every other mode;
//! `--auth-mode` is ignored because integrity comes from the AEAD tag. Keys are the
//! direction-specific HKDF outputs (`cipher_key_encrypt[..32]` to send,
//! `cipher_key_decrypt[..32]` to receive), like the hmac_sha1 mode.
//!
//! Nonces come from a per-thread ChaCha12 CSPRNG seeded from the OS and reseeded every
//! 2^24 nonces — no lock and no syscall per packet. With 192 random bits, a repeat under
//! one key needs of the order of 2^96 packets.

use crate::util::secure_random_bytes;
use chacha20::ChaCha12Rng;
use chacha20::rand_core::{Rng, SeedableRng};
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use std::cell::RefCell;

pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
/// Bytes added to a packet by this mode.
pub const OVERHEAD: usize = NONCE_LEN + TAG_LEN;
const RESEED_EVERY: u32 = 1 << 24;

thread_local! {
    static NONCE_RNG: RefCell<Option<(ChaCha12Rng, u32)>> = const { RefCell::new(None) };
}

fn seeded_rng() -> ChaCha12Rng {
    let mut seed = [0u8; 32];
    secure_random_bytes(&mut seed);
    ChaCha12Rng::from_seed(seed)
}

/// A fresh random nonce from this thread's CSPRNG.
pub fn random_nonce() -> [u8; NONCE_LEN] {
    NONCE_RNG.with(|cell| {
        let mut slot = cell.borrow_mut();
        let (rng, left) = slot.get_or_insert_with(|| (seeded_rng(), RESEED_EVERY));
        if *left == 0 {
            *rng = seeded_rng();
            *left = RESEED_EVERY;
        }
        *left -= 1;
        let mut n = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut n);
        n
    })
}

pub struct Aead {
    enc: XChaCha20Poly1305,
    dec: XChaCha20Poly1305,
}

impl Aead {
    /// `enc_key`/`dec_key`: at least 32 bytes each.
    pub fn new(enc_key: &[u8], dec_key: &[u8]) -> Aead {
        Aead {
            enc: XChaCha20Poly1305::new_from_slice(&enc_key[..32]).expect("xchacha20poly1305 key length"),
            dec: XChaCha20Poly1305::new_from_slice(&dec_key[..32]).expect("xchacha20poly1305 key length"),
        }
    }

    /// In place: the plaintext buffer becomes `nonce || ciphertext || tag`.
    pub fn encrypt_vec(&self, buf: Vec<u8>) -> Option<Vec<u8>> {
        self.encrypt_with_nonce(buf, random_nonce())
    }

    pub fn encrypt_with_nonce(&self, mut buf: Vec<u8>, nonce: [u8; NONCE_LEN]) -> Option<Vec<u8>> {
        self.enc.encrypt_in_place(&XNonce::from(nonce), b"", &mut buf).ok()?;
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
        self.dec.decrypt_in_place(&XNonce::from(nonce), b"", &mut buf).ok()?;
        Some(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{hex, unhex};
    use std::collections::HashSet;

    /// RFC 8439 §2.8.2 (ChaCha20-Poly1305 with its AAD): checks the underlying primitive.
    #[test]
    fn rfc8439_aead_vector() {
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};
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

    /// draft-irtf-cfrg-xchacha-03 §A.3.1 (XChaCha20-Poly1305 with its AAD): the variant on the wire.
    #[test]
    fn xchacha_draft_vector() {
        let key = unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
        let nonce: [u8; 24] = unhex("404142434445464748494a4b4c4d4e4f5051525354555657").unwrap().try_into().unwrap();
        let aad = unhex("50515253c0c1c2c3c4c5c6c7").unwrap();
        let mut buf = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".to_vec();
        let c = XChaCha20Poly1305::new_from_slice(&key).unwrap();
        c.encrypt_in_place(&XNonce::from(nonce), &aad, &mut buf).unwrap();
        assert_eq!(
            hex(&buf),
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52ec0875924c1c7987947deafd8780acf49"
        );
    }

    #[test]
    fn roundtrip_tamper_and_random_nonces() {
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
            let i = bad.len() / 2;
            bad[i] ^= 1;
            assert!(b.decrypt_vec(bad).is_none(), "tampered packet accepted");
            let mut bad_nonce = ct.clone();
            bad_nonce[0] ^= 1;
            assert!(b.decrypt_vec(bad_nonce).is_none(), "modified nonce accepted");
        }
        assert!(b.decrypt_vec(vec![0u8; OVERHEAD - 1]).is_none());
        // nonces: all distinct, no fixed prefix, and the same plaintext never encrypts the same way
        let nonces: Vec<[u8; NONCE_LEN]> = (0..4096).map(|_| random_nonce()).collect();
        assert_eq!(nonces.iter().collect::<HashSet<_>>().len(), nonces.len());
        assert!(nonces.iter().map(|n| n[..4].to_vec()).collect::<HashSet<_>>().len() > 4000);
        let c1 = a.encrypt_vec(vec![7u8; 100]).unwrap();
        let c2 = a.encrypt_vec(vec![7u8; 100]).unwrap();
        assert_ne!(c1, c2);
        // another thread has its own generator and does not repeat ours
        let mine: HashSet<[u8; NONCE_LEN]> = nonces.into_iter().collect();
        let theirs: Vec<[u8; NONCE_LEN]> = std::thread::spawn(|| (0..1024).map(|_| random_nonce()).collect()).join().unwrap();
        assert!(theirs.iter().all(|n| !mine.contains(n)));
    }
}
