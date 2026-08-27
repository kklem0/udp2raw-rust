//! Cipher modes: none, xor, aes128cbc, aes128cfb — byte-compatible with the C++.
//!
//! * All AES modes use a zero IV; uniqueness comes from the random/nonce first block of
//!   every packet (handshake nonce, or the per-packet anti-replay sequence number).
//! * `aes128cbc` pads like the C++ `padding()`: at least one byte, up to a multiple of 16,
//!   the last byte holds the pad length (other pad bytes are zero here; the C++ leaves
//!   them uninitialised, and the receiver never reads them).
//! * `aes128cfb` first ECB-encrypts block 0 with the HKDF-derived `cipher_key_encrypt`
//!   (unless the legacy `aes128cfb_0` variant is selected), then runs CFB-128.

use aes::cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes::Aes128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherMode {
    None,
    Xor,
    Aes128Cbc,
    Aes128Cfb,
}

impl CipherMode {
    /// Returns (mode, legacy_cfb_without_first_block_ecb).
    pub fn parse(s: &str) -> Option<(CipherMode, bool)> {
        match s {
            "none" => Some((CipherMode::None, false)),
            "xor" => Some((CipherMode::Xor, false)),
            "aes128cbc" => Some((CipherMode::Aes128Cbc, false)),
            "aes128cfb" => Some((CipherMode::Aes128Cfb, false)),
            "aes128cfb_0" => Some((CipherMode::Aes128Cfb, true)),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            CipherMode::None => "none",
            CipherMode::Xor => "xor",
            CipherMode::Aes128Cbc => "aes128cbc",
            CipherMode::Aes128Cfb => "aes128cfb",
        }
    }

    pub fn is_aes(self) -> bool {
        matches!(self, CipherMode::Aes128Cbc | CipherMode::Aes128Cfb)
    }
}

pub type Block = [u8; 16];

/// One AES-128 key schedule (both directions of the block cipher).
#[derive(Clone)]
pub struct AesKey {
    cipher: Aes128,
}

impl AesKey {
    pub fn new(key16: &[u8]) -> Self {
        let cipher = Aes128::new_from_slice(&key16[..16]).expect("aes key length");
        AesKey { cipher }
    }

    #[inline]
    pub fn encrypt_block(&self, block: &mut Block) {
        let mut b = Array::from(*block);
        self.cipher.encrypt_block(&mut b);
        block.copy_from_slice(&b);
    }

    #[inline]
    pub fn decrypt_block(&self, block: &mut Block) {
        let mut b = Array::from(*block);
        self.cipher.decrypt_block(&mut b);
        block.copy_from_slice(&b);
    }

    /// CBC encrypt in place with a zero IV. `data.len()` must be a multiple of 16.
    pub fn cbc_encrypt_zero_iv(&self, data: &mut [u8]) {
        debug_assert!(data.len() % 16 == 0);
        let mut prev = [0u8; 16];
        for chunk in data.chunks_exact_mut(16) {
            for i in 0..16 {
                chunk[i] ^= prev[i];
            }
            let mut b: Block = chunk.try_into().unwrap();
            self.encrypt_block(&mut b);
            chunk.copy_from_slice(&b);
            prev = b;
        }
    }

    /// CBC decrypt in place with a zero IV. `data.len()` must be a multiple of 16.
    pub fn cbc_decrypt_zero_iv(&self, data: &mut [u8]) {
        debug_assert!(data.len() % 16 == 0);
        // Decrypt all blocks first (independent, lets the backend pipeline them), then
        // XOR each with the previous ciphertext block.
        let n = data.len() / 16;
        if n == 0 {
            return;
        }
        let mut blocks: Vec<Array<u8, aes::cipher::consts::U16>> = data
            .chunks_exact(16)
            .map(|c| Array::from(<Block>::try_from(c).unwrap()))
            .collect();
        self.cipher.decrypt_blocks(&mut blocks);
        let mut prev = [0u8; 16];
        for (i, chunk) in data.chunks_exact_mut(16).enumerate() {
            let ct: Block = chunk.try_into().unwrap();
            for j in 0..16 {
                chunk[j] = blocks[i][j] ^ prev[j];
            }
            prev = ct;
        }
    }

    /// CFB-128 (full-block CFB) encrypt in place with a zero IV; any length.
    pub fn cfb_encrypt_zero_iv(&self, data: &mut [u8]) {
        let mut iv = [0u8; 16];
        let mut off = 0usize;
        for byte in data.iter_mut() {
            if off == 0 {
                self.encrypt_block(&mut iv);
            }
            *byte ^= iv[off];
            iv[off] = *byte;
            off = (off + 1) & 0x0f;
        }
    }

    /// CFB-128 decrypt in place with a zero IV; any length.
    pub fn cfb_decrypt_zero_iv(&self, data: &mut [u8]) {
        let mut iv = [0u8; 16];
        let mut off = 0usize;
        for byte in data.iter_mut() {
            if off == 0 {
                self.encrypt_block(&mut iv);
            }
            let c = *byte;
            *byte = c ^ iv[off];
            iv[off] = c;
            off = (off + 1) & 0x0f;
        }
    }
}

/// Append PKCS#7-like padding as the C++ `padding()` does: `len += 1`, round up to a
/// multiple of 16, last byte = number of bytes added.
pub fn pad16(buf: &mut Vec<u8>) {
    let old = buf.len();
    let mut new_len = old + 1;
    if new_len % 16 != 0 {
        new_len = (new_len / 16) * 16 + 16;
    }
    buf.resize(new_len, 0);
    buf[new_len - 1] = (new_len - old) as u8;
}

/// Inverse of [`pad16`]; mirrors `de_padding()` (a pad byte of 0 is tolerated).
pub fn unpad16(buf: &mut Vec<u8>) -> bool {
    if buf.is_empty() {
        return false;
    }
    let p = *buf.last().unwrap() as usize;
    if p > 16 || p > buf.len() {
        return false;
    }
    buf.truncate(buf.len() - p);
    true
}

pub fn xor_in_place(data: &mut [u8], key16: &[u8]) {
    for (i, b) in data.iter_mut().enumerate() {
        *b ^= key16[i & 15];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{hex, unhex};

    // NIST SP 800-38A F.1.1 / F.2.1 / F.3.13 vectors (AES-128), first blocks with zero IV
    const KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";
    const PT: &str = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51";

    #[test]
    fn ecb_known_answer() {
        let k = AesKey::new(&unhex(KEY).unwrap());
        let mut b: Block = unhex("6bc1bee22e409f96e93d7e117393172a").unwrap().try_into().unwrap();
        k.encrypt_block(&mut b);
        assert_eq!(hex(&b), "3ad77bb40d7a3660a89ecaf32466ef97");
        k.decrypt_block(&mut b);
        assert_eq!(hex(&b), "6bc1bee22e409f96e93d7e117393172a");
    }

    #[test]
    fn cbc_zero_iv_roundtrip_and_first_block() {
        let k = AesKey::new(&unhex(KEY).unwrap());
        let mut d = unhex(PT).unwrap();
        k.cbc_encrypt_zero_iv(&mut d);
        // with IV = 0 the first block equals ECB(pt0)
        assert_eq!(hex(&d[..16]), "3ad77bb40d7a3660a89ecaf32466ef97");
        k.cbc_decrypt_zero_iv(&mut d);
        assert_eq!(hex(&d), PT);
    }

    #[test]
    fn cfb_zero_iv_roundtrip() {
        let k = AesKey::new(&unhex(KEY).unwrap());
        let mut d = unhex(PT).unwrap();
        d.push(0x42); // partial block
        let orig = d.clone();
        k.cfb_encrypt_zero_iv(&mut d);
        assert_ne!(d, orig);
        k.cfb_decrypt_zero_iv(&mut d);
        assert_eq!(d, orig);
    }

    #[test]
    fn padding_matches_cpp() {
        for len in 0..40 {
            let mut v = vec![0xaa; len];
            pad16(&mut v);
            assert_eq!(v.len() % 16, 0);
            assert!(v.len() > len);
            assert_eq!(*v.last().unwrap() as usize, v.len() - len);
            assert!(unpad16(&mut v));
            assert_eq!(v.len(), len);
        }
        let mut bad = vec![0u8; 16];
        bad[15] = 17;
        assert!(!unpad16(&mut bad));
    }
}
