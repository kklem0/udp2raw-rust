//! Key derivation and the packet-level encrypt/decrypt used by every udp2raw packet.
//!
//! Composition (identical to `encrypt.cpp`):
//! * auth mode `hmac_sha1` → Encrypt-then-MAC: `cipher(data, cipher_key) || HMAC(hmac_key, ct)`
//! * any other auth mode   → MAC-then-encrypt: `cipher(data || tag, normal_key)`
//!
//! [`Crypto`] is immutable after construction and `Send + Sync`, so worker threads can
//! share one instance behind an `Arc`.

pub mod aes_table;
pub mod auth;
pub mod cipher;
pub mod kdf;

pub use auth::{AuthMode, Authenticator};
pub use cipher::{AesBackend, AesKey, CipherMode, cpu_has_aes, resolve_backend};

use crate::consts::MAX_DATA_LEN;
use cipher::{pad16, unpad16, xor_in_place};

pub const HMAC_KEY_LEN: usize = 64;
pub const CIPHER_KEY_LEN: usize = 64;

/// All key material derived from the password, for one role (client or server).
#[derive(Clone)]
pub struct Keys {
    /// md5(password || "key1") — used by the legacy MAC-then-encrypt path.
    pub normal_key: [u8; 16],
    pub cipher_key_encrypt: [u8; CIPHER_KEY_LEN],
    pub cipher_key_decrypt: [u8; CIPHER_KEY_LEN],
    pub hmac_key_encrypt: [u8; HMAC_KEY_LEN],
    pub hmac_key_decrypt: [u8; HMAC_KEY_LEN],
    /// Obfuscation bytes for the `--fix-gro` length prefix in xor mode.
    pub gro_xor: [u8; 256],
}

impl Keys {
    pub fn derive(password: &str, is_client: bool) -> Keys {
        let mut tmp = password.as_bytes().to_vec();
        tmp.extend_from_slice(b"key1");
        let normal_key = kdf::md5(&tmp);

        let salt = kdf::md5(b"udp2raw_salt1");
        let mut prk = [0u8; 32];
        kdf::pbkdf2_hmac_sha256(password.as_bytes(), &salt[..16], 10000, &mut prk);

        let (info_hmac_enc, info_hmac_dec, info_cipher_enc, info_cipher_dec): (&[u8], &[u8], &[u8], &[u8]) =
            if is_client {
                (
                    b"hmac_key client-->server",
                    b"hmac_key server-->client",
                    b"cipher_key client-->server",
                    b"cipher_key server-->client",
                )
            } else {
                (
                    b"hmac_key server-->client",
                    b"hmac_key client-->server",
                    b"cipher_key server-->client",
                    b"cipher_key client-->server",
                )
            };

        let mut cipher_key_encrypt = [0u8; CIPHER_KEY_LEN];
        let mut cipher_key_decrypt = [0u8; CIPHER_KEY_LEN];
        let mut hmac_key_encrypt = [0u8; HMAC_KEY_LEN];
        let mut hmac_key_decrypt = [0u8; HMAC_KEY_LEN];
        let mut gro_xor = [0u8; 256];
        kdf::hkdf_sha256_expand(&prk, info_cipher_enc, &mut cipher_key_encrypt);
        kdf::hkdf_sha256_expand(&prk, info_cipher_dec, &mut cipher_key_decrypt);
        kdf::hkdf_sha256_expand(&prk, info_hmac_enc, &mut hmac_key_encrypt);
        kdf::hkdf_sha256_expand(&prk, info_hmac_dec, &mut hmac_key_decrypt);
        kdf::hkdf_sha256_expand(&prk, b"gro", &mut gro_xor);

        Keys {
            normal_key,
            cipher_key_encrypt,
            cipher_key_decrypt,
            hmac_key_encrypt,
            hmac_key_decrypt,
            gro_xor,
        }
    }
}

/// Encrypt/decrypt engine for one role. Immutable; share via `Arc`.
pub struct Crypto {
    cipher_mode: CipherMode,
    auth_mode: AuthMode,
    cfb_legacy: bool,
    keys: Keys,
    /// Cipher key used by `encrypt`: normal_key (legacy) or cipher_key_encrypt (hmac).
    tx_xor_key: [u8; 16],
    rx_xor_key: [u8; 16],
    tx_aes: Option<AesKey>,
    rx_aes: Option<AesKey>,
    /// ECB keys derived from cipher_key_encrypt/decrypt — used for the CFB first block and
    /// for the `--fix-gro` length-prefix obfuscation, in every auth mode.
    ecb_enc: Option<AesKey>,
    ecb_dec: Option<AesKey>,
    tx_auth: Authenticator,
    rx_auth: Authenticator,
}

impl Crypto {
    /// Auto-selected AES backend (hardware if the CPU has it, else table-driven).
    pub fn new(cipher_mode: CipherMode, auth_mode: AuthMode, cfb_legacy: bool, keys: Keys) -> Crypto {
        Self::with_backend(cipher_mode, auth_mode, cfb_legacy, keys, AesBackend::Auto)
    }

    pub fn with_backend(cipher_mode: CipherMode, auth_mode: AuthMode, cfb_legacy: bool, keys: Keys, backend: AesBackend) -> Crypto {
        let hmac = auth_mode == AuthMode::HmacSha1;
        let tx_key: [u8; 16] = if hmac {
            keys.cipher_key_encrypt[..16].try_into().unwrap()
        } else {
            keys.normal_key
        };
        let rx_key: [u8; 16] = if hmac {
            keys.cipher_key_decrypt[..16].try_into().unwrap()
        } else {
            keys.normal_key
        };
        let (tx_aes, rx_aes, ecb_enc, ecb_dec) = if cipher_mode.is_aes() {
            (
                Some(AesKey::with_backend(&tx_key, backend)),
                Some(AesKey::with_backend(&rx_key, backend)),
                Some(AesKey::with_backend(&keys.cipher_key_encrypt[..16], backend)),
                Some(AesKey::with_backend(&keys.cipher_key_decrypt[..16], backend)),
            )
        } else {
            (None, None, None, None)
        };
        let tx_auth = Authenticator::new(auth_mode, &keys.hmac_key_encrypt);
        let rx_auth = Authenticator::new(auth_mode, &keys.hmac_key_decrypt);
        Crypto {
            cipher_mode,
            auth_mode,
            cfb_legacy,
            keys,
            tx_xor_key: tx_key,
            rx_xor_key: rx_key,
            tx_aes,
            rx_aes,
            ecb_enc,
            ecb_dec,
            tx_auth,
            rx_auth,
        }
    }

    pub fn cipher_mode(&self) -> CipherMode {
        self.cipher_mode
    }
    pub fn auth_mode(&self) -> AuthMode {
        self.auth_mode
    }
    pub fn keys(&self) -> &Keys {
        &self.keys
    }
    pub fn is_hmac_used(&self) -> bool {
        self.auth_mode == AuthMode::HmacSha1
    }
    /// The AES backend in use (`None` for non-AES cipher modes).
    pub fn aes_backend(&self) -> Option<AesBackend> {
        self.tx_aes.as_ref().map(|k| k.backend())
    }

    /// `my_encrypt`: returns the on-the-wire bytes for `data`, or `None` if `data` is too long.
    pub fn encrypt(&self, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() > MAX_DATA_LEN {
            log::warn!("len>max_data_len");
            return None;
        }
        let mut buf = Vec::with_capacity(data.len() + 64);
        buf.extend_from_slice(data);
        if self.is_hmac_used() {
            self.cipher_encrypt(&mut buf)?;
            self.tx_auth.append_tag(&mut buf);
        } else {
            self.tx_auth.append_tag(&mut buf);
            self.cipher_encrypt(&mut buf)?;
        }
        Some(buf)
    }

    /// `my_decrypt`: returns the plaintext, or `None` on any integrity/format failure.
    pub fn decrypt(&self, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() > MAX_DATA_LEN {
            log::warn!("len>max_data_len");
            return None;
        }
        if self.is_hmac_used() {
            let body_len = self.rx_auth.verify(data)?;
            let mut buf = data[..body_len].to_vec();
            self.cipher_decrypt(&mut buf)?;
            Some(buf)
        } else {
            let mut buf = data.to_vec();
            self.cipher_decrypt(&mut buf)?;
            let body_len = self.rx_auth.verify(&buf)?;
            buf.truncate(body_len);
            Some(buf)
        }
    }

    fn cipher_encrypt(&self, buf: &mut Vec<u8>) -> Option<()> {
        match self.cipher_mode {
            CipherMode::None => {}
            CipherMode::Xor => xor_in_place(buf, &self.tx_xor_key),
            CipherMode::Aes128Cbc => {
                pad16(buf);
                self.tx_aes.as_ref().unwrap().cbc_encrypt_zero_iv(buf);
            }
            CipherMode::Aes128Cfb => {
                if buf.len() < 16 {
                    log::debug!("aes128cfb requires len>=16");
                    return None;
                }
                if !self.cfb_legacy {
                    let mut b: [u8; 16] = buf[..16].try_into().unwrap();
                    self.ecb_enc.as_ref().unwrap().encrypt_block(&mut b);
                    buf[..16].copy_from_slice(&b);
                }
                self.tx_aes.as_ref().unwrap().cfb_encrypt_zero_iv(buf);
            }
        }
        Some(())
    }

    fn cipher_decrypt(&self, buf: &mut Vec<u8>) -> Option<()> {
        match self.cipher_mode {
            CipherMode::None => {}
            CipherMode::Xor => xor_in_place(buf, &self.rx_xor_key),
            CipherMode::Aes128Cbc => {
                if buf.len() % 16 != 0 {
                    log::debug!("len%16!=0");
                    return None;
                }
                self.rx_aes.as_ref().unwrap().cbc_decrypt_zero_iv(buf);
                if !unpad16(buf) {
                    return None;
                }
            }
            CipherMode::Aes128Cfb => {
                if buf.len() < 16 {
                    return None;
                }
                self.rx_aes.as_ref().unwrap().cfb_decrypt_zero_iv(buf);
                if !self.cfb_legacy {
                    let mut b: [u8; 16] = buf[..16].try_into().unwrap();
                    self.ecb_dec.as_ref().unwrap().decrypt_block(&mut b);
                    buf[..16].copy_from_slice(&b);
                }
            }
        }
        Some(())
    }

    /// `aes_ecb_encrypt1`: ECB-encrypt 16 bytes in place with cipher_key_encrypt.
    pub fn ecb_encrypt1(&self, block: &mut [u8]) {
        let mut b: [u8; 16] = block[..16].try_into().unwrap();
        self.ecb_enc.as_ref().expect("ecb key").encrypt_block(&mut b);
        block[..16].copy_from_slice(&b);
    }

    /// `aes_ecb_decrypt1`: ECB-decrypt 16 bytes in place with cipher_key_decrypt.
    pub fn ecb_decrypt1(&self, block: &mut [u8]) {
        let mut b: [u8; 16] = block[..16].try_into().unwrap();
        self.ecb_dec.as_ref().expect("ecb key").decrypt_block(&mut b);
        block[..16].copy_from_slice(&b);
    }

    /// `--fix-gro` obfuscation of the 2-byte length prefix (operates on the first 16 bytes
    /// for AES modes, first 2 bytes for xor, nothing for `none`). Buffer must be ≥16 bytes
    /// for AES modes.
    pub fn gro_obfuscate_head(&self, head: &mut [u8]) {
        match self.cipher_mode {
            CipherMode::Xor => {
                head[0] ^= self.keys.gro_xor[0];
                head[1] ^= self.keys.gro_xor[1];
            }
            CipherMode::Aes128Cbc | CipherMode::Aes128Cfb => self.ecb_encrypt1(head),
            CipherMode::None => {}
        }
    }

    pub fn gro_deobfuscate_head(&self, head: &mut [u8]) {
        match self.cipher_mode {
            CipherMode::Xor => {
                head[0] ^= self.keys.gro_xor[0];
                head[1] ^= self.keys.gro_xor[1];
            }
            CipherMode::Aes128Cbc | CipherMode::Aes128Cfb => self.ecb_decrypt1(head),
            CipherMode::None => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(cm: CipherMode, am: AuthMode) -> (Crypto, Crypto) {
        let c = Crypto::new(cm, am, false, Keys::derive("secret key", true));
        let s = Crypto::new(cm, am, false, Keys::derive("secret key", false));
        (c, s)
    }

    #[test]
    fn roundtrip_every_mode_both_directions() {
        let modes = [CipherMode::None, CipherMode::Xor, CipherMode::Aes128Cbc, CipherMode::Aes128Cfb];
        let auths = [AuthMode::None, AuthMode::Md5, AuthMode::Crc32, AuthMode::Simple, AuthMode::HmacSha1];
        for backend in [AesBackend::Auto, AesBackend::Table, AesBackend::Fixslice] {
        for cm in modes {
            for am in auths {
                let c = Crypto::with_backend(cm, am, false, Keys::derive("secret key", true), backend);
                let s = Crypto::with_backend(cm, am, false, Keys::derive("secret key", false), backend);
                // 1700 leaves room for tag + padding below MAX_DATA_LEN (the C++ rejects
                // ciphertexts longer than max_data_len on the receive side too).
                for len in [0usize, 1, 15, 16, 17, 33, 100, 1401, 1700] {
                    let msg: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
                    let cipher_input_len = if am == AuthMode::HmacSha1 { len } else { len + am.tag_len() };
                    let ct = match c.encrypt(&msg) {
                        Some(ct) => ct,
                        None => {
                            assert!(cm == CipherMode::Aes128Cfb && cipher_input_len < 16, "unexpected encrypt failure {cm:?} {am:?} {len}");
                            continue;
                        }
                    };
                    let pt = s.decrypt(&ct).unwrap_or_else(|| panic!("decrypt failed {cm:?} {am:?} len={len}"));
                    assert_eq!(pt, msg, "{cm:?} {am:?} len={len}");
                    // and the other direction
                    let ct2 = s.encrypt(&msg).unwrap();
                    assert_eq!(c.decrypt(&ct2).unwrap(), msg);
                    // only hmac_sha1 keys are direction-specific; the legacy modes share normal_key
                    if am == AuthMode::HmacSha1 {
                        assert!(c.decrypt(&ct).is_none(), "wrong role accepted {cm:?} len={len}");
                    }
                }
                assert!(c.encrypt(&vec![0u8; 1801]).is_none());
            }
        }
        }
    }

    #[test]
    fn keys_are_direction_swapped() {
        let c = Keys::derive("pw", true);
        let s = Keys::derive("pw", false);
        assert_eq!(c.cipher_key_encrypt, s.cipher_key_decrypt);
        assert_eq!(c.cipher_key_decrypt, s.cipher_key_encrypt);
        assert_eq!(c.hmac_key_encrypt, s.hmac_key_decrypt);
        assert_eq!(c.normal_key, s.normal_key);
        assert_eq!(c.gro_xor, s.gro_xor);
        assert_ne!(c.cipher_key_encrypt, c.cipher_key_decrypt);
    }

    #[test]
    fn gro_head_roundtrip() {
        for cm in [CipherMode::Xor, CipherMode::Aes128Cbc, CipherMode::Aes128Cfb, CipherMode::None] {
            let (c, s) = pair(cm, AuthMode::Md5);
            let mut head = [0x11u8; 16];
            let orig = head;
            c.gro_obfuscate_head(&mut head);
            s.gro_deobfuscate_head(&mut head);
            assert_eq!(head, orig);
        }
    }
}
