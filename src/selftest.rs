//! `--unit-test`: a self-test of the crypto, framing and checksum code on the machine at
//! hand (what the C++ `--unit-test` loosely did). Prints what it checks and which AES
//! backend this CPU gets. Returns an error message on the first failure.

use crate::crypto::{cpu_has_aes, resolve_backend, AesBackend, AuthMode, CipherMode, Crypto, Keys};
use crate::packet::checksum;
use crate::util::hex;
use crate::wire;

/// Known-good prefixes of the keys the C++ implementation derives from the default password
/// (`tests/data/vectors.txt`, client role).
const NORMAL_KEY_SECRET_KEY: &str = "6ead9a3ed55af4058a3b112c2a2cf041";
const CIPHER_KEY_ENCRYPT_CLIENT_PREFIX: &str = "d1e4fc2d0c165470f18502bcf5a2cf11";
const CIPHER_KEY_DECRYPT_CLIENT_PREFIX: &str = "3866cca763a21a2a3a805c0546e2dce4";

pub fn run() -> Result<(), String> {
    println!("cpu aes instructions: {}", cpu_has_aes());
    println!("aes backend (auto):   {}", resolve_backend(AesBackend::Auto).name());

    let k = Keys::derive("secret key", true);
    if hex(&k.normal_key) != NORMAL_KEY_SECRET_KEY
        || hex(&k.cipher_key_encrypt[..16]) != CIPHER_KEY_ENCRYPT_CLIENT_PREFIX
        || hex(&k.cipher_key_decrypt[..16]) != CIPHER_KEY_DECRYPT_CLIENT_PREFIX
    {
        return Err("key derivation does not match the C++ reference".into());
    }
    println!("key derivation:       ok (matches the C++ reference)");

    let modes = [CipherMode::None, CipherMode::Xor, CipherMode::Aes128Cbc, CipherMode::Aes128Cfb, CipherMode::ChaCha20Poly1305];
    let auths = [AuthMode::None, AuthMode::Md5, AuthMode::Crc32, AuthMode::Simple, AuthMode::HmacSha1];
    let backends: &[AesBackend] = if cpu_has_aes() { &[AesBackend::Hardware, AesBackend::Table, AesBackend::Fixslice] } else { &[AesBackend::Table, AesBackend::Fixslice] };
    let mut checked = 0;
    for &backend in backends {
        for cm in modes {
            for am in auths {
                let c = Crypto::with_backend(cm, am, false, Keys::derive("secret key", true), backend);
                let s = Crypto::with_backend(cm, am, false, Keys::derive("secret key", false), backend);
                for len in [0usize, 1, 16, 33, 100, 1400] {
                    let msg: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
                    let cipher_input = if am == AuthMode::HmacSha1 || cm.is_aead() { len } else { len + am.tag_len() };
                    if cm == CipherMode::Aes128Cfb && cipher_input < 16 {
                        continue;
                    }
                    let ct = c.encrypt(&msg).ok_or_else(|| format!("encrypt failed: {cm:?} {am:?} len={len} backend={backend:?}"))?;
                    let pt = s.decrypt(&ct).ok_or_else(|| format!("decrypt failed: {cm:?} {am:?} len={len} backend={backend:?}"))?;
                    if pt != msg {
                        return Err(format!("roundtrip mismatch: {cm:?} {am:?} len={len} backend={backend:?}"));
                    }
                    if (am != AuthMode::None || cm.is_aead()) && !ct.is_empty() {
                        let mut bad = ct.clone();
                        let i = bad.len() / 2;
                        bad[i] ^= 0x55;
                        if s.decrypt(&bad).is_some() {
                            return Err(format!("tampered packet accepted: {cm:?} {am:?} len={len} backend={backend:?}"));
                        }
                    }
                    checked += 1;
                }
            }
        }
    }
    println!("cipher/auth roundtrips: ok ({checked} cases, backends {:?})", backends);

    if cpu_has_aes() {
        let msg: Vec<u8> = (0..1424u32).map(|i| (i * 31 + 7) as u8).collect();
        let hw = Crypto::with_backend(CipherMode::Aes128Cbc, AuthMode::Md5, false, Keys::derive("x", true), AesBackend::Hardware);
        let tb = Crypto::with_backend(CipherMode::Aes128Cbc, AuthMode::Md5, false, Keys::derive("x", true), AesBackend::Table);
        if hw.encrypt(&msg) != tb.encrypt(&msg) {
            return Err("hardware and table AES disagree".into());
        }
        println!("hardware vs table AES: ok (identical output)");
    }

    let h = wire::SaferHeader { my_id: 1, oppsite_id: 2, seq: 3, ptype: b'd', roller: 4 };
    let p = wire::build_safer(&h, &[9, 8, 7]);
    let ids = wire::parse_safer_ids(&p).ok_or("safer ids")?;
    let (t, r, d) = wire::parse_safer_body(&p).ok_or("safer body")?;
    if ids.seq != 3 || ids.oppsite_id != 1 || t != b'd' || r != 4 || d != [9, 8, 7] {
        return Err("safer framing mismatch".into());
    }
    if checksum::csum(&[1, 2, 3, 4, 5]) != 0xf6f9 {
        return Err("checksum mismatch".into());
    }
    println!("framing and checksum: ok");
    Ok(())
}
