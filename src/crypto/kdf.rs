//! Key-derivation primitives: MD5, HMAC-SHA1/SHA256, PBKDF2-HMAC-SHA256, HKDF-SHA256-expand.
//!
//! HMAC/PBKDF2/HKDF are written out here (they are a few lines each) so the crate only
//! depends on the hash crates, whose aarch64 hardware acceleration is auto-detected.

use md5::{Digest, Md5};
use sha1::Sha1;
use sha2::Sha256;

pub fn md5(data: &[u8]) -> [u8; 16] {
    let d = Md5::digest(data);
    let mut out = [0u8; 16];
    out.copy_from_slice(&d);
    out
}

pub fn sha1(data: &[u8]) -> [u8; 20] {
    let d = Sha1::digest(data);
    let mut out = [0u8; 20];
    out.copy_from_slice(&d);
    out
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let d = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// Precomputed HMAC-SHA1 pads (block size 64). Cloning the inner/outer state per
/// message saves hashing the key twice on every packet.
#[derive(Clone)]
pub struct HmacSha1 {
    inner: Sha1,
    outer: Sha1,
}

impl HmacSha1 {
    pub fn new(key: &[u8]) -> Self {
        let mut k = [0u8; 64];
        if key.len() > 64 {
            k[..20].copy_from_slice(&sha1(key));
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0x36u8; 64];
        let mut opad = [0x5cu8; 64];
        for i in 0..64 {
            ipad[i] ^= k[i];
            opad[i] ^= k[i];
        }
        let mut inner = Sha1::new();
        inner.update(ipad);
        let mut outer = Sha1::new();
        outer.update(opad);
        HmacSha1 { inner, outer }
    }

    pub fn mac(&self, data: &[u8]) -> [u8; 20] {
        let mut inner = self.inner.clone();
        inner.update(data);
        let ih = inner.finalize();
        let mut outer = self.outer.clone();
        outer.update(ih);
        let mut out = [0u8; 20];
        out.copy_from_slice(&outer.finalize());
        out
    }
}

pub fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    HmacSha1::new(key).mac(data)
}

#[derive(Clone)]
pub struct HmacSha256 {
    inner: Sha256,
    outer: Sha256,
}

impl HmacSha256 {
    pub fn new(key: &[u8]) -> Self {
        let mut k = [0u8; 64];
        if key.len() > 64 {
            k[..32].copy_from_slice(&sha256(key));
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0x36u8; 64];
        let mut opad = [0x5cu8; 64];
        for i in 0..64 {
            ipad[i] ^= k[i];
            opad[i] ^= k[i];
        }
        let mut inner = Sha256::new();
        inner.update(ipad);
        let mut outer = Sha256::new();
        outer.update(opad);
        HmacSha256 { inner, outer }
    }

    pub fn mac_parts(&self, parts: &[&[u8]]) -> [u8; 32] {
        let mut inner = self.inner.clone();
        for p in parts {
            inner.update(p);
        }
        let ih = inner.finalize();
        let mut outer = self.outer.clone();
        outer.update(ih);
        let mut out = [0u8; 32];
        out.copy_from_slice(&outer.finalize());
        out
    }

    pub fn mac(&self, data: &[u8]) -> [u8; 32] {
        self.mac_parts(&[data])
    }
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    HmacSha256::new(key).mac(data)
}

/// PKCS#5 PBKDF2 with HMAC-SHA256 (RFC 8018).
pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    let prf = HmacSha256::new(password);
    let mut block_index = 1u32;
    let mut written = 0;
    while written < out.len() {
        let mut u = prf.mac_parts(&[salt, &block_index.to_be_bytes()]);
        let mut t = u;
        for _ in 1..iterations {
            u = prf.mac(&u);
            for i in 0..32 {
                t[i] ^= u[i];
            }
        }
        let n = (out.len() - written).min(32);
        out[written..written + n].copy_from_slice(&t[..n]);
        written += n;
        block_index += 1;
    }
}

/// HKDF-Expand with HMAC-SHA256 (RFC 5869 §2.3). `prk` must be at least 32 bytes.
pub fn hkdf_sha256_expand(prk: &[u8], info: &[u8], out: &mut [u8]) {
    assert!(prk.len() >= 32, "hkdf prk too short");
    assert!(out.len() <= 255 * 32, "hkdf output too long");
    let prf = HmacSha256::new(prk);
    let mut prev: Vec<u8> = Vec::new();
    let mut written = 0;
    let mut counter = 1u8;
    while written < out.len() {
        let t = prf.mac_parts(&[&prev, info, &[counter]]);
        let n = (out.len() - written).min(32);
        out[written..written + n].copy_from_slice(&t[..n]);
        written += n;
        prev = t.to_vec();
        counter += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{hex, unhex};

    #[test]
    fn md5_rfc1321() {
        assert_eq!(hex(&md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex(&md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn hmac_sha1_rfc2202() {
        let key = [0x0bu8; 20];
        assert_eq!(
            hex(&hmac_sha1(&key, b"Hi There")),
            "b617318655057264e28bc0b6fb378c8ef146be00"
        );
        // test case 3: key 0xaa*20, data 0xdd*50
        let key = [0xaau8; 20];
        let data = [0xddu8; 50];
        assert_eq!(
            hex(&hmac_sha1(&key, &data)),
            "125d7342b9ac11cd91a39af48aa17b4f63f175d3"
        );
        // key longer than block size (test case 6): 80 * 0xaa
        let key = [0xaau8; 80];
        assert_eq!(
            hex(&hmac_sha1(&key, b"Test Using Larger Than Block-Size Key - Hash Key First")),
            "aa4ae5e15272d00e95705637ce8a3b55ed402112"
        );
    }

    #[test]
    fn hmac_sha256_rfc4231() {
        let key = [0x0bu8; 20];
        assert_eq!(
            hex(&hmac_sha256(&key, b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn pbkdf2_sha256_rfc7914() {
        let mut out = [0u8; 64];
        pbkdf2_hmac_sha256(b"passwd", b"salt", 1, &mut out);
        assert_eq!(
            hex(&out),
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
        );
        let mut out = [0u8; 64];
        pbkdf2_hmac_sha256(b"Password", b"NaCl", 80000, &mut out);
        assert_eq!(
            hex(&out),
            "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"
        );
    }

    #[test]
    fn hkdf_expand_rfc5869() {
        let prk = unhex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5").unwrap();
        let info = unhex("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let mut okm = [0u8; 42];
        hkdf_sha256_expand(&prk, &info, &mut okm);
        assert_eq!(
            hex(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }
}
