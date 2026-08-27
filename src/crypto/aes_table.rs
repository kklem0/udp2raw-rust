//! Table-driven AES-128 (the classic FIPS-197 "T-table" formulation used by PolarSSL /
//! mbedTLS, OpenSSL's `aes_core.c`, and therefore the original udp2raw).
//!
//! It is used when the CPU has no AES instructions. There the `aes` crate falls back to a
//! constant-time bitsliced implementation that is only fast when it can process several
//! blocks at once; CBC encryption is strictly serial, and on a Cortex-A72 the T-table code
//! is 2–4× faster for it. The cache-timing profile is the same as the C++ implementation's.
//!
//! Tables are generated at first use from the S-box definition (GF(2^8) inverse + affine
//! map), so there are no 4 KB constant blobs to get wrong; the NIST vectors below pin them.

use std::sync::OnceLock;

struct Tables {
    sbox: [u8; 256],
    inv_sbox: [u8; 256],
    te: [[u32; 256]; 4],
    td: [[u32; 256]; 4],
}

#[inline]
fn xtime(x: u8) -> u8 {
    (x << 1) ^ if x & 0x80 != 0 { 0x1b } else { 0 }
}

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        a = xtime(a);
        b >>= 1;
    }
    p
}

fn gen_tables() -> Tables {
    // powers of the generator 3 give every non-zero element; inverse via logs
    let mut pow = [0u8; 256];
    let mut log = [0u8; 256];
    let mut x = 1u8;
    for i in 0..255 {
        pow[i] = x;
        log[x as usize] = i as u8;
        x ^= xtime(x); // x *= 3
    }
    let mut sbox = [0u8; 256];
    let mut inv_sbox = [0u8; 256];
    for i in 0..256usize {
        let inv = if i == 0 { 0u8 } else { pow[(255 - log[i] as usize) % 255] };
        let mut s = inv;
        let mut y = inv;
        for _ in 0..4 {
            y = y.rotate_left(1);
            s ^= y;
        }
        s ^= 0x63;
        sbox[i] = s;
        inv_sbox[s as usize] = i as u8;
    }
    let mut te = [[0u32; 256]; 4];
    let mut td = [[0u32; 256]; 4];
    for i in 0..256usize {
        let s = sbox[i];
        let s2 = xtime(s);
        let s3 = s2 ^ s;
        let t0 = ((s2 as u32) << 24) | ((s as u32) << 16) | ((s as u32) << 8) | s3 as u32;
        te[0][i] = t0;
        te[1][i] = t0.rotate_right(8);
        te[2][i] = t0.rotate_right(16);
        te[3][i] = t0.rotate_right(24);
        let si = inv_sbox[i];
        let d0 = ((gf_mul(si, 0x0e) as u32) << 24) | ((gf_mul(si, 0x09) as u32) << 16) | ((gf_mul(si, 0x0d) as u32) << 8) | gf_mul(si, 0x0b) as u32;
        td[0][i] = d0;
        td[1][i] = d0.rotate_right(8);
        td[2][i] = d0.rotate_right(16);
        td[3][i] = d0.rotate_right(24);
    }
    Tables { sbox, inv_sbox, te, td }
}

fn tables() -> &'static Tables {
    static T: OnceLock<Tables> = OnceLock::new();
    T.get_or_init(gen_tables)
}

const RCON: [u32; 10] = [0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000];

#[derive(Clone)]
pub struct AesTable {
    ek: [u32; 44],
    dk: [u32; 44],
}

#[inline]
fn get_u32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

impl AesTable {
    pub fn new(key: &[u8]) -> AesTable {
        let t = tables();
        let s = &t.sbox;
        let mut ek = [0u32; 44];
        for i in 0..4 {
            ek[i] = get_u32(&key[i * 4..]);
        }
        for i in 0..10 {
            let tmp = ek[4 * i + 3];
            let sub = ((s[((tmp >> 16) & 0xff) as usize] as u32) << 24)
                ^ ((s[((tmp >> 8) & 0xff) as usize] as u32) << 16)
                ^ ((s[(tmp & 0xff) as usize] as u32) << 8)
                ^ (s[(tmp >> 24) as usize] as u32);
            ek[4 * i + 4] = ek[4 * i] ^ sub ^ RCON[i];
            ek[4 * i + 5] = ek[4 * i + 1] ^ ek[4 * i + 4];
            ek[4 * i + 6] = ek[4 * i + 2] ^ ek[4 * i + 5];
            ek[4 * i + 7] = ek[4 * i + 3] ^ ek[4 * i + 6];
        }
        // decryption schedule: reversed round keys, InvMixColumns applied to rounds 1..9
        let mut dk = [0u32; 44];
        for i in 0..11 {
            dk[4 * i..4 * i + 4].copy_from_slice(&ek[4 * (10 - i)..4 * (10 - i) + 4]);
        }
        for w in dk.iter_mut().take(40).skip(4) {
            let v = *w;
            *w = t.td[0][s[(v >> 24) as usize] as usize]
                ^ t.td[1][s[((v >> 16) & 0xff) as usize] as usize]
                ^ t.td[2][s[((v >> 8) & 0xff) as usize] as usize]
                ^ t.td[3][s[(v & 0xff) as usize] as usize];
        }
        AesTable { ek, dk }
    }

    #[inline]
    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        let t = tables();
        let (te, s) = (&t.te, &t.sbox);
        let rk = &self.ek;
        let mut s0 = get_u32(&block[0..]) ^ rk[0];
        let mut s1 = get_u32(&block[4..]) ^ rk[1];
        let mut s2 = get_u32(&block[8..]) ^ rk[2];
        let mut s3 = get_u32(&block[12..]) ^ rk[3];
        let mut k = 4;
        for _ in 0..9 {
            let t0 = te[0][(s0 >> 24) as usize] ^ te[1][((s1 >> 16) & 0xff) as usize] ^ te[2][((s2 >> 8) & 0xff) as usize] ^ te[3][(s3 & 0xff) as usize] ^ rk[k];
            let t1 = te[0][(s1 >> 24) as usize] ^ te[1][((s2 >> 16) & 0xff) as usize] ^ te[2][((s3 >> 8) & 0xff) as usize] ^ te[3][(s0 & 0xff) as usize] ^ rk[k + 1];
            let t2 = te[0][(s2 >> 24) as usize] ^ te[1][((s3 >> 16) & 0xff) as usize] ^ te[2][((s0 >> 8) & 0xff) as usize] ^ te[3][(s1 & 0xff) as usize] ^ rk[k + 2];
            let t3 = te[0][(s3 >> 24) as usize] ^ te[1][((s0 >> 16) & 0xff) as usize] ^ te[2][((s1 >> 8) & 0xff) as usize] ^ te[3][(s2 & 0xff) as usize] ^ rk[k + 3];
            s0 = t0;
            s1 = t1;
            s2 = t2;
            s3 = t3;
            k += 4;
        }
        let o0 = ((s[(s0 >> 24) as usize] as u32) << 24) ^ ((s[((s1 >> 16) & 0xff) as usize] as u32) << 16) ^ ((s[((s2 >> 8) & 0xff) as usize] as u32) << 8) ^ (s[(s3 & 0xff) as usize] as u32) ^ rk[40];
        let o1 = ((s[(s1 >> 24) as usize] as u32) << 24) ^ ((s[((s2 >> 16) & 0xff) as usize] as u32) << 16) ^ ((s[((s3 >> 8) & 0xff) as usize] as u32) << 8) ^ (s[(s0 & 0xff) as usize] as u32) ^ rk[41];
        let o2 = ((s[(s2 >> 24) as usize] as u32) << 24) ^ ((s[((s3 >> 16) & 0xff) as usize] as u32) << 16) ^ ((s[((s0 >> 8) & 0xff) as usize] as u32) << 8) ^ (s[(s1 & 0xff) as usize] as u32) ^ rk[42];
        let o3 = ((s[(s3 >> 24) as usize] as u32) << 24) ^ ((s[((s0 >> 16) & 0xff) as usize] as u32) << 16) ^ ((s[((s1 >> 8) & 0xff) as usize] as u32) << 8) ^ (s[(s2 & 0xff) as usize] as u32) ^ rk[43];
        block[0..4].copy_from_slice(&o0.to_be_bytes());
        block[4..8].copy_from_slice(&o1.to_be_bytes());
        block[8..12].copy_from_slice(&o2.to_be_bytes());
        block[12..16].copy_from_slice(&o3.to_be_bytes());
    }

    #[inline]
    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        let t = tables();
        let (td, si) = (&t.td, &t.inv_sbox);
        let rk = &self.dk;
        let mut s0 = get_u32(&block[0..]) ^ rk[0];
        let mut s1 = get_u32(&block[4..]) ^ rk[1];
        let mut s2 = get_u32(&block[8..]) ^ rk[2];
        let mut s3 = get_u32(&block[12..]) ^ rk[3];
        let mut k = 4;
        for _ in 0..9 {
            let t0 = td[0][(s0 >> 24) as usize] ^ td[1][((s3 >> 16) & 0xff) as usize] ^ td[2][((s2 >> 8) & 0xff) as usize] ^ td[3][(s1 & 0xff) as usize] ^ rk[k];
            let t1 = td[0][(s1 >> 24) as usize] ^ td[1][((s0 >> 16) & 0xff) as usize] ^ td[2][((s3 >> 8) & 0xff) as usize] ^ td[3][(s2 & 0xff) as usize] ^ rk[k + 1];
            let t2 = td[0][(s2 >> 24) as usize] ^ td[1][((s1 >> 16) & 0xff) as usize] ^ td[2][((s0 >> 8) & 0xff) as usize] ^ td[3][(s3 & 0xff) as usize] ^ rk[k + 2];
            let t3 = td[0][(s3 >> 24) as usize] ^ td[1][((s2 >> 16) & 0xff) as usize] ^ td[2][((s1 >> 8) & 0xff) as usize] ^ td[3][(s0 & 0xff) as usize] ^ rk[k + 3];
            s0 = t0;
            s1 = t1;
            s2 = t2;
            s3 = t3;
            k += 4;
        }
        let o0 = ((si[(s0 >> 24) as usize] as u32) << 24) ^ ((si[((s3 >> 16) & 0xff) as usize] as u32) << 16) ^ ((si[((s2 >> 8) & 0xff) as usize] as u32) << 8) ^ (si[(s1 & 0xff) as usize] as u32) ^ rk[40];
        let o1 = ((si[(s1 >> 24) as usize] as u32) << 24) ^ ((si[((s0 >> 16) & 0xff) as usize] as u32) << 16) ^ ((si[((s3 >> 8) & 0xff) as usize] as u32) << 8) ^ (si[(s2 & 0xff) as usize] as u32) ^ rk[41];
        let o2 = ((si[(s2 >> 24) as usize] as u32) << 24) ^ ((si[((s1 >> 16) & 0xff) as usize] as u32) << 16) ^ ((si[((s0 >> 8) & 0xff) as usize] as u32) << 8) ^ (si[(s3 & 0xff) as usize] as u32) ^ rk[42];
        let o3 = ((si[(s3 >> 24) as usize] as u32) << 24) ^ ((si[((s2 >> 16) & 0xff) as usize] as u32) << 16) ^ ((si[((s1 >> 8) & 0xff) as usize] as u32) << 8) ^ (si[(s0 & 0xff) as usize] as u32) ^ rk[43];
        block[0..4].copy_from_slice(&o0.to_be_bytes());
        block[4..8].copy_from_slice(&o1.to_be_bytes());
        block[8..12].copy_from_slice(&o2.to_be_bytes());
        block[12..16].copy_from_slice(&o3.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{hex, unhex};

    #[test]
    fn sbox_known_values() {
        let t = tables();
        assert_eq!(t.sbox[0x00], 0x63);
        assert_eq!(t.sbox[0x01], 0x7c);
        assert_eq!(t.sbox[0x53], 0xed);
        assert_eq!(t.sbox[0xff], 0x16);
        assert_eq!(t.inv_sbox[0x63], 0x00);
        assert_eq!(t.te[0][0x00], 0xc66363a5);
        assert_eq!(t.td[0][0x00], 0x51f4a750);
    }

    #[test]
    fn fips197_c1_vector() {
        let k = AesTable::new(&unhex("000102030405060708090a0b0c0d0e0f").unwrap());
        let mut b: [u8; 16] = unhex("00112233445566778899aabbccddeeff").unwrap().try_into().unwrap();
        k.encrypt_block(&mut b);
        assert_eq!(hex(&b), "69c4e0d86a7b0430d8cdb78070b4c55a");
        k.decrypt_block(&mut b);
        assert_eq!(hex(&b), "00112233445566778899aabbccddeeff");
    }

    #[test]
    fn sp800_38a_ecb_vector() {
        let k = AesTable::new(&unhex("2b7e151628aed2a6abf7158809cf4f3c").unwrap());
        let mut b: [u8; 16] = unhex("6bc1bee22e409f96e93d7e117393172a").unwrap().try_into().unwrap();
        k.encrypt_block(&mut b);
        assert_eq!(hex(&b), "3ad77bb40d7a3660a89ecaf32466ef97");
        k.decrypt_block(&mut b);
        assert_eq!(hex(&b), "6bc1bee22e409f96e93d7e117393172a");
    }

    #[test]
    fn matches_aes_crate_on_random_blocks() {
        use aes::cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
        let mut key = [0u8; 16];
        let mut block = [0u8; 16];
        for round in 0..200u32 {
            crate::util::secure_random_bytes(&mut key);
            crate::util::secure_random_bytes(&mut block);
            let ours = AesTable::new(&key);
            let theirs = aes::Aes128::new_from_slice(&key).unwrap();
            let mut a = block;
            ours.encrypt_block(&mut a);
            let mut b = Array::from(block);
            theirs.encrypt_block(&mut b);
            assert_eq!(&a[..], &b[..], "encrypt mismatch round {round}");
            ours.decrypt_block(&mut a);
            theirs.decrypt_block(&mut b);
            assert_eq!(&a[..], &b[..], "decrypt mismatch round {round}");
            assert_eq!(a, block);
        }
    }
}
