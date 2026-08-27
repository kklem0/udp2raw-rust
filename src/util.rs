//! Time, randomness, byte-order and hex helpers.

use std::cell::RefCell;
use std::fs::File;
use std::io::Read;
use std::sync::OnceLock;
use std::time::Instant;

/// Milliseconds since process start (monotonic). The C++ used wall-clock time; only
/// differences matter, plus the low 32 bits are used as the TCP timestamp option.
pub fn now_ms() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    let start = START.get_or_init(Instant::now);
    start.elapsed().as_millis() as u64
}

pub fn now_us() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    let start = START.get_or_init(Instant::now);
    start.elapsed().as_micros() as u64
}

thread_local! {
    static URANDOM: RefCell<Option<File>> = const { RefCell::new(None) };
    static FAST_RNG: RefCell<Xoshiro256> = RefCell::new(Xoshiro256::from_os());
}

/// Fill `buf` from the OS CSPRNG (`/dev/urandom`). Used for ids, initial sequence
/// numbers, handshake nonces — anything an attacker must not predict.
pub fn secure_random_bytes(buf: &mut [u8]) {
    URANDOM.with(|cell| {
        let mut slot = cell.borrow_mut();
        if slot.is_none() {
            *slot = Some(File::open("/dev/urandom").expect("open /dev/urandom"));
        }
        slot.as_mut().unwrap().read_exact(buf).expect("read /dev/urandom");
    });
}

pub fn secure_random_u32() -> u32 {
    let mut b = [0u8; 4];
    secure_random_bytes(&mut b);
    u32::from_ne_bytes(b)
}

pub fn secure_random_u64() -> u64 {
    let mut b = [0u8; 8];
    secure_random_bytes(&mut b);
    u64::from_ne_bytes(b)
}

/// Non-zero random u32 (ids must never be zero: zero means "unset" in the handshake).
pub fn secure_random_u32_nz() -> u32 {
    loop {
        let v = secure_random_u32();
        if v != 0 {
            return v;
        }
    }
}

/// xoshiro256** — fast, non-cryptographic. Used for per-packet cosmetics (TCP window
/// jitter, random port selection) where the C++ paid a `read(/dev/urandom)` syscall.
pub struct Xoshiro256 {
    s: [u64; 4],
}

impl Xoshiro256 {
    pub fn from_os() -> Self {
        let mut seed = [0u8; 32];
        secure_random_bytes(&mut seed);
        let mut s = [0u64; 4];
        for (i, w) in s.iter_mut().enumerate() {
            *w = u64::from_le_bytes(seed[i * 8..i * 8 + 8].try_into().unwrap());
        }
        if s.iter().all(|&x| x == 0) {
            s[0] = 0x9E3779B97F4A7C15;
        }
        Xoshiro256 { s }
    }

    pub fn next_u64(&mut self) -> u64 {
        let s = &mut self.s;
        let result = s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = s[1] << 17;
        s[2] ^= s[0];
        s[3] ^= s[1];
        s[1] ^= s[2];
        s[0] ^= s[3];
        s[2] ^= t;
        s[3] = s[3].rotate_left(45);
        result
    }

    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }
}

pub fn fast_random_u32() -> u32 {
    FAST_RNG.with(|r| r.borrow_mut().next_u32())
}

pub fn fast_random_u64() -> u64 {
    FAST_RNG.with(|r| r.borrow_mut().next_u64())
}

#[inline]
pub fn read_u16_be(p: &[u8]) -> u16 {
    u16::from_be_bytes([p[0], p[1]])
}
#[inline]
pub fn read_u32_be(p: &[u8]) -> u32 {
    u32::from_be_bytes([p[0], p[1], p[2], p[3]])
}
#[inline]
pub fn read_u64_be(p: &[u8]) -> u64 {
    u64::from_be_bytes(p[..8].try_into().unwrap())
}
#[inline]
pub fn write_u16_be(p: &mut [u8], v: u16) {
    p[..2].copy_from_slice(&v.to_be_bytes());
}
#[inline]
pub fn write_u32_be(p: &mut [u8], v: u32) {
    p[..4].copy_from_slice(&v.to_be_bytes());
}
#[inline]
pub fn write_u64_be(p: &mut [u8], v: u64) {
    p[..8].copy_from_slice(&v.to_be_bytes());
}

/// Serial-number comparison, identical to the C++ `larger_than_u32`.
#[inline]
pub fn larger_than_u32(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}
#[inline]
pub fn larger_than_u16(a: u16, b: u16) -> bool {
    (a.wrapping_sub(b) as i16) > 0
}

pub fn hex(bytes: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(D[(b >> 4) as usize] as char);
        s.push(D[(b & 15) as usize] as char);
    }
    s
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if s == "-" {
        return Some(Vec::new());
    }
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    for i in (0..b.len()).step_by(2) {
        let hi = (b[i] as char).to_digit(16)?;
        let lo = (b[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

/// A free list of reusable packet buffers (single-thread use).
pub struct BufPool {
    free: Vec<Vec<u8>>,
    buf_cap: usize,
    max_free: usize,
}

impl BufPool {
    pub fn new(buf_cap: usize, max_free: usize) -> BufPool {
        BufPool { free: Vec::with_capacity(max_free), buf_cap, max_free }
    }

    /// An empty buffer with at least `buf_cap` capacity.
    pub fn take(&mut self) -> Vec<u8> {
        self.free.pop().unwrap_or_else(|| Vec::with_capacity(self.buf_cap))
    }

    pub fn recycle(&mut self, mut b: Vec<u8>) {
        if self.free.len() < self.max_free && b.capacity() >= self.buf_cap {
            b.clear();
            self.free.push(b);
        }
    }
}

/// Constant-time equality for MAC tags.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b) {
        acc |= x ^ y;
    }
    acc == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serial_compare() {
        assert!(larger_than_u32(1, 0));
        assert!(!larger_than_u32(0, 1));
        assert!(larger_than_u32(0, 0xffff_ffff)); // wrap-around
        assert!(!larger_than_u32(5, 5));
        assert!(larger_than_u16(0, 0xffff));
    }

    #[test]
    fn hex_roundtrip() {
        let v = vec![0u8, 1, 0xab, 0xff];
        assert_eq!(unhex(&hex(&v)).unwrap(), v);
        assert_eq!(unhex("-").unwrap(), Vec::<u8>::new());
        assert!(unhex("abc").is_none());
    }

    #[test]
    fn randomness_smoke() {
        assert_ne!(secure_random_u64(), secure_random_u64());
        assert_ne!(secure_random_u32_nz(), 0);
        let a = fast_random_u64();
        let b = fast_random_u64();
        assert_ne!(a, b);
    }
}
