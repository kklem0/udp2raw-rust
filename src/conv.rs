//! Conversation (multiplexed UDP flow) bookkeeping with LRU expiry — `conv_manager_t`.
//!
//! Client: `T` = the local UDP peer address. Server: `T` = the connected UDP socket
//! (fd + registration token).

use crate::consts::{CONV_CLEAR_INTERVAL_MS, CONV_CLEAR_MIN, CONV_CLEAR_RATIO, CONV_TIMEOUT_MS};
use crate::util::secure_random_u32_nz;
use std::collections::{BTreeSet, HashMap};
use std::hash::Hash;

pub struct ConvManager<T: Clone + Eq + Hash> {
    data_to_conv: HashMap<T, u32>,
    conv_to_data: HashMap<u32, T>,
    last_active: HashMap<u32, u64>,
    /// Ordered by (timestamp, conv): the first element is the least recently active.
    lru: BTreeSet<(u64, u32)>,
    last_clear_time: u64,
}

impl<T: Clone + Eq + Hash> Default for ConvManager<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone + Eq + Hash> ConvManager<T> {
    pub fn new() -> Self {
        ConvManager {
            data_to_conv: HashMap::new(),
            conv_to_data: HashMap::new(),
            last_active: HashMap::new(),
            lru: BTreeSet::new(),
            last_clear_time: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.conv_to_data.len()
    }
    pub fn is_empty(&self) -> bool {
        self.conv_to_data.is_empty()
    }

    pub fn new_conv(&self) -> u32 {
        loop {
            let c = secure_random_u32_nz();
            if !self.conv_to_data.contains_key(&c) {
                return c;
            }
        }
    }

    pub fn is_conv_used(&self, conv: u32) -> bool {
        self.conv_to_data.contains_key(&conv)
    }
    pub fn is_data_used(&self, data: &T) -> bool {
        self.data_to_conv.contains_key(data)
    }
    pub fn find_conv_by_data(&self, data: &T) -> Option<u32> {
        self.data_to_conv.get(data).copied()
    }
    pub fn find_data_by_conv(&self, conv: u32) -> Option<&T> {
        self.conv_to_data.get(&conv)
    }

    pub fn insert(&mut self, conv: u32, data: T, now: u64) {
        self.data_to_conv.insert(data.clone(), conv);
        self.conv_to_data.insert(conv, data);
        self.last_active.insert(conv, now);
        self.lru.insert((now, conv));
    }

    pub fn update_active_time(&mut self, conv: u32, now: u64) {
        if let Some(old) = self.last_active.get_mut(&conv) {
            if *old == now {
                return;
            }
            self.lru.remove(&(*old, conv));
            *old = now;
            self.lru.insert((now, conv));
        }
    }

    /// Remove one conv; returns its data so the caller can release resources.
    pub fn erase(&mut self, conv: u32) -> Option<T> {
        let data = self.conv_to_data.remove(&conv)?;
        self.data_to_conv.remove(&data);
        if let Some(ts) = self.last_active.remove(&conv) {
            self.lru.remove(&(ts, conv));
        }
        Some(data)
    }

    /// Drain everything (connection teardown); returns the data of all convs.
    pub fn clear(&mut self) -> Vec<T> {
        let all: Vec<T> = self.conv_to_data.values().cloned().collect();
        self.data_to_conv.clear();
        self.conv_to_data.clear();
        self.last_active.clear();
        self.lru.clear();
        all
    }

    /// Expire idle convs. Rate-limited to once per second; each pass inspects at most
    /// `size/30 + 1` entries to avoid latency spikes. Returns the expired (conv, data).
    pub fn clear_inactive(&mut self, now: u64) -> Vec<(u32, T)> {
        if now.saturating_sub(self.last_clear_time) <= CONV_CLEAR_INTERVAL_MS {
            return Vec::new();
        }
        self.last_clear_time = now;
        let size = self.lru.len();
        let num_to_clean = (size / CONV_CLEAR_RATIO + CONV_CLEAR_MIN).min(size);
        let mut out = Vec::new();
        for _ in 0..num_to_clean {
            let Some(&(ts, conv)) = self.lru.iter().next() else { break };
            if now.saturating_sub(ts) < CONV_TIMEOUT_MS {
                break;
            }
            if let Some(data) = self.erase(conv) {
                out.push((conv, data));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_lookup_erase() {
        let mut m: ConvManager<u64> = ConvManager::new();
        let c = m.new_conv();
        m.insert(c, 42, 1000);
        assert!(m.is_conv_used(c));
        assert!(m.is_data_used(&42));
        assert_eq!(m.find_conv_by_data(&42), Some(c));
        assert_eq!(m.find_data_by_conv(c), Some(&42));
        assert_eq!(m.erase(c), Some(42));
        assert!(m.is_empty());
    }

    #[test]
    fn expiry_is_lru_and_rate_limited() {
        let mut m: ConvManager<u64> = ConvManager::new();
        m.insert(1, 10, 0);
        m.insert(2, 20, 0);
        m.update_active_time(1, 5000);
        // first call at t=2000 is allowed (last_clear_time=0, 2000>1000) but nothing is old enough
        assert!(m.clear_inactive(2000).is_empty());
        // at 180_500 conv 2 (ts 0) is expired, conv 1 (ts 5000) is not
        let gone = m.clear_inactive(CONV_TIMEOUT_MS + 500);
        assert_eq!(gone, vec![(2, 20)]);
        // rate limited: immediately again returns nothing
        assert!(m.clear_inactive(CONV_TIMEOUT_MS + 600).is_empty());
        let gone = m.clear_inactive(CONV_TIMEOUT_MS + 5001 + 1001);
        assert_eq!(gone, vec![(1, 10)]);
    }
}
