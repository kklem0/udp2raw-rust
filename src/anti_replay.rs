//! Sliding-window anti-replay, identical in behaviour to `anti_replay_t` in the C++.

use crate::consts::ANTI_REPLAY_WINDOW_SIZE;
use crate::util::secure_random_u64;

pub struct AntiReplay {
    max_packet_received: u64,
    window: Vec<u8>,
    next_send_seq: u64,
    disabled: bool,
}

impl AntiReplay {
    pub fn new(disabled: bool) -> AntiReplay {
        AntiReplay {
            max_packet_received: 0,
            window: vec![0u8; ANTI_REPLAY_WINDOW_SIZE as usize],
            // random first seq, leaving room before u64 wrap
            next_send_seq: secure_random_u64() / 10,
            disabled,
        }
    }

    /// Reset the receive side (a new connection / handshake).
    pub fn re_init(&mut self) {
        self.max_packet_received = 0;
    }

    pub fn next_seq_for_send(&mut self) -> u64 {
        let s = self.next_send_seq;
        self.next_send_seq = self.next_send_seq.wrapping_add(1);
        s
    }

    /// Returns true if `seq` is new and marks it as seen.
    pub fn is_valid(&mut self, seq: u64) -> bool {
        if self.disabled {
            return true;
        }
        let w = ANTI_REPLAY_WINDOW_SIZE;
        if seq == self.max_packet_received {
            false
        } else if seq > self.max_packet_received {
            if seq - self.max_packet_received >= w {
                self.window.iter_mut().for_each(|b| *b = 0);
                self.window[(seq % w) as usize] = 1;
            } else {
                let mut i = self.max_packet_received + 1;
                while i < seq {
                    self.window[(i % w) as usize] = 0;
                    i += 1;
                }
                self.window[(seq % w) as usize] = 1;
            }
            self.max_packet_received = seq;
            true
        } else {
            if self.max_packet_received - seq >= w {
                return false;
            }
            let slot = (seq % w) as usize;
            if self.window[slot] == 1 {
                false
            } else {
                self.window[slot] = 1;
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_window_semantics() {
        let mut a = AntiReplay::new(false);
        assert!(!a.is_valid(0)); // equal to initial max (0) => replay
        assert!(a.is_valid(1));
        assert!(!a.is_valid(1));
        assert!(a.is_valid(5));
        assert!(a.is_valid(3)); // inside window, unseen
        assert!(!a.is_valid(3));
        assert!(a.is_valid(5 + 3999)); // jump within window
        assert!(!a.is_valid(4)); // 4 < max-window? max=4004, 4004-4=4000 >= 4000 => too old
        assert!(a.is_valid(4004 + 10_000)); // far jump clears window
        assert!(!a.is_valid(4004)); // too old now
    }

    #[test]
    fn disabled_accepts_everything() {
        let mut a = AntiReplay::new(true);
        assert!(a.is_valid(7));
        assert!(a.is_valid(7));
    }

    #[test]
    fn send_seq_increments() {
        let mut a = AntiReplay::new(false);
        let s = a.next_seq_for_send();
        assert_eq!(a.next_seq_for_send(), s + 1);
        assert!(s < u64::MAX / 10 + 1);
    }
}
