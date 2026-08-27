//! Protocol constants. Every value here mirrors the C++ implementation (`common.h`,
//! `misc.h`, `network.cpp`); changing one changes on-the-wire behaviour or timing.

/// Largest tunnel payload (before encryption) accepted in either direction.
pub const MAX_DATA_LEN: usize = 1800;
/// Working buffer size for one packet.
pub const BUF_LEN: usize = MAX_DATA_LEN + 400;
/// A raw packet with a link-level header may exceed 65535 bytes (GRO).
pub const HUGE_DATA_LEN: usize = 65535 + 100;
pub const HUGE_BUF_LEN: usize = HUGE_DATA_LEN + 100;

pub const MAX_HANDSHAKE_CONN_NUM: usize = 10000;
pub const MAX_READY_CONN_NUM: usize = 1000;
pub const ANTI_REPLAY_WINDOW_SIZE: u64 = 4000;
pub const MAX_CONV_NUM: usize = 10000;

pub const CLIENT_HANDSHAKE_TIMEOUT_MS: u64 = 5000;
pub const CLIENT_RETRY_INTERVAL_MS: u64 = 1000;
/// Server handshake timeout; longer than the client's so the client retries first.
pub const SERVER_HANDSHAKE_TIMEOUT_MS: u64 = CLIENT_HANDSHAKE_TIMEOUT_MS + 5000;

/// The conv garbage collector inspects 1/30 of all convs per pass.
pub const CONV_CLEAR_RATIO: usize = 30;
pub const CONN_CLEAR_RATIO: usize = 50;
pub const CONV_CLEAR_MIN: usize = 1;
pub const CONN_CLEAR_MIN: usize = 1;

pub const CONV_CLEAR_INTERVAL_MS: u64 = 1000;
pub const CONN_CLEAR_INTERVAL_MS: u64 = 1000;

pub const HEARTBEAT_INTERVAL_MS: u64 = 600;
/// Must be smaller than the heartbeat and retry intervals.
pub const TIMER_INTERVAL_MS: u64 = 400;

pub const CONV_TIMEOUT_MS: u64 = 180_000;
pub const CLIENT_CONN_TIMEOUT_MS: u64 = 10_000;
pub const CLIENT_CONN_UPLINK_TIMEOUT_MS: u64 = CLIENT_CONN_TIMEOUT_MS + 2000;
/// 60 s longer than the conv timeout so convs are destructed gradually.
pub const SERVER_CONN_TIMEOUT_MS: u64 = CONV_TIMEOUT_MS + 60_000;

pub const IPTABLES_RULE_KEEP_INTERVAL_S: u64 = 20;

/// FakeTCP advertised window: lower bound plus a random offset below `RECEIVE_WINDOW_RANDOM_RANGE`.
pub const RECEIVE_WINDOW_LOWER_BOUND: u32 = 40960;
pub const RECEIVE_WINDOW_RANDOM_RANGE: u32 = 512;
/// TCP window-scale option value advertised in SYN packets.
pub const WSCALE: u8 = 0x05;
/// MSS advertised in SYN packets (0x05b4).
pub const SYN_MSS: u16 = 1460;

pub const MAX_SEQ_MODE: i32 = 4;
pub const DEFAULT_SEQ_MODE: i32 = 3;

/// Default heartbeat payload length (`--hb-len`).
pub const DEFAULT_HB_LEN: usize = 1200;
pub const DEFAULT_MTU_WARN: usize = 1375;
pub const DEFAULT_SOCKET_BUF_SIZE: usize = 1024 * 1024;
pub const DEFAULT_TTL: u8 = 64;
pub const DEFAULT_MAX_RST_TO_SHOW: i32 = 15;
pub const DEFAULT_MAX_RST_ALLOWED: i32 = -1;

/// Packet type bytes inside a "safer" packet.
pub const TYPE_HEARTBEAT: u8 = b'h';
pub const TYPE_DATA: u8 = b'd';
/// Marker byte inside a "bare" (handshake) packet.
pub const BARE_MARKER: u8 = b'b';
