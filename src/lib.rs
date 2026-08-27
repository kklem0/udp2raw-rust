//! udp2raw-rust — a wire-compatible Rust port of [udp2raw](https://github.com/wangyu-/udp2raw).
//!
//! The crate is split into platform-independent modules (crypto, wire framing, packet
//! header codecs, anti-replay, connection bookkeeping, config) that are unit-tested
//! everywhere, and Linux-only modules (`net`, `conn`, `faketcp`, `pipeline`, `client`,
//! `server`, `iptables`, `fifo`) that talk to raw sockets.

pub mod anti_replay;
pub mod config;
pub mod consts;
pub mod conv;
pub mod crypto;
pub mod logging;
pub mod packet;
pub mod selftest;
pub mod types;
pub mod util;
pub mod wire;

#[cfg(target_os = "linux")]
pub mod client;
#[cfg(target_os = "linux")]
pub mod conn;
#[cfg(target_os = "linux")]
pub mod faketcp;
#[cfg(target_os = "linux")]
pub mod fifo;
#[cfg(target_os = "linux")]
pub mod iptables;
#[cfg(target_os = "linux")]
pub mod net;
#[cfg(target_os = "linux")]
pub mod pipeline;
#[cfg(target_os = "linux")]
pub mod server;
