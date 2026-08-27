//! Packet header codecs (pure functions over byte slices; no sockets).

pub mod checksum;
pub mod icmp;
pub mod ip;
pub mod tcp;
pub mod udp;
