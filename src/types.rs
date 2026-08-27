//! Small shared enums.

use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RawMode {
    FakeTcp,
    Udp,
    Icmp,
}

impl RawMode {
    pub fn parse(s: &str) -> Option<(RawMode, bool)> {
        // Returns (mode, easy_faketcp)
        match s {
            "faketcp" => Some((RawMode::FakeTcp, false)),
            "easyfaketcp" | "easy_faketcp" | "easy-faketcp" => Some((RawMode::FakeTcp, true)),
            "udp" => Some((RawMode::Udp, false)),
            "icmp" => Some((RawMode::Icmp, false)),
            _ => None,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            RawMode::FakeTcp => "faketcp",
            RawMode::Udp => "udp",
            RawMode::Icmp => "icmp",
        }
    }
}

impl fmt::Display for RawMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgramMode {
    Client,
    Server,
}

impl ProgramMode {
    pub fn is_client(self) -> bool {
        self == ProgramMode::Client
    }
}
