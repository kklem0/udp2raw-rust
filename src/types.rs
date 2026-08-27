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

/// How the I/O thread hands packets to the kernel: one `recvmmsg`/`sendmmsg` per batch, or
/// one `recvfrom`/`sendto` per packet.
///
/// The multi-message calls save syscall entries but touch the caller's `mmsghdr`, iovec,
/// address, `msg_namelen`, `msg_flags`, `msg_controllen` and `msg_len` for *every* message
/// (about 8 user-memory accesses per received packet vs 3 for `recvfrom`, 5 per sent packet vs
/// 2 for `sendto`). On ARMv8.0 cores without hardware PAN (Cortex-A53/A72, e.g. Raspberry Pi
/// 3/4) the kernel implements PAN by switching TTBR0 around each of those accesses, which
/// costs ~1-2k cycles a piece — measured on a Pi 4: +10k instructions and +10 % CPU per packet
/// with `mmsg`. `Auto` therefore picks `Single` on aarch64 CPUs without LSE atomics (which
/// arrived with PAN in ARMv8.1) and `Mmsg` everywhere else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Syscalls {
    Auto,
    Mmsg,
    Single,
}

impl Syscalls {
    pub fn parse(s: &str) -> Option<Syscalls> {
        match s {
            "auto" => Some(Syscalls::Auto),
            "mmsg" => Some(Syscalls::Mmsg),
            "single" => Some(Syscalls::Single),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Syscalls::Auto => "auto",
            Syscalls::Mmsg => "mmsg",
            Syscalls::Single => "single",
        }
    }

    /// `Auto` resolved for this CPU.
    pub fn resolve(self) -> Syscalls {
        match self {
            Syscalls::Auto => {
                if cpu_has_lse() {
                    Syscalls::Mmsg
                } else {
                    Syscalls::Single
                }
            }
            m => m,
        }
    }
}

/// Whether the CPU has the ARMv8.1 LSE atomics (a proxy for hardware PAN); always true on
/// other architectures.
pub fn cpu_has_lse() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        std::arch::is_aarch64_feature_detected!("lse")
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        true
    }
}
