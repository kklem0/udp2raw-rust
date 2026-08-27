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
/// 3/4) a kernel built with `CONFIG_ARM64_SW_TTBR0_PAN` implements PAN by switching TTBR0
/// around each of those accesses, which costs ~1-2k cycles a piece — measured on a Pi 4:
/// +10k instructions and +10 % CPU per packet with `mmsg`. `Auto` therefore picks `Single`
/// on aarch64 CPUs without LSE atomics (which arrived together with PAN in ARMv8.1) unless
/// the running kernel's config (`/boot/config-<release>`) says software PAN is off, and
/// `Mmsg` everywhere else.
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

    /// `Auto` resolved for this CPU and kernel, with the reason.
    pub fn resolve(self) -> (Syscalls, &'static str) {
        match self {
            Syscalls::Auto => {
                let lse = cpu_has_lse();
                decide(lse, if lse { None } else { kernel_sw_pan() })
            }
            m => (m, "requested"),
        }
    }
}

/// The `Auto` rule. `has_lse`: ARMv8.1+ CPU, i.e. hardware PAN. `sw_pan`: whether the
/// kernel was built with software PAN (`None` = unknown; assumed on, as every stock arm64
/// distribution kernel has it).
pub fn decide(has_lse: bool, sw_pan: Option<bool>) -> (Syscalls, &'static str) {
    if has_lse {
        return (Syscalls::Mmsg, "cpu has LSE atomics: ARMv8.1+ with hardware PAN");
    }
    match sw_pan {
        Some(false) => (Syscalls::Mmsg, "ARMv8.0 cpu, kernel built without software PAN"),
        Some(true) => (Syscalls::Single, "ARMv8.0 cpu, kernel uses software PAN (CONFIG_ARM64_SW_TTBR0_PAN)"),
        None => (Syscalls::Single, "ARMv8.0 cpu, kernel config not readable: assuming software PAN"),
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

/// Whether the running kernel was built with `CONFIG_ARM64_SW_TTBR0_PAN`, from
/// `/boot/config-<release>` (Debian/Ubuntu layout); `None` when that cannot be read.
pub fn kernel_sw_pan() -> Option<bool> {
    #[cfg(target_os = "linux")]
    {
        let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").ok()?;
        let text = std::fs::read_to_string(format!("/boot/config-{}", release.trim())).ok()?;
        sw_pan_from_config(&text)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Parse a kernel `.config` for `CONFIG_ARM64_SW_TTBR0_PAN`.
pub fn sw_pan_from_config(text: &str) -> Option<bool> {
    for line in text.lines() {
        match line.trim() {
            "CONFIG_ARM64_SW_TTBR0_PAN=y" => return Some(true),
            "# CONFIG_ARM64_SW_TTBR0_PAN is not set" => return Some(false),
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod syscalls_tests {
    use super::*;

    #[test]
    fn auto_rule() {
        assert_eq!(decide(true, None).0, Syscalls::Mmsg);
        assert_eq!(decide(true, Some(true)).0, Syscalls::Mmsg);
        assert_eq!(decide(false, Some(true)).0, Syscalls::Single);
        assert_eq!(decide(false, None).0, Syscalls::Single);
        assert_eq!(decide(false, Some(false)).0, Syscalls::Mmsg);
        assert_ne!(Syscalls::Auto.resolve().0, Syscalls::Auto);
        assert_eq!(Syscalls::Single.resolve(), (Syscalls::Single, "requested"));
        assert_eq!(Syscalls::parse("mmsg"), Some(Syscalls::Mmsg));
        assert_eq!(Syscalls::parse("batch"), None);
    }

    #[test]
    fn kernel_config_parsing() {
        assert_eq!(sw_pan_from_config("CONFIG_ARM64_PAN=y\nCONFIG_ARM64_SW_TTBR0_PAN=y\n"), Some(true));
        assert_eq!(sw_pan_from_config("# CONFIG_ARM64_SW_TTBR0_PAN is not set\n"), Some(false));
        assert_eq!(sw_pan_from_config("CONFIG_ARM64_PAN=y\n"), None);
        assert_eq!(sw_pan_from_config(""), None);
    }
}
