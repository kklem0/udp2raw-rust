//! iptables rule management (`-a`, `-g`, `--gen-add`, `--keep-rule`, `--clear`,
//! `--wait-lock`) — a port of the `iptables_*` functions in `misc.cpp`. The kernel must
//! not answer our fake TCP/ICMP packets, so a DROP rule for them is inserted into INPUT
//! via a private chain named `udp2rawDwrW_<const_id>_C0`.

use crate::config::Config;
use crate::consts::IPTABLES_RULE_KEEP_INTERVAL_S;
use crate::types::RawMode;
use std::io;
use std::net::SocketAddr;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// Run `cmd` through `sh -c`. Returns (success, stdout). `show_log` mirrors the C++ flag:
/// failures are logged at warn level (else debug) and stderr is folded into stdout.
pub fn run_command(cmd: &str, show_log: bool) -> (bool, String) {
    let full = if show_log { cmd.to_string() } else { format!("{cmd} 2>&1 ") };
    log::debug!("run_command {full}");
    match Command::new("sh").arg("-c").arg(&full).output() {
        Ok(out) => {
            let s = String::from_utf8_lossy(&out.stdout).into_owned();
            if !out.status.success() {
                if show_log {
                    log::warn!("commnad {cmd} ,exit status {:?}", out.status.code());
                } else {
                    log::debug!("commnad {cmd} ,exit status {:?}", out.status.code());
                }
                (false, s)
            } else {
                (true, s)
            }
        }
        Err(e) => {
            log::warn!("command {cmd} failed to start: {e}");
            (false, String::new())
        }
    }
}

pub fn base_command(cfg: &Config) -> String {
    let mut c = if cfg.raw_is_v6() { "ip6tables ".to_string() } else { "iptables ".to_string() };
    if cfg.wait_lock {
        c.push_str("-w ");
    }
    c
}

/// The match part of the DROP rule for the configured remote (client) or listener (server).
pub fn pattern(cfg: &Config) -> String {
    pattern_for(cfg, cfg.remote_addr)
}

/// The match part of the DROP rule; `remote` is the relay address a client talks to (it
/// changes when a hostname `-r` resolves to a new address).
pub fn pattern_for(cfg: &Config, remote: SocketAddr) -> String {
    let v6 = cfg.raw_is_v6();
    if cfg.is_client() {
        let ip = remote.ip();
        let port = remote.port();
        match cfg.raw_mode {
            RawMode::FakeTcp => format!("-s {ip} -p tcp -m tcp --sport {port}"),
            RawMode::Udp => format!("-s {ip} -p udp -m udp --sport {port}"),
            RawMode::Icmp => {
                if v6 {
                    format!("-s {ip} -p icmpv6 --icmpv6-type 129")
                } else {
                    format!("-s {ip} -p icmp --icmp-type 0")
                }
            }
        }
    } else {
        let mut p = String::new();
        if !cfg.local_addr.ip().is_unspecified() {
            p.push_str(&format!("-d {} ", cfg.local_addr.ip()));
        }
        let port = cfg.local_addr.port();
        p.push_str(&match cfg.raw_mode {
            RawMode::FakeTcp => format!("-p tcp -m tcp --dport {port}"),
            RawMode::Udp => format!("-p udp -m udp --dport {port}"),
            RawMode::Icmp => {
                if v6 {
                    "-p icmpv6 --icmpv6-type 128".to_string()
                } else {
                    "-p icmp --icmp-type 8".to_string()
                }
            }
        });
        p
    }
}

/// `--clear`: remove every rule and chain this program ever added.
pub fn clear_all(cfg: &Config) {
    let cmd = base_command(cfg);
    let (r1, _) = run_command(&format!("{cmd}-S|sed -n '/udp2rawDwrW/p'|sed -n 's/^-A/{cmd}-D/p'|sh"), true);
    let (r2, _) = run_command(&format!("{cmd}-S|sed -n '/udp2rawDwrW/p'|sed -n 's/^-N/{cmd}-X/p'|sh"), true);
    log::info!("tried to clear all iptables rule created previously,return value {} {}", r1 as i32, r2 as i32);
}

/// `-g`: print the rule and let the user add it.
pub fn print_generated_rule(cfg: &Config, pattern: &str) {
    println!("generated iptables rule:");
    println!("{}-I INPUT {pattern} -j DROP", base_command(cfg));
}

/// `--gen-add`: add a permanent rule through the shared chain `udp2rawDwrW_C`.
pub fn gen_add(cfg: &Config, pattern: &str) -> io::Result<()> {
    let cmd = base_command(cfg);
    let chain = "udp2rawDwrW_C";
    let rule_keep = format!("{pattern} -j {chain}");
    let add = format!("{cmd}-I INPUT {rule_keep}");
    let del = format!("{cmd}-D INPUT {rule_keep}");
    run_command(&format!("{cmd}-N {chain}"), false);
    run_command(&format!("{cmd}-F {chain}"), true);
    run_command(&format!("{cmd}-I {chain} -j DROP"), true);
    run_command(&del, false);
    run_command(&del, false);
    if !run_command(&add, true).0 {
        return Err(io::Error::other(format!("auto added iptables failed by: {add}")));
    }
    Ok(())
}

/// The `-a` rules of one process: private DROP chain(s) plus one INPUT jump per active
/// match pattern. A client with a hostname `-r` adds a pattern for a new relay address
/// before trying it and removes the old one only after the new address authenticated (or
/// the attempt is rolled back), so the kernel never answers a relay's fake TCP.
pub struct Iptables {
    cmd: String,
    chains: [String; 2],
    keep: bool,
    keep_index: AtomicUsize,
    /// Match patterns currently jumping to the chain, in insertion order.
    patterns: Mutex<Vec<String>>,
}

impl Iptables {
    /// `iptables_rule_init` (`-a`): create the private chain(s) and the INPUT jump.
    pub fn init(cfg: &Config, pattern: &str, const_id: u32, keep: bool) -> io::Result<Iptables> {
        let cmd = base_command(cfg);
        let chains = [format!("udp2rawDwrW_{const_id:x}_C0"), format!("udp2rawDwrW_{const_id:x}_C1")];
        let it = Iptables { cmd, chains, keep, keep_index: AtomicUsize::new(0), patterns: Mutex::new(Vec::new()) };
        for i in 0..=(keep as usize) {
            run_command(&format!("{}-N {}", it.cmd, it.chains[i]), true);
            run_command(&format!("{}-F {}", it.cmd, it.chains[i]), true);
            run_command(&format!("{}-I {} -j DROP", it.cmd, it.chains[i]), true);
            let add = it.jump_add(i, pattern);
            if !run_command(&add, true).0 {
                return Err(io::Error::other(format!("auto added iptables failed by: {add}")));
            }
        }
        it.patterns.lock().unwrap().push(pattern.to_string());
        log::warn!("auto added iptables rules");
        Ok(it)
    }

    fn jump_add(&self, chain: usize, pattern: &str) -> String {
        format!("{}-I INPUT {pattern} -j {}", self.cmd, self.chains[chain])
    }

    fn jump_del(&self, chain: usize, pattern: &str) -> String {
        format!("{}-D INPUT {pattern} -j {}", self.cmd, self.chains[chain])
    }

    /// The chain the most recent `keep` round (or `init`) pointed INPUT at.
    fn active_chain(&self) -> usize {
        if self.keep { self.keep_index.load(Ordering::Relaxed) % 2 } else { 0 }
    }

    /// Add the INPUT jump for one more match pattern (a new relay address). Idempotent.
    pub fn add_pattern(&self, pattern: &str) -> io::Result<()> {
        let mut pats = self.patterns.lock().unwrap();
        if pats.iter().any(|p| p == pattern) {
            return Ok(());
        }
        let add = self.jump_add(self.active_chain(), pattern);
        if !run_command(&add, true).0 {
            return Err(io::Error::other(format!("iptables rule for the new endpoint failed: {add}")));
        }
        pats.push(pattern.to_string());
        log::info!("iptables: added rule [{pattern}]");
        Ok(())
    }

    /// Remove the INPUT jumps of one match pattern (from both chains, however many times
    /// they were added). Unknown patterns are ignored.
    pub fn del_pattern(&self, pattern: &str) {
        let mut pats = self.patterns.lock().unwrap();
        let Some(pos) = pats.iter().position(|p| p == pattern) else { return };
        pats.remove(pos);
        for i in 0..2 {
            let del = self.jump_del(i, pattern);
            for _ in 0..4 {
                if !run_command(&del, false).0 {
                    break;
                }
            }
        }
        log::info!("iptables: removed rule [{pattern}]");
    }

    pub fn patterns(&self) -> Vec<String> {
        self.patterns.lock().unwrap().clone()
    }

    /// `keep_iptables_rule`: re-create the alternate chain and re-insert the jumps, so the
    /// rules survive firewall reloads on boxes without `iptables --check`.
    pub fn keep(&self) {
        log::debug!("keep_iptables_rule begin");
        let pats = self.patterns.lock().unwrap();
        let i = (self.keep_index.fetch_add(1, Ordering::Relaxed) + 1) % 2;
        run_command(&format!("{}-N {}", self.cmd, self.chains[i]), false);
        if !run_command(&format!("{}-F {}", self.cmd, self.chains[i]), false).0 {
            log::warn!("iptables -F failed {i}");
        }
        if !run_command(&format!("{}-I {} -j DROP", self.cmd, self.chains[i]), false).0 {
            log::warn!("iptables -I failed {i}");
        }
        for pattern in pats.iter() {
            let del = self.jump_del(i, pattern);
            if !run_command(&del, false).0 {
                log::warn!("rule_keep_del failed {i}");
            }
            run_command(&del, false); // twice, in case it fails for unknown random reason
            if !run_command(&self.jump_add(i, pattern), true).0 {
                log::warn!("rule_keep_add failed {i}");
            }
        }
        log::debug!("keep_iptables_rule end");
    }

    /// `clear_iptables_rule`: remove everything `init`/`add_pattern` added (called at exit).
    pub fn clear(&self) {
        let pats = self.patterns.lock().unwrap();
        for i in 0..=(self.keep as usize) {
            for pattern in pats.iter() {
                run_command(&self.jump_del(i, pattern), true);
            }
            run_command(&format!("{}-F {}", self.cmd, self.chains[i]), true);
            run_command(&format!("{}-X {}", self.cmd, self.chains[i]), true);
        }
    }
}

/// `--keep-rule`: re-add the rule every 20 s from a background thread.
pub fn spawn_keep_thread(ipt: Arc<Iptables>) {
    std::thread::Builder::new()
        .name("udp2raw-keep-rule".into())
        .spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(IPTABLES_RULE_KEEP_INTERVAL_S));
            ipt.keep();
        })
        .expect("spawn keep-rule thread");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ParseOutcome, parse_args};

    fn cfg(s: &str) -> Config {
        let args: Vec<String> = s.split_whitespace().map(String::from).collect();
        match parse_args(&args).unwrap() {
            ParseOutcome::Run(c) => *c,
            _ => panic!(),
        }
    }

    #[test]
    fn client_pattern_follows_the_remote_address() {
        let c = cfg("-c -l 127.0.0.1:7000 -r relay.example:8443 --dns-server 1.1.1.1");
        assert_eq!(pattern_for(&c, "47.243.1.1:8443".parse().unwrap()), "-s 47.243.1.1 -p tcp -m tcp --sport 8443");
        assert_eq!(pattern_for(&c, "47.243.2.2:8443".parse().unwrap()), "-s 47.243.2.2 -p tcp -m tcp --sport 8443");
        let u = cfg("-c -l 127.0.0.1:7000 -r 47.243.1.1:8443 --raw-mode udp");
        assert_eq!(pattern(&u), "-s 47.243.1.1 -p udp -m udp --sport 8443");
        let s = cfg("-s -l 0.0.0.0:8443 -r 127.0.0.1:51820");
        assert_eq!(pattern(&s), "-p tcp -m tcp --dport 8443");
    }
}
