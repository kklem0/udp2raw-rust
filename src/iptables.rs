//! iptables rule management (`-a`, `-g`, `--gen-add`, `--keep-rule`, `--clear`,
//! `--wait-lock`) — a port of the `iptables_*` functions in `misc.cpp`. The kernel must
//! not answer our fake TCP/ICMP packets, so a DROP rule for them is inserted into INPUT
//! via a private chain named `udp2rawDwrW_<const_id>_C0`.

use crate::config::Config;
use crate::consts::IPTABLES_RULE_KEEP_INTERVAL_S;
use crate::types::RawMode;
use std::io;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

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

/// The match part of the DROP rule.
pub fn pattern(cfg: &Config) -> String {
    let v6 = cfg.raw_is_v6();
    if cfg.is_client() {
        let ip = cfg.remote_addr.ip();
        let port = cfg.remote_addr.port();
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

pub struct Iptables {
    cmd: String,
    chains: [String; 2],
    rule_keep_add: [String; 2],
    rule_keep_del: [String; 2],
    keep: bool,
    keep_index: AtomicUsize,
}

impl Iptables {
    /// `iptables_rule_init` (`-a`): create the private chain(s) and the INPUT jump.
    pub fn init(cfg: &Config, pattern: &str, const_id: u32, keep: bool) -> io::Result<Iptables> {
        let cmd = base_command(cfg);
        let chains = [format!("udp2rawDwrW_{const_id:x}_C0"), format!("udp2rawDwrW_{const_id:x}_C1")];
        let rule_keep = [format!("{pattern} -j {}", chains[0]), format!("{pattern} -j {}", chains[1])];
        let rule_keep_add = [format!("{cmd}-I INPUT {}", rule_keep[0]), format!("{cmd}-I INPUT {}", rule_keep[1])];
        let rule_keep_del = [format!("{cmd}-D INPUT {}", rule_keep[0]), format!("{cmd}-D INPUT {}", rule_keep[1])];
        let it = Iptables { cmd, chains, rule_keep_add, rule_keep_del, keep, keep_index: AtomicUsize::new(0) };
        for i in 0..=(keep as usize) {
            run_command(&format!("{}-N {}", it.cmd, it.chains[i]), true);
            run_command(&format!("{}-F {}", it.cmd, it.chains[i]), true);
            run_command(&format!("{}-I {} -j DROP", it.cmd, it.chains[i]), true);
            if !run_command(&it.rule_keep_add[i], true).0 {
                return Err(io::Error::other(format!("auto added iptables failed by: {}", it.rule_keep_add[i])));
            }
        }
        log::warn!("auto added iptables rules");
        Ok(it)
    }

    /// `keep_iptables_rule`: re-create the alternate chain and re-insert the jump, so the
    /// rule survives firewall reloads on boxes without `iptables --check`.
    pub fn keep(&self) {
        log::debug!("keep_iptables_rule begin");
        let i = (self.keep_index.fetch_add(1, Ordering::Relaxed) + 1) % 2;
        run_command(&format!("{}-N {}", self.cmd, self.chains[i]), false);
        if !run_command(&format!("{}-F {}", self.cmd, self.chains[i]), false).0 {
            log::warn!("iptables -F failed {i}");
        }
        if !run_command(&format!("{}-I {} -j DROP", self.cmd, self.chains[i]), false).0 {
            log::warn!("iptables -I failed {i}");
        }
        if !run_command(&self.rule_keep_del[i], false).0 {
            log::warn!("rule_keep_del failed {i}");
        }
        run_command(&self.rule_keep_del[i], false); // twice, in case it fails for unknown random reason
        if !run_command(&self.rule_keep_add[i], true).0 {
            log::warn!("rule_keep_add failed {i}");
        }
        log::debug!("keep_iptables_rule end");
    }

    /// `clear_iptables_rule`: remove what `init` added (called at exit).
    pub fn clear(&self) {
        for i in 0..=(self.keep as usize) {
            run_command(&self.rule_keep_del[i], true);
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
