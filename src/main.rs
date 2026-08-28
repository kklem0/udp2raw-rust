use udp2raw::config::{self, HELP_TEXT, ParseOutcome};
use udp2raw::logging;

/// The process arguments with any `-k`/`--key` value replaced by `<redacted>`, so the
/// password never reaches the `argv:` log. `--key-file` takes a path (not the secret) and is
/// left as-is. Returns the redacted line and whether a key was passed on the command line.
fn redact_argv(args: &[String]) -> (String, bool) {
    let mut out = Vec::with_capacity(args.len());
    let mut redacted = false;
    let mut skip_next = false;
    for a in args {
        if skip_next {
            out.push("<redacted>".to_string());
            skip_next = false;
            redacted = true;
        } else if a == "-k" || a == "--key" {
            out.push(a.clone());
            skip_next = true;
        } else if a.starts_with("--key=") {
            out.push("--key=<redacted>".to_string());
            redacted = true;
        } else if a.len() > 2 && a.starts_with("-k") && !a.starts_with("--") {
            out.push("-k<redacted>".to_string());
            redacted = true;
        } else {
            out.push(a.clone());
        }
    }
    (out.join(" "), redacted)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // provisional logger so option-parsing warnings are visible
    logging::init(4, true, false);
    let cfg = match config::parse_args(&args) {
        Ok(ParseOutcome::Run(c)) => c,
        Ok(ParseOutcome::Help) => {
            print!("{HELP_TEXT}");
            std::process::exit(0);
        }
        Ok(ParseOutcome::UnitTest) => match udp2raw::selftest::run() {
            Ok(()) => {
                println!("self-test passed");
                std::process::exit(0);
            }
            Err(e) => {
                println!("self-test FAILED: {e}");
                std::process::exit(1);
            }
        },
        Err(e) => {
            log::error!("{e}");
            print!("{HELP_TEXT}");
            std::process::exit(255);
        }
    };
    logging::init(cfg.log_level, cfg.log_color, cfg.log_position);
    let (argv_redacted, key_on_cmdline) = redact_argv(&args);
    log::info!("argv: {argv_redacted}");
    if key_on_cmdline {
        log::warn!("the key was passed with -k/--key and is visible in the process list (ps, /proc/*/cmdline); use --key-file (or a systemd credential) to keep it out");
    }
    log::info!(
        "important variables: log_level={}:{} raw_mode={} cipher_mode={} auth_mode={} key={} local_addr={} remote_addr={} socket_buf_size={} threads={}{}",
        cfg.log_level,
        logging::level_name(cfg.log_level),
        cfg.raw_mode,
        cfg.cipher_mode.name(),
        cfg.auth_mode.name(),
        "<redacted>",
        cfg.local_addr,
        cfg.remote,
        cfg.socket_buf_size,
        cfg.threads,
        if cfg.easy_faketcp { " easy_faketcp=1" } else { "" }
    );
    log::info!("key fingerprint (sha256[..4]): {} — both ends must match", udp2raw::crypto::fingerprint(cfg.key.as_bytes()));
    #[cfg(not(target_os = "linux"))]
    {
        log::error!("udp2raw-rust only runs on Linux (raw sockets + BPF); this build is a {} host", std::env::consts::OS);
        std::process::exit(255);
    }
    #[cfg(target_os = "linux")]
    {
        let code = linux::run(*cfg);
        if logging::color_enabled() {
            println!("{}", logging::RESET);
        }
        std::process::exit(code);
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;
    use udp2raw::config::Config;
    use udp2raw::crypto::{Crypto, Keys, fingerprint};
    use udp2raw::dns::{DnsConfig, Resolver};
    use udp2raw::endpoint::{EndpointController, EndpointOptions};
    use udp2raw::types::ProgramMode;
    use udp2raw::util::{now_ms, secure_random_u32_nz};
    use udp2raw::{client, iptables, server};

    static EXIT_FLAG: AtomicBool = AtomicBool::new(false);

    extern "C" fn on_signal(_sig: libc::c_int) {
        EXIT_FLAG.store(true, Ordering::Relaxed);
    }

    fn install_signals() {
        unsafe {
            libc::signal(libc::SIGPIPE, libc::SIG_IGN);
            for s in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
                libc::signal(s, on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t);
            }
        }
    }

    /// Client: decide the relay address to start with (DNS, then the cache, then
    /// `--bootstrap-addr`) and keep the controller for later re-resolution.
    fn bootstrap_endpoint(cfg: &mut Config) -> Result<EndpointController, i32> {
        let opts = EndpointOptions {
            allow_private: cfg.allow_private_endpoint,
            cache_file: cfg.endpoint_cache.clone(),
            bootstrap: cfg.bootstrap_addr,
            last_good_fallback: cfg.last_good_fallback.clone(),
            ..EndpointOptions::default()
        };
        let dns_overall_timeout_ms = if cfg.last_good_fallback.enabled {
            cfg.last_good_fallback.preferred_round_timeout_ms.min(10_000)
        } else {
            10_000
        };
        let dns = DnsConfig {
            servers: cfg.dns_servers.clone(),
            device: cfg.underlay_dev.clone(),
            timeout: Duration::from_millis(cfg.dns_timeout_ms),
            overall_timeout: Duration::from_millis(dns_overall_timeout_ms),
            allow_private: cfg.allow_private_endpoint,
        };
        if cfg.remote.is_dynamic() {
            log::info!("endpoint: resolving {} through {:?}{} (timeout {} ms, cache {})", cfg.remote, cfg.dns_servers, cfg.underlay_dev.as_deref().map_or(String::new(), |d| format!(" via {d}")), cfg.dns_timeout_ms, cfg.endpoint_cache.as_deref().map_or("off".to_string(), |p| p.display().to_string()));
            let p = &cfg.last_good_fallback;
            log::info!(
                "endpoint: authenticated-last-good fallback {} (after {} failed DNS handshakes, max {} pre-charged probes per answer, global capacity {}, cooldown {:.1}s, round {:.1}s, probation {:.1}s, rollback {:.1}s, startup-cache max age {:.1}s)",
                if p.enabled { "enabled" } else { "disabled" },
                p.after_failures,
                p.max_attempts,
                p.global_capacity,
                p.cooldown_ms as f64 / 1000.0,
                p.preferred_round_timeout_ms as f64 / 1000.0,
                p.probation_ms as f64 / 1000.0,
                p.rollback_window_ms as f64 / 1000.0,
                p.max_age_ms as f64 / 1000.0
            );
        }
        loop {
            match EndpointController::bootstrap(cfg.remote.clone(), Box::new(Resolver { cfg: dns.clone() }), opts.clone(), now_ms()) {
                Ok(ep) => {
                    cfg.remote_addr = ep.current();
                    return Ok(ep);
                }
                Err(e) if cfg.retry_on_error => {
                    log::warn!("endpoint: {e}; retry in 10 seconds");
                    for _ in 0..100 {
                        if EXIT_FLAG.load(Ordering::Relaxed) {
                            return Err(0);
                        }
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
                Err(e) => {
                    log::error!("endpoint: {e}");
                    return Err(255);
                }
            }
        }
    }

    pub fn run(mut cfg: Config) -> i32 {
        install_signals();
        if unsafe { libc::geteuid() } != 0 {
            log::warn!("root check failed, it seems like you are using a non-root account. we can try to continue, but it may fail. If you want to run udp2raw as non-root, you have to add iptables rule manually, and grant udp2raw CAP_NET_RAW capability, check README.md in repo for more info.");
        } else {
            log::warn!("you can run udp2raw with non-root account for better security. check README.md in repo for more info.");
        }
        let endpoint = match cfg.mode {
            ProgramMode::Client => match bootstrap_endpoint(&mut cfg) {
                Ok(ep) => Some(ep),
                Err(code) => return code,
            },
            ProgramMode::Server => None,
        };
        log::info!("remote_ip=[{}], make sure this is a vaild IP address", cfg.remote_addr.ip());

        let const_id = secure_random_u32_nz();
        log::info!("const_id:{const_id:x}");

        let keys = Keys::derive(&cfg.key, cfg.is_client());
        log::debug!("derived key fingerprints (sha256[..4]): normal={} cipher_enc={} cipher_dec={}", fingerprint(&keys.normal_key), fingerprint(&keys.cipher_key_encrypt), fingerprint(&keys.cipher_key_decrypt));
        let crypto = Arc::new(Crypto::with_backend(cfg.cipher_mode, cfg.auth_mode, cfg.cfb_legacy, keys, cfg.aes_backend));
        let (sc, why) = udp2raw::net::set_syscalls(cfg.syscalls);
        log::info!("syscalls: {} (requested {}; {})", sc.name(), cfg.syscalls.name(), why);
        if let Some(b) = crypto.aes_backend() {
            log::info!("aes backend: {} (cpu aes instructions: {})", b.name(), udp2raw::crypto::cpu_has_aes());
        }

        if cfg.clear_rules {
            iptables::clear_all(&cfg);
            return 255;
        }
        let pattern = iptables::pattern(&cfg);
        if cfg.gen_rule {
            iptables::print_generated_rule(&cfg, &pattern);
            return 0;
        }
        if cfg.gen_add {
            return match iptables::gen_add(&cfg, &pattern) {
                Ok(()) => 0,
                Err(e) => {
                    log::error!("{e}");
                    255
                }
            };
        }
        let ipt = if cfg.auto_rule {
            match iptables::Iptables::init(&cfg, &pattern, const_id, cfg.keep_rule) {
                Ok(i) => {
                    let i = Arc::new(i);
                    if cfg.keep_rule {
                        iptables::spawn_keep_thread(i.clone());
                    }
                    Some(i)
                }
                Err(e) => {
                    log::error!("{e}");
                    return 255;
                }
            }
        } else {
            log::warn!(" -a has not been set, make sure you have added the needed iptables rules manually");
            None
        };

        let result = match cfg.mode {
            ProgramMode::Client => client::run(cfg, crypto, const_id, &EXIT_FLAG, endpoint.expect("client endpoint"), ipt.clone()),
            ProgramMode::Server => server::run(cfg, crypto, const_id, &EXIT_FLAG),
        };
        if let Some(i) = &ipt {
            i.clear();
        }
        match result {
            Ok(()) => 0,
            Err(e) => {
                log::error!("{e}");
                255
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::redact_argv;

    fn v(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn redacts_every_key_form_but_not_paths() {
        let (r, k) = redact_argv(&v(&["-c", "-k", "secret", "-l", "1.2.3.4:5"]));
        assert_eq!(r, "-c -k <redacted> -l 1.2.3.4:5");
        assert!(k);
        assert_eq!(redact_argv(&v(&["--key", "s"])), ("--key <redacted>".to_string(), true));
        assert_eq!(redact_argv(&v(&["--key=hunter2"])), ("--key=<redacted>".to_string(), true));
        assert_eq!(redact_argv(&v(&["-ksecret"])), ("-k<redacted>".to_string(), true));
        // a key value that itself looks like a flag is still redacted (it follows -k)
        assert_eq!(redact_argv(&v(&["-k", "-l"])), ("-k <redacted>".to_string(), true));
        // --key-file is a path, not a secret
        assert_eq!(redact_argv(&v(&["--key-file", "/etc/udp2raw/key"])), ("--key-file /etc/udp2raw/key".to_string(), false));
        // nothing to redact
        assert_eq!(redact_argv(&v(&["-c", "-a", "--fix-gro"])), ("-c -a --fix-gro".to_string(), false));
    }
}
