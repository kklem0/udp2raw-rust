use udp2raw::config::{self, HELP_TEXT, ParseOutcome};
use udp2raw::logging;

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
        Ok(ParseOutcome::UnitTest) => {
            println!("unit tests live in the cargo test suite: run `cargo test`");
            std::process::exit(0);
        }
        Err(e) => {
            log::error!("{e}");
            print!("{HELP_TEXT}");
            std::process::exit(255);
        }
    };
    logging::init(cfg.log_level, cfg.log_color, cfg.log_position);
    log::info!("argv: {}", args.join(" "));
    log::info!(
        "important variables: log_level={}:{} raw_mode={} cipher_mode={} auth_mode={} key={} local_addr={} remote_addr={} socket_buf_size={} threads={}{}",
        cfg.log_level,
        logging::level_name(cfg.log_level),
        cfg.raw_mode,
        cfg.cipher_mode.name(),
        cfg.auth_mode.name(),
        cfg.key,
        cfg.local_addr,
        cfg.remote_addr,
        cfg.socket_buf_size,
        cfg.threads,
        if cfg.easy_faketcp { " easy_faketcp=1" } else { "" }
    );
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
    use udp2raw::config::Config;
    use udp2raw::crypto::{Crypto, Keys};
    use udp2raw::types::ProgramMode;
    use udp2raw::util::{hex, secure_random_u32_nz};
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

    pub fn run(cfg: Config) -> i32 {
        install_signals();
        if unsafe { libc::geteuid() } != 0 {
            log::warn!("root check failed, it seems like you are using a non-root account. we can try to continue, but it may fail. If you want to run udp2raw as non-root, you have to add iptables rule manually, and grant udp2raw CAP_NET_RAW capability, check README.md in repo for more info.");
        } else {
            log::warn!("you can run udp2raw with non-root account for better security. check README.md in repo for more info.");
        }
        log::info!("remote_ip=[{}], make sure this is a vaild IP address", cfg.remote_addr.ip());

        let const_id = secure_random_u32_nz();
        log::info!("const_id:{const_id:x}");

        let keys = Keys::derive(&cfg.key, cfg.is_client());
        log::debug!("normal_key={} cipher_key_encrypt={} cipher_key_decrypt={}", hex(&keys.normal_key), hex(&keys.cipher_key_encrypt), hex(&keys.cipher_key_decrypt));
        let crypto = Arc::new(Crypto::new(cfg.cipher_mode, cfg.auth_mode, cfg.cfb_legacy, keys));

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
            ProgramMode::Client => client::run(cfg, crypto, const_id, &EXIT_FLAG),
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
