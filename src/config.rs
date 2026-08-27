//! Command line / conf-file parsing. Option names and semantics follow the C++ `misc.cpp`
//! (`process_arg`, `load_config`, `parse_conf_line`); `--threads` is new.

use crate::consts::*;
use crate::crypto::{AuthMode, CipherMode};
use crate::types::{ProgramMode, RawMode};
use clap::Parser;
use std::net::{IpAddr, SocketAddr};

#[derive(Parser, Debug, Default)]
#[command(name = "udp2raw", disable_help_flag = true, disable_version_flag = true, no_binary_name = true)]
struct Cli {
    #[arg(short = 'c')]
    client: bool,
    #[arg(short = 's')]
    server: bool,
    #[arg(short = 'l')]
    local: Option<String>,
    #[arg(short = 'r')]
    remote: Option<String>,
    #[arg(short = 'k', long = "key")]
    key: Option<String>,
    #[arg(short = 'a', long = "auto-rule")]
    auto_rule: bool,
    #[arg(short = 'g', long = "gen-rule")]
    gen_rule: bool,
    #[arg(long = "gen-add")]
    gen_add: bool,
    #[arg(long = "keep-rule")]
    keep_rule: bool,
    #[arg(long)]
    clear: bool,
    #[arg(long = "wait-lock")]
    wait_lock: bool,
    #[arg(long = "raw-mode")]
    raw_mode: Option<String>,
    #[arg(long = "cipher-mode")]
    cipher_mode: Option<String>,
    #[arg(long = "auth-mode")]
    auth_mode: Option<String>,
    #[arg(long = "disable-anti-replay")]
    disable_anti_replay: bool,
    #[arg(long = "fix-gro")]
    fix_gro: bool,
    #[arg(long = "source-ip")]
    source_ip: Option<String>,
    #[arg(long = "source-port")]
    source_port: Option<u16>,
    /// Only here so the option is documented; it is expanded before clap runs.
    #[arg(long = "conf-file")]
    conf_file: Option<String>,
    #[arg(long)]
    fifo: Option<String>,
    #[arg(long = "log-level")]
    log_level: Option<i32>,
    #[arg(long = "log-position")]
    log_position: bool,
    #[arg(long = "disable-color")]
    disable_color: bool,
    #[arg(long = "enable-color")]
    enable_color: bool,
    #[arg(long = "disable-bpf")]
    disable_bpf: bool,
    #[arg(long)]
    dev: Option<String>,
    #[arg(long = "sock-buf")]
    sock_buf: Option<usize>,
    #[arg(long = "force-sock-buf")]
    force_sock_buf: bool,
    #[arg(long = "seq-mode")]
    seq_mode: Option<i32>,
    #[arg(long = "lower-level")]
    lower_level: Option<String>,
    #[arg(long = "hb-mode")]
    hb_mode: Option<i32>,
    #[arg(long = "hb-len")]
    hb_len: Option<usize>,
    #[arg(long = "mtu-warn")]
    mtu_warn: Option<usize>,
    #[arg(long = "max-rst-to-show")]
    max_rst_to_show: Option<i32>,
    #[arg(long = "max-rst-allowed")]
    max_rst_allowed: Option<i32>,
    #[arg(long = "set-ttl")]
    set_ttl: Option<u8>,
    #[arg(long = "retry-on-error")]
    retry_on_error: bool,
    #[arg(long = "random-drop")]
    random_drop: Option<u32>,
    #[arg(long = "easy-tcp")]
    easy_tcp: bool,
    #[arg(long = "dns-resolve")]
    dns_resolve: bool,
    #[arg(long = "simple-rule")]
    simple_rule: bool,
    #[arg(long)]
    debug: bool,
    #[arg(long = "unit-test")]
    unit_test: bool,
    /// Number of crypto worker threads (0 = do everything on the I/O thread).
    #[arg(long)]
    threads: Option<usize>,
    #[arg(short = 'h', long)]
    help: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LowerLevel {
    Auto,
    Manual { if_name: String, dest_mac: [u8; 6] },
}

#[derive(Clone, Debug)]
pub struct Config {
    pub mode: ProgramMode,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub key: String,
    pub raw_mode: RawMode,
    /// `--raw-mode easy-faketcp` / `--easy-tcp`: use a kernel TCP socket for the 3-way handshake.
    pub easy_faketcp: bool,
    pub cipher_mode: CipherMode,
    pub cfb_legacy: bool,
    pub auth_mode: AuthMode,
    pub disable_anti_replay: bool,
    pub fix_gro: bool,
    pub source_ip: Option<IpAddr>,
    pub source_port: Option<u16>,
    pub fifo: Option<String>,
    pub log_level: i32,
    pub log_position: bool,
    pub log_color: bool,
    pub disable_bpf: bool,
    pub dev: Option<String>,
    /// bytes
    pub socket_buf_size: usize,
    pub force_socket_buf: bool,
    pub seq_mode: i32,
    pub lower_level: Option<LowerLevel>,
    pub hb_mode: i32,
    pub hb_len: usize,
    pub mtu_warn: usize,
    pub max_rst_to_show: i32,
    pub max_rst_allowed: i32,
    pub ttl: u8,
    pub retry_on_error: bool,
    pub random_drop: u32,
    pub auto_rule: bool,
    pub gen_rule: bool,
    pub gen_add: bool,
    pub keep_rule: bool,
    pub clear_rules: bool,
    pub wait_lock: bool,
    pub debug: bool,
    pub threads: usize,
}

impl Config {
    pub fn is_client(&self) -> bool {
        self.mode == ProgramMode::Client
    }
    /// The address family of the raw socket: client follows -r, server follows -l.
    pub fn raw_is_v6(&self) -> bool {
        match self.mode {
            ProgramMode::Client => self.remote_addr.is_ipv6(),
            ProgramMode::Server => self.local_addr.is_ipv6(),
        }
    }
}

pub const HELP_TEXT: &str = "udp2raw-rust
repository: https://github.com/kklem0/udp2raw-rust (port of https://github.com/wangyu-/udp2raw)

usage:
    run as client : ./this_program -c -l local_listen_ip:local_port -r server_address:server_port  [options]
    run as server : ./this_program -s -l server_listen_ip:server_port -r remote_address:remote_port  [options]

common options,these options must be same on both side:
    --raw-mode            <string>        available values:faketcp(default),udp,icmp and easy-faketcp
    -k,--key              <string>        password to gen symetric key,default:\"secret key\"
    --cipher-mode         <string>        available values:aes128cfb,aes128cbc(default),xor,none
    --auth-mode           <string>        available values:hmac_sha1,md5(default),crc32,simple,none
    -a,--auto-rule                        auto add (and delete) iptables rule
    -g,--gen-rule                         generate iptables rule then exit,so that you can copy and
                                          add it manually.overrides -a
    --disable-anti-replay                 disable anti-replay,not suggested
    --fix-gro                             try to fix huge packet caused by GRO. this option is at an early stage.
                                          make sure client and server are at same version.
client options:
    --source-ip           <ip>            force source-ip for raw socket
    --source-port         <port>          force source-port for raw socket,tcp/udp only
                                          this option disables port changing while re-connecting
other options:
    --threads             <number>        crypto worker threads, 0 = single-threaded (default: auto)
    --conf-file           <string>        read options from a configuration file instead of command line.
                                          check example.conf in repo for format
    --fifo                <string>        use a fifo(named pipe) for sending commands to the running program,
                                          check readme.md in repository for supported commands.
    --log-level           <number>        0:never    1:fatal   2:error   3:warn
                                          4:info (default)     5:debug   6:trace
    --log-position                        enable file name,function name,line number in log
    --disable-color                       disable log color
    --disable-bpf                         disable the kernel space filter,most time its not necessary
                                          unless you suspect there is a bug
    --dev                 <string>        bind raw socket to a device, not necessary but improves performance
    --sock-buf            <number>        buf size for socket,>=10 and <=10240,unit:kbyte,default:1024
    --force-sock-buf                      bypass system limitation while setting sock-buf
    --seq-mode            <number>        seq increase mode for faketcp:
                                          0:static header,do not increase seq and ack_seq
                                          1:increase seq for every packet,simply ack last seq
                                          2:increase seq randomly, about every 3 packets,simply ack last seq
                                          3:simulate an almost real seq/ack procedure(default)
                                          4:similiar to 3,but do not consider TCP Option Window_Scale,
                                          maybe useful when firewall doesnt support TCP Option
    --lower-level         <string>        send packets at OSI level 2, format:'if_name#dest_mac_adress'
                                          ie:'eth0#00:23:45:67:89:b9'.or try '--lower-level auto' to obtain
                                          the parameter automatically,specify it manually if 'auto' failed
    --wait-lock                           wait for xtables lock while invoking iptables, need iptables v1.4.20+
    --gen-add                             generate iptables rule and add it permanently,then exit.overrides -g
    --keep-rule                           monitor iptables and auto re-add if necessary.implys -a
    --hb-len              <number>        length of heart-beat packet, >=0 and <=1500
    --mtu-warn            <number>        mtu warning threshold, unit:byte, default:1375
    --clear                               clear any iptables rules added by this program.overrides everything
    --retry-on-error                      retry on error, allow to start udp2raw before network is initialized
    -h,--help                             print this help message
";

/// Split one conf-file line into at most two tokens, like the C++ `parse_conf_line`.
pub fn parse_conf_line(line: &str) -> Result<Vec<String>, String> {
    let s = line.trim_matches(|c| c == ' ' || c == '\t');
    if s.is_empty() || s.starts_with('#') {
        return Ok(Vec::new());
    }
    if !s.starts_with('-') {
        return Err(format!("line :<{s}> not begin with '-'"));
    }
    match s.find([' ', '\t']) {
        None => Ok(vec![s.to_string()]),
        Some(i) => {
            let (a, b) = s.split_at(i);
            let b = b.trim_start_matches([' ', '\t']);
            Ok(vec![a.to_string(), b.to_string()])
        }
    }
}

/// Expand `--conf-file` (exactly once, not nested) into the argument list.
pub fn expand_conf_file(args: &[String]) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut conf: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--conf-file" {
            if conf.is_some() {
                return Err("duplicated --conf-file option".into());
            }
            let Some(path) = args.get(i + 1) else {
                return Err("--conf-file need a parameter".into());
            };
            if path.starts_with('-') {
                return Err("--conf-file need a parameter".into());
            }
            conf = Some(path.clone());
            i += 2;
        } else {
            out.push(args[i].clone());
            i += 1;
        }
    }
    if let Some(path) = conf {
        let text = std::fs::read_to_string(&path).map_err(|e| format!("conf_file {path} open failed,reason :{e}"))?;
        for line in text.lines() {
            for tok in parse_conf_line(line)? {
                if tok == "--conf-file" {
                    return Err("cant have --conf-file in a config file".into());
                }
                out.push(tok);
            }
        }
        log::info!("configuration loaded from {path}");
    }
    Ok(out)
}

fn parse_socket_addr(s: &str, what: &str) -> Result<SocketAddr, String> {
    let a: SocketAddr = s.parse().map_err(|_| format!("invalid parameter for {what} ,{s},should be ip:port or [ipv6]:port"))?;
    if a.port() == 22 {
        return Err("port 22 not allowed".into());
    }
    Ok(a)
}

fn parse_mac(s: &str) -> Result<[u8; 6], String> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return Err(format!("invalid mac address {s}"));
    }
    let mut mac = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(p, 16).map_err(|_| format!("invalid mac address {s}"))?;
    }
    Ok(mac)
}

pub enum ParseOutcome {
    Run(Box<Config>),
    Help,
    UnitTest,
}

pub fn default_threads() -> usize {
    let n = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1) as i64;
    (n - 2).clamp(0, 4) as usize
}

/// Parse the process arguments (without argv[0]).
pub fn parse_args(raw_args: &[String]) -> Result<ParseOutcome, String> {
    if raw_args.iter().any(|a| a == "--unit-test") {
        return Ok(ParseOutcome::UnitTest);
    }
    if raw_args.is_empty() || raw_args.iter().any(|a| a == "-h" || a == "--help") {
        return Ok(ParseOutcome::Help);
    }
    for a in raw_args {
        if a.is_empty() {
            return Err("found an empty string in options".into());
        }
        if a == "-" || a == "--" {
            return Err(format!("invaild option '{a}' in argv"));
        }
    }
    let args = expand_conf_file(raw_args)?;
    let cli = Cli::try_parse_from(&args).map_err(|e| e.to_string().trim().to_string())?;

    if cli.client && cli.server {
        return Err("-s /-c has already been set,conflict".into());
    }
    let mode = if cli.client {
        ProgramMode::Client
    } else if cli.server {
        ProgramMode::Server
    } else {
        return Err("error: -c /-s  hasnt been set".into());
    };
    let local_addr = parse_socket_addr(cli.local.as_deref().ok_or("error: -l not found")?, "-l")?;
    let remote_addr = parse_socket_addr(cli.remote.as_deref().ok_or("error: -r not found")?, "-r")?;

    let (mut raw_mode, mut easy) = (RawMode::FakeTcp, false);
    if let Some(s) = &cli.raw_mode {
        (raw_mode, easy) = RawMode::parse(s).ok_or_else(|| format!("no such raw_mode {s}"))?;
    }
    if cli.easy_tcp {
        easy = true;
    }
    let (mut cipher_mode, mut cfb_legacy) = (CipherMode::Aes128Cbc, false);
    if let Some(s) = &cli.cipher_mode {
        (cipher_mode, cfb_legacy) = CipherMode::parse(s).ok_or_else(|| format!("no such cipher_mode {s}"))?;
        if cfb_legacy {
            log::warn!("aes128cfb_0 is used");
        }
    }
    let mut auth_mode = AuthMode::Md5;
    let mut disable_anti_replay = cli.disable_anti_replay;
    if let Some(s) = &cli.auth_mode {
        auth_mode = AuthMode::parse(s).ok_or_else(|| format!("no such auth_mode {s}"))?;
        if auth_mode == AuthMode::None {
            disable_anti_replay = true;
        }
    }
    let source_ip = match &cli.source_ip {
        Some(s) => Some(s.parse::<IpAddr>().map_err(|_| format!("ip_addr {s} is invalid"))?),
        None => None,
    };
    let socket_buf_size = match cli.sock_buf {
        Some(kb) if (10..=10 * 1024).contains(&kb) => kb * 1024,
        Some(_) => return Err("sock-buf value must be between 1 and 10240 (kbyte)".into()),
        None => DEFAULT_SOCKET_BUF_SIZE,
    };
    let seq_mode = cli.seq_mode.unwrap_or(DEFAULT_SEQ_MODE);
    if !(0..=MAX_SEQ_MODE).contains(&seq_mode) {
        return Err(format!("seq_mode value must be between 0 and {MAX_SEQ_MODE}"));
    }
    let lower_level = match &cli.lower_level {
        None => None,
        Some(s) if s == "auto" => Some(LowerLevel::Auto),
        Some(s) => {
            let (if_name, mac) = s.split_once('#').ok_or("lower-level parameter invaild,check help page for format")?;
            Some(LowerLevel::Manual { if_name: if_name.to_string(), dest_mac: parse_mac(mac)? })
        }
    };
    let hb_mode = cli.hb_mode.unwrap_or(1);
    if hb_mode != 0 && hb_mode != 1 {
        return Err("hb-mode must be 0 or 1".into());
    }
    let hb_len = cli.hb_len.unwrap_or(DEFAULT_HB_LEN);
    if hb_len > 1500 {
        return Err("hb-len must be >=0 and <=1500".into());
    }
    let mtu_warn = cli.mtu_warn.unwrap_or(DEFAULT_MTU_WARN);
    if mtu_warn == 0 {
        return Err("mtu-warn must be > 0".into());
    }
    let random_drop = cli.random_drop.unwrap_or(0);
    if random_drop > 10000 {
        return Err("random_drop must be between 0 10000".into());
    }
    let log_level = cli.log_level.unwrap_or(4);
    if !(0..=6).contains(&log_level) {
        return Err("invalid log_level".into());
    }
    let mut auto_rule = cli.auto_rule;
    let mut gen_rule = cli.gen_rule;
    if auto_rule && gen_rule {
        log::warn!(" -g overrides -a");
        auto_rule = false;
    }
    if cli.gen_add && gen_rule {
        log::warn!(" --gen-add overrides -g");
        gen_rule = false;
    }
    if cli.keep_rule && !auto_rule {
        auto_rule = true;
        gen_rule = false;
        log::warn!(" --keep_rule implys -a");
    }
    if auto_rule && easy {
        log::error!("-a,--auto-rule is not supposed to be used with easyfaketcp mode, you are likely making a mistake, but we can try to continue");
    }
    if cli.keep_rule && easy {
        log::error!("--keep-rule is not supposed to be used with easyfaketcp mode, you are likely making a mistake, but we can try to continue");
    }
    let local_v6 = local_addr.is_ipv6();
    if local_v6 != remote_addr.is_ipv6() && lower_level.is_none() {
        // The C++ allows mixed families (raw socket follows one side, UDP side the other).
        log::debug!("local and remote addresses use different address families");
    }
    let cfg = Config {
        mode,
        local_addr,
        remote_addr,
        key: cli.key.clone().unwrap_or_else(|| "secret key".to_string()),
        raw_mode,
        easy_faketcp: easy,
        cipher_mode,
        cfb_legacy,
        auth_mode,
        disable_anti_replay,
        fix_gro: cli.fix_gro,
        source_ip,
        source_port: cli.source_port,
        fifo: cli.fifo.clone(),
        log_level,
        log_position: cli.log_position,
        log_color: !cli.disable_color,
        disable_bpf: cli.disable_bpf,
        dev: cli.dev.clone(),
        socket_buf_size,
        force_socket_buf: cli.force_sock_buf,
        seq_mode,
        lower_level,
        hb_mode,
        hb_len,
        mtu_warn,
        max_rst_to_show: cli.max_rst_to_show.unwrap_or(DEFAULT_MAX_RST_TO_SHOW),
        max_rst_allowed: cli.max_rst_allowed.unwrap_or(DEFAULT_MAX_RST_ALLOWED),
        ttl: cli.set_ttl.unwrap_or(DEFAULT_TTL),
        retry_on_error: cli.retry_on_error,
        random_drop,
        auto_rule,
        gen_rule,
        gen_add: cli.gen_add,
        keep_rule: cli.keep_rule,
        clear_rules: cli.clear,
        wait_lock: cli.wait_lock,
        debug: cli.debug,
        threads: cli.threads.unwrap_or_else(default_threads),
    };
    Ok(ParseOutcome::Run(Box::new(cfg)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn conf_line_parsing_matches_cpp_unit_test() {
        assert_eq!(parse_conf_line("---aaa").unwrap(), vec!["---aaa"]);
        assert_eq!(parse_conf_line("--aaa bbb").unwrap(), vec!["--aaa", "bbb"]);
        assert_eq!(parse_conf_line("-a bbb").unwrap(), vec!["-a", "bbb"]);
        assert_eq!(parse_conf_line(" \t \t \t-a\t \t \t bbbbb\t \t \t ").unwrap(), vec!["-a", "bbbbb"]);
        assert_eq!(parse_conf_line("# comment").unwrap(), Vec::<String>::new());
        assert_eq!(parse_conf_line("").unwrap(), Vec::<String>::new());
        assert!(parse_conf_line("aaa").is_err());
    }

    #[test]
    fn client_defaults() {
        let out = parse_args(&args("-c -l 127.0.0.1:3333 -r 44.55.66.77:4096 -k pw --raw-mode faketcp -a")).unwrap();
        let ParseOutcome::Run(c) = out else { panic!() };
        assert_eq!(c.mode, ProgramMode::Client);
        assert_eq!(c.key, "pw");
        assert_eq!(c.cipher_mode, CipherMode::Aes128Cbc);
        assert_eq!(c.auth_mode, AuthMode::Md5);
        assert_eq!(c.seq_mode, 3);
        assert_eq!(c.hb_len, 1200);
        assert_eq!(c.hb_mode, 1);
        assert!(c.auto_rule && !c.gen_rule);
        assert!(!c.raw_is_v6());
        assert_eq!(c.socket_buf_size, 1024 * 1024);
    }

    #[test]
    fn server_v6_and_modes() {
        let out = parse_args(&args("-s -l [::]:4096 -r 127.0.0.1:7777 --cipher-mode aes128cfb_0 --auth-mode none --raw-mode easy-faketcp --lower-level eth0#00:23:45:67:89:b9 --threads 3 --sock-buf 2048 --seq-mode 4")).unwrap();
        let ParseOutcome::Run(c) = out else { panic!() };
        assert_eq!(c.mode, ProgramMode::Server);
        assert!(c.raw_is_v6());
        assert_eq!(c.cipher_mode, CipherMode::Aes128Cfb);
        assert!(c.cfb_legacy);
        assert!(c.disable_anti_replay, "auth none disables anti-replay");
        assert!(c.easy_faketcp);
        assert_eq!(c.lower_level, Some(LowerLevel::Manual { if_name: "eth0".into(), dest_mac: [0x00, 0x23, 0x45, 0x67, 0x89, 0xb9] }));
        assert_eq!(c.threads, 3);
        assert_eq!(c.socket_buf_size, 2048 * 1024);
        assert_eq!(c.seq_mode, 4);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(parse_args(&args("-c -s -l 1.1.1.1:1 -r 2.2.2.2:2")).is_err());
        assert!(parse_args(&args("-c -l 1.1.1.1:22 -r 2.2.2.2:2")).is_err());
        assert!(parse_args(&args("-c -l 1.1.1.1:1")).is_err());
        assert!(parse_args(&args("-c -l 1.1.1.1:1 -r 2.2.2.2:2 --cipher-mode rot13")).is_err());
        assert!(parse_args(&args("-c -l 1.1.1.1:1 -r 2.2.2.2:2 --bogus")).is_err());
        assert!(parse_args(&args("-c -l 1.1.1.1:1 -r 2.2.2.2:2 --sock-buf 5")).is_err());
        assert!(matches!(parse_args(&args("-h")), Ok(ParseOutcome::Help)));
        assert!(matches!(parse_args(&[]), Ok(ParseOutcome::Help)));
    }

    #[test]
    fn conf_file_expansion() {
        let dir = std::env::temp_dir().join(format!("udp2raw-conf-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.conf");
        std::fs::write(&path, "# This is client\n-c\n-l 127.0.0.1:56789\n-r 45.66.77.88:45678\n-k my_awesome_password\n--raw-mode faketcp\n--log-level 4\n").unwrap();
        let out = parse_args(&[String::from("--conf-file"), path.to_string_lossy().to_string()]).unwrap();
        let ParseOutcome::Run(c) = out else { panic!() };
        assert_eq!(c.key, "my_awesome_password");
        assert_eq!(c.remote_addr.port(), 45678);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
