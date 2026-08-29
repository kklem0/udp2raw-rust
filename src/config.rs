//! Command line / conf-file parsing. Option names and semantics follow the C++ `misc.cpp`
//! (`process_arg`, `load_config`, `parse_conf_line`); `--threads` is new.

use crate::consts::*;
use crate::crypto::{AesBackend, AuthMode, CipherMode};
use crate::dns::check_endpoint_ip;
use crate::endpoint::{EndpointSpec, LastGoodFallbackPolicy};
use crate::types::{ProgramMode, RawMode, Syscalls};
use clap::Parser;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

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
    /// Read the password from a file instead of `-k` (keeps it out of the process list;
    /// point it at a systemd credential, e.g. `--key-file %d/udp2raw-key`).
    #[arg(long = "key-file")]
    key_file: Option<String>,
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
    /// Accepted for compatibility; a hostname in -r always resolves.
    #[arg(long = "dns-resolve")]
    dns_resolve: bool,
    /// DNS server for a hostname -r, `ip` or `ip:port` (repeatable, tried in order).
    #[arg(long = "dns-server")]
    dns_server: Vec<String>,
    /// Per-server DNS timeout in milliseconds.
    #[arg(long = "dns-timeout")]
    dns_timeout: Option<u64>,
    /// Native interface for DNS queries and relay traffic (`SO_BINDTODEVICE` + host routes).
    #[arg(long = "underlay-dev")]
    underlay_dev: Option<String>,
    /// Gateway on the underlay for the relay's host routes (default: learned from the route to the bootstrap address).
    #[arg(long = "underlay-gateway")]
    underlay_gateway: Option<String>,
    /// Accept RFC 1918 / CGNAT addresses from DNS.
    #[arg(long = "allow-private-endpoint")]
    allow_private_endpoint: bool,
    /// Last-known-good address file for a hostname -r (`none` disables).
    #[arg(long = "endpoint-cache")]
    endpoint_cache: Option<String>,
    /// Literal IPv4 to start with when DNS and the cache are both unavailable.
    #[arg(long = "bootstrap-addr")]
    bootstrap_addr: Option<String>,
    /// Enable bounded authenticated last-known-good rollback for hostname endpoints.
    #[arg(long = "last-good-fallback")]
    last_good_fallback: bool,
    /// Failed DNS-candidate handshake cycles before probing authenticated last-good.
    #[arg(long = "last-good-fallback-after")]
    last_good_fallback_after: Option<u32>,
    /// Failed last-good probes allowed per unchanged DNS answer.
    #[arg(long = "last-good-fallback-max-attempts")]
    last_good_fallback_max_attempts: Option<u32>,
    /// Seconds before another failed last-good probe is permitted.
    #[arg(long = "last-good-fallback-cooldown")]
    last_good_fallback_cooldown: Option<u64>,
    /// Maximum age in seconds of a cached authentication proof used for fallback.
    #[arg(long = "last-good-fallback-max-age")]
    last_good_fallback_max_age: Option<u64>,
    /// Global persisted old-address probe capacity across changing DNS answers.
    #[arg(long = "last-good-fallback-global-attempts")]
    last_good_fallback_global_attempts: Option<u32>,
    /// Seconds required to refill one persisted global old-address probe token.
    #[arg(long = "last-good-fallback-global-refill")]
    last_good_fallback_global_refill: Option<u64>,
    /// Overall seconds allowed for one preferred DNS candidate handshake round.
    #[arg(long = "last-good-fallback-round-timeout")]
    last_good_fallback_round_timeout: Option<u64>,
    /// Minimum span of authenticated payload evidence before FIFO promotion is accepted.
    #[arg(long = "last-good-fallback-probation")]
    last_good_fallback_probation: Option<u64>,
    /// Maximum seconds the previous committed endpoint remains available for rollback.
    #[arg(long = "last-good-fallback-rollback-window")]
    last_good_fallback_rollback_window: Option<u64>,
    #[arg(long = "simple-rule")]
    simple_rule: bool,
    #[arg(long)]
    debug: bool,
    #[arg(long = "unit-test")]
    unit_test: bool,
    /// Number of crypto worker threads (0 = do everything on the I/O thread).
    #[arg(long)]
    threads: Option<usize>,
    /// AES implementation: auto (default), hw, table, fixslice.
    #[arg(long = "aes-backend")]
    aes_backend: Option<String>,
    /// Socket syscalls: auto (default), mmsg, single.
    #[arg(long = "syscalls")]
    syscalls: Option<String>,
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
    /// The address in use at startup. For a hostname `-r` this is `0.0.0.0:port` until the
    /// first resolution in `main` replaces it; the client tracks later changes itself.
    pub remote_addr: SocketAddr,
    /// What `-r` said: a literal or a hostname to keep resolving.
    pub remote: EndpointSpec,
    /// `--dns-server`, in order.
    pub dns_servers: Vec<SocketAddr>,
    pub dns_timeout_ms: u64,
    pub underlay_dev: Option<String>,
    pub underlay_gateway: Option<Ipv4Addr>,
    pub allow_private_endpoint: bool,
    pub endpoint_cache: Option<PathBuf>,
    pub bootstrap_addr: Option<Ipv4Addr>,
    pub last_good_fallback: LastGoodFallbackPolicy,
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
    pub aes_backend: AesBackend,
    pub syscalls: Syscalls,
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
                                          (visible in the process list; prefer --key-file)
    --key-file            <path>          read the password from a file instead of -k. The file's
                                          content is the key (one trailing newline is stripped).
                                          For a systemd credential: LoadCredential=udp2raw-key:/path
                                          and --key-file %d/udp2raw-key . Rust build only; the key
                                          derivation and wire format are unchanged, so it interops
                                          with a -k peer using the same password.
    --cipher-mode         <string>        available values:aes128cfb,aes128cbc(default),xor,none,
                                          chacha20poly1305 (udp2raw-rust only, both ends; AEAD, no --auth-mode)
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
    --aes-backend         <string>        auto(default),hw,table,fixslice. auto = CPU AES instructions
                                          if present, otherwise table-driven software AES
    --syscalls            <string>        auto(default),mmsg,single. mmsg = recvmmsg/sendmmsg per batch,
                                          single = recvfrom/sendto per packet. auto = single on ARMv8.0
                                          CPUs (Cortex-A53/A72: no hardware PAN, so the kernel's software
                                          PAN makes every user-memory access in a syscall expensive)
                                          unless the kernel config says software PAN is off, mmsg otherwise
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
    -r host:port          (client)        a hostname is resolved through --dns-server at startup, whenever a
                                          failed session reconnects, at expired-TTL reconnects, or when forced;
                                          server -r remains numeric
    --dns-server          <ip[:port]>     DNS server for a hostname -r; repeat to add more (tried in order)
    --dns-timeout         <ms>            per-server DNS timeout (default 2000)
    --underlay-dev        <string>        native interface for DNS and relay traffic: SO_BINDTODEVICE on the
                                          sockets and a /32 route per relay address (implies --dev if unset)
    --underlay-gateway    <ip>            next hop on --underlay-dev for those routes (default: learned)
    --allow-private-endpoint              accept RFC 1918 / CGNAT addresses from DNS
    --endpoint-cache      <path|none>     last-known-good address file (default /var/lib/udp2raw/endpoint_<host>_<port>)
    --bootstrap-addr      <ip>            address to start with if DNS and the cache are both unavailable
    --last-good-fallback                  opt in to bounded authenticated last-good rollback (default off;
                                          requires a hostname, --endpoint-cache and --fifo)
    --last-good-fallback-after <count>    failed DNS-candidate handshakes before trying recent last-good (default 3)
    --last-good-fallback-max-attempts <count>
                                          pre-charged old-address probes per unchanged DNS answer (default 2)
    --last-good-fallback-cooldown <sec>   delay between failed old-address probes (default 300)
    --last-good-fallback-max-age <sec>    maximum cache age eligible for fallback (default 86400)
    --last-good-fallback-global-attempts <count>
                                          persisted token capacity across changing DNS answers (default 4)
    --last-good-fallback-global-refill <sec>
                                          seconds to refill one global probe token (default 900)
    --last-good-fallback-round-timeout <sec>
                                          overall preferred-candidate handshake deadline (default 30)
    --last-good-fallback-probation <sec>  authenticated payload evidence span before promotion (default 30)
    --last-good-fallback-rollback-window <sec>
                                          maximum probation/rollback window (default 300)
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

/// `ip` or `ip:port` / `[ipv6]:port` for `--dns-server`; the port defaults to 53.
fn parse_dns_server(s: &str) -> Result<SocketAddr, String> {
    if let Ok(a) = s.parse::<SocketAddr>() {
        return Ok(a);
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, 53));
    }
    Err(format!("invalid --dns-server {s}, expected ip or ip:port"))
}

/// Read the password from a file (`--key-file`, incl. a systemd credential). The content is
/// the key verbatim except one trailing newline (`\n` or `\r\n`) is stripped, so
/// `echo secret > key` works. Errors on a missing/unreadable file, non-UTF-8, or an empty
/// key (almost always a broken credential — safer to refuse than to run with no key).
fn read_key_file(path: &str) -> Result<String, String> {
    let mut bytes = std::fs::read(path).map_err(|e| format!("--key-file {path}: {e}"))?;
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    if bytes.is_empty() {
        return Err(format!("--key-file {path} produced an empty key"));
    }
    String::from_utf8(bytes).map_err(|_| format!("--key-file {path}: key is not valid UTF-8"))
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

fn bounded_u32(name: &str, value: u32, min: u32, max: u32) -> Result<u32, String> {
    if (min..=max).contains(&value) {
        Ok(value)
    } else {
        Err(format!("{name} must be between {min} and {max}"))
    }
}

fn bounded_u64(name: &str, value: u64, min: u64, max: u64) -> Result<u64, String> {
    if (min..=max).contains(&value) {
        Ok(value)
    } else {
        Err(format!("{name} must be between {min} and {max}"))
    }
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
    let remote_str = cli.remote.as_deref().ok_or("error: -r not found")?;
    let remote = if mode == ProgramMode::Client {
        EndpointSpec::parse(remote_str).map_err(|e| format!("invalid parameter for -r ,{e}"))?
    } else if remote_str.parse::<SocketAddr>().is_ok() {
        EndpointSpec::Literal(parse_socket_addr(remote_str, "-r")?)
    } else {
        return Err(format!(
            "invalid parameter for -r ,{remote_str},server -r must be ip:port or [ipv6]:port (hostnames are supported for the client only)"
        ));
    };
    if remote.port() == 22 {
        return Err("port 22 not allowed".into());
    }
    let remote_addr = match &remote {
        EndpointSpec::Literal(a) => *a,
        EndpointSpec::Hostname { port, .. } => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), *port),
    };
    let mut dns_servers = Vec::new();
    for s in &cli.dns_server {
        dns_servers.push(parse_dns_server(s)?);
    }
    if remote.is_dynamic() && dns_servers.is_empty() {
        return Err("-r with a hostname needs at least one --dns-server".into());
    }
    let dns_timeout_ms = cli.dns_timeout.unwrap_or(2000);
    if !(100..=30_000).contains(&dns_timeout_ms) {
        return Err("--dns-timeout must be between 100 and 30000 ms".into());
    }
    let underlay_gateway = match &cli.underlay_gateway {
        Some(g) => Some(g.parse::<Ipv4Addr>().map_err(|_| format!("--underlay-gateway {g} is not an ipv4 address"))?),
        None => None,
    };
    if underlay_gateway.is_some() && cli.underlay_dev.is_none() {
        return Err("--underlay-gateway needs --underlay-dev".into());
    }
    if let (Some(dev), Some(underlay)) = (&cli.dev, &cli.underlay_dev) {
        if dev != underlay {
            return Err(format!(
                "--dev {dev} conflicts with --underlay-dev {underlay}; relay send and receive traffic must use the same interface"
            ));
        }
    }
    let bootstrap_addr = match &cli.bootstrap_addr {
        Some(b) => {
            let ip = b
                .parse::<Ipv4Addr>()
                .map_err(|_| format!("--bootstrap-addr {b} is not an ipv4 address"))?;
            check_endpoint_ip(ip, cli.allow_private_endpoint)
                .map_err(|why| format!("unsafe --bootstrap-addr {b}: {why}"))?;
            Some(ip)
        }
        None => None,
    };
    let endpoint_cache = match (&cli.endpoint_cache, &remote) {
        (Some(p), _) if p == "none" || p.is_empty() => None,
        (Some(p), _) => Some(PathBuf::from(p)),
        (None, EndpointSpec::Hostname { name, port }) => Some(PathBuf::from(format!("/var/lib/udp2raw/endpoint_{name}_{port}"))),
        (None, EndpointSpec::Literal(_)) => None,
    };
    let fallback_tuning_present = cli.last_good_fallback_after.is_some()
        || cli.last_good_fallback_max_attempts.is_some()
        || cli.last_good_fallback_cooldown.is_some()
        || cli.last_good_fallback_max_age.is_some()
        || cli.last_good_fallback_global_attempts.is_some()
        || cli.last_good_fallback_global_refill.is_some()
        || cli.last_good_fallback_round_timeout.is_some()
        || cli.last_good_fallback_probation.is_some()
        || cli.last_good_fallback_rollback_window.is_some();
    if fallback_tuning_present && !cli.last_good_fallback {
        return Err("last-good fallback tuning requires explicit --last-good-fallback opt-in".into());
    }
    if cli.last_good_fallback {
        if !remote.is_dynamic() {
            return Err("--last-good-fallback requires a hostname -r".into());
        }
        if endpoint_cache.is_none() {
            return Err("--last-good-fallback requires an owner-only --endpoint-cache for persistent limits".into());
        }
        if cli.fifo.is_none() {
            return Err("--last-good-fallback requires --fifo for attended promotion and rollback".into());
        }
    }
    let probation_ms = bounded_u64("--last-good-fallback-probation", cli.last_good_fallback_probation.unwrap_or(30), 1, 86_400)?.saturating_mul(1000);
    let rollback_window_ms = bounded_u64("--last-good-fallback-rollback-window", cli.last_good_fallback_rollback_window.unwrap_or(300), 2, 7 * 86_400)?.saturating_mul(1000);
    let preferred_round_timeout_ms = bounded_u64("--last-good-fallback-round-timeout", cli.last_good_fallback_round_timeout.unwrap_or(30), 5, 600)?.saturating_mul(1000);
    let required_rollback_ms = CLIENT_CONN_TIMEOUT_MS
        .saturating_add(preferred_round_timeout_ms)
        .saturating_add(CLIENT_HANDSHAKE_TIMEOUT_MS)
        .saturating_add(probation_ms)
        .saturating_add(2 * TIMER_INTERVAL_MS);
    if cli.last_good_fallback && required_rollback_ms >= rollback_window_ms {
        return Err(format!(
            "--last-good-fallback-rollback-window must exceed connection-loss detection + preferred round + one handshake + probation + two timer intervals ({:.1}s)",
            required_rollback_ms as f64 / 1000.0
        ));
    }
    let last_good_fallback = LastGoodFallbackPolicy {
        enabled: cli.last_good_fallback,
        after_failures: bounded_u32("--last-good-fallback-after", cli.last_good_fallback_after.unwrap_or(3), 1, 100)?,
        max_attempts: bounded_u32("--last-good-fallback-max-attempts", cli.last_good_fallback_max_attempts.unwrap_or(2), 1, 100)?,
        cooldown_ms: bounded_u64("--last-good-fallback-cooldown", cli.last_good_fallback_cooldown.unwrap_or(300), 1, 86_400)?.saturating_mul(1000),
        max_age_ms: bounded_u64("--last-good-fallback-max-age", cli.last_good_fallback_max_age.unwrap_or(86_400), 1, 31 * 86_400)?.saturating_mul(1000),
        global_capacity: bounded_u32("--last-good-fallback-global-attempts", cli.last_good_fallback_global_attempts.unwrap_or(4), 1, 100)?,
        global_refill_ms: bounded_u64("--last-good-fallback-global-refill", cli.last_good_fallback_global_refill.unwrap_or(900), 1, 7 * 86_400)?.saturating_mul(1000),
        preferred_round_timeout_ms,
        probation_ms,
        rollback_window_ms,
    };

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
    if let Some(s) = &cli.auth_mode {
        auth_mode = AuthMode::parse(s).ok_or_else(|| format!("no such auth_mode {s}"))?;
    }
    let mut disable_anti_replay = cli.disable_anti_replay;
    if cipher_mode.is_aead() {
        // An AEAD authenticates every packet itself, so --auth-mode is ignored -- and, crucially,
        // anti-replay stays meaningful because the in-plaintext sequence number is covered by the
        // tag. It must NOT be disabled just because --auth-mode none was passed (it is a no-op here).
        if cli.auth_mode.is_some() && auth_mode != AuthMode::None {
            log::warn!("--auth-mode {} ignored: {} authenticates every packet itself", auth_mode.name(), cipher_mode.name());
        }
        auth_mode = AuthMode::None;
    } else if auth_mode == AuthMode::None {
        // No authentication: an attacker can forge the sequence number, so anti-replay would be
        // pointless -- disable it, matching the C++.
        disable_anti_replay = true;
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
            Some(LowerLevel::Manual {
                if_name: if_name.to_string(),
                dest_mac: parse_mac(mac)?,
            })
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
    let aes_backend = match &cli.aes_backend {
        Some(s) => AesBackend::parse(s).ok_or_else(|| format!("no such aes backend {s}"))?,
        None => AesBackend::Auto,
    };
    let syscalls = match &cli.syscalls {
        Some(s) => Syscalls::parse(s).ok_or_else(|| format!("no such syscalls mode {s} (auto, mmsg, single)"))?,
        None => Syscalls::Auto,
    };
    let log_level = cli.log_level.unwrap_or(4);
    if !(0..=6).contains(&log_level) {
        return Err("invalid log_level".into());
    }
    let key = match (&cli.key, &cli.key_file) {
        (Some(_), Some(_)) => return Err("specify only one of -k/--key and --key-file".into()),
        (Some(k), None) => k.clone(),
        (None, Some(path)) => read_key_file(path)?,
        (None, None) => "secret key".to_string(),
    };
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
        remote,
        dns_servers,
        dns_timeout_ms,
        underlay_dev: cli.underlay_dev.clone(),
        underlay_gateway,
        allow_private_endpoint: cli.allow_private_endpoint,
        endpoint_cache,
        bootstrap_addr,
        last_good_fallback,
        key,
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
        aes_backend,
        syscalls,
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
    fn key_file_and_precedence() {
        let dir = std::env::temp_dir().join(format!("udp2raw-key-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let kf = dir.join("k");
        let base = "-c -l 127.0.0.1:3333 -r 1.2.3.4:4096";
        std::fs::write(&kf, b"filekey\n").unwrap(); // trailing newline stripped
        let ParseOutcome::Run(cfg) = parse_args(&args(&format!("{base} --key-file {}", kf.display()))).unwrap() else {
            panic!()
        };
        assert_eq!(cfg.key, "filekey");
        // -k still works, default preserved
        let ParseOutcome::Run(cfg) = parse_args(&args(&format!("{base} -k plainkey"))).unwrap() else {
            panic!()
        };
        assert_eq!(cfg.key, "plainkey");
        let ParseOutcome::Run(cfg) = parse_args(&args(base)).unwrap() else { panic!() };
        assert_eq!(cfg.key, "secret key");
        // CRLF stripped
        std::fs::write(&kf, b"crlfkey\r\n").unwrap();
        let ParseOutcome::Run(cfg) = parse_args(&args(&format!("{base} --key-file {}", kf.display()))).unwrap() else {
            panic!()
        };
        assert_eq!(cfg.key, "crlfkey");
        // key with an embedded space (only the newline is stripped, not inner whitespace)
        std::fs::write(&kf, b"a b c\n").unwrap();
        let ParseOutcome::Run(cfg) = parse_args(&args(&format!("{base} --key-file {}", kf.display()))).unwrap() else {
            panic!()
        };
        assert_eq!(cfg.key, "a b c");
        // errors: both, missing, empty
        assert!(parse_args(&args(&format!("{base} -k x --key-file {}", kf.display()))).is_err());
        assert!(parse_args(&args(&format!("{base} --key-file {}/does-not-exist", dir.display()))).is_err());
        let ek = dir.join("empty");
        std::fs::write(&ek, b"").unwrap();
        assert!(parse_args(&args(&format!("{base} --key-file {}", ek.display()))).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hostname_endpoint_options() {
        let out = parse_args(&args(
            "-c -l 127.0.0.1:7000 -r relay.example.com:8443 --dns-server 223.5.5.5 --dns-server 223.6.6.6:53 --underlay-dev eth0 --underlay-gateway 192.168.1.1 --bootstrap-addr 47.243.1.1",
        ))
        .unwrap();
        let ParseOutcome::Run(cfg) = out else { panic!() };
        assert_eq!(
            cfg.remote,
            EndpointSpec::Hostname {
                name: "relay.example.com".into(),
                port: 8443
            }
        );
        assert_eq!(cfg.remote_addr.to_string(), "0.0.0.0:8443");
        assert!(!cfg.raw_is_v6());
        assert_eq!(cfg.dns_servers, vec!["223.5.5.5:53".parse::<SocketAddr>().unwrap(), "223.6.6.6:53".parse().unwrap()]);
        assert_eq!(cfg.dns_timeout_ms, 2000);
        assert_eq!(cfg.underlay_dev.as_deref(), Some("eth0"));
        assert_eq!(cfg.underlay_gateway, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(cfg.bootstrap_addr, Some(Ipv4Addr::new(47, 243, 1, 1)));
        assert_eq!(cfg.endpoint_cache.as_deref(), Some(std::path::Path::new("/var/lib/udp2raw/endpoint_relay.example.com_8443")));
        assert_eq!(cfg.last_good_fallback, LastGoodFallbackPolicy::default());
        assert!(!cfg.allow_private_endpoint);
        // numeric -r: unchanged behaviour, no cache, no dns
        let ParseOutcome::Run(cfg) = parse_args(&args("-c -l 127.0.0.1:7000 -r 47.243.1.1:8443")).unwrap() else {
            panic!()
        };
        assert_eq!(cfg.remote, EndpointSpec::Literal("47.243.1.1:8443".parse().unwrap()));
        assert_eq!(cfg.remote_addr.to_string(), "47.243.1.1:8443");
        assert!(cfg.dns_servers.is_empty());
        assert!(cfg.endpoint_cache.is_none());
        // ipv6 literal still works for the client
        let ParseOutcome::Run(cfg) = parse_args(&args("-c -l 127.0.0.1:7000 -r [2001:db8::1]:8443")).unwrap() else {
            panic!()
        };
        assert!(cfg.raw_is_v6());
        // options
        let ParseOutcome::Run(cfg) = parse_args(&args(
            "-c -l 127.0.0.1:7000 -r relay.example:8443 --dns-server 1.1.1.1 --endpoint-cache none --dns-timeout 500 --allow-private-endpoint",
        ))
        .unwrap() else {
            panic!()
        };
        assert!(cfg.endpoint_cache.is_none());
        assert_eq!(cfg.dns_timeout_ms, 500);
        assert!(cfg.allow_private_endpoint);
        let ParseOutcome::Run(cfg) = parse_args(&args(
            "-c -l 127.0.0.1:7000 -r relay.example:8443 --dns-server 1.1.1.1 --allow-private-endpoint --bootstrap-addr 10.0.0.1",
        ))
        .unwrap() else {
            panic!()
        };
        assert_eq!(cfg.bootstrap_addr, Some(Ipv4Addr::new(10, 0, 0, 1)));
        let ParseOutcome::Run(cfg) = parse_args(&args("-c -l 127.0.0.1:7000 -r relay.example:8443 --dns-server 1.1.1.1 --endpoint-cache /tmp/x")).unwrap() else {
            panic!()
        };
        assert_eq!(cfg.endpoint_cache.as_deref(), Some(std::path::Path::new("/tmp/x")));
        let ParseOutcome::Run(cfg) = parse_args(&args("-c -l 127.0.0.1:7000 -r relay.example:8443 --dns-server 1.1.1.1 --endpoint-cache /tmp/x --fifo /tmp/f --last-good-fallback --last-good-fallback-after 4 --last-good-fallback-max-attempts 2 --last-good-fallback-cooldown 7 --last-good-fallback-max-age 13 --last-good-fallback-global-attempts 3 --last-good-fallback-global-refill 17 --last-good-fallback-round-timeout 5 --last-good-fallback-probation 2 --last-good-fallback-rollback-window 30")).unwrap() else { panic!() };
        assert_eq!(
            cfg.last_good_fallback,
            LastGoodFallbackPolicy {
                enabled: true,
                after_failures: 4,
                max_attempts: 2,
                cooldown_ms: 7_000,
                max_age_ms: 13_000,
                global_capacity: 3,
                global_refill_ms: 17_000,
                preferred_round_timeout_ms: 5_000,
                probation_ms: 2_000,
                rollback_window_ms: 30_000,
            }
        );
        // errors
        for bad in [
            "-c -l 127.0.0.1:7000 -r relay.example:8443",                         // no dns server
            "-c -l 127.0.0.1:7000 -r relay.example:22 --dns-server 1.1.1.1",      // port 22
            "-c -l 127.0.0.1:7000 -r relay.example --dns-server 1.1.1.1",         // no port
            "-c -l 127.0.0.1:7000 -r bad_name.example:8443 --dns-server 1.1.1.1", // underscore
            "-c -l 127.0.0.1:7000 -r -relay.example:8443 --dns-server 1.1.1.1",   // leading hyphen
            "-c -l 127.0.0.1:7000 -r relay.example:8443 --dns-server not-an-ip",  // bad server
            "-c -l 127.0.0.1:7000 -r relay.example:8443 --dns-server 1.1.1.1 --dns-timeout 5",
            "-c -l 127.0.0.1:7000 -r relay.example:8443 --dns-server 1.1.1.1 --underlay-gateway 192.168.1.1", // gateway without dev
            "-c -l 127.0.0.1:7000 -r relay.example:8443 --dns-server 1.1.1.1 --underlay-dev eth0 --dev wg0", // split send/receive path
            "-c -l 127.0.0.1:7000 -r relay.example:8443 --dns-server 1.1.1.1 --bootstrap-addr nope",
            "-c -l 127.0.0.1:7000 -r relay.example:8443 --dns-server 1.1.1.1 --bootstrap-addr 127.0.0.1",
            "-c -l 127.0.0.1:7000 -r relay.example:8443 --dns-server 1.1.1.1 --bootstrap-addr 10.0.0.1",
            "-c -l 127.0.0.1:7000 -r relay.example:8443 --dns-server 1.1.1.1 --last-good-fallback-after 0",
            "-c -l 127.0.0.1:7000 -r relay.example:8443 --dns-server 1.1.1.1 --last-good-fallback-max-attempts 101",
            "-c -l 127.0.0.1:7000 -r relay.example:8443 --dns-server 1.1.1.1 --last-good-fallback-cooldown 0",
            "-c -l 127.0.0.1:7000 -r relay.example:8443 --dns-server 1.1.1.1 --last-good-fallback-probe-interval 0",
            "-c -l 127.0.0.1:7000 -r relay.example:8443 --dns-server 1.1.1.1 --last-good-fallback-max-age 0",
            "-c -l 127.0.0.1:7000 -r relay.example:8443 --dns-server 1.1.1.1 --last-good-fallback --fifo /tmp/f --endpoint-cache none",
            "-c -l 127.0.0.1:7000 -r relay.example:8443 --dns-server 1.1.1.1 --last-good-fallback --endpoint-cache /tmp/x",
            "-c -l 127.0.0.1:7000 -r 47.243.1.1:8443 --last-good-fallback --endpoint-cache /tmp/x --fifo /tmp/f",
            "-c -l 127.0.0.1:7000 -r relay.example:8443 --dns-server 1.1.1.1 --last-good-fallback --endpoint-cache /tmp/x --fifo /tmp/f --last-good-fallback-probation 10 --last-good-fallback-rollback-window 10",
            "-c -l 127.0.0.1:7000 -r relay.example:8443 --dns-server 1.1.1.1 --last-good-fallback --endpoint-cache /tmp/x --fifo /tmp/f --last-good-fallback-round-timeout 30 --last-good-fallback-rollback-window 30",
            "-c -l 127.0.0.1:7000 -r relay.example:8443 --dns-server 1.1.1.1 --last-good-fallback --endpoint-cache /tmp/x --fifo /tmp/f --last-good-fallback-round-timeout 5 --last-good-fallback-probation 2 --last-good-fallback-rollback-window 10",
            "-s -l 0.0.0.0:8443 -r relay.example:7777", // server: numeric only
            "-s -l 0.0.0.0:8443 -r 127.0.0.1:22",
        ] {
            assert!(parse_args(&args(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn syscalls_option() {
        let out = parse_args(&args("-c -l 1.1.1.1:1 -r 2.2.2.2:2 --syscalls single")).unwrap();
        let ParseOutcome::Run(cfg) = out else { panic!() };
        assert_eq!(cfg.syscalls, Syscalls::Single);
        let out = parse_args(&args("-c -l 1.1.1.1:1 -r 2.2.2.2:2")).unwrap();
        let ParseOutcome::Run(cfg) = out else { panic!() };
        assert_eq!(cfg.syscalls, Syscalls::Auto);
        assert!(parse_args(&args("-c -l 1.1.1.1:1 -r 2.2.2.2:2 --syscalls batch")).is_err());
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
        let out = parse_args(&args(
            "-s -l [::]:4096 -r 127.0.0.1:7777 --cipher-mode aes128cfb_0 --auth-mode none --raw-mode easy-faketcp --lower-level eth0#00:23:45:67:89:b9 --threads 3 --sock-buf 2048 --seq-mode 4",
        ))
        .unwrap();
        let ParseOutcome::Run(c) = out else { panic!() };
        assert_eq!(c.mode, ProgramMode::Server);
        assert!(c.raw_is_v6());
        assert_eq!(c.cipher_mode, CipherMode::Aes128Cfb);
        assert!(c.cfb_legacy);
        assert!(c.disable_anti_replay, "auth none disables anti-replay");
        assert!(c.easy_faketcp);
        assert_eq!(
            c.lower_level,
            Some(LowerLevel::Manual {
                if_name: "eth0".into(),
                dest_mac: [0x00, 0x23, 0x45, 0x67, 0x89, 0xb9]
            })
        );
        assert_eq!(c.threads, 3);
        assert_eq!(c.socket_buf_size, 2048 * 1024);
        assert_eq!(c.seq_mode, 4);
    }

    #[test]
    fn aead_mode_ignores_auth_mode_but_keeps_anti_replay() {
        let out = parse_args(&args("-c -l 1.1.1.1:1 -r 2.2.2.2:2 --cipher-mode chacha20poly1305 --auth-mode md5")).unwrap();
        let ParseOutcome::Run(c) = out else { panic!() };
        assert_eq!(c.cipher_mode, CipherMode::ChaCha20Poly1305);
        assert_eq!(c.auth_mode, AuthMode::None);
        assert!(!c.disable_anti_replay);
    }

    #[test]
    fn aead_keeps_anti_replay_even_with_explicit_auth_none() {
        // regression: `--auth-mode none` (a no-op in AEAD mode) must not disable anti-replay,
        // since the AEAD tag authenticates the sequence number.
        let ParseOutcome::Run(c) = parse_args(&args("-c -l 1.1.1.1:1 -r 2.2.2.2:2 --cipher-mode chacha20poly1305 --auth-mode none")).unwrap() else {
            panic!()
        };
        assert_eq!(c.auth_mode, AuthMode::None);
        assert!(!c.disable_anti_replay, "AEAD authenticates, so --auth-mode none must not disable anti-replay");
        // --disable-anti-replay is still honoured with an AEAD cipher
        let ParseOutcome::Run(c) = parse_args(&args("-c -l 1.1.1.1:1 -r 2.2.2.2:2 --cipher-mode chacha20poly1305 --disable-anti-replay")).unwrap() else {
            panic!()
        };
        assert!(c.disable_anti_replay);
        // legacy behaviour unchanged: a non-AEAD cipher with --auth-mode none still disables it
        let ParseOutcome::Run(c) = parse_args(&args("-c -l 1.1.1.1:1 -r 2.2.2.2:2 --cipher-mode aes128cbc --auth-mode none")).unwrap() else {
            panic!()
        };
        assert!(c.disable_anti_replay, "no authentication -> anti-replay disabled");
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
        std::fs::write(
            &path,
            "# This is client\n-c\n-l 127.0.0.1:56789\n-r 45.66.77.88:45678\n-k my_awesome_password\n--raw-mode faketcp\n--log-level 4\n",
        )
        .unwrap();
        let out = parse_args(&[String::from("--conf-file"), path.to_string_lossy().to_string()]).unwrap();
        let ParseOutcome::Run(c) = out else { panic!() };
        assert_eq!(c.key, "my_awesome_password");
        assert_eq!(c.remote_addr.port(), 45678);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
