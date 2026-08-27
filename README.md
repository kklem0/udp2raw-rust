# udp2raw-rust

A wire-compatible Rust port of [udp2raw](https://github.com/wangyu-/udp2raw): tunnel UDP
traffic through encrypted FakeTCP / UDP / ICMP raw sockets to get through UDP-hostile
firewalls and NATs. A Rust client talks to a stock C++ server and vice versa — same
options, same key derivation, same packet format.

What is different from the C++ version:

* **Multithreaded crypto pipeline.** Packet encryption/decryption runs on `--threads N`
  worker threads (default: auto, `cores - 2` capped at 4) while one I/O thread owns the
  sockets and all connection state. Completions are applied in submission order, so
  sequence numbers, anti-replay and FakeTCP seq/ack behave exactly as single-threaded.
  `--threads 0` gives the old single-threaded behaviour.
* **Hardware crypto without special builds.** AES uses the ARMv8 Cryptography Extensions
  (Raspberry Pi 5, most ARM servers) or AES-NI when the CPU has them, detected at runtime;
  SHA-1/SHA-2 likewise. The Pi 4 (Cortex-A72, no crypto extensions) falls back to a
  constant-time software AES.
* **Linux only.** Windows/macOS (the `udp2raw-multiplatform` pcap build) is not ported.
* No per-packet `/dev/urandom` reads, no per-packet heap churn in the hot path, and the
  code is memory-safe — it runs as root / with `CAP_NET_RAW` and parses untrusted packets.

Everything else — `--raw-mode faketcp|udp|icmp|easy-faketcp`, `--cipher-mode`,
`--auth-mode`, `-a/-g/--gen-add/--keep-rule/--clear`, `--fix-gro`, `--seq-mode`,
`--lower-level`, `--source-ip/--source-port`, `--conf-file`, `--fifo`, `--dev`,
`--sock-buf`, IPv6, connection recovery on the server — follows the original.

## Build

```sh
cargo build --release                         # native
# Raspberry Pi from a Debian/Ubuntu x86_64 host:
sudo apt-get install g++-aarch64-linux-gnu
rustup target add aarch64-unknown-linux-gnu
cargo build --release --target aarch64-unknown-linux-gnu
# fully static (musl) binary:
rustup target add aarch64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl
```

Building on the Pi itself also works (`rustup` + `cargo build --release`).

## Usage

Identical to udp2raw; see `udp2raw -h` and the
[original README](https://github.com/wangyu-/udp2raw#getting-started).

```sh
# server (e.g. a VPS or the Pi at home)
sudo ./udp2raw -s -l 0.0.0.0:4096 -r 127.0.0.1:51820 -k "passwd" --raw-mode faketcp -a
# client
sudo ./udp2raw -c -l 127.0.0.1:3333 -r 44.55.66.77:4096 -k "passwd" --raw-mode faketcp -a
```

Performance notes for the Raspberry Pi are in [PLAN.md](PLAN.md).

## Tests

```sh
cargo test                                   # unit tests + golden vectors (any OS)
docker build -t udp2raw-rust-dev tools/docker
docker run --rm --cap-add NET_RAW --cap-add NET_ADMIN -v "$PWD":/work \
    -v /path/to/udp2raw-cpp:/cpp:ro udp2raw-rust-dev tools/docker/e2e.sh   # loopback tunnels + C++ interop
```

`tests/data/vectors.txt` holds 1,754 records produced by the unmodified C++ code
(`tools/cpp_harness/`): key derivation, every cipher × auth mode in both directions,
and tamper rejection. `tests/vectors.rs` checks the Rust implementation against them
byte for byte.

## License

MIT, like the original. See [LICENSE](LICENSE).
