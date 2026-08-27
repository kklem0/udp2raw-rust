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
  `--threads 0` gives the old single-threaded behaviour. On a 4-core Pi 4 running only the
  daemon, `--threads 2` (the auto default) doubles the single-threaded rate in the Docker
  model; see PLAN.md for measurements.
* **Hardware crypto without special builds.** AES uses the ARMv8 Cryptography Extensions
  (Raspberry Pi 5, most ARM servers) or AES-NI when the CPU has them, detected at runtime;
  SHA-1/SHA-2 likewise. CPUs without AES instructions (Raspberry Pi 4, Cortex-A72) get a
  table-driven AES like the C++ version's — the `aes` crate's constant-time bitsliced
  fallback is 2–4× slower for udp2raw's serial CBC encryption. `--aes-backend
  auto|hw|table|fixslice` overrides the choice.
* **Linux only.** Windows/macOS (the `udp2raw-multiplatform` pcap build) is not ported.
* No per-packet `/dev/urandom` reads, no per-packet heap churn in the hot path, and the
  code is memory-safe — it runs as root / with `CAP_NET_RAW` and parses untrusted packets.

* **`--cipher-mode chacha20poly1305`** (Rust↔Rust only): a real AEAD, and the fast choice
  on CPUs without AES instructions (NEON ChaCha20). `--auth-mode` is ignored in this mode;
  anti-replay stays on. Both ends must run this port.
* **`--unit-test`** runs a built-in self-test: key derivation against the C++ reference,
  every cipher/auth mode on every AES backend the CPU offers, framing and checksums — handy
  right after copying a binary to a new box.
* The I/O thread uses `recvmmsg`/`sendmmsg` (one syscall per batch of up to 32/64 packets),
  pooled buffers and in-place crypto; the C++ does one syscall and several copies per packet.

Everything else — `--raw-mode faketcp|udp|icmp|easy-faketcp`, `--cipher-mode`,
`--auth-mode`, `-a/-g/--gen-add/--keep-rule/--clear`, `--fix-gro`, `--seq-mode`,
`--lower-level`, `--source-ip/--source-port`, `--conf-file`, `--fifo`, `--dev`,
`--sock-buf`, IPv6, connection recovery on the server — follows the original.

## Build

```sh
cargo build --release                         # native (on the Pi itself, with rustup)
# cross-compile for the Pi from a Debian/Ubuntu x86_64 host:
sudo apt-get install g++-aarch64-linux-gnu
rustup target add aarch64-unknown-linux-gnu
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    cargo build --release --target aarch64-unknown-linux-gnu
# fully static binary without a local cross toolchain (needs Docker):
cargo install cross && cross build --release --target aarch64-unknown-linux-musl
```

## Usage

Identical to udp2raw; see `udp2raw -h` and the
[original README](https://github.com/wangyu-/udp2raw#getting-started).

```sh
# server (e.g. a VPS or the Pi at home)
sudo ./udp2raw -s -l 0.0.0.0:4096 -r 127.0.0.1:51820 -k "passwd" --raw-mode faketcp -a
# client
sudo ./udp2raw -c -l 127.0.0.1:3333 -r 44.55.66.77:4096 -k "passwd" --raw-mode faketcp -a
```

## Performance

Loss-free throughput ("no-drop rate": highest offered rate with ≤2 % loss, RFC 2544 style),
1300-byte datagrams, `faketcp` + `aes128cbc` + `md5` + `--fix-gro` (the udp2raw defaults),
client and server of the same implementation, UDP in one direction through both daemons.
C++ = stock udp2raw `fb13730`; Rust = this repo. Raw logs and method: `docs/bench/`,
[PLAN.md](PLAN.md).

**Raspberry Pi 4** (Cortex-A72 ×4 @1.8 GHz, no AES instructions, Ubuntu 24.04), both daemons
on the Pi over loopback, 2026-08-27:

| | loss-free pps | Mbit/s | server / client CPU | vs C++ |
|---|---:|---:|---|---:|
| C++ | 10,220 | 106 | 98 % / 87 % | 1.00× |
| Rust `--threads 0` | 14,784 | 154 | 91 % / 97 % | 1.45× |
| Rust `--threads 2` | 18,720 | 195 | 130 % / 135 % | 1.83× |

Both ends share the Pi's four cores here, which limits what the workers can add; the C++
figure varied between 4.7k and 10.2k across runs (it drops packets under bursts before it is
CPU-bound), the Rust figures were stable.

**Docker, arm64, daemons pinned to 4 cores each** (fast cores, so only the ratios matter;
`--aes-backend table` forces the Pi 4's software-AES code path):

| | both ends on one 4-core box | one daemon per 4-core box |
|---|---:|---:|
| C++ | 82k pps | 86k pps |
| Rust `--threads 0` | 132k (1.6×) | 133k (1.6×) |
| Rust `--threads 2` | 187k (2.3×) | **265k (3.1×)** |
| Rust `--threads 0`, hardware AES (Pi 5 class) | 208k | 205k |
| Rust `--threads 2`, hardware AES | 222k | 294k |

Where the difference comes from: table-driven AES instead of a bitsliced fallback on CPUs
without AES instructions, batched socket drains (the C++ handles one packet per event-loop
iteration and loses packets under bursts), and crypto on worker threads with batched
handoff. With two workers the I/O thread's syscalls become the limit
(`recvmmsg`/`sendmmsg` is the next step).

## Tests

```sh
cargo test                                   # unit tests + golden vectors (any OS)
docker build -t udp2raw-rust-dev tools/docker
docker run --rm --cap-add NET_RAW --cap-add NET_ADMIN --cap-add SYS_ADMIN -v "$PWD":/work \
    -v /path/to/udp2raw-cpp:/cpp:ro udp2raw-rust-dev tools/docker/e2e.sh   # loopback + veth tunnels, C++ interop
```

`tests/data/vectors.txt` holds 1,754 records produced by the unmodified C++ code
(`tools/cpp_harness/`): key derivation, every cipher × auth mode in both directions,
and tamper rejection. `tests/vectors.rs` checks the Rust implementation against them
byte for byte.

## License

MIT, like the original. See [LICENSE](LICENSE).
