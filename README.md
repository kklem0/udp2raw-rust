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
* **Hostname relay endpoints with in-process switching.** A client `-r host:port` is
  re-resolved through explicit `--dns-server`s at every reconnect; a new address is adopted
  without changing the process, the local listener or WireGuard. See "Hostname endpoints".
* **Linux only.** Windows/macOS (the `udp2raw-multiplatform` pcap build) is not ported.
* No per-packet `/dev/urandom` reads, no per-packet heap churn in the hot path, and the
  code is memory-safe — it runs as root / with `CAP_NET_RAW` and parses untrusted packets.

* **`--syscalls auto|mmsg|single`**: batched `recvmmsg`/`sendmmsg` where they pay off, one
  `recvfrom`/`sendto` per packet on ARMv8.0 cores (Raspberry Pi 3/4: no hardware PAN, so the
  kernel's software PAN makes every user-memory access inside a syscall expensive and the
  batched calls cost ~10 % more CPU per packet — auto-detected, see PLAN.md).
* **`--cipher-mode chacha20poly1305`** (Rust↔Rust only): a real AEAD, and the fast choice
  on CPUs without AES instructions (NEON ChaCha20). XChaCha20-Poly1305 with a fresh random
  24-byte nonce per packet (`[nonce 24][ciphertext][tag 16]`, +40 bytes), so the payload
  carries no counter or constant — it is indistinguishable from random bytes, like the AES
  modes. The cipher only changes the payload: `--raw-mode faketcp|udp|icmp` and `--fix-gro`
  disguise it exactly as before. `--auth-mode` is ignored in this mode (the AEAD tag
  authenticates every packet); anti-replay stays on regardless, including with an explicit
  `--auth-mode none`. Both ends must run this port.
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

### The password / key

The key is never written to a log. `-k`/`--key` still works exactly as in the C++ (and is
interoperable with a C++ peer using the same password), but the value is redacted from the
`argv:` and `important variables:` lines and a warning notes that a `-k` key is visible in
the process list (`ps`, `/proc/<pid>/cmdline`). Instead the logs print a **fingerprint** —
the first four bytes of `SHA-256(key)`, hex — so two ends can confirm they share a key
without it ever appearing:

```
key fingerprint (sha256[..4]): bb06c3ea — both ends must match
```

Derived key material is logged the same way (fingerprints, not the bytes) at `--log-level 6`.

**`--key-file <path>`** reads the password from a file instead of `-k`, keeping it out of the
process list. The file's content is the key verbatim except one trailing newline (`\n` or
`\r\n`) is stripped, so `printf %s "$KEY" > key` and `echo "$KEY" > key` both work; an empty
file is rejected. It is a Rust-build-only convenience — the key, the derivation and the wire
format are unchanged, so a `--key-file` client interoperates with a `-k` C++ or Rust peer
that uses the same password.

**systemd credentials.** A systemd credential is a file in `$CREDENTIALS_DIRECTORY`, so point
`--key-file` at it with the `%d` specifier:

```ini
[Service]
LoadCredential=udp2raw-key:/etc/udp2raw/key       # 0600, root-owned
ExecStart=/opt/udp2raw -c -l 127.0.0.1:3333 -r relay.example.com:8443 \
    --raw-mode faketcp -a --key-file %d/udp2raw-key
```

The key then never appears in the unit file, the process list, or the logs.

### Hostname endpoints (client `-r`, in-process relay switching)

A client `-r` may be a hostname. The client resolves it through the DNS servers you give
with `--dns-server` (never `/etc/resolv.conf`, never `dig`), keeps the connection while it
is healthy, and when it fails and the client reconnects it re-resolves and, if DNS now
returns a different address, switches to it **in the same process** — the udp2raw PID, the
local UDP listener and everything above it (e.g. WireGuard) are untouched. This lets you
move a relay by changing one DNS record instead of restarting the tunnel.

New client options:

| option | meaning |
|---|---|
| `-r host:port` | resolve `host` (IPv4 `A` records) instead of a literal address; a literal `-r ip:port` is unchanged. Server `-r` stays numeric. |
| `--dns-server ip[:port]` | resolver to use (default port 53); repeat to add more, tried in order, first usable answer wins. Required with a hostname `-r`. |
| `--dns-timeout ms` | per-server timeout (default 2000). |
| `--underlay-dev dev` | native interface for DNS **and** relay traffic: `SO_BINDTODEVICE` on the sockets plus a `/32` host route per relay address, so the lookup and the tunnel take the real link even when the default route is a VPN. Implies `--dev` when `--dev` is unset. |
| `--underlay-gateway ip` | next hop on `--underlay-dev` for those routes; by default it is learned from the box's existing route to the bootstrap address (on-link if none). |
| `--allow-private-endpoint` | accept RFC 1918 / CGNAT answers (rejected by default, along with loopback, link-local, multicast, broadcast, reserved and documentation ranges). |
| `--endpoint-cache path` | file holding the last address whose handshake succeeded (default `/var/lib/udp2raw/endpoint_<host>_<port>`, mode 0600; `none` disables). Used to bootstrap before DNS answers. |
| `--bootstrap-addr ip` | literal to start with when DNS **and** the cache are both unavailable at startup. |

How it behaves: a DNS answer is only a *candidate* — an address becomes "last-known-good"
(and is written to the cache) only after the udp2raw authenticated handshake succeeds on it,
so a poisoned answer cannot redirect the tunnel (the relay still has to prove the key). The
current address is always tried first and answer order is ignored, so a reordered or
duplicated answer never causes a switch; a genuinely new address is adopted at the next
reconnect boundary. Failed queries back off exponentially with jitter, and NXDOMAIN /
SERVFAIL / timeout / malformed replies / a lost resolver never erase the current endpoint.
`echo reconnect > <fifo>` forces a fresh query for a planned cutover without restarting.
TTL is clamped to 10–3600 s; a healthy session is never interrupted by TTL expiry. The
lookup runs only from the reconnecting (idle) state, never during a healthy session, so it
cannot stall live traffic; but note a reconnect can take up to `(servers × --dns-timeout)`
longer while a `--dns-server` is unreachable (the current/last-known address is kept
throughout).

**DNS record recommendation:** publish exactly **one** unproxied IPv4 `A` record with a
**30–60 second TTL**. Keep it a plain A record (no CDN/proxy in front — the tunnel must reach
the relay's real address), and change the single address to rotate.

**Example** (a mainland client, AliDNS resolvers, `eth0` as the native underlay):

```sh
sudo ./udp2raw -c -l 127.0.0.1:7000 -r relay.example.com:8443 -k "passwd"     --raw-mode faketcp -a --fix-gro     --dns-server 223.5.5.5:53     --dns-server 223.6.6.6:53     --underlay-dev eth0
```

The `223.5.5.5` / `223.6.6.6` queries and the tunnel both leave through `eth0`, and the
client installs a `/32` route for each resolved relay address over `eth0` — so a newly
resolved address works even though the box keeps no `/32` escape route for it in advance
(a direct-routing policy table's default via the LAN gateway still applies, but the
explicit `/32` guarantees it regardless of what the default route is doing).

**Rotation workflow (zero-touch cutover):**

1. Prepare the new relay first: bring up the new EIP / listener / firewall and confirm it
   serves the same key and mode.
2. Update the DNS `A` record to the new address.
3. Keep the **old** EIP running through the TTL grace period (30–60 s) so in-flight sessions
   are not cut.
4. Either force the cutover now with `echo reconnect > <fifo>` (re-resolves immediately), or
   wait for the client's own failure detection when you retire the old EIP. The switch is
   in-process; WireGuard above it never notices beyond a brief reconnect.
5. Retire the old EIP once the client has moved (its log shows `relay is now <new> …` and
   `<new> is now last-known-good`).

**Rollback / break-glass:** point the DNS record back to the previous address and
`echo reconnect > <fifo>`. If DNS itself is the problem, start the client with a literal
`-r <ip>:<port>` (no `--dns-server`) — identical to classic udp2raw, no resolution at all —
or rely on the cached last-known-good address and `--bootstrap-addr` which keep the service
usable through a startup-time DNS outage.

## Performance

Loss-free throughput ("no-drop rate": highest offered rate with ≤2 % loss, RFC 2544 style),
1300-byte datagrams, `faketcp` + `aes128cbc` + `md5` + `--fix-gro` (the udp2raw defaults),
client and server of the same implementation, UDP in one direction through both daemons.
C++ = stock udp2raw `fb13730`; Rust = this repo. Raw logs and method: `docs/bench/`,
[PLAN.md](PLAN.md).

**Raspberry Pi 5** (Cortex-A76 ×4 @2.4 GHz, hardware AES + hardware PAN, Ubuntu 24.04), both
daemons on the Pi over loopback, 2026-08-28. `auto` picks hardware AES and `mmsg` syscalls
here (logged at startup); thread scaling in the deployed mode:

| | loss-free pps | Mbit/s | server / client CPU | vs C++ |
|---|---:|---:|---|---:|
| C++ | 46,028 | 479 | 99 % / 96 % | 1.00× |
| Rust `--threads 0` | 66,788 | 695 | 94 % / 93 % | 1.45× |
| Rust `--threads 1` | 72,512 | 754 | 129 % / 114 % | 1.58× |
| Rust `--threads 2` | 72,640 | 755 | 130 % / 119 % | 1.58× |
| Rust `--threads 3` | 82,828 | 861 | 139 % / 135 % | 1.80× |

With hardware AES the cipher barely matters (`chacha20poly1305` is 67.9k/77.3k pps at
`--threads 0`/`2` vs 66.8k/72.6k for aes128cbc+md5 — within ~6 %), and `mmsg` vs `single` is
a wash (the Pi 4's software-PAN penalty is gone); the table backend is 1.24–1.29× slower than
hardware AES. All four cores are shared with the generator, so a real one-daemon-per-box
deployment would scale further. Details: [PLAN.md](PLAN.md).

**Raspberry Pi 4** (Cortex-A72 ×4 @1.8 GHz, no AES instructions, Ubuntu 24.04), both daemons
on the Pi over loopback, 2026-08-27 (before the box was upgraded to a Pi 5):

| | loss-free pps | Mbit/s | server / client CPU | vs C++ |
|---|---:|---:|---|---:|
| C++ | 10,220 | 106 | 98 % / 87 % | 1.00× |
| Rust `--threads 0` | 14,784 | 154 | 91 % / 97 % | 1.45× |
| Rust `--threads 2` | 18,720 | 195 | 130 % / 135 % | 1.83× |

Both ends share the Pi's four cores here, which limits what the workers can add; the C++
figure varied between 4.7k and 10.2k across runs (it drops packets under bursts before it is
CPU-bound), the Rust figures were stable.

**Cipher modes on the Pi 4** (same setup, 2026-08-27/28, current build with `--syscalls auto`;
compare these rows only with each other — the C++ row is from the same session):

| | loss-free pps | Mbit/s | server / client CPU |
|---|---:|---:|---|
| C++, aes128cbc + md5 | 9,984 | 104 | 95 % / 83 % |
| Rust `--threads 0`, aes128cbc + md5 | 13,984 | 145 | 87 % / 86 % |
| Rust `--threads 0`, chacha20poly1305 | 16,992 | 177 | 94 % / 94 % |
| Rust `--threads 2`, aes128cbc + md5 | 14,976 | 156 | 112 % / 111 % |
| Rust `--threads 2`, chacha20poly1305 | **19,968** | 208 | 121 % / 121 % |

`chacha20poly1305` cuts the daemons' own (user) CPU by about a third on this CPU (at 10k pps:
17 % vs 26 % on the server, 14 % vs 22 % on the client); most of the per-packet cost on the
Pi 4 is kernel time, which no cipher removes. Use it Rust↔Rust; it is not wire-compatible
with the C++. The same measurement caught the `recvmmsg`/`sendmmsg` build costing 10 % more
CPU per packet than its predecessor on this CPU — the story and the fix (`--syscalls`) are in
[PLAN.md](PLAN.md).

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
handoff. With two workers the I/O thread's syscalls become the limit; the current build drains
and flushes sockets in batches (pooled buffers, one flush per event-loop round) and uses
`recvmmsg`/`sendmmsg` only where they are cheaper than per-packet calls (`--syscalls auto`:
a few percent on fast cores, a 10 % loss on the Pi 4 — see [PLAN.md](PLAN.md)).

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
