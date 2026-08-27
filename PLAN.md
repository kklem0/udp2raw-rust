# udp2raw-rust — plan and status

Goal: a wire-compatible Rust port of udp2raw that uses more than one core, for a
Raspberry Pi 5 (Cortex-A76 with ARMv8 AES/SHA) and a Raspberry Pi 4 (Cortex-A72, no
crypto extensions). The C++ daemon pegs one core well before the link is saturated.

This file is the hand-off document: what exists, how it is verified, what is left, and
how to test on the Pis. Keep the **Status** section current.

## Status (2026-08-27)

| Area | State |
|---|---|
| Key derivation, all cipher/auth modes, `--fix-gro` framing | done — byte-exact against the C++ (1,754 golden vectors) |
| Wire framing (bare/safer/handshake/data), anti-replay, conv LRU | done, unit-tested |
| IPv4/IPv6 + TCP/UDP/ICMP header codecs, checksums | done, unit-tested |
| CLI / conf-file, identical option names (+ `--threads`) | done, unit-tested |
| Raw sockets (AF_PACKET + BPF, IPPROTO_RAW, `--lower-level`, `--dev`) | done, type-checked for aarch64-linux; exercised by the Docker e2e |
| Client state machine (faketcp / udp / icmp / easy-faketcp, reconnect, fifo) | done |
| Server (many clients, conv sockets, connection recovery, GC) | done |
| Ordered multithreaded crypto pipeline | done, unit-tested (ordering + roundtrip) |
| iptables `-a/-g/--gen-add/--keep-rule/--clear/--wait-lock` | done |
| Docker loopback e2e: Rust↔Rust all modes, Rust↔C++ interop | **16/16 pass** (2026-08-27, see run log below) |
| Pi 4 measurements (loopback, C++ vs Rust) | **done 2026-08-27** — see "Raspberry Pi 4 benchmark" below; Pi 5 and a two-box measurement still to do |

Docker e2e results are appended at the bottom of this file after each run.

## Architecture

```
src/
  crypto/      Keys::derive (md5/pbkdf2/hkdf), Authenticator, AesKey (CBC/CFB/ECB, zero IV),
               Crypto::{encrypt,decrypt} — pure, Send+Sync, shared by workers via Arc
  wire.rs      bare / safer / handshake / data payload layouts, --fix-gro wrap/unwrap
  anti_replay  sliding window (4000)
  conv.rs      ConvManager<T>: conv ids <-> peer data, LRU expiry (180 s, 1/30 per pass)
  packet/      ip.rs tcp.rs udp.rs icmp.rs checksum.rs — header build/parse
  config.rs    clap CLI + conf-file expansion (same semantics as misc.cpp)
  net/         raw.rs (sockets, BPF attach, send/recv), bpf.rs (programs copied verbatim),
               addr.rs (sockaddr, port reservation, src-address trick), lower_level.rs
  faketcp.rs   PacketInfo/RawInfo/RawCtx: send_raw, parse_recv, peek, after_send/after_recv
               (seq_mode 0-4), RecvMeta snapshot for the pipeline
  conn.rs      ConnInfo + prepare_safer / encrypt_safer / transmit_safer / accept_safer
  pipeline.rs  Pipeline: N workers, strict round-robin dispatch and collection => ordered
  client.rs    mio event loop: udp fd, raw fd, pipeline eventfd, fifo, 400 ms timer
  server.rs    mio event loop: raw fd, per-conv udp sockets (slab + tokens), timer, GC
  iptables.rs  rule pattern/chains/keep thread
  main.rs      arg parsing, signals, iptables lifecycle, run client/server
```

Threading model (the reason for the port):

* The I/O thread owns every socket and all mutable state (connections, anti-replay,
  FakeTCP seq/ack, conv tables). Nothing is shared except the immutable `Crypto`.
* Per packet it does: recv → parse headers → `prepare_safer` (assigns the anti-replay
  send seq in order) → `Job::Encrypt` / `Job::Decrypt` to worker `k mod N`.
* Workers only run `Crypto::encrypt/decrypt` (+ GRO wrap/split) and push results back.
* Completions are collected from worker `j mod N` in the same order, so sends leave in
  submission order and `after_send/after_recv` run in order. A `RecvMeta` snapshot of the
  received headers travels with each decrypt job so `after_recv` sees the right values.
* Overload policy: if a worker queue (512) is full the packet is dropped and a warning is
  logged once per power of two — the I/O thread never blocks.
* Socket drains are bounded (`DRAIN_BUDGET` = 64 packets per socket per round; sources
  that still have data are re-polled with a zero timeout). Without this an overload burst
  starved the send side: the first e2e run showed the client forwarding nothing for the
  whole 3 s blast and then flushing a huge backlog (edge-triggered epoll + unbounded loop).
* `--threads 0` runs the same code inline.

## Verification so far

* `cargo test` on macOS: 42 unit tests + `tests/vectors.rs` (golden vectors) pass.
* `cargo check --target aarch64-unknown-linux-gnu --all-targets`: clean.
* Docker (`rust:1-bookworm`, arm64, `--cap-add NET_RAW,NET_ADMIN`): `tools/docker/e2e.sh`
  builds the C++ reference from the mounted checkout and runs client+server over
  loopback with `-a` in every raw mode, cipher/auth combos, `--fix-gro`, `--threads 0/3`,
  and C++↔Rust in both directions, probing 2,000 datagrams on 2 convs plus a throughput
  blast. Results are logged at the end of this file.

## Next session: verification on the Pis

1. Build: on the Pi `cargo build --release` (or cross-compile, see README). Check the
   AES backend is hardware on the Pi 5: `grep -o aes /proc/cpuinfo | head -1` (the `aes`
   crate auto-detects; nothing to configure).
2. Smoke test against the running C++ deployment (it is wire-compatible, so swap one side
   at a time): same `-k`, `--raw-mode`, `--cipher-mode`, `--auth-mode`, `--fix-gro` on
   both ends. Watch for `rst==1` warnings (iptables rule missing) and
   `huge packet ... --fix-gro` (GRO merging FakeTCP segments — use `--fix-gro` on both
   ends or `ethtool -K eth0 gro off`).
3. Measure with iperf3 through WireGuard (or `tools/udp_bench.py`) for:
   `--threads 0`, `1`, `2`, `3` on each Pi; `--cipher-mode aes128cbc --auth-mode md5`
   (default) vs `--cipher-mode none --auth-mode hmac_sha1` (WireGuard inside) vs
   `xor/simple`. Record pps, Mbit/s, `mpstat -P ALL 1` (user vs softirq per core), and
   `perf top -p $(pidof udp2raw)`.
4. Kernel-side knobs to try: `--dev eth0`, RPS
   (`echo f > /sys/class/net/eth0/queues/rx-0/rps_cpus`), pin the daemon away from the
   NIC IRQ CPU (`taskset`), `--sock-buf 4096`.
5. Long-run soak (hours) for connection recovery: kill/restart the client, change the
   client's port, check the server logs `grabbed a connection` and that convs survive.

## Known gaps / ideas (in rough priority order)

Done since the first hand-off: worker handoff batching (`77276c9`), busy-poll fix
(`8f1b17b`), `recvmmsg`/`sendmmsg` on the I/O thread with pooled buffers and in-place
crypto (`1a7fd3b`), `--cipher-mode chacha20poly1305` (AEAD, Rust↔Rust), a real
`--unit-test`, e2e coverage for `easy-faketcp` and for `--lower-level auto` over a veth
pair in a network namespace (also C++ interop across it).

* **Measure again** (not yet done on purpose): the batched-syscall build on the Pi 4, the
  deployment shape (Pi client ↔ VPS server over eth0), and the Pi 5. `bench.sh quick` in
  Docker is the ~1 min regression check; `tools/bench/run_fixed_pi.sh` the user/sys CPU split.
* TPACKET_V3 ring for RX; write headers into headroom of the job buffer to drop the last
  copy on the TX path.
* CBC decrypt already batches blocks (`decrypt_blocks`); CBC encrypt is inherently serial.
* IPv6 e2e (`-l [::1]:4096`) — needs `ip6tables` in the container; not needed for now.
* The fifo only supports `reconnect` (same as the C++).
* Logging goes to stdout with the C++ format; `--log-position` prints file:line.

## Wire-format reference (for debugging)

```
keys:   normal_key = md5(password || "key1")
        prk        = PBKDF2-HMAC-SHA256(password, md5("udp2raw_salt1"), 10000, 32)
        cipher/hmac keys = HKDF-SHA256-expand(prk, "<cipher_key|hmac_key> <dir>", 64)
        gro_xor    = HKDF-SHA256-expand(prk, "gro", 256)
packet: auth != hmac_sha1:  cipher(plain || tag, normal_key)
        auth == hmac_sha1:  cipher(plain, cipher_key_encrypt[..16]) || HMAC-SHA1(hmac_key_encrypt[..20], ct)
        aes128cbc: zero IV, pad to 16 (last byte = pad len)
        aes128cfb: ECB(cipher_key_encrypt)(block0) then CFB-128 with zero IV
bare:   [iv u64][pad u64]['b'][payload]            handshake payload = 3 × u32 BE ids
safer:  [my_id u32][oppsite_id u32][seq u64]['h'|'d'][roller][payload]; 'd' payload = [conv u32][datagram]
gro:    [len u16][encrypted] with the first 16 bytes ECB-encrypted (xor: first 2 bytes ^ gro_xor)
```

## Raspberry Pi 4 benchmark (2026-08-27)

Box: `test-site-1`, Raspberry Pi 4 (Cortex-A72 ×4, 1.8 GHz, no AES/SHA instructions), Ubuntu
24.04, kernel 6.8. It is a live router (dnsmasq, VLANs, WireGuard, a 38-rule INPUT chain,
conntrack) running the production `udp2raw-fb13730-arm64-hw-aes-static` as a client; the
benchmark used separate ports on loopback and never touched that instance. C++ reference =
that production binary (on the Pi 4 it uses the portable C AES). Rust = this repo at
`7b12ba1` (table AES). Tools: `tools/bench/` (static `udpbench` generator/sink,
`bench_ndr.sh`, `run_ndr_pi.sh`); raw logs in `docs/bench/`.

Topology: `udpbench blast → client :33333 → raw tunnel (lo) → server :34096 → udpbench sink
:37777`, both daemons on the Pi, `-a --fix-gro`, 1300-byte datagrams, governor pinned to
`performance`, `rmem_max` raised for the run. **No-drop rate** = highest offered rate with
≤2 % loss (binary search, 4 s per step, exact sent/received counts).

| case (production config: faketcp, aes128cbc, md5, --fix-gro unless noted) | no-drop pps | Mbit/s | server / client CPU | vs C++ |
|---|---:|---:|---|---:|
| C++ ↔ C++ | 4,672 | 49 | 55 % / 46 % | 1.00× |
| Rust ↔ Rust `--threads 0` | 9,185 | 96 | 67 % / 66 % | **1.97×** |
| Rust ↔ Rust `--threads 0 --aes-backend fixslice` (control) | 5,616 | 58 | 43 % / 70 % | 1.20× |
| Rust ↔ Rust `--threads 1` | 9,284 | 97 | 81 % / 83 % | 1.99× |
| Rust ↔ Rust `--threads 2` | 8,267 | 86 | 82 % / 75 % | 1.77× |
| Rust ↔ Rust `--threads 3` | 8,410 | 87 | 84 % / 83 % | 1.80× |
| C++ server ↔ Rust client `--threads 2` | 5,616 | 58 | 60 % / 54 % | 1.20× |
| Rust server `--threads 3` ↔ C++ client | 6,436 | 67 | 90 % / 64 % | 1.38× |
| Rust server `--threads 3` ↔ Rust client `--threads 0` | 9,360 | 97 | 95 % / 69 % | 2.00× |
| Rust server `--threads 3` ↔ Rust client `--threads 2` | 8,408 | 87 | 90 % / 81 % | 1.80× |
| C++ ↔ C++, `--cipher-mode none --auth-mode hmac_sha1` | 8,344 | 87 | 76 % / 67 % | — |
| Rust ↔ Rust `--threads 2`, `none + hmac_sha1` | 11,211 | 117 | 88 % / 92 % | 1.34× vs C++ same mode |

Earlier "overload" pass (offered ≈ 29k pps, 10 s, steady-state received rate) with the
*first* Rust binary (bitsliced AES): C++ 7,128 pps at 77 %/80 % CPU; Rust t0 5,864; t1
6,064; t2 7,464. That run was cut short (thermal cooldowns) and is superseded by the table.

What the numbers mean:

* **The AES implementation dominates on the A72.** The `aes` crate's bitsliced fallback
  made the Rust client *slower* than C++ (serial CBC encryption cannot batch blocks); the
  table-driven AES (`crypto/aes_table.rs`, auto-selected when the CPU lacks AES
  instructions) gives 9.2k vs 5.6k pps on the same binary. Golden vectors pass for every
  backend.
* **This box saturates in the kernel at ≈10k tunnel packets/s (~100 Mbit/s of 1300-byte
  datagrams)**: above that the received rate stops growing regardless of offered load while
  the daemons sit at 65–85 % CPU and IRQ/softirq burns a full core (each tunnel packet is
  three loopback packets through conntrack and the 38-rule INPUT chain; `softnet_stat`
  shows `time_squeeze` on CPU0). Rust reaches that ceiling loss-free; C++ starts losing
  packets at ~5k pps under the generator's 64-packet bursts, well before it is CPU-bound —
  one packet per event-loop iteration vs the Rust loop's 64-packet drains.
* **Threads cannot show a gain against a kernel ceiling**; here they only add handoff CPU
  (t1 = t0 throughput at +15 % CPU). Client-side isolation (fast Rust server): Rust
  `--threads 0` client 9,360 pps vs C++ client 6,436 pps (1.45×) at similar client CPU.
* Cheaper crypto (`none + hmac_sha1`, i.e. integrity only with WireGuard inside) lifts C++
  to 8.3k pps and Rust to 11.2k pps.
* Interop cases (C++ on one side) worked in both directions at every step (probe 500/500).

Caveats and next steps:

* Both ends on one 4-core box, on loopback, on a busy router — the absolute numbers are a
  lower bound for the real deployment (Pi = client, VPS = server, traffic over eth0, no
  loopback triple-processing). Measure that next: the same scripts work with the sink on
  the VPS.
* `tools/bench/run_fixed_pi.sh` (prepared, not yet run) offers a fixed 7k pps with 8-packet
  bursts and reports **user vs system CPU per daemon**, which isolates the daemons' own
  cost from kernel work and settles the burst-sensitivity question. Run it next, then the
  Pi 5 (hardware AES).
* The generator on the Pi tops out near 29k pps offered (`usleep` pacing); enough for these
  capacities, not for a Pi 5.
* `net.core.rmem_max` is 212992 on this box, so the daemons' requested 1 MB socket buffers
  are capped in production; consider raising it (or `--force-sock-buf`).

## Docker 4-core benchmark and the threading fixes (2026-08-27)

Long runs on the Pi disturb the router it lives on, so the threading study moved to the
arm64 dev container on the Mac (`tools/docker/bench.sh`): daemons pinned to 4 cores
(`taskset`), `--aes-backend table` to take the Pi 4's no-AES-instructions code path, the
C++ reference built from the same checkout (portable-C AES), same no-drop-rate search.
Cores are ~5× faster than an A72, so absolute numbers do not transfer; ratios do.

Two defects found and fixed on the way (both also explain the flat threading results on the Pi):

1. **I/O thread busy-polled while jobs were in flight** (`poll` timeout 0 whenever
   `pipeline.in_flight() > 0`), burning a core that the workers needed. Completions already
   wake the loop through the eventfd; the zero timeout is now used only for sockets whose
   drain budget ran out. (`8f1b17b`)
2. **Per-packet handoff**: one channel message + one eventfd write per packet. Jobs are now
   handed over in batches of 16 (`pipeline.rs`, `77276c9`); ordering is unchanged.

No-drop rate, 1300-byte datagrams (`docs/bench/docker-ndr-2026-08-27.txt`;
`extra_*` = build before the two fixes):

| case | shared: all on 4 cores | split: each daemon on its own 4 cores |
|---|---:|---:|
| C++ ↔ C++ | 81.8k pps | 85.9k pps |
| Rust `--threads 0` (table AES) | 132k (1.62×) | 133k (1.55×) |
| Rust `--threads 1` | 149k | 140k |
| Rust `--threads 2` | 187k | **265k (3.1× C++, 2.0× threads 0)** |
| Rust `--threads 3` | 200k (2.45×) | 250k |
| Rust `--threads 0`, hardware AES | 208k | 205k |
| Rust `--threads 2`, hardware AES | 222k | 294k |
| before fixes, `--threads 2` (table) | 122k (slower than threads 0) | 259k |
| before fixes, `--threads 2` (hw) | 152k | 286k |

Reading: with the fixes, threads scale in both models; with its own cores a daemon doubles
its single-threaded rate with two workers, after which **the I/O thread is the limit**
(~100 % at 265k pps: one `recvfrom` + one `sendto` per packet plus header work). That is the
next optimisation (`recvmmsg`/`sendmmsg`). On a CPU with hardware AES the crypto is cheap, so
`--threads 0` is already 2.4× C++ and `--threads 2` adds another 1.4×.

Guidance: Pi 4 as the only udp2raw daemon on the box → `--threads 2` (the default auto
value); Pi 5 → `--threads 0` or `2`, measure; both ends on one small box → `--threads 1`.
The Pi 4 loopback numbers above were taken **before** these fixes and under a kernel
ceiling; re-measure there (briefly) with `--threads 2` when convenient.

## Raspberry Pi 4, quick re-run with the final build (2026-08-27, 88 s)

Same loopback setup as the long run, final binary (`60a36d6`: table AES, batched handoff,
no busy-poll), 5 search steps of 2 s (`docs/bench/pi4-quick-2026-08-27.txt`):

| case | no-drop pps | Mbit/s | server / client CPU | vs C++ |
|---|---:|---:|---|---:|
| C++ ↔ C++ | 10,220 | 106 | 98 % / 87 % | 1.00× |
| Rust `--threads 0` | 14,784 | 154 | 91 % / 97 % | 1.45× |
| Rust `--threads 2` | 18,720 | 195 | 130 % / 135 % | 1.83× |

Notes: the C++ reached 10.2k this time (4.7k in the long run) — its loss under bursts is
erratic between runs, so treat its number as 5–10k; the Rust numbers were stable across
steps. Both ends share the 4 cores here (3 threads each with `--threads 2`, plus the
generator), which is why the threaded gain (1.27× over single-threaded) is smaller than the
2.0× seen with one daemon per 4-core box in Docker — the deployment case still needs a
two-box measurement.

## e2e run log

### 2026-08-27 — Docker Desktop (Apple Silicon), `rust:1-bookworm` arm64, loopback

Setup: `tools/docker/e2e.sh`; client and server both `-a`; probe = 2,000 × 1,000-byte
datagrams on 2 convs (must echo back intact); then a 3 s one-direction UDP blast
(Python, ~950k pps offered) into a sink behind the server. The C++ reference is the
generic `make dynamic` build (portable C AES). CPU is shared by both daemons, the blaster
and the sink, so the throughput column is only a relative indication.

| case | probe | tunnel throughput (sink) |
|---|---|---|
| cpp_cpp_baseline | 2000/2000 | 84k pps / 875 Mbit/s |
| rust_rust_default (4 threads) | 2000/2000 | 154k pps / 1600 Mbit/s |
| rust_rust_threads0 | 2000/2000 | 226k pps / 2349 Mbit/s |
| rust_rust_threads3 | 2000/2000 | 268k pps / 2783 Mbit/s |
| rust_rust_cfb_hmac_gro | 2000/2000 | 178k pps / 1847 Mbit/s |
| rust_rust_xor_simple_seq1 | 2000/2000 | 132k pps / 1370 Mbit/s |
| rust_rust_none_none | 2000/2000 | 109k pps / 1132 Mbit/s |
| rust_rust_udp | 2000/2000 | 144k pps / 1497 Mbit/s |
| rust_rust_icmp | 2000/2000 | 160k pps / 1662 Mbit/s |
| rust_rust_hbmode0 | 2000/2000 | 149k pps / 1551 Mbit/s |
| cpp_server_rust_client | 2000/2000 | 74k pps / 773 Mbit/s |
| rust_server_cpp_client | 2000/2000 | 94k pps / 979 Mbit/s |
| cpp_server_rust_client_cfb (aes128cfb+hmac_sha1) | 2000/2000 | 68k pps / 704 Mbit/s |
| rust_server_cpp_client_icmp (xor+crc32) | 2000/2000 | 126k pps / 1307 Mbit/s |
| cpp_server_rust_client_udp (simple) | 2000/2000 | 94k pps / 979 Mbit/s |
| rust_server_cpp_client_gro (--fix-gro) | 2000/2000 | 92k pps / 957 Mbit/s |

Lessons: (1) the first probe version overflowed its own 212 KB receive buffer and reported
9% delivery in every case — udp2raw's `--sock-buf` is silently capped by
`net.core.rmem_max` too, so raise it on the Pi (`sysctl -w net.core.rmem_max=16777216`)
or use `--force-sock-buf`; (2) the unbounded drain loop starvation described above.
