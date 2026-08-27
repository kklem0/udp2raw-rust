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
| Docker e2e: loopback + veth/netns, all modes incl. chacha20poly1305, easy-faketcp, `--lower-level auto`, Rust↔C++ interop | **25/25 pass** (2026-08-27; veth cases need `--cap-add SYS_ADMIN`); 25/25 again with `RUST_EXTRA="--syscalls single"` (2026-08-28) |
| Pi 4 measurements (loopback, C++ vs Rust; deployed mode vs `chacha20poly1305`; batched-I/O regression found and fixed with `--syscalls`) | **done 2026-08-27/28** — see the "Raspberry Pi 4" sections below; Pi 5 and a two-box measurement still to do |
| **Production on the Pi 4** (`udp2raw-wutong.service`, faketcp client to the VPS, WireGuard inside) | **`0e0b3fa` deployed 2026-08-28 01:28** (`/opt/udp2raw-rust-0e0b3fa-arm64`, unchanged conf, `--syscalls auto` → single); replaced `60a36d6`. See "Deployment" below |

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
crypto (`1a7fd3b`; per-packet `recvfrom`/`sendto` on ARMv8.0 CPUs since `--syscalls`,
2026-08-28), `--cipher-mode chacha20poly1305` (AEAD, Rust↔Rust), a real
`--unit-test`, e2e coverage for `easy-faketcp` and for `--lower-level auto` over a veth
pair in a network namespace (also C++ interop across it).

* `--syscalls auto` = LSE-atomics hwcap (ARMv8.1+ → `mmsg`), otherwise the running kernel's
  config (`/boot/config-<release>`: software PAN off → `mmsg`, on or unreadable → `single`);
  the reason is logged at startup. `/proc/config.gz` is not read (would need zlib).
* **Measure again**: the deployment shape (Pi client ↔ VPS server over eth0) and the Pi 5
  (hardware PAN and AES: expect `mmsg` + `hw`). `bench.sh quick` in Docker is the ~1 min
  regression check; `tools/bench/run_quick_pi.sh` the ~30 s-per-case Pi check (`FIXED=<pps>`
  gives the user/sys split per daemon); `tools/bench/sysprof_pi.sh` the syscall/PMU profile.
* TPACKET_V3 ring for RX; write headers into headroom of the job buffer to drop the last
  copy on the TX path.
* CBC decrypt already batches blocks (`decrypt_blocks`); CBC encrypt is inherently serial.
* IPv6 e2e (`-l [::1]:4096`) — needs `ip6tables` in the container; not needed for now.
* The fifo only supports `reconnect` (same as the C++).
* Logging goes to stdout with the C++ format; `--log-position` prints file:line.

## Deployment (Pi 4 client, 2026-08-28)

Convention: hash-named binaries in `/opt` (`udp2raw-rust-<short hash>-arm64`, built by
`cargo build --release` in the arm64 dev container from a clean checkout), the systemd unit
`/etc/systemd/system/udp2raw-wutong.service` points at one of them
(`ExecStart=/opt/udp2raw-rust-<hash>-arm64 --conf-file /etc/udp2raw/wutong.conf --threads 2`);
the conf does not name `--syscalls`/`--aes-backend`, so `auto` applies (single + table on
this CPU, logged at level 4 — the conf runs at level 3, so verify with a tracepoint sample
or a smoke run instead). Procedure used:

1. `--unit-test` on the box, then a smoke run as a *second* client against the real server
   with a copy of the conf on another `-l` port (7001 was taken by an unrelated listener;
   `ss -lun` first) and `--log-level 4`: `client_ready` within a second, iptables rule removed
   on exit. Delete the copy afterwards (it holds the key).
2. Back up the unit, `sed` the `ExecStart` path, `daemon-reload`, `restart`; wait for the
   wg1 handshake (8 s), `ping 10.66.0.1` (0 % loss at 12 ms), check the journal.
   Rollback = restore the backup unit (`/root/bench/udp2raw-wutong.service.bak-60a36d6`),
   `daemon-reload`, `restart`; the previous binary stays in `/opt`.
3. Live check of the syscall mode: tracefs `raw_syscalls` on the main PID for 2 s showed
   only `sendto`/`recvfrom`/`epoll_pwait`/`read`/`futex` — no mmsg calls.

Known, pre-existing: the client logs `WARN unexpected adress <ip> <server ip> <port>
<server port>` (~50/day) when a foreign TCP packet reaches its raw socket — ignored
packets, same message as the C++.

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
gro:    [len u16][encrypted] with the first 16 bytes ECB-encrypted (xor/chacha: first 2 bytes ^ gro_xor)
chacha20poly1305 (Rust only): [nonce 24, random][XChaCha20-Poly1305(plain)][tag 16], keys =
        cipher_key_encrypt/decrypt[..32]; ids and anti-replay seq stay inside the plaintext
```

## Raspberry Pi 4 benchmark (2026-08-27)

Box: `wutong`, Raspberry Pi 4 (Cortex-A72 ×4, 1.8 GHz, no AES/SHA instructions), Ubuntu
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

## Raspberry Pi 4: chacha20poly1305 vs the deployed mode (2026-08-27, 4 batches of ≤ 96 s)

Same loopback setup, driven by `tools/bench/run_quick_pi.sh` (sets `rmem_max`/`wmem_max`
and the governor for the run, restores them, prints a health check); raw log
`docs/bench/pi4-chacha-2026-08-27.txt`. Generator `udpbench2` (sendmmsg, 64-packet
bursts), 5 search steps of 2 s. Rust = this repo at `3c380ad` (`udp2raw-head`: table AES,
batched I/O); "old" = the running production binary `60a36d6` (per-packet syscalls) as a
same-session control; C++ = production `fb13730`. Deployed mode = faketcp + aes128cbc +
md5 + `--fix-gro`; chacha = the same with `--cipher-mode chacha20poly1305`.

| case | no-drop pps | Mbit/s | server / client CPU | vs C++ |
|---|---:|---:|---|---:|
| C++ ↔ C++, deployed mode | 9,984 | 104 | 95 % / 83 % | 1.00× |
| Rust `--threads 0`, deployed mode | 11,968 | 124 | 88 % / 89 % | 1.20× |
| Rust `--threads 2`, deployed mode | 14,818 | 154 | 117 % / 121 % | 1.48× |
| Rust `--threads 0`, chacha20poly1305 | 13,984 | 145 | 86 % / 92 % | 1.40× |
| Rust `--threads 2`, chacha20poly1305 | 14,976 | 156 | 108 % / 108 % | 1.50× |
| old `60a36d6` `--threads 0`, deployed mode (control) | 13,984 | 145 | 86 % / 91 % | 1.40× |
| old `60a36d6` `--threads 2`, deployed mode (control) | 14,976 | 156 | 110 % / 112 % | 1.50× |

Fixed 10,000 pps for 5 s (zero loss in every case); each daemon's CPU split into user (its
own work: crypto, framing) and sys (kernel work inside its syscalls, including loopback
delivery of what it sends):

| case | server user / sys | client user / sys | whole box busy |
|---|---|---|---|
| Rust t0, aes128cbc + md5 | 26 % / 46 % | 22 % / 52 % | 201 % |
| Rust t0, chacha20poly1305 | 17 % / 47 % | 14 % / 51 % | 171 % |
| old `60a36d6` t0, aes128cbc + md5 | 29 % / 36 % | 24 % / 40 % | 183 % |
| Rust t2, aes128cbc + md5 | 30 % / 54 % | 23 % / 59 % | 215 % |
| Rust t2, chacha20poly1305 | 19 % / 56 % | 14 % / 59 % | 198 % |
| old `60a36d6` t2, aes128cbc + md5 | 30 % / 49 % | 27 % / 51 % | 207 % |

What the numbers mean:

* **ChaCha20-Poly1305 cuts the daemons' own CPU by about a third on the A72** (user time
  17 % vs 26 % on the server, 14 % vs 22 % on the client at 10k pps) and lifts the
  single-threaded no-drop rate from 12.0k to 14.0k pps (+17 %). With `--threads 2` both
  modes reach this session's loopback ceiling (~15k pps, `sys_busy` 250–290 %), chacha at
  ~10 points less CPU per daemon. It is the mode to use Rust↔Rust on a Pi 4; the gain is
  bounded because on this box the kernel, not the crypto, is most of the per-packet cost
  (sys 46–59 % vs user 14–30 % per daemon).
* **The batched-I/O build (`1a7fd3b`) spends more system time here than `60a36d6`**:
  same session, same generator — old t0 13,984 pps vs HEAD 11,968; at 10k pps sys 46/52 %
  vs 36/40 % per daemon while user time is slightly *lower* (in-place crypto). Root cause
  and fix in the next section (`--syscalls`); the table above is the *unfixed* build.
* The C++ reproduced its earlier figure (9,984 vs 10,220). The `--threads 2` ceiling was
  15k pps in this session vs 18.7k in the earlier quick run (generator burst shape and
  router load differ between sessions) — compare rows only within one session.
* All cases: probe 500/500, no `dropped`/`overloaded`/`rst` warnings; after every batch
  `rmem_max`/`wmem_max` back at 212992 and the governor at `ondemand`, no leftover
  processes, production daemon active, WireGuard handshakes continuing, temperature ≤ 63 °C.

## Why the batched-I/O build was slower on the Pi 4, and the fix (2026-08-28)

Symptom (previous section): same box, same generator, `60a36d6` (one `recvfrom`/`sendto`
per packet) reached 13,984 pps single-threaded, HEAD with `recvmmsg`/`sendmmsg` 11,968, and
at a fixed 10k pps HEAD's daemons spent 46/52 % in the kernel vs 36/40 % — with *lower* user
time. Docker (arm64 VM, kernel 6.12) showed no difference at all. Tool:
`tools/bench/sysprof_pi.sh` (fixed rate; user/sys split, context switches, per-syscall kernel
time from the tracefs `raw_syscalls` tracepoints, PMU counters and a `perf` profile per
daemon); raw logs `docs/bench/pi4-syscalls-2026-08-28.txt` and
`docs/bench/docker-syscalls-2026-08-28.txt`.

1. Syscall counts (`strace -c` in Docker): HEAD makes far *fewer* syscalls — 50k packets cost
   the client 788 `sendmmsg` + 2,350 `recvmmsg` + 1,578 `epoll_pwait` instead of 37k
   `sendto` + 37k `recvfrom`. (The server's UDP replies are one `sendto` per packet in both.)
2. Kernel time per syscall on the Pi (tracepoints, 5k pps): `recvfrom` 9.3 µs and `sendto`
   27 µs per packet; `recvmmsg` 19 µs and `sendmmsg` 36 µs *per packet*, with only 10–20
   packets per call. The batched calls cost about twice as much per packet.
3. Not scheduling: pinning server, client and generator to separate cores cut involuntary
   context switches 5× for both builds and left the gap untouched (sys 35/37 % vs 45/51 %).
4. PMU counters: HEAD retires ~10k *more instructions* per packet (server 96.8k → 105.4k,
   client 101k → 115k) at the same IPC and with fewer L1 misses — extra kernel work, not
   stalls, contention or cache thrashing.
5. `perf`: the only symbols that grow are `uaccess_ttbr0_enable`/`uaccess_ttbr0_disable` —
   25.7 % of HEAD's samples vs 12.2 % of `60a36d6`'s; netfilter, softirq and spinlocks are
   identical. The Cortex-A72 is ARMv8.0 and has no hardware PAN, so the Ubuntu kernel
   (`CONFIG_ARM64_SW_TTBR0_PAN`) switches TTBR0 with an ISB around *every* user-memory access
   inside a syscall. `recvmmsg` touches the caller's `mmsghdr`, iovec, address,
   `msg_namelen`, `msg_flags`, `msg_controllen` and `msg_len` per message (~8 switches per
   packet vs 3 for `recvfrom`; `sendmmsg` ~5 vs 2 for `sendto`), and each switch costs
   ~1–2k cycles here. On CPUs with hardware PAN (ARMv8.1+: Pi 5, the Docker VM) the switch is
   a single instruction, which is why Docker never showed it.

Fix — `--syscalls auto|mmsg|single` (`types::Syscalls`, `net::set_syscalls`): the batched
drain loop, pooled buffers and deferred flush stay; only the kernel calls change. `single` =
one `recvfrom`/`sendto` per packet inside the same batch structure; `auto` = `single` on
aarch64 CPUs without LSE atomics (LSE and PAN both arrived in ARMv8.1, so "no LSE" =
Cortex-A53/A72 class), `mmsg` otherwise. The startup log shows the choice:
`syscalls: single (requested auto; cpu lse atomics: false)`.

Pi 4, fixed 10k pps, per daemon (server / client):

| build | user / sys | cycles per packet | instructions per packet |
|---|---|---|---|
| `60a36d6` (per-packet syscalls) | 29 / 36 %, 27 / 40 % | 87.0k / 86.9k | 96.8k / 101k |
| HEAD `3c380ad` (mmsg) | 28 / 47 %, 24 / 53 % | 92.8k / 96.4k | 105k / 115k |
| fixed, `--syscalls auto` → single | 27 / 39 %, 23 / 40 % | **83.8k / 81.5k** | 96.8k / 98.5k |
| fixed, `--syscalls mmsg` (control) | 28 / 48 %, 23 / 53 % | — | — |

Pi 4 no-drop rate, same setup as the previous section (`docs/bench/pi4-syscalls-2026-08-28.txt`):

| case | fixed build | HEAD `3c380ad` (mmsg) | `60a36d6` |
|---|---:|---:|---:|
| aes128cbc + md5, `--threads 0` | 13,984 (87 % / 86 %) | 11,968 (88 % / 89 %) | 13,984 (87 % / 90 %) |
| chacha20poly1305, `--threads 0` | **15,968** (85 % / 86 %) | 13,984 (86 % / 92 %) | — |
| aes128cbc + md5, `--threads 2` | 14,976 (112 % / 111 %) | 14,818 (117 % / 121 %) | 14,976 (110 % / 112 %) |
| chacha20poly1305, `--threads 2` | **18,863** (117 % / 116 %) | 14,976 (108 % / 108 %) | — |

The fixed build matches the old build's rate at slightly less CPU in the deployed mode, and
with chacha it goes past what looked like a 15k pps kernel ceiling (18.9k with `--threads 2`).

**chacha20poly1305 nonces (2026-08-28, same day):** the first version sent a 12-byte nonce
of `[4-byte per-process constant][8-byte counter]` in the clear, and `--fix-gro` masks only
the two length bytes in this mode — a visible pattern at the start of every payload that the
AES modes do not have. The mode now uses XChaCha20-Poly1305 with a fresh random 24-byte
nonce per packet from a per-thread ChaCha12 CSPRNG (seeded from the OS, reseeded every 2^24
nonces; no lock, no syscall per packet): `[nonce 24][ciphertext][tag 16]`, +40 bytes, payload
indistinguishable from random. Pi 4 quick run (`docs/bench/pi4-xchacha-2026-08-28.txt`):
chacha `--threads 0` 16,992 pps (94 % / 94 %), `--threads 2` 19,968 pps (121 % / 121 %) —
no measurable cost vs the 12-byte-nonce build (15,968 / 18,863). The raw-mode disguise is
untouched by the cipher mode: nothing in `faketcp.rs`/`client.rs`/`server.rs` branches on
it. Wire-format change of a mode only this port speaks; both ends update together.

Docker (fast cores, hardware PAN, split cores; `docs/bench/docker-syscalls-2026-08-28.txt`):
`mmsg` vs `single` is 137k vs 124–135k pps at `--threads 0` (table AES), 298k vs 298k at
`--threads 2` (table) and 311–323k vs 282–308k at `--threads 2` (hardware AES) — a few
percent at most, so `auto` keeps `mmsg` there. The `single` path is covered by the Docker
e2e with `RUST_EXTRA="--syscalls single"` (25/25 pass, 2026-08-28; the hook adds options to
the Rust daemons only, so the C++ interop cases still run).

Lesson: on ARMv8.0 cores the expensive part of a syscall is not the entry but every
user-memory access inside it, so APIs that write per-message bookkeeping back to user space
lose to the plain calls — measure on the target CPU, not on a stand-in.

## e2e run log

### 2026-08-28 — same suite, `RUST_EXTRA="--syscalls single"` (per-packet recvfrom/sendto path)

25/25 pass (`tools/docker/e2e.sh`, Docker Desktop arm64, `--cap-add NET_RAW,NET_ADMIN,SYS_ADMIN`,
C++ reference built from `~/git/udp2raw`); every probe 2000/2000.

### 2026-08-28 — `ONLY=chacha` after the switch to XChaCha20-Poly1305 random nonces

rust_rust_chacha and rust_rust_chacha_gro (faketcp, `--fix-gro --threads 2`): 2/2 pass,
probes 2000/2000, blast 405–415k pps through the tunnel (unpinned container).

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
