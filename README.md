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
  re-resolved through explicit `--dns-server`s whenever an established session enters a
  reconnect cycle, when an expired TTL is observed at another reconnect boundary, or when a
  refresh is forced; a new address is adopted without changing the process, local listener,
  or WireGuard configuration. See "Hostname endpoints".
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
# reproducible static Pi 4/5 release (needs Docker; requires a clean commit):
tools/release/build_arm64_static.sh
```

The release script snapshots one clean commit, builds it twice offline using the captured ID of a
pinned ARM64 container, verifies matching hashes and a static AArch64 ELF, and atomically publishes
a versioned directory containing the binary, attestation, and checksums. See
[`docs/release-arm64-static.md`](docs/release-arm64-static.md).

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

A client `-r` may be a hostname. It is resolved only through the explicitly configured
`--dns-server`s (never `/etc/resolv.conf` or an external command). Switching remains in the
same process, so the PID and local UDP listener do not change. The conservative v1 policy is
availability-first: a healthy Ready session is not interrupted merely because its DNS TTL
expired or DNS now prefers another address. Resolution happens at startup or from a
reconnect boundary. A failed established session always starts a fresh lookup even if the
cached TTL has time left. If that lookup fails, its refresh intent remains pending and is
retried with bounded exponential backoff and jitter; the current and committed-good
addresses are retained. A usable answer that still points at the dead address also leaves
the refresh pending: it is retried at the minimum interval instead of being suppressed by
the answer's fresh TTL, and only authentication clears that pending state. TTL expiry means
the *next* other reconnect must also refresh the answer.

Options specific to hostname endpoints and rollback:

| option | meaning |
|---|---|
| `-r host:port` | Resolve IPv4 `A` records for `host`; literal client endpoints and server `-r` remain numeric and unchanged. |
| `--dns-server ip[:port]` | Resolver to use (default port 53); repeat to add resolvers in priority order. The first resolver with a policy-valid answer wins. Required with hostname `-r`. |
| `--dns-timeout ms` | Per-resolver, per-transport timeout (default 2000); the complete resolver pass also has one shared elapsed-time limit. |
| `--underlay-dev dev` | Bind DNS and relay sockets to the native interface and manage one `/32` route per relay address. Implies `--dev` when unset. |
| `--underlay-gateway ip` | Next hop on `--underlay-dev`; by default it is learned from the existing route to the bootstrap address (on-link if none). |
| `--allow-private-endpoint` | Also permit RFC 1918 and CGNAT endpoints. Unspecified, loopback, link-local, multicast, broadcast, reserved, documentation, benchmark and other unsuitable special-purpose ranges remain forbidden. |
| `--endpoint-cache path` | Committed-good cache (default `/var/lib/udp2raw/endpoint_<host>_<port>`); `none` disables it. |
| `--bootstrap-addr ip` | Literal start address only when DNS and the cache are both unavailable. |
| `--last-good-fallback` | Explicitly enable bounded authenticated rollback. It is **off by default** and requires hostname `-r`, an enabled owner-only endpoint cache, and `--fifo`. |
| `--last-good-fallback-after count` | Failed preferred-candidate handshakes before blind rollback may be considered (default 3); absent the overall round deadline, the canonical candidate set gets a turn first. |
| `--last-good-fallback-max-attempts count` | Pre-charged old-address probes allowed for one unchanged canonical DNS set and candidate (default 2). |
| `--last-good-fallback-cooldown sec` | Per-set cooldown between blind old-address probes (default 300). |
| `--last-good-fallback-max-age sec` | Maximum age of a startup cache timestamp used as fallback proof (default 86400). This does not age out fresh authenticated runtime health. |
| `--last-good-fallback-global-attempts count` | Persisted global old-address probe token capacity across changing DNS sets (default 4). |
| `--last-good-fallback-global-refill sec` | Seconds to refill one global token (default 900). |
| `--last-good-fallback-round-timeout sec` | Overall preferred-candidate round deadline (default 30). |
| `--last-good-fallback-probation sec` | Minimum sustained authenticated DATA span required before promotion (default 30). |
| `--last-good-fallback-rollback-window sec` | Maximum health-freshness window in which the prior committed endpoint can be retained for rollback (default 300). |

Fallback tuning flags without `--last-good-fallback` are rejected; the feature cannot become
enabled merely because a hostname or cache is present.

#### State machine: committed-good, candidate and probationary

A DNS address is only a candidate. With rollback enabled, the cache names one
**committed-good** endpoint: the durable rollback point. A different endpoint that completes
one correctly keyed handshake is only **probationary**. Its handshake proves possession of
the tunnel key, not that it carries real traffic, so it cannot overwrite the cache or release
the previous endpoint's native route/rule.

Startup-cache freshness and runtime health are separate clocks. `saved=` is a wall-clock
proof used when the process starts. Once committed-good authenticates in this process, its
successful handshake and every accepted authenticated heartbeat or DATA packet refresh
monotonic runtime health. Thus an endpoint still carrying authenticated traffic remains
rollback-eligible even when its original handshake and cache entry are older than 24 hours.
When another endpoint is tried, that last runtime timestamp is frozen and remains eligible
for at most the configured rollback window.

There is no periodic Ready-state DNS refresh and no destructive five-minute preferred probe.
A working fallback stays connected until it fails or an operator requests an attended
cutover. `echo reconnect > <fifo>` is that attended operation: it may interrupt the tunnel
once, performs one fresh bounded resolution/candidate attempt, and returns directly to the
preserved committed endpoint if the candidate cannot authenticate. This direct return does
not consume the blind old-IP budget. Before switching, the client also refuses a cutover
whose committed endpoint cannot remain rollback-eligible through the round, handshake,
probation and timer grace.

If the candidate authenticates, both endpoints are retained during probation. A candidate
from the attended cutover can return directly to the endpoint that was working immediately
beforehand. Startup- and automatic-origin probation returns are blind old-address probes and
must first consume the durable per-set and global budgets; if a timed rollback cannot be
pre-charged, a live probationary candidate is not torn down. No destructive rollback is
scheduled after committed-good eligibility has expired.

The deployment's external gateway health collector (or an attending operator) is the v1
promotion authority. FIFO promotion/rollback verdicts are endpoint-qualified so a delayed
verdict cannot apply to a later candidate:

```sh
echo reconnect > /run/udp2raw.fifo               # fresh DNS + one attended cutover
echo "promote 47.243.2.40" > /run/udp2raw.fifo  # commit this active candidate
echo "rollback 47.243.2.40" > /run/udp2raw.fifo # reject this active candidate
```

`promote <candidate-ip>` succeeds only when all of the following are true:

* that exact address is the active, authenticated probationary candidate; when a safe
  automatic rollback deadline was scheduled, promotion is still before that deadline and
  the previous committed endpoint remains eligible;
* at least three accepted inbound authenticated DATA packets for a live local conversation
  were delivered from that candidate; handshakes, heartbeats and unknown conversations do
  not count;
* the first-to-last counted DATA span is at least
  `--last-good-fallback-probation`;
* no gap in the counted run, and no age of the most recent evidence at promotion time, is
  greater than `min(probation, 5 seconds)`; a larger gap resets the evidence run; and
* persisting the new committed cache succeeds.

Only then is the candidate committed and the previous route/rule released. If stale startup
history could not support a safe automatic rollback deadline, the old cache/route stay
preserved and explicit promotion is still allowed after the full DATA evidence; no automatic
destructive rollback is scheduled in that case. `rollback <candidate-ip>` is accepted only
for that active probationary address while its preserved committed endpoint is still
eligible.

#### Bounded DNS influence

Each resolver's answer is validated *before* that resolver is considered successful. An
answer containing only forbidden/unusable addresses does not suppress the next configured
resolver. Valid addresses are deduplicated, sorted numerically and capped at eight; DNS wire
order therefore cannot enlarge or reorder a candidate round. Continuity keeps the current
or already committed address first when it is still in the set, with remaining choices in
numeric order.

One resolver pass is capped at 10 seconds total across every configured resolver and any
UDP-to-TCP retry; with fallback enabled it is further capped by the configured preferred
round timeout. The preferred round has its own overall deadline, so eight answers or a
churning/poisoned set cannot multiply per-address handshakes into minutes of delayed
recovery. TTLs are clamped to 10–3600 seconds, and failed queries back off without erasing
the current endpoint or last usable candidates.

#### Durable cache and retry limits

The endpoint-cache text format remains backward compatible. Canonical files contain
`host=`, `port=`, `addr=` and `saved=` (plus the existing optional comment). Legacy files
without `saved=` remain valid as startup-only history, but cannot override usable DNS until
that address authenticates in this process. Host and port must exactly match the configured
endpoint, and the address must be canonical and pass the same safety policy as DNS.

Cache input is limited to 4 KiB and must be one strict document with no trailing fields or
data. The cache, fallback sidecar and lock must be regular files owned by the effective uid,
mode exactly `0600`, with one link: symlinks, hard links, FIFOs and devices are rejected.
Their containing directory is created if needed, then must be a real, effective-uid-owned
directory with no group/world write bits; a symlinked or replaced directory is rejected.

The FIFO is also an authority, not an ordinary world-writable pipe. A new command FIFO is
created with exact mode `0600`; a pre-existing one is accepted only when it is a real FIFO
owned by the effective uid, mode `0600`, with one link. It is opened relative to the held
trusted parent with `O_NOFOLLOW`; symlinks, regular files, devices, unsafe parents and raced
replacements fail startup. Put it in an effective-uid-owned non-writable directory such as a
dedicated directory below `/run`, not directly in a shared writable directory.

Writes use an unpredictable 128-bit-CSPRNG same-directory temporary opened create-new /
exclusive with `O_NOFOLLOW` and mode `0600`. Metadata is revalidated, contents are written
fully, the file is `fsync`ed, rename is atomic, and the directory is `fsync`ed. Existing
unsafe destinations are rejected rather than replaced or followed.

With fallback enabled, `<cache>.fallback-state` is a strict, owner-only v1 sidecar (maximum
16 KiB) protected by `<cache>.fallback-state.lock`. Each blind old-IP attempt is reloaded and
**pre-charged under the durable lock before the network probe begins**, so a crash cannot
refund it and concurrent processes cannot lose an update. A per-set entry is keyed by
hostname, port, canonical DNS-answer set and candidate address; the global token bucket and
refill timestamp span every answer set. At most 16 charged set entries are retained; a 17th
key is refused rather than evicting history. DNS-set churn can therefore neither reset the
global bucket nor create unbounded state. Unsafe, corrupt or unwritable sidecar/lock state
disables unattended old-address probes fail-closed, while an already-authorized rollback or
the endpoint-qualified direct return from an attended cutover remains available.

Runtime-health timestamps are intentionally process-local; after a restart, only the strict
cache `saved=` timestamp can establish startup freshness until the endpoint authenticates
again. V1 performs no automatic sidecar migration: for example, lowering global capacity
below a persisted token count makes that state invalid and disables blind probes until an
operator performs a reviewed, attended state migration. It is never silently reset, because
resetting would refund attempts.

#### Route/rule ownership and timing validation

Protocol-235 `/32` routes and iptables rules have independent desired state and independent
five-second repair retries for both the active endpoint and a preserved rollback endpoint.
An existing rule, or inability to list it, is not evidence that the route exists. Cleanup
bookkeeping remains until each deletion is confirmed. If an endpoint becomes retained again
after an unconfirmed deletion, the resource stays unknown: the route is reconciled with an
IPv4 main-table dump that must match the exact `/32`, protocol 235, unicast type, gateway,
interface, preferred source and per-process metric; the rule is reconciled against the exact
active-chain INPUT jump, including address, protocol and port/type. Verified absence is
recreated, verified presence is retained, and an inconclusive check remains retryable. An
unavailable iptables listing gets one real availability-first insert attempt rather than
being treated as proof of presence.

Routes use create-exclusive, per-process metrics and exact-match deletion, so two cooperating
clients can share one relay `/32` without one deleting the other's route; operator routes are
not owned or removed. Linux rtnetlink has no per-process route owner cookie, so the random
metric plus exact native-path tuple is the ownership token. A process that deliberately
recreates that identical tuple during a lost-ACK window cannot be distinguished without a
larger cross-process lease registry or a different kernel tagging scheme.

Fallback configuration is rejected unless:

```text
rollback_window > connection-loss detection (10 s)
                + preferred_round_timeout
                + one handshake timeout (5 s)
                + probation
                + two 400 ms timer intervals
```

The defaults require more than 75.8 seconds and provide 300 seconds. This validation and the
per-cutover runtime-freshness check prevent a destructive candidate attempt from being
scheduled after the rollback point would already be ineligible; they supplement, rather
than replace, activity-based health.

Failure-state summary:

| state / input | smallest-safe v1 result | durable/resource effect |
|---|---|---|
| Healthy Ready endpoint; TTL expires or DNS changes | Keep carrying traffic; do not query or cut over merely for TTL/convergence | No cache, budget, route or rule change |
| Attended `reconnect`; fresh answer has a different address | Interrupt once and try the deterministic preferred candidate only if rollback remains safe | Preserve committed cache and both endpoint resources during the attempt |
| Attended candidate is down or has the wrong key | Return directly to the just-working committed endpoint | No blind-probe token charged; candidate never enters cache |
| New relay handshakes but black-holes DATA | Keep it probationary; reject promotion without sustained accepted DATA; collector/operator rolls it back | Previous cache and native route/rule remain intact |
| Startup/automatic probation needs to return to old | Return only after a locked durable pre-charge; if denied, do not tear down a live candidate | Consume per-set/cooldown and global limits like every blind old-IP probe |
| Candidate meets DATA evidence and receives matching `promote` | Persist candidate, then make it committed-good | Release previous route/rule only after durable cache success |
| Preferred candidates fail without an attendant | After the configured threshold and a bounded candidate turn/deadline, try eligible committed-good only after locked durable pre-charge | Consume both its per-set charge/cooldown and one global token before probing |
| Resolver one returns only unsafe addresses | Treat that resolver as failed and query resolver two within the shared deadline | Last usable set and committed state remain unchanged |
| Resolver timeout, NXDOMAIN, malformed reply or overall deadline | Keep current/last usable state; retry with backoff | Does not refund/reset persisted budgets |
| Process crashes or restarts with unchanged/churning DNS | Reload the locked sidecar; an in-flight attempt was already charged | Per-set cooldown/cap and global bucket survive restart and set churn |
| Cache/sidecar is oversized, malformed, wrong identity/mode/owner/type or unsafe | Reject it; DNS then safe `--bootstrap-addr` decide startup. Unsafe budget state disables blind fallback | Never follow a symlink/FIFO/device; fail closed |
| Route or rule creation/deletion fails | Retry independently; keep failed cleanup pending; exact-reconcile an uncertain deletion before re-retaining it | Never infer one resource from the other or delete a peer client's exact route |
| Preferred round deadline expires | Stop extending that round with more candidate handshakes | Preserve the rollback point and begin only a later bounded reconnect round |

**DNS record recommendation:** publish exactly one unproxied IPv4 `A` record with a 30–60
second TTL. Multiple answers are bounded safely, but one record makes an attended migration
and its rollback unambiguous.

Karsen example (AliDNS, native `eth0`, and an attended FIFO cutover):

```sh
sudo ./udp2raw -c -l 127.0.0.1:7000 -r hk1b-udp2raw.clement.hk:8443 \
    --key-file /etc/udp2raw/key --raw-mode faketcp -a --fix-gro \
    --dns-server 223.5.5.5:53 --dns-server 223.6.6.6:53 \
    --underlay-dev eth0 --fifo /run/udp2raw-karsen/control.fifo
```

Wutong example (the same relay identity and resolver policy, with independent local state):

```sh
sudo ./udp2raw -c -l 127.0.0.1:7000 -r hk1b-udp2raw.clement.hk:8443 \
    --key-file /etc/udp2raw/key --raw-mode faketcp -a --fix-gro \
    --dns-server 223.5.5.5:53 --dns-server 223.6.6.6:53 \
    --underlay-dev eth0 --fifo /run/udp2raw-wutong/control.fifo
```

The default cache for both examples is
`/var/lib/udp2raw/endpoint_hk1b-udp2raw.clement.hk_8443`; each is local to its own host.
Add `--underlay-gateway <native-lan-gateway>` when the gateway cannot be learned from an
existing native route. `--last-good-fallback` and its tuning flags are optional, separately
documented controls for bounded *unattended* old-address probes; a failed candidate selected
by the attended FIFO command returns directly to the endpoint that command interrupted even
without that opt-in.

Attended rotation workflow:

1. Prepare the new relay and independently verify its key, mode, listener, firewall and real
   gateway traffic path. Keep the old relay running.
2. Update the one unproxied `A` record to the new address.
3. Keep the old EIP/listener/firewall through at least the full 30–60 second TTL grace period,
   including resolver and clock skew. Healthy sessions remain on it during this interval.
4. After the grace period, request one cutover with
   `echo reconnect > /run/udp2raw-karsen/control.fifo` (and the Wutong FIFO), or retire the
   old relay and let normal failure detection trigger the reconnect-boundary lookup.
5. With `--last-good-fallback`, let the external health collector measure the real service
   path while the new address is probationary. Send `promote <new-ip>` only after it is
   healthy; send `rollback <new-ip>` immediately if it black-holes or degrades traffic.
   Without that opt-in, the authenticated udp2raw handshake commits the candidate directly.
6. Retire the old EIP only after every client log confirms the new committed-good address
   (and, when probation is enabled, promotion and release of the previous endpoint).

Automatic migration from a healthy fallback is deliberately deferred. A future version may
add an independent parallel canary socket/session with measured packet-loss bounds and true
make-before-break behavior; v1 never performs recurring destructive convergence probes.
Rollback by restoring the prior `A` record while the old relay is still prepared, waiting
through the TTL grace period, and issuing the endpoint-qualified FIFO cutover/rollback as
appropriate. For break-glass startup when DNS itself is unavailable, the strict cache and a
safe `--bootstrap-addr` remain available. A literal `-r <ip>:<port>` with no hostname options
restores classic no-resolution behavior and is the final numeric escape hatch.

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
