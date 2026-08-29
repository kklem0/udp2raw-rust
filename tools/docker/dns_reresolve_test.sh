#!/bin/bash
# Integration test for the client's `-r hostname:port` re-resolution (Linux, root; needs
# NET_ADMIN, NET_RAW and SYS_ADMIN for network namespaces). Inside the dev container:
#   docker run --rm --cap-add NET_RAW --cap-add NET_ADMIN --cap-add SYS_ADMIN -v "$PWD":/work \
#       -v udp2raw-cargo:/usr/local/cargo/registry -v udp2raw-target:/work/target-linux \
#       udp2raw-rust-dev tools/docker/dns_reresolve_test.sh
#
# Topology: namespace "cli" (the client; veth0 10.99.0.1/24; default route = blackhole, i.e.
# a VPN default whose far end is gone) <-> namespace "peer" (veth1 10.99.0.2/24; the DNS stub
# on :53). Each relay address 10.99.1.{10,20,30,40,99} lives on peer's lo with ITS OWN udp2raw
# server bound to that address (-l 10.99.1.X:4096, so a server answers only its own address);
# "down_addr X" stops that server, "up_addr X" starts it. Nothing in "cli" reaches a relay
# unless a /32 via 10.99.0.2 on veth0 exists, so the client has to install the route itself.
set -euo pipefail
WORKDIR=${DNS_RERESOLVE_WORKDIR:-/work}
cd "$WORKDIR"

# The usual target directory is a named volume and can contain an executable from another
# checkout. Build this run in a newly-created empty directory, and never name the shared
# release artifact as the test binary. A failed Cargo invocation therefore has no stale
# executable that the namespace suite could accidentally run.
SHARED_TARGET_DIR=${CARGO_TARGET_DIR:-/work/target-linux}
BUILD_PARENT=$SHARED_TARGET_DIR/dns-reresolve-fresh-builds
mkdir -p "$BUILD_PARENT"
FRESH_TARGET_DIR=$(mktemp -d "$BUILD_PARENT/run.XXXXXXXX")
cleanup_build() {
    case ${FRESH_TARGET_DIR:-} in
        "$BUILD_PARENT"/run.*) rm -rf -- "$FRESH_TARGET_DIR" ;;
    esac
}
trap cleanup_build EXIT
export CARGO_TARGET_DIR=$FRESH_TARGET_DIR
RUST=$FRESH_TARGET_DIR/release/udp2raw
BUILD_LOG=$FRESH_TARGET_DIR/cargo-build.log
CARGO_BIN=${CARGO_BIN:-cargo}
echo "== fresh release build ($FRESH_TARGET_DIR)"
if ! "$CARGO_BIN" build --release > "$BUILD_LOG" 2>&1; then
    echo "cargo build failed; namespace setup was not started" >&2
    tail -40 "$BUILD_LOG" >&2 || true
    exit 1
fi
if [ ! -x "$RUST" ]; then
    echo "cargo reported success but fresh binary is missing: $RUST" >&2
    exit 1
fi
tail -1 "$BUILD_LOG" || true

LOGDIR=${LOGDIR:-$SHARED_TARGET_DIR/dns-test-logs}; rm -rf "$LOGDIR"; mkdir -p "$LOGDIR"
ANS=$LOGDIR/answers.txt; FIFO=$LOGDIR/fifo; CACHE=$LOGDIR/endpoint.cache; CLOG=$LOGDIR/client.log
FIFO2=$LOGDIR/fifo.2; CACHE2=$LOGDIR/endpoint.2.cache; CLOG2=$LOGDIR/client.2.log
C="ip netns exec cli"; P="ip netns exec peer"
PASS=0; FAIL=0; pids=(); CPID=""; CPID2=""; PROBE_PID=""; declare -A SRV
ok() { PASS=$((PASS + 1)); echo "   ok   $1"; }
bad() { FAIL=$((FAIL + 1)); echo "   FAIL $1"; }
expect() { if "${@:2}" > /dev/null 2>&1; then ok "$1"; else bad "$1"; fi; }
expect_not() { if "${@:2}" > /dev/null 2>&1; then bad "$1"; else ok "$1"; fi; }
cleanup() {
    set +e
    [ -n "$CPID" ] && kill "$CPID" 2>/dev/null
    [ -n "$CPID2" ] && kill "$CPID2" 2>/dev/null
    [ -n "$PROBE_PID" ] && kill "$PROBE_PID" 2>/dev/null
    for p in "${SRV[@]:-}" "${pids[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
    sleep 0.5
    ip netns del cli 2>/dev/null; ip netns del peer 2>/dev/null
    cleanup_build
}
trap cleanup EXIT
up_addr() { # X : start a server bound to 10.99.1.X (idempotent)
    local a=$1
    [ -n "${SRV[$a]:-}" ] && kill -0 "${SRV[$a]}" 2>/dev/null && return
    $P "$RUST" -s -l "10.99.1.$a:4096" -r 127.0.0.1:7777 -k pw -a --log-level 3 --fix-gro > "$LOGDIR/server.$a.log" 2>&1 &
    SRV[$a]=$!
}
up_bad_addr() { # X : reachable server with the wrong key (can never authenticate)
    local a=$1
    [ -n "${SRV[$a]:-}" ] && kill -0 "${SRV[$a]}" 2>/dev/null && return
    $P "$RUST" -s -l "10.99.1.$a:4096" -r 127.0.0.1:7777 -k wrong-key -a --log-level 3 --fix-gro > "$LOGDIR/server.$a.bad-key.log" 2>&1 &
    SRV[$a]=$!
}
up_blackhole_addr() { # X : authenticates with the right key but has no working UDP backend
    local a=$1
    [ -n "${SRV[$a]:-}" ] && kill -0 "${SRV[$a]}" 2>/dev/null && return
    $P "$RUST" -s -l "10.99.1.$a:4096" -r 127.0.0.1:7799 -k pw -a --log-level 3 --fix-gro > "$LOGDIR/server.$a.blackhole.log" 2>&1 &
    SRV[$a]=$!
}
down_addr() { # X : stop the server for 10.99.1.X
    local a=$1
    [ -n "${SRV[$a]:-}" ] && kill "${SRV[$a]}" 2>/dev/null
    SRV[$a]=""
    sleep 0.3
}
wait_log() { local f=${3:-$CLOG}; for _ in $(seq 1 $(($2 * 10))); do grep -q -- "$1" "$f" 2>/dev/null && return 0; sleep 0.1; done; return 1; }
wait_ready_file() { local f=$1 count=$2 seconds=$3; for _ in $(seq 1 $((seconds * 10))); do [ "$(grep -c 'client_handshake2 to client_ready' "$f" 2>/dev/null || true)" -ge "$count" ] && return 0; sleep 0.1; done; return 1; }
wait_ready() { wait_ready_file "$CLOG" "$1" "$2"; }
# Liveness probe: datagrams must round-trip through the tunnel. Retried for a few seconds
# because the data plane can take a moment to settle right after a (re)connect.
probe() {
    probe_port 3333
}
probe_port() {
    local port=$1
    for _ in $(seq 1 8); do
        $C python3 tools/udp_probe.py 127.0.0.1 "$port" 60 1000 2 0.70 > "$LOGDIR/probe.$port.log" 2>&1 && return 0
        sleep 1
    done
    return 1
}
start_continuous_probe() { # name duration max-loss-gap min-ratio [port]
    local name=$1 duration=$2 max_gap=$3 min_ratio=$4 port=${5:-3333}
    local log=$LOGDIR/continuous.$name.log
    $C python3 tools/docker/continuous_udp_probe.py 127.0.0.1 "$port" "$duration" 0.10 0.75 "$max_gap" "$min_ratio" > "$log" 2>&1 &
    PROBE_PID=$!
    wait_log "continuous probe started" 3 "$log"
}
finish_continuous_probe() {
    local pid=$PROBE_PID
    PROBE_PID=""
    [ -n "$pid" ] || return 1
    wait "$pid"
}
route_has() { $C ip route show "$1/32" | grep -q "proto 235"; }
rule_has() { $C iptables -S INPUT | grep -q -- "-s $1/32 "; }
route_count() { $C ip -o route show "$1/32" | awk '$0 ~ /proto 235/ { n++ } END { print n + 0 }'; }
rule_count() { $C iptables -S INPUT | awk -v ip="$1/32" 'index($0, "-s " ip " ") { n++ } END { print n + 0 }'; }
wait_route_count() { local ip=$1 count=$2; for _ in $(seq 1 30); do [ "$(route_count "$ip")" -eq "$count" ] && return 0; sleep 0.1; done; return 1; }
cache_addr() { sed -n 's/^addr=//p' "$CACHE" 2>/dev/null; }
write_cache() { # address [saved-unix-seconds]
    local saved=${2:-$(date +%s)}
    printf '# udp2raw endpoint cache: the last address whose handshake succeeded\nhost=relay.test\nport=4096\naddr=%s\nsaved=%s\n' "$1" "$saved" > "$CACHE"
    chmod 600 "$CACHE"
}
clear_endpoint_state() { rm -f -- "$CACHE" "$CACHE.fallback-state" "$FIFO"; }
listener_ino_port() { $C ss -lune 2>/dev/null | grep "127.0.0.1:$1" | grep -o "ino:[0-9]*"; }
listener_ino() { listener_ino_port 3333; }
dns_queries() { awk '/ query relay[.]test / { n++ } END { print n + 0 }' "$LOGDIR/stub.log" 2>/dev/null; }
start_client() {
    : > "$CLOG"
    $C "$RUST" -c -l 127.0.0.1:3333 -r relay.test:4096 -k pw -a --log-level 4 --fix-gro --dns-server 10.99.0.2:53 --dns-timeout 500 --allow-private-endpoint --endpoint-cache "$CACHE" --fifo "$FIFO" "$@" > "$CLOG" 2>&1 &
    CPID=$!
}
start_client2() {
    : > "$CLOG2"
    $C "$RUST" -c -l 127.0.0.1:3334 -r relay.test:4096 -k pw -a --log-level 4 --fix-gro --dns-server 10.99.0.2:53 --dns-timeout 500 --allow-private-endpoint --endpoint-cache "$CACHE2" --fifo "$FIFO2" "$@" > "$CLOG2" 2>&1 &
    CPID2=$!
}
start_easy_client() {
    : > "$CLOG"
    $C "$RUST" -c -l 127.0.0.1:3333 -r relay.test:4096 -k pw --raw-mode easy-faketcp --log-level 5 --fix-gro --dns-server 10.99.0.2:53 --dns-timeout 500 --allow-private-endpoint --endpoint-cache "$CACHE" --fifo "$FIFO" "$@" > "$CLOG" 2>&1 &
    CPID=$!
}
stop_client() { [ -z "$CPID" ] || { kill "$CPID" 2>/dev/null || true; wait "$CPID" 2>/dev/null || true; }; CPID=""; sleep 0.5; }
stop_client2() { [ -z "$CPID2" ] || { kill "$CPID2" 2>/dev/null || true; wait "$CPID2" 2>/dev/null || true; }; CPID2=""; sleep 0.5; }
phase() { echo "== $1"; cp "$CLOG" "$LOGDIR/client.$2.log" 2>/dev/null || true; }

echo "== setup"
ip netns del cli 2>/dev/null || true
ip netns del peer 2>/dev/null || true
ip netns add cli && ip netns add peer || exit 1
ip link add veth0 type veth peer name veth1 && ip link set veth0 netns cli && ip link set veth1 netns peer || exit 1
$C ip addr add 10.99.0.1/24 dev veth0 && $C ip link set veth0 up && $C ip link set lo up
$P ip addr add 10.99.0.2/24 dev veth1 && $P ip link set veth1 up && $P ip link set lo up
for a in 10 20 30 40 99; do $P ip addr add 10.99.1.$a/32 dev lo; done
$P sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.veth1.rp_filter=0 net.ipv4.conf.lo.rp_filter=0 2>/dev/null || true
$C sysctl -qw net.ipv4.conf.all.rp_filter=0 2>/dev/null || true
mac0=$($C cat /sys/class/net/veth0/address); mac1=$($P cat /sys/class/net/veth1/address)
$C ip neigh replace 10.99.0.2 lladdr "$mac1" dev veth0 nud permanent
$P ip neigh replace 10.99.0.1 lladdr "$mac0" dev veth1 nud permanent
$C ip route add blackhole default
echo "relay.test 10.99.1.10 3600" > "$ANS"
$P python3 tools/dns_stub.py 10.99.0.2 53 "$ANS" 2> "$LOGDIR/stub.log" & pids+=($!)
$P python3 tools/udp_echo.py 127.0.0.1 7777 & pids+=($!)
$P python3 tools/docker/udp_sink.py 127.0.0.1 7799 & pids+=($!)
up_addr 10; up_addr 20
sleep 1
expect "no route from cli to a relay address before the client runs (blackhole default)" bash -c "! $C ip route get 10.99.1.10 2>&1 | grep -q 'dev veth0'"

echo "== A1 startup: hostname resolves, route + rule installed, tunnel works"
start_client --underlay-dev veth0 --underlay-gateway 10.99.0.2
if wait_ready 1 20; then ok "client_ready on the resolved address"; else bad "client never became ready"; tail -5 "$CLOG"; fi
expect "log: resolved relay.test:4096 -> 10.99.1.10" grep -q "endpoint: relay.test:4096 -> 10.99.1.10" "$CLOG"
expect "route 10.99.1.10/32 proto 235 installed by the client" route_has 10.99.1.10
expect "iptables rule for 10.99.1.10 present" rule_has 10.99.1.10
expect "probe through the tunnel" probe
expect "cache holds 10.99.1.10 after the authenticated handshake" [ "$(cache_addr)" = "10.99.1.10" ]
PID0=$CPID; INO0=$(listener_ino); echo "   pid $PID0 listener $INO0"
phase "A2 healthy session: DNS moves to 10.99.1.20, nothing changes" A1
echo "relay.test 10.99.1.20 3600" > "$ANS"
Q1=$(dns_queries); sleep 14
expect_not "no switch while the session is healthy" grep -q "relay is now" "$CLOG"
expect "at most one refresh query while healthy (was $Q1, now $(dns_queries))" [ "$(( $(dns_queries) - Q1 ))" -le 1 ]
expect "probe still fine" probe

phase "A3 current address fails before DNS changes: stale-success refresh stays armed" A2
# Model the real blocked-EIP race: the established relay dies while recursive DNS still
# returns the old address with an hour of TTL. The first forced reconnect lookup therefore
# succeeds but is stale. Only after observing that lookup do we publish the replacement.
echo "relay.test 10.99.1.10 3600" > "$ANS"
Q_STALE_BEFORE=$(dns_queries)
down_addr 10
if wait_log "reconnect refresh remains pending until authentication" 40; then
    ok "successful stale DNS answer kept reconnect refresh armed"
else
    bad "stale successful DNS answer disarmed reconnect refresh"; tail -12 "$CLOG"
fi
Q_AFTER_STALE=$(dns_queries)
expect "session loss queried stale DNS before the 3600-second TTL" [ "$Q_AFTER_STALE" -gt "$Q_STALE_BEFORE" ]
echo "relay.test 10.99.1.20 3600" > "$ANS"
if wait_log "relay is now 10.99.1.20" 40; then ok "switched to 10.99.1.20 after the session died"; else bad "no switch"; tail -8 "$CLOG"; fi
if wait_ready 2 20; then ok "client_ready on 10.99.1.20"; else bad "not ready on the new address"; tail -8 "$CLOG"; fi
expect "same process" kill -0 "$PID0"
expect "same local UDP listener socket ($INO0)" [ "$(listener_ino)" = "$INO0" ]
expect "a later pre-TTL query discovered the replacement" [ "$(dns_queries)" -gt "$Q_AFTER_STALE" ]
expect "probe through the new address" probe
expect "route 10.99.1.20/32 installed" route_has 10.99.1.20
expect_not "route 10.99.1.10/32 removed after authentication" route_has 10.99.1.10
expect "rule for 10.99.1.20 present" rule_has 10.99.1.20
expect_not "rule for 10.99.1.10 removed" rule_has 10.99.1.10
expect "cache now 10.99.1.20" [ "$(cache_addr)" = "10.99.1.20" ]
expect "log: new address becomes committed-good" grep -q "10.99.1.20 is now committed-good" "$CLOG"

phase "A4 planned cutover: fifo reconnect forces a fresh query while healthy" A3
up_addr 10; echo "relay.test 10.99.1.10 10" > "$ANS"; sleep 1
echo reconnect > "$FIFO"
if wait_log "relay is now 10.99.1.10" 15 && wait_ready 3 20; then ok "forced cutover back to 10.99.1.10"; else bad "forced cutover failed"; tail -8 "$CLOG"; fi
expect "probe" probe
expect "route .10 present" route_has 10.99.1.10
expect_not "route .20 gone" route_has 10.99.1.20
expect_not "rule .20 gone" rule_has 10.99.1.20
expect "cache 10.99.1.10" [ "$(cache_addr)" = "10.99.1.10" ]

phase "A5 bad candidate: keep last-known-good state during the attempt, roll back" A4
echo "relay.test 10.99.1.99 10" > "$ANS"    # .99 has no server: nothing answers there
sleep 1; echo reconnect > "$FIFO"
if wait_log "relay is now 10.99.1.99" 15; then ok "trying the candidate 10.99.1.99"; else bad "candidate not tried"; fi
sleep 1
expect "candidate rule installed before the attempt" rule_has 10.99.1.99
expect "candidate route installed before the attempt" route_has 10.99.1.99
expect "old rule (.10) retained while the candidate is unauthenticated" rule_has 10.99.1.10
expect "old route (.10) retained" route_has 10.99.1.10
expect "cache untouched by the unauthenticated candidate" [ "$(cache_addr)" = "10.99.1.10" ]
expect "handshake to the candidate times out" wait_log "state back to client_idle from client_tcp_handshake" 12
if wait_log "attended candidate 10.99.1.99 failed; returning directly to preserved 10.99.1.10" 15 && wait_ready 4 20; then ok "bad attended candidate rolled back without another DNS change"; else bad "no direct rollback from the bad candidate"; tail -8 "$CLOG"; fi
expect "same process after failed candidate rollback" kill -0 "$PID0"
expect "same listener after failed candidate rollback" [ "$(listener_ino)" = "$INO0" ]
expect_not "candidate rule rolled back" rule_has 10.99.1.99
expect_not "candidate route rolled back" route_has 10.99.1.99
expect "probe" probe

phase "A6 resolver outage: keep current address, bounded retries, recover later" A5
kill "${pids[0]}" 2>/dev/null || true       # stop the DNS stub
sleep 0.3
Q_BEFORE=$(grep -c "endpoint: dns relay.test failed" "$CLOG" || true)
echo reconnect > "$FIFO"
sleep 3
expect "dns failure keeps the tunnel up on 10.99.1.10" probe
down_addr 10                                # now the relay dies too, resolver still dead
sleep 32
Q_AFTER=$(grep -c "endpoint: dns relay.test failed" "$CLOG" || true)
echo "   dns failures logged during ~32 s of outage: $((Q_AFTER - Q_BEFORE))"
expect "bounded query rate under outage (<= 9)" [ $((Q_AFTER - Q_BEFORE)) -le 9 ]
expect "still targeting the last-known address" grep -q "keeping 10.99.1.10:4096" "$CLOG"
expect "same process after the outage" kill -0 "$PID0"
up_addr 20; echo "relay.test 10.99.1.20 10" > "$ANS"
$P python3 tools/dns_stub.py 10.99.0.2 53 "$ANS" 2>> "$LOGDIR/stub.log" & pids[0]=$!
if wait_log "relay is now 10.99.1.20:4096 (was 10.99.1.10" 90 && wait_ready 5 30; then ok "recovered to 10.99.1.20 when the resolver returned"; else bad "no recovery after the outage"; tail -8 "$CLOG"; fi
expect "probe" probe
expect "same local UDP listener socket through everything" [ "$(listener_ino)" = "$INO0" ]

phase "A7 exit: routes and rules of this process are gone" A6
stop_client
expect_not "route .20 removed at exit" route_has 10.99.1.20
expect_not "no proto-235 routes left" bash -c "$C ip route show | grep -q 'proto 235'"
expect_not "no udp2rawDwrW chains left in cli" bash -c "$C iptables -S | grep -q udp2rawDwrW"

phase "B gateway learned from an operator /32 (no --underlay-gateway)" A7
up_addr 30; up_addr 40
$C ip route add 10.99.1.30/32 via 10.99.0.2 dev veth0
echo "relay.test 10.99.1.30 10" > "$ANS"; rm -f "$CACHE"
start_client --underlay-dev veth0
if wait_ready 1 20; then ok "ready on 10.99.1.30 (operator route)"; else bad "not ready"; tail -5 "$CLOG"; fi
expect "gateway learned from the operator route" grep -q "underlay: dev veth0 ifindex .* gateway 10.99.0.2" "$CLOG"
echo "relay.test 10.99.1.40 10" > "$ANS"; sleep 1; echo reconnect > "$FIFO"
if wait_log "relay is now 10.99.1.40" 15 && wait_ready 2 20; then ok "switched to 10.99.1.40, which had no route before"; else bad "switch to .40 failed"; tail -8 "$CLOG"; fi
expect "route .40 via the learned gateway" bash -c "$C ip route show 10.99.1.40/32 | grep -q 'via 10.99.0.2 dev veth0'"
expect "probe" probe
stop_client
expect "operator route untouched" bash -c "$C ip route show 10.99.1.30/32 | grep -q veth0"
expect_not "our route .40 removed" route_has 10.99.1.40
$C ip route del 10.99.1.30/32 2>/dev/null || true

phase "C control: without --underlay-dev the new address is unreachable (blackhole default)" B
echo "relay.test 10.99.1.10 10" > "$ANS"; rm -f "$CACHE"; up_addr 10
start_client
sleep 8
expect_not "control: never ready without the underlay route" wait_ready 1 1
stop_client

phase "C2 easy-faketcp retargets its kernel socket and keeps the listener" C
clear_endpoint_state; up_addr 10; up_addr 20
echo "relay.test 10.99.1.10 3600" > "$ANS"
start_easy_client --underlay-dev veth0 --underlay-gateway 10.99.0.2
if wait_ready 1 20; then ok "easy-faketcp ready on .10"; else bad "easy-faketcp did not become ready on .10"; tail -10 "$CLOG"; fi
EPID=$CPID; EINO=$(listener_ino)
expect "easy-faketcp socket initially targets .10" grep -q "easy-faketcp socket destination is now 10.99.1.10:4096" "$CLOG"
echo "relay.test 10.99.1.20 3600" > "$ANS"; echo reconnect > "$FIFO"
if wait_log "easy-faketcp socket destination is now 10.99.1.20:4096" 15 && wait_ready 2 20; then ok "easy-faketcp retargeted to .20"; else bad "easy-faketcp did not retarget to .20"; tail -12 "$CLOG"; fi
expect "easy-faketcp switch keeps the process" [ "$CPID" = "$EPID" ]
expect "easy-faketcp switch keeps the local listener" [ "$(listener_ino)" = "$EINO" ]
expect "easy-faketcp new destination uses a native host route" route_has 10.99.1.20
expect "easy-faketcp tunnel works after retarget" probe
stop_client
expect_not "easy-faketcp route is cleaned at exit" route_has 10.99.1.20

phase "D0 last-good fallback remains opt-in" C2
up_addr 10; up_bad_addr 99
clear_endpoint_state; write_cache 10.99.1.10
echo "relay.test 10.99.1.99 1" > "$ANS"
start_client --underlay-dev veth0 --underlay-gateway 10.99.0.2
expect "without opt-in, DNS-preferred .99 is selected" wait_log "endpoint: relay.test:4096 -> 10.99.1.99" 5
sleep 8
expect_not "without --last-good-fallback, cached .10 is never probed behind DNS" grep -q "relay is now 10.99.1.10:4096 (was 10.99.1.99" "$CLOG"
expect "disabled fallback does not rewrite the cached rollback point" [ "$(cache_addr)" = "10.99.1.10" ]
expect "client remains alive while retrying only the preferred endpoint" kill -0 "$CPID"
stop_client
expect_not "disabled-fallback candidate route is cleaned at exit" route_has 10.99.1.99

FALLBACK_ARGS=(
    --underlay-dev veth0 --underlay-gateway 10.99.0.2
    --last-good-fallback --last-good-fallback-after 1
    --last-good-fallback-max-attempts 1 --last-good-fallback-cooldown 2
    --last-good-fallback-max-age 1 --last-good-fallback-global-attempts 2
    --last-good-fallback-global-refill 60 --last-good-fallback-round-timeout 5
    --last-good-fallback-probation 1 --last-good-fallback-rollback-window 30
)

phase "D1 a healthy committed endpoint survives cache age and routine DNS churn without interruption" D0
clear_endpoint_state; up_addr 10
echo "relay.test 10.99.1.10 1" > "$ANS"
start_client "${FALLBACK_ARGS[@]}"
if wait_ready 1 20; then ok "opted-in client is ready on .10"; else bad "opted-in client did not become ready"; tail -12 "$CLOG"; fi
expect "initial authenticated traffic commits .10" probe
expect "cache records committed-good .10" [ "$(cache_addr)" = "10.99.1.10" ]
FPID=$CPID; FINO=$(listener_ino); FQ=$(dns_queries)
if start_continuous_probe steady-fallback 14 0.50 0.95; then ok "continuous fallback probe started"; else bad "continuous fallback probe did not start"; fi
echo "relay.test 10.99.1.20 1" > "$ANS"
expect "continuous traffic sees no recurring outage after DNS TTL/change" finish_continuous_probe
expect_not "healthy Ready tunnel is not destructively moved to preferred DNS" grep -q "relay is now 10.99.1.20:4096 (was 10.99.1.10" "$CLOG"
expect "healthy Ready operation does not enter repeated resolver cycles" [ "$(( $(dns_queries) - FQ ))" -le 1 ]
expect "same process remains on the committed fallback" [ "$CPID" = "$FPID" ]
expect "same local listener remains on the committed fallback" [ "$(listener_ino)" = "$FINO" ]
expect "runtime-authenticated .10 remains cached beyond the 1-second startup-cache age" [ "$(cache_addr)" = "10.99.1.10" ]

phase "D2 attended FIFO cutover to a bad endpoint returns directly to the just-working endpoint" D1
echo "relay.test 10.99.1.99 1" > "$ANS"
if start_continuous_probe attended-bad 14 8.00 0.40; then ok "continuous attended-cutover probe started"; else bad "continuous attended-cutover probe did not start"; fi
echo reconnect > "$FIFO"
expect "attended reconnect tries the current DNS-preferred .99" wait_log "relay is now 10.99.1.99:4096 (was 10.99.1.10" 8
expect "candidate route is installed before the attempt" route_has 10.99.1.99
expect "preserved .10 native route remains during the attempt" route_has 10.99.1.10
expect "bad candidate cannot rewrite committed cache" [ "$(cache_addr)" = "10.99.1.10" ]
if wait_log "attended candidate 10.99.1.99 failed; returning directly to preserved 10.99.1.10" 12 && wait_ready 2 12; then
    ok "failed attended candidate returned directly to preserved .10"
else
    bad "attended failure did not return promptly"; tail -16 "$CLOG"
fi
expect "the one attended interruption stays within the measured outage bound" finish_continuous_probe
expect "attended FIFO cutover tried the bad candidate exactly once" [ "$(grep -c 'relay is now 10.99.1.99:4096 (was 10.99.1.10' "$CLOG" || true)" -eq 1 ]
expect "same process survives attended rollback" [ "$CPID" = "$FPID" ]
expect "same listener survives attended rollback" [ "$(listener_ino)" = "$FINO" ]
expect "committed cache is still .10 after rollback" [ "$(cache_addr)" = "10.99.1.10" ]
expect_not "failed .99 route is released after rollback" route_has 10.99.1.99
expect "traffic works after attended rollback" probe

phase "D3 a keyed black-hole remains probationary and cannot erase the rollback point" D2
down_addr 20; up_blackhole_addr 20
echo "relay.test 10.99.1.20 1" > "$ANS"
if start_continuous_probe probation-blackhole 10 5.50 0.35; then ok "continuous probation probe started"; else bad "continuous probation probe did not start"; fi
echo reconnect > "$FIFO"
expect "attended reconnect reaches correctly keyed .20" wait_log "relay is now 10.99.1.20:4096 (was 10.99.1.10" 8
expect "correctly keyed .20 completes an authenticated handshake" wait_ready 3 10
expect "authenticated .20 is explicitly probationary" wait_log "10.99.1.20 authenticated but remains probationary" 5
sleep 2
expect "black-hole probation preserves .10 in the cache" [ "$(cache_addr)" = "10.99.1.10" ]
expect "black-hole probation preserves the .10 native route" route_has 10.99.1.10
expect "probationary .20 has its own independently managed route" route_has 10.99.1.20
echo "promote 10.99.1.20" > "$FIFO"
expect "handshake and heartbeats alone cannot satisfy promotion evidence" wait_log "promote 10.99.1.20 rejected: InsufficientEvidence" 4
expect "rejected promotion still cannot rewrite the committed cache" [ "$(cache_addr)" = "10.99.1.10" ]
echo "rollback 10.99.1.20" > "$FIFO"
if wait_log "rolling back to preserved committed-good 10.99.1.10" 8 && wait_ready 4 10; then
    ok "explicit FIFO health verdict rolled the black-hole back to .10"
else
    bad "black-hole did not return to preserved .10"; tail -16 "$CLOG"
fi
expect "continuous traffic bounds the explicit probation rollback outage" finish_continuous_probe
expect_not "black-hole .20 was never promoted" grep -q "probationary 10.99.1.20 promoted to committed-good" "$CLOG"
expect "rollback cache remains .10" [ "$(cache_addr)" = "10.99.1.10" ]
expect_not "probationary .20 route is released after rollback" route_has 10.99.1.20
expect "traffic works after probation rollback" probe
expect "same process after probation rollback" [ "$CPID" = "$FPID" ]
expect "same listener after probation rollback" [ "$(listener_ino)" = "$FINO" ]
stop_client

phase "E two clients sharing one relay /32 retain independent route/rule ownership" D3
down_addr 20; up_addr 20; up_addr 10
clear_endpoint_state; rm -f -- "$CACHE2" "$CACHE2.fallback-state" "$FIFO2"
echo "relay.test 10.99.1.10 10" > "$ANS"
start_client --underlay-dev veth0 --underlay-gateway 10.99.0.2
if wait_ready_file "$CLOG" 1 20; then ok "first shared-relay client is ready"; else bad "first shared-relay client not ready"; tail -10 "$CLOG"; fi
start_client2 --underlay-dev veth0 --underlay-gateway 10.99.0.2
if wait_ready_file "$CLOG2" 1 20; then ok "second shared-relay client is ready"; else bad "second shared-relay client not ready"; tail -10 "$CLOG2"; fi
TPID1=$CPID; TPID2=$CPID2; TINO2=$(listener_ino_port 3334)
expect "shared-relay clients have distinct process owners" [ "$TPID1" != "$TPID2" ]
expect "both local listeners are owned and live" bash -c "kill -0 $TPID1 && kill -0 $TPID2 && [ -n '$TINO2' ]"
expect "both clients install separately owned protocol-235 routes" [ "$(route_count 10.99.1.10)" -eq 2 ]
expect "both clients install separately owned INPUT rules" [ "$(rule_count 10.99.1.10)" -eq 2 ]
expect "first shared-relay tunnel carries traffic" probe_port 3333
expect "second shared-relay tunnel carries traffic" probe_port 3334
stop_client
expect "stopping client one removes only its owned route" wait_route_count 10.99.1.10 1
expect "client two's INPUT rule survives client one's cleanup" [ "$(rule_count 10.99.1.10)" -eq 1 ]
expect "client two remains alive" kill -0 "$TPID2"
expect "client two keeps the same listener after peer cleanup" [ "$(listener_ino_port 3334)" = "$TINO2" ]
expect "client two still carries traffic" probe_port 3334
stop_client2
expect "last protocol-235 route is removed after both clients exit" wait_route_count 10.99.1.10 0
expect "last shared INPUT rule is removed after both clients exit" [ "$(rule_count 10.99.1.10)" -eq 0 ]
expect_not "no protocol-235 routes remain" bash -c "$C ip route show | grep -q 'proto 235'"
expect_not "no udp2raw private chains remain" bash -c "$C iptables -S | grep -q udp2rawDwrW"

echo "== summary: pass=$PASS fail=$FAIL (logs in $LOGDIR)"
[ "$FAIL" -eq 0 ]
