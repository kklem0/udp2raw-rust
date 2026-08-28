#!/bin/bash
# Integration test for the client's `-r hostname:port` re-resolution (Linux, root; needs
# NET_ADMIN, NET_RAW and SYS_ADMIN for network namespaces). Inside the dev container:
#   docker run --rm --cap-add NET_RAW --cap-add NET_ADMIN --cap-add SYS_ADMIN -v "$PWD":/work \
#       -v udp2raw-cargo:/usr/local/cargo/registry -v udp2raw-target:/work/target-linux \
#       udp2raw-rust-dev tools/docker/dns_reresolve_test.sh
#
# Topology: namespace "cli" (the client; veth0 10.99.0.1/24; default route = blackhole, i.e.
# a VPN default whose far end is gone) <-> namespace "peer" (veth1 10.99.0.2/24; the DNS stub
# on :53). Each relay address 10.99.1.{10,20,30,40} lives on peer's lo with ITS OWN udp2raw
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
C="ip netns exec cli"; P="ip netns exec peer"
PASS=0; FAIL=0; pids=(); CPID=""; declare -A SRV
ok() { PASS=$((PASS + 1)); echo "   ok   $1"; }
bad() { FAIL=$((FAIL + 1)); echo "   FAIL $1"; }
expect() { if "${@:2}" > /dev/null 2>&1; then ok "$1"; else bad "$1"; fi; }
expect_not() { if "${@:2}" > /dev/null 2>&1; then bad "$1"; else ok "$1"; fi; }
cleanup() {
    set +e
    [ -n "$CPID" ] && kill "$CPID" 2>/dev/null
    for p in "${SRV[@]:-}" "${pids[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
    sleep 0.5
    ip netns del cli 2>/dev/null; ip netns del peer 2>/dev/null
    cleanup_build
}
trap cleanup EXIT
up_addr() { # X : start a server bound to 10.99.1.X (idempotent)
    local a=$1
    [ -n "${SRV[$a]:-}" ] && kill -0 "${SRV[$a]}" 2>/dev/null && return
    $P "$RUST" -s -l 10.99.1.$a:4096 -r 127.0.0.1:7777 -k pw -a --log-level 3 --fix-gro > "$LOGDIR/server.$a.log" 2>&1 &
    SRV[$a]=$!
}
down_addr() { # X : stop the server for 10.99.1.X
    local a=$1
    [ -n "${SRV[$a]:-}" ] && kill "${SRV[$a]}" 2>/dev/null
    SRV[$a]=""
    sleep 0.3
}
wait_log() { local f=${3:-$CLOG}; for _ in $(seq 1 $(($2 * 10))); do grep -q -- "$1" "$f" 2>/dev/null && return 0; sleep 0.1; done; return 1; }
wait_ready() { for _ in $(seq 1 $(($2 * 10))); do [ "$(grep -c 'client_handshake2 to client_ready' "$CLOG")" -ge "$1" ] && return 0; sleep 0.1; done; return 1; }
# Liveness probe: datagrams must round-trip through the tunnel. Retried for a few seconds
# because the data plane can take a moment to settle right after a (re)connect.
probe() {
    for _ in $(seq 1 8); do
        $C python3 tools/udp_probe.py 127.0.0.1 3333 60 1000 2 0.70 > "$LOGDIR/probe.log" 2>&1 && return 0
        sleep 1
    done
    return 1
}
route_has() { $C ip route show "$1/32" | grep -q "proto 235"; }
rule_has() { $C iptables -S INPUT | grep -q -- "-s $1/32 "; }
cache_addr() { sed -n 's/^addr=//p' "$CACHE" 2>/dev/null; }
listener_ino() { $C ss -lune 2>/dev/null | grep "127.0.0.1:3333" | grep -o "ino:[0-9]*"; }
dns_queries() { grep -c " query relay.test " "$LOGDIR/stub.log" 2>/dev/null || echo 0; }
start_client() {
    : > "$CLOG"
    $C "$RUST" -c -l 127.0.0.1:3333 -r relay.test:4096 -k pw -a --log-level 4 --fix-gro --dns-server 10.99.0.2:53 --dns-timeout 500 --allow-private-endpoint --endpoint-cache "$CACHE" --fifo "$FIFO" "$@" > "$CLOG" 2>&1 &
    CPID=$!
}
stop_client() { kill "$CPID" 2>/dev/null; wait "$CPID" 2>/dev/null; CPID=""; sleep 0.5; }
phase() { echo "== $1"; cp "$CLOG" "$LOGDIR/client.$2.log" 2>/dev/null || true; }

echo "== setup"
ip netns del cli 2>/dev/null; ip netns del peer 2>/dev/null
ip netns add cli && ip netns add peer || exit 1
ip link add veth0 type veth peer name veth1 && ip link set veth0 netns cli && ip link set veth1 netns peer || exit 1
$C ip addr add 10.99.0.1/24 dev veth0 && $C ip link set veth0 up && $C ip link set lo up
$P ip addr add 10.99.0.2/24 dev veth1 && $P ip link set veth1 up && $P ip link set lo up
for a in 10 20 30 40; do $P ip addr add 10.99.1.$a/32 dev lo; done
$P sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.veth1.rp_filter=0 net.ipv4.conf.lo.rp_filter=0 2>/dev/null || true
$C sysctl -qw net.ipv4.conf.all.rp_filter=0 2>/dev/null || true
mac0=$($C cat /sys/class/net/veth0/address); mac1=$($P cat /sys/class/net/veth1/address)
$C ip neigh replace 10.99.0.2 lladdr "$mac1" dev veth0 nud permanent
$P ip neigh replace 10.99.0.1 lladdr "$mac0" dev veth1 nud permanent
$C ip route add blackhole default
echo "relay.test 10.99.1.10 10" > "$ANS"
$P python3 tools/dns_stub.py 10.99.0.2 53 "$ANS" 2> "$LOGDIR/stub.log" & pids+=($!)
$P python3 tools/udp_echo.py 127.0.0.1 7777 & pids+=($!)
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
echo "relay.test 10.99.1.20 10" > "$ANS"
Q1=$(dns_queries); sleep 14
expect_not "no switch while the session is healthy" grep -q "relay is now" "$CLOG"
expect "at most one refresh query while healthy (was $Q1, now $(dns_queries))" [ "$(( $(dns_queries) - Q1 ))" -le 1 ]
expect "probe still fine" probe

phase "A3 current address fails: re-resolve and switch in-process" A2
down_addr 10
if wait_log "relay is now 10.99.1.20" 40; then ok "switched to 10.99.1.20 after the session died"; else bad "no switch"; tail -8 "$CLOG"; fi
if wait_ready 2 20; then ok "client_ready on 10.99.1.20"; else bad "not ready on the new address"; tail -8 "$CLOG"; fi
expect "same process" kill -0 "$PID0"
expect "same local UDP listener socket ($INO0)" [ "$(listener_ino)" = "$INO0" ]
expect "probe through the new address" probe
expect "route 10.99.1.20/32 installed" route_has 10.99.1.20
expect_not "route 10.99.1.10/32 removed after authentication" route_has 10.99.1.10
expect "rule for 10.99.1.20 present" rule_has 10.99.1.20
expect_not "rule for 10.99.1.10 removed" rule_has 10.99.1.10
expect "cache now 10.99.1.20" [ "$(cache_addr)" = "10.99.1.20" ]
expect "log: new address becomes last-known-good" grep -q "10.99.1.20 is now last-known-good" "$CLOG"

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
echo "relay.test 10.99.1.10 10" > "$ANS"
if wait_log "relay is now 10.99.1.10:4096 (was 10.99.1.99" 30 && wait_ready 4 20; then ok "back on 10.99.1.10 once DNS says so"; else bad "no recovery from the bad candidate"; tail -8 "$CLOG"; fi
expect_not "candidate rule rolled back" rule_has 10.99.1.99
expect_not "candidate route rolled back" route_has 10.99.1.99
expect "probe" probe

phase "A6 resolver outage: keep current address, bounded retries, recover later" A5
kill "${pids[0]}" 2>/dev/null; sleep 0.3    # stop the DNS stub
Q_BEFORE=$(grep -c "endpoint: dns relay.test failed" "$CLOG")
echo reconnect > "$FIFO"
sleep 3
expect "dns failure keeps the tunnel up on 10.99.1.10" probe
down_addr 10                                # now the relay dies too, resolver still dead
sleep 32
Q_AFTER=$(grep -c "endpoint: dns relay.test failed" "$CLOG")
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
$C ip route del 10.99.1.30/32 2>/dev/null

phase "C control: without --underlay-dev the new address is unreachable (blackhole default)" B
echo "relay.test 10.99.1.10 10" > "$ANS"; rm -f "$CACHE"; up_addr 10
start_client
sleep 8
expect_not "control: never ready without the underlay route" wait_ready 1 1
stop_client

echo "== summary: pass=$PASS fail=$FAIL (logs in $LOGDIR)"
[ "$FAIL" -eq 0 ]
