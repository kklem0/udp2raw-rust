#!/bin/bash
# End-to-end tests over loopback inside the dev container (needs --cap-add NET_RAW,NET_ADMIN).
#
#   docker build -t udp2raw-rust-dev tools/docker
#   docker run --rm --cap-add NET_RAW --cap-add NET_ADMIN \
#       -v "$PWD":/work -v /path/to/udp2raw-cpp:/cpp:ro \
#       -v udp2raw-cargo:/usr/local/cargo/registry -v udp2raw-target:/work/target-linux \
#       udp2raw-rust-dev tools/docker/e2e.sh [quick]
#
# Topology (everything on 127.0.0.1):
#   udp_probe -> :3333 (client -l) ==raw tunnel==> :4096 (server -l) -> :7777 (udp_echo, server -r)
set -uo pipefail
cd /work
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-/work/target-linux}
LOGDIR=${LOGDIR:-/work/target-linux/e2e-logs}
mkdir -p "$LOGDIR"
QUICK=${1:-}

echo "== unit tests (linux)"
cargo test --release 2>&1 | grep -E "^test result|FAILED|panicked" || true
echo "== build release"
cargo build --release 2>&1 | tail -1
RUST=$CARGO_TARGET_DIR/release/udp2raw
[ -x "$RUST" ] || { echo "rust build failed"; exit 1; }

CPP=""
if [ -d /cpp ]; then
    echo "== build C++ reference"
    rm -rf /tmp/cpp && cp -r /cpp /tmp/cpp && cd /tmp/cpp
    echo 'const char *gitversion = "e2e";' > git_version.h
    if make dynamic > /tmp/cpp-build.log 2>&1; then
        CPP=/tmp/cpp/udp2raw_dynamic
    else
        echo "C++ build failed (see /tmp/cpp-build.log); interop tests skipped"; tail -5 /tmp/cpp-build.log
    fi
    cd /work
fi

# udp2raw asks for 1 MB socket buffers; the kernel silently caps at rmem_max (212 KB by default)
sysctl -w net.core.rmem_max=16777216 net.core.wmem_max=16777216 >/dev/null 2>&1 || echo "WARN: could not raise rmem_max/wmem_max"

PASS=0; FAIL=0; FAILED_NAMES=""
pids=()
cleanup() {
    for p in "${pids[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
    pids=()
    sleep 0.3
    iptables -S 2>/dev/null | grep -q udp2rawDwrW && echo "WARN: leftover iptables rules:" && iptables -S | grep udp2rawDwrW
}
trap cleanup EXIT

wait_for() { # pattern file timeout
    local i=0
    while [ $i -lt $(( $3 * 10 )) ]; do
        grep -q "$1" "$2" 2>/dev/null && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}

# run_case NAME SERVER_BIN CLIENT_BIN "COMMON ARGS" "SERVER ARGS" "CLIENT ARGS" [PROBE ARGS]
run_case() {
    local name=$1 sbin=$2 cbin=$3 common=$4 sargs=$5 cargs=$6 probe=${7:-"2000 1000 2"}
    echo "== case: $name"
    python3 tools/udp_echo.py 127.0.0.1 7777 & pids+=($!)
    $sbin -s -l 127.0.0.1:4096 -r 127.0.0.1:7777 -k pw -a $common $sargs > "$LOGDIR/$name.server.log" 2>&1 & pids+=($!)
    sleep 0.5
    $cbin -c -l 127.0.0.1:3333 -r 127.0.0.1:4096 -k pw -a $common $cargs > "$LOGDIR/$name.client.log" 2>&1 & pids+=($!)
    local ok=1
    if ! wait_for "client_ready" "$LOGDIR/$name.client.log" 20; then
        echo "   client never became ready"; ok=0
    else
        sleep 0.3
        if python3 tools/udp_probe.py 127.0.0.1 3333 $probe; then :; else ok=0; fi
    fi
    if [ $ok = 1 ] && [ -z "$QUICK" ]; then
        # throughput smoke: blast one direction for 3 s into a sink behind the server
        kill "${pids[0]}" 2>/dev/null
        python3 tools/udp_bench.py sink 127.0.0.1 7777 5 & local sink=$!; pids+=($sink)
        sleep 0.3
        python3 tools/udp_bench.py blast 127.0.0.1 3333 3 1300
        wait $sink 2>/dev/null
        grep -h -E "dropped|overloaded|rst==1" "$LOGDIR/$name.client.log" "$LOGDIR/$name.server.log" | sort | uniq -c | head -5
    fi
    cleanup
    if [ $ok = 1 ]; then PASS=$((PASS + 1)); echo "   PASS"; else FAIL=$((FAIL + 1)); FAILED_NAMES="$FAILED_NAMES $name"; echo "   FAIL (logs in $LOGDIR/$name.*)"; tail -5 "$LOGDIR/$name.client.log"; fi
}

D="--log-level 4"
if [ -n "$CPP" ]; then
    run_case cpp_cpp_baseline       "$CPP"  "$CPP"  "$D" "" ""
fi
run_case rust_rust_default          "$RUST" "$RUST" "$D" "" ""
run_case rust_rust_threads0         "$RUST" "$RUST" "$D" "--threads 0" "--threads 0"
run_case rust_rust_threads3         "$RUST" "$RUST" "$D" "--threads 3" "--threads 3"
run_case rust_rust_table_aes        "$RUST" "$RUST" "$D --aes-backend table" "" ""
run_case rust_rust_cfb_hmac_gro     "$RUST" "$RUST" "$D --cipher-mode aes128cfb --auth-mode hmac_sha1 --fix-gro" "" ""
run_case rust_rust_xor_simple_seq1  "$RUST" "$RUST" "$D --cipher-mode xor --auth-mode simple --seq-mode 1" "" ""
run_case rust_rust_none_none        "$RUST" "$RUST" "$D --cipher-mode none --auth-mode none" "" ""
run_case rust_rust_udp              "$RUST" "$RUST" "$D --raw-mode udp" "" ""
run_case rust_rust_icmp             "$RUST" "$RUST" "$D --raw-mode icmp" "" ""
run_case rust_rust_hbmode0          "$RUST" "$RUST" "$D --hb-mode 0 --hb-len 0" "" ""
if [ -n "$CPP" ]; then
    run_case cpp_server_rust_client     "$CPP"  "$RUST" "$D" "" ""
    run_case rust_server_cpp_client     "$RUST" "$CPP"  "$D" "" ""
    run_case cpp_server_rust_client_cfb "$CPP"  "$RUST" "$D --cipher-mode aes128cfb --auth-mode hmac_sha1" "" ""
    run_case rust_server_cpp_client_icmp "$RUST" "$CPP" "$D --raw-mode icmp --cipher-mode xor --auth-mode crc32" "" ""
    run_case cpp_server_rust_client_udp "$CPP"  "$RUST" "$D --raw-mode udp --auth-mode simple" "" ""
    run_case rust_server_cpp_client_gro "$RUST" "$CPP"  "$D --fix-gro" "" ""
fi

echo "== summary: pass=$PASS fail=$FAIL$FAILED_NAMES"
[ $FAIL = 0 ]
