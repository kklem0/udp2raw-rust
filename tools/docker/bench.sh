#!/bin/bash
# Loopback benchmark matrix inside the dev container (stand-in for a small ARM box):
# pins everything to CPUSET (default 0-3), builds the C++ reference from /cpp and the
# Rust binary from /work, and runs no-drop-rate searches (tools/bench/bench_ndr.sh).
#
#   docker run --rm --cap-add NET_RAW --cap-add NET_ADMIN -v "$PWD":/work -v /path/to/udp2raw-cpp:/cpp:ro \
#       -v udp2raw-cargo:/usr/local/cargo/registry -v udp2raw-target:/work/target-linux \
#       [-v /path/with/extra/binaries:/bin-extra:ro] udp2raw-rust-dev tools/docker/bench.sh
#
# env: CPUSET (0-3), HI (max offered pps for the search, 300000), SECS (4), RUST_EXTRA
#      (path of an additional Rust binary to compare, e.g. /bin-extra/udp2raw-rust-v1)
# `bench.sh quick`: C++ vs Rust --threads 0/2 only, split cores, 5 search steps of 2 s (~1 min
# after a cached build) instead of the full two-matrix run (~17 min).
set -uo pipefail
QUICK=${1:-}
if [ "$QUICK" = quick ]; then SECS=${SECS:-2}; export ITER=${ITER:-5}; fi
cd /work
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-/work/target-linux}
CPUSET=${CPUSET:-0-3}; HI=${HI:-300000}; SECS=${SECS:-4}; RUST_EXTRA=${RUST_EXTRA:-}
B=/tmp/bench; mkdir -p $B
echo "== build"
cargo build --release 2>&1 | tail -1
rm -rf /tmp/cpp && cp -r /cpp /tmp/cpp && cd /tmp/cpp && echo 'const char *gitversion = "bench";' > git_version.h && make dynamic > /tmp/cpp-build.log 2>&1 && cd /work || { echo "C++ build failed"; tail -3 /tmp/cpp-build.log; exit 1; }
gcc -O2 -o $B/udpbench tools/bench/udpbench.c || exit 1
cp tools/bench/bench_ndr.sh tools/bench/bench_fixed.sh tools/udp_probe.py tools/udp_echo.py $B/
ln -sf /tmp/cpp/udp2raw_dynamic $B/udp2raw-cpp
ln -sf $CARGO_TARGET_DIR/release/udp2raw $B/udp2raw-rust
[ -n "$RUST_EXTRA" ] && ln -sf "$RUST_EXTRA" $B/udp2raw-rust-extra
cd $B
sysctl -w net.core.rmem_max=16777216 net.core.wmem_max=16777216 >/dev/null 2>&1 || echo "WARN: could not raise rmem_max"
export BENCH=./udpbench PROBE=./udp_probe.py LOGDIR=$B/logs
echo "# $(date -Is) docker nproc=$(nproc) cpuset=$CPUSET hi=$HI secs=$SECS"
echo "# cpp=$(./udp2raw-cpp -h 2>&1 | sed -n 2p | tr -s ' ') rust=$(git -C /work rev-parse --short HEAD 2>/dev/null)"
run() {
    local out
    out=$(bash ./bench_ndr.sh "$1" "$2" "$3" "$4" "$5" "$6" 1300 "$HI" "$SECS" 2>&1)
    if ! printf '%s\n' "$out" | grep -E "^NDR"; then echo "case $1 produced no result:"; printf '%s\n' "$out" | tail -5; fi
    sleep 1
}
PROD="--log-level 4 --fix-gro"
T="--aes-backend table"    # the code path of a CPU without AES instructions (Raspberry Pi 4)
matrix() {
    run cpp_cpp                 ./udp2raw-cpp  ./udp2raw-cpp  "$PROD" "" ""
    run rust_t0_table           ./udp2raw-rust ./udp2raw-rust "$PROD $T" "--threads 0" "--threads 0"
    run rust_t1_table           ./udp2raw-rust ./udp2raw-rust "$PROD $T" "--threads 1" "--threads 1"
    run rust_t2_table           ./udp2raw-rust ./udp2raw-rust "$PROD $T" "--threads 2" "--threads 2"
    run rust_t3_table           ./udp2raw-rust ./udp2raw-rust "$PROD $T" "--threads 3" "--threads 3"
    run rust_t0_hw              ./udp2raw-rust ./udp2raw-rust "$PROD" "--threads 0" "--threads 0"
    run rust_t2_hw              ./udp2raw-rust ./udp2raw-rust "$PROD" "--threads 2" "--threads 2"
    if [ -n "$RUST_EXTRA" ]; then
        run extra_t0_table      ./udp2raw-rust-extra ./udp2raw-rust-extra "$PROD $T" "--threads 0" "--threads 0"
        run extra_t2_table      ./udp2raw-rust-extra ./udp2raw-rust-extra "$PROD $T" "--threads 2" "--threads 2"
        run extra_t2_hw         ./udp2raw-rust-extra ./udp2raw-rust-extra "$PROD" "--threads 2" "--threads 2"
    fi
}
if [ "$QUICK" = quick ]; then
    echo "## quick: server cpus 0-3, client cpus 4-7, generator cpus 8-9"
    export SERVER_CPUS=0-3 CLIENT_CPUS=4-7 GEN_CPUS=8-9
    run cpp_cpp           ./udp2raw-cpp  ./udp2raw-cpp  "$PROD" "" ""
    run rust_t0_table     ./udp2raw-rust ./udp2raw-rust "$PROD $T" "--threads 0" "--threads 0"
    run rust_t2_table     ./udp2raw-rust ./udp2raw-rust "$PROD $T" "--threads 2" "--threads 2"
    echo "# done $(date -Is)"; exit 0
fi
# pass 1: both daemons plus the generator share 4 cores (a single small box running both ends)
echo "## shared: everything on cpus $CPUSET"
export SERVER_CPUS=$CPUSET CLIENT_CPUS=$CPUSET GEN_CPUS=$CPUSET
matrix
# pass 2: each daemon gets its own 4 cores (one daemon per box), generator elsewhere
if [ "$(nproc)" -ge 10 ]; then
    echo "## split: server cpus 0-3, client cpus 4-7, generator cpus 8-9"
    export SERVER_CPUS=0-3 CLIENT_CPUS=4-7 GEN_CPUS=8-9
    matrix
fi
echo "# done $(date -Is)"
