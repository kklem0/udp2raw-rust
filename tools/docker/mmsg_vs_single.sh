#!/bin/bash
# Does recvmmsg/sendmmsg batching buy anything on this CPU? No-drop-rate search of
# `--syscalls mmsg` vs `--syscalls single` with the same binary, split cores (server 0-3,
# client 4-7, generator 8-9; needs >= 10 cores), two rounds. Inside the dev container:
#   docker run --rm --privileged -v "$PWD":/work -v udp2raw-cargo:/usr/local/cargo/registry \
#       -v udp2raw-target:/work/target-linux udp2raw-rust-dev tools/docker/mmsg_vs_single.sh
# env: BIN (the binary to test; default: build /work with cargo), HI (400000), SECS (2), ITER (5)
set -uo pipefail
cd /work; B=/tmp/b; mkdir -p $B/logs
if [ -z "${BIN:-}" ]; then
    export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-/work/target-linux}
    cargo build --release 2>&1 | tail -1; BIN=$CARGO_TARGET_DIR/release/udp2raw
fi
gcc -O2 -o $B/udpbench tools/bench/udpbench.c || exit 1
cp tools/bench/bench_ndr.sh tools/udp_probe.py tools/udp_echo.py $B/; cp "$BIN" $B/fix; cd $B
sysctl -w net.core.rmem_max=16777216 net.core.wmem_max=16777216 >/dev/null 2>&1 || echo "# WARN: rmem_max not raised"
export BENCH=./udpbench PROBE=./udp_probe.py LOGDIR=$B/logs ITER=${ITER:-5} SERVER_CPUS=0-3 CLIENT_CPUS=4-7 GEN_CPUS=8-9
echo "# $(date -Is) docker nproc=$(nproc) kernel=$(uname -r) split cores, hi=${HI:-400000} secs=${SECS:-2} iter=$ITER fix=$(md5sum < fix | cut -c1-8)"
PROD="--log-level 4 --fix-gro"
for mode in single mmsg single mmsg; do
    for cfg in "t0_table|--aes-backend table|--threads 0" "t2_table|--aes-backend table|--threads 2" "t2_hw||--threads 2"; do
        IFS='|' read -r tag extra thr <<< "$cfg"
        ./bench_ndr.sh ${mode}_$tag ./fix ./fix "$PROD --syscalls $mode $extra" "$thr" "$thr" 1300 ${HI:-400000} ${SECS:-2} 2>&1 | grep -E "^NDR" | sed 's/ | probe.*//'
        sleep 1
    done
done
echo "# done $(date -Is)"
