#!/bin/bash
# Quick no-drop-rate matrix on the Pi 4 (a live router): the deployed cipher mode
# (faketcp + aes128cbc + md5 + --fix-gro) vs --cipher-mode chacha20poly1305, C++ reference
# vs Rust, both daemons on the box over loopback. Raises the socket-buffer limits and pins
# the governor for the run, restores them on exit and prints a health check of the box.
#   ./run_quick_pi.sh [CASE...]      (default: all five cases, ~2.5 min; ~30 s per case)
#   FIXED=10000 SECS=5 ./run_quick_pi.sh [CASE...]   fixed offered rate instead of the search:
#                                    reports each daemon's user/sys CPU split (bench_fixed.sh)
# env: HI (32000) SECS (2) ITER (5) FIXED (unset) BURST (64) CPP (./udp2raw-cpp) RUST (./udp2raw-head)
#      OLD (/opt/udp2raw-rust-60a36d6-arm64, the previous build: cases old_current_t0/t2) BENCH (./udpbench2) LOGDIR
set -uo pipefail
HI=${HI:-32000}; SECS=${SECS:-2}; export ITER=${ITER:-5}; FIXED=${FIXED:-}; BURST=${BURST:-64}
CPP=${CPP:-./udp2raw-cpp}; RUST=${RUST:-./udp2raw-head}; OLD=${OLD:-/opt/udp2raw-rust-60a36d6-arm64}
export BENCH=${BENCH:-./udpbench2} PROBE=./udp_probe.py LOGDIR=${LOGDIR:-$PWD/logs-quick}
mkdir -p "$LOGDIR"
ALL="cpp_current rust_current_t0 rust_current_t2 rust_chacha_t0 rust_chacha_t2"
CASES=${*:-$ALL}
OLD_RMEM=$(sysctl -n net.core.rmem_max); OLD_WMEM=$(sysctl -n net.core.wmem_max)
OLD_GOV=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo "")
temp_c() { awk '{printf "%d", $1/1000}' /sys/class/thermal/thermal_zone0/temp 2>/dev/null || echo 0; }
restore() {
    sysctl -w net.core.rmem_max="$OLD_RMEM" net.core.wmem_max="$OLD_WMEM" >/dev/null 2>&1
    if [ -n "$OLD_GOV" ]; then for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo "$OLD_GOV" > "$g" 2>/dev/null; done; fi
    sleep 1
    echo "# restored rmem_max=$(sysctl -n net.core.rmem_max) wmem_max=$(sysctl -n net.core.wmem_max) governor=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null)"
    echo "# leftover bench processes: $(pgrep -a -f 'udpbench|udp_echo|udp_probe|/bench/udp2raw' | wc -l); udp2raw processes: $(pgrep -a udp2raw | paste -sd';')"
    local svc=${PROD_SVC:-udp2raw.service}   # set PROD_SVC to your deployed unit to health-check it after a run
    echo "# $svc: $(systemctl is-active "$svc" 2>/dev/null); wg1 latest handshake: $(wg show wg1 latest-handshakes 2>/dev/null | awk -v now="$(date +%s)" '{print now-$2 "s ago"}' | paste -sd,)"
    echo "# done $(date -Is) temp=$(temp_c)C"
}
trap restore EXIT
sysctl -w net.core.rmem_max=16777216 net.core.wmem_max=16777216 >/dev/null
for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo performance > "$g" 2>/dev/null; done
cool_down() { for _ in $(seq 1 24); do [ "$(temp_c)" -lt 72 ] && return; sleep 5; done; }
echo "# $(date -Is) host=$(hostname) kernel=$(uname -r) ncpu=$(nproc) max_khz=$(cat /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq) temp=$(temp_c)C load=$(cut -d' ' -f1-3 /proc/loadavg)"
if [ -n "$FIXED" ]; then echo "# fixed-rate rate=$FIXED burst=$BURST secs=$SECS size=1300 bench=$BENCH"
else echo "# no-drop-rate search hi=$HI secs=$SECS iter=$ITER max_loss=${MAX_LOSS:-0.02} size=1300 bench=$BENCH"; fi
echo "# cpp=$CPP ($(md5sum < "$CPP" | cut -c1-8)) rust=$RUST ($(md5sum < "$RUST" | cut -c1-8))$([ -f "$OLD" ] && echo " old=$OLD ($(md5sum < "$OLD" | cut -c1-8))")"
run() {
    cool_down
    if [ -n "$FIXED" ]; then ./bench_fixed.sh "$1" "$2" "$3" "$4" "$5" "$6" "$FIXED" 1300 "$SECS" "$BURST" 2>&1
    else ./bench_ndr.sh "$1" "$2" "$3" "$4" "$5" "$6" 1300 "$HI" "$SECS" 2>&1; fi
    sleep 2
}
PROD="--log-level 4 --fix-gro"                 # the deployed mode: faketcp + aes128cbc + md5 + --fix-gro
CHA="$PROD --cipher-mode chacha20poly1305"     # Rust-only AEAD mode
for c in $CASES; do
    case $c in
        cpp_current)     run "$c" "$CPP"  "$CPP"  "$PROD" "" "" ;;
        rust_current_t0) run "$c" "$RUST" "$RUST" "$PROD" "--threads 0" "--threads 0" ;;
        rust_current_t2) run "$c" "$RUST" "$RUST" "$PROD" "--threads 2" "--threads 2" ;;
        rust_chacha_t0)  run "$c" "$RUST" "$RUST" "$CHA"  "--threads 0" "--threads 0" ;;
        rust_chacha_t2)  run "$c" "$RUST" "$RUST" "$CHA"  "--threads 2" "--threads 2" ;;
        old_current_t0)  run "$c" "$OLD"  "$OLD"  "$PROD" "--threads 0" "--threads 0" ;;
        old_current_t2)  run "$c" "$OLD"  "$OLD"  "$PROD" "--threads 2" "--threads 2" ;;
        *) echo "# unknown case $c" ;;
    esac
done
