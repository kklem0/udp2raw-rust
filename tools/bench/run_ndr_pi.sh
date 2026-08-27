#!/bin/bash
# No-drop-rate comparison matrix (C++ vs Rust) on one box. See bench_ndr.sh.
#   ./run_ndr_pi.sh [HI_PPS] [SECS] > ndr.txt
set -uo pipefail
HI=${1:-120000}; SECS=${2:-4}
CPP=${CPP:-./udp2raw-cpp}; RUST=${RUST:-./udp2raw-rust}
export BENCH=./udpbench PROBE=./udp_probe.py LOGDIR=${LOGDIR:-$PWD/logs-ndr}
mkdir -p "$LOGDIR"
OLD_RMEM=$(sysctl -n net.core.rmem_max); OLD_WMEM=$(sysctl -n net.core.wmem_max)
OLD_GOV=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo "")
restore() {
    sysctl -w net.core.rmem_max="$OLD_RMEM" net.core.wmem_max="$OLD_WMEM" >/dev/null 2>&1
    if [ -n "$OLD_GOV" ]; then for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo "$OLD_GOV" > "$g" 2>/dev/null; done; fi
    echo "# restored rmem_max=$OLD_RMEM wmem_max=$OLD_WMEM governor=$OLD_GOV"
}
trap restore EXIT
sysctl -w net.core.rmem_max=16777216 net.core.wmem_max=16777216 >/dev/null
for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo performance > "$g" 2>/dev/null; done
temp_c() { awk '{printf "%d", $1/1000}' /sys/class/thermal/thermal_zone0/temp 2>/dev/null || echo 0; }
cool_down() { for _ in $(seq 1 60); do [ "$(temp_c)" -lt 66 ] && return; sleep 5; done; }
echo "# $(date -Is) host=$(hostname) kernel=$(uname -r) ncpu=$(nproc) max_khz=$(cat /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq) no-drop-rate search hi=$HI secs=$SECS max_loss=${MAX_LOSS:-0.02}"
run() { cool_down; ./bench_ndr.sh "$1" "$2" "$3" "$4" "$5" "$6" "${7:-1300}" "$HI" "$SECS" 2>&1; sleep 2; }
PROD="--log-level 4 --fix-gro"
run cpp_cpp                   $CPP  $CPP  "$PROD" "" ""
run rust_rust_t0              $RUST $RUST "$PROD" "--threads 0" "--threads 0"
run rust_rust_t0_fixslice     $RUST $RUST "$PROD --aes-backend fixslice" "--threads 0" "--threads 0"
run rust_rust_t1              $RUST $RUST "$PROD" "--threads 1" "--threads 1"
run rust_rust_t2              $RUST $RUST "$PROD" "--threads 2" "--threads 2"
run rust_rust_t3              $RUST $RUST "$PROD" "--threads 3" "--threads 3"
run cpp_server_rust_client_t2 $CPP  $RUST "$PROD" "" "--threads 2"
run rustsrv_t3_cpp_client     $RUST $CPP  "$PROD" "--threads 3" ""
run rustsrv_t3_rust_client_t0 $RUST $RUST "$PROD" "--threads 3" "--threads 0"
run rustsrv_t3_rust_client_t2 $RUST $RUST "$PROD" "--threads 3" "--threads 2"
NH="--log-level 4 --fix-gro --cipher-mode none --auth-mode hmac_sha1"
run cpp_cpp_none_hmac         $CPP  $CPP  "$NH" "" ""
run rust_rust_t2_none_hmac    $RUST $RUST "$NH" "--threads 2" "--threads 2"
XS="--log-level 4 --fix-gro --cipher-mode xor --auth-mode simple"
run cpp_cpp_xor_simple        $CPP  $CPP  "$XS" "" ""
run rust_rust_t2_xor_simple   $RUST $RUST "$XS" "--threads 2" "--threads 2"
echo "# done $(date -Is) temp=$(temp_c)C"
