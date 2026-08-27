#!/bin/bash
# Fixed-rate efficiency matrix (C++ vs Rust) below the box's kernel ceiling. See bench_fixed.sh.
#   RUST=./udp2raw-rust2 ./run_fixed_pi.sh [RATE] [BURST] [SECS] > fixed.txt
set -uo pipefail
RATE=${1:-7000}; BURST=${2:-8}; SECS=${3:-8}
CPP=${CPP:-./udp2raw-cpp}; RUST=${RUST:-./udp2raw-rust}
export BENCH=${BENCH:-./udpbench2} LOGDIR=${LOGDIR:-$PWD/logs-fixed}
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
cool_down() { for _ in $(seq 1 60); do [ "$(temp_c)" -lt 72 ] && return; sleep 5; done; }
echo "# $(date -Is) host=$(hostname) fixed-rate rate=$RATE burst=$BURST secs=$SECS"
run() { cool_down; ./bench_fixed.sh "$1" "$2" "$3" "$4" "$5" "$6" "$RATE" "${7:-1300}" "$SECS" "${8:-$BURST}" 2>&1; sleep 2; }
PROD="--log-level 4 --fix-gro"
run cpp_cpp                    $CPP  $CPP  "$PROD" "" ""
run cpp_cpp_burst64            $CPP  $CPP  "$PROD" "" "" 1300 64
run rust_rust_t0               $RUST $RUST "$PROD" "--threads 0" "--threads 0"
run rust_rust_t0_burst64       $RUST $RUST "$PROD" "--threads 0" "--threads 0" 1300 64
run rust_rust_t0_fixslice      $RUST $RUST "$PROD --aes-backend fixslice" "--threads 0" "--threads 0"
run rust_rust_t1               $RUST $RUST "$PROD" "--threads 1" "--threads 1"
run rust_rust_t2               $RUST $RUST "$PROD" "--threads 2" "--threads 2"
run rust_rust_t3               $RUST $RUST "$PROD" "--threads 3" "--threads 3"
run cpp_server_rust_client_t0  $CPP  $RUST "$PROD" "" "--threads 0"
run cpp_server_rust_client_t2  $CPP  $RUST "$PROD" "" "--threads 2"
run rust_server_t0_cpp_client  $RUST $CPP  "$PROD" "--threads 0" ""
NH="--log-level 4 --fix-gro --cipher-mode none --auth-mode hmac_sha1"
run cpp_cpp_none_hmac          $CPP  $CPP  "$NH" "" ""
run rust_rust_t0_none_hmac     $RUST $RUST "$NH" "--threads 0" "--threads 0"
XS="--log-level 4 --fix-gro --cipher-mode xor --auth-mode simple"
run cpp_cpp_xor_simple         $CPP  $CPP  "$XS" "" ""
run rust_rust_t0_xor_simple    $RUST $RUST "$XS" "--threads 0" "--threads 0"
echo "# done $(date -Is) temp=$(temp_c)C"
