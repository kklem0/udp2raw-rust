#!/bin/bash
# Full C++ vs Rust comparison matrix on one box (loopback). Run as root in a directory that
# holds: udp2raw-cpp, udp2raw-rust, udpbench, bench_pi.sh, udp_probe.py, udp_echo.py.
#
#   ./run_matrix_pi.sh [SECONDS] [MAX_PPS]  > results.txt
#
# Pins the cpufreq governor to `performance` and raises the socket-buffer sysctls for the
# duration, restoring both afterwards; waits for the SoC to cool between runs.
set -uo pipefail
SECS=${1:-10}; MAXPPS=${2:-150000}
CPP=${CPP:-./udp2raw-cpp}; RUST=${RUST:-./udp2raw-rust}
export BENCH=./udpbench PROBE=./udp_probe.py LOGDIR=${LOGDIR:-$PWD/logs}
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
cool_down() {
    local t
    for _ in $(seq 1 60); do t=$(temp_c); [ "$t" -lt 66 ] && return; sleep 5; done
}

echo "# $(date -Is) host=$(hostname) kernel=$(uname -r) cpu=$(grep -m1 'CPU part' /proc/cpuinfo | awk '{print $NF}') ncpu=$(nproc) max_khz=$(cat /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq) secs=$SECS max_pps=$MAXPPS"
echo "# cpp=$($CPP -h 2>&1 | sed -n 2p | tr -s ' ')  rust=$($RUST -h 2>&1 | sed -n 1p)"

run() { # NAME SBIN CBIN COMMON SARGS CARGS [SIZE]
    cool_down
    ./bench_pi.sh "$1" "$2" "$3" "$4" "$5" "$6" "$SECS" "${7:-1300}" "$MAXPPS" 2>&1 | grep "^RESULT"
    sleep 3
}

PROD="--log-level 4 --fix-gro"   # the production configuration: faketcp, aes128cbc, md5, --fix-gro
run cpp_cpp                 $CPP  $CPP  "$PROD" "" ""
run rust_rust_t0            $RUST $RUST "$PROD" "--threads 0" "--threads 0"
run rust_rust_t1            $RUST $RUST "$PROD" "--threads 1" "--threads 1"
run rust_rust_t2            $RUST $RUST "$PROD" "--threads 2" "--threads 2"
run rust_rust_t3            $RUST $RUST "$PROD" "--threads 3" "--threads 3"
# deployment-like: only one side replaced
run cpp_server_rust_client_t2  $CPP  $RUST "$PROD" "" "--threads 2"
run rust_server_cpp_client_t2  $RUST $CPP  "$PROD" "--threads 2" ""
# isolate the client side: a fast Rust server (3 threads) behind C++ / Rust clients
run rustsrv_t3_cpp_client   $RUST $CPP  "$PROD" "--threads 3" ""
run rustsrv_t3_rust_client_t0 $RUST $RUST "$PROD" "--threads 3" "--threads 0"
run rustsrv_t3_rust_client_t2 $RUST $RUST "$PROD" "--threads 3" "--threads 2"
# cheaper crypto: integrity only (WireGuard inside) and obfuscation only
NH="--log-level 4 --fix-gro --cipher-mode none --auth-mode hmac_sha1"
run cpp_cpp_none_hmac       $CPP  $CPP  "$NH" "" ""
run rust_rust_t0_none_hmac  $RUST $RUST "$NH" "--threads 0" "--threads 0"
run rust_rust_t2_none_hmac  $RUST $RUST "$NH" "--threads 2" "--threads 2"
XS="--log-level 4 --fix-gro --cipher-mode xor --auth-mode simple"
run cpp_cpp_xor_simple      $CPP  $CPP  "$XS" "" ""
run rust_rust_t2_xor_simple $RUST $RUST "$XS" "--threads 2" "--threads 2"
# small packets: per-packet overhead dominates
run cpp_cpp_300             $CPP  $CPP  "$PROD" "" "" 300
run rust_rust_t2_300        $RUST $RUST "$PROD" "--threads 2" "--threads 2" 300
echo "# done $(date -Is) temp=$(temp_c)C"
