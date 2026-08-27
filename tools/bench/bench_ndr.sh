#!/bin/bash
# No-drop-rate benchmark (RFC 2544 style) for one udp2raw configuration over loopback:
# binary-search the offered packet rate for the highest rate the tunnel carries with
# <= MAX_LOSS loss, and report the daemons' CPU at that rate. Runs as root on the box under test.
#
#   bench_ndr.sh NAME SERVER_BIN CLIENT_BIN "COMMON ARGS" "SERVER ARGS" "CLIENT ARGS" [SIZE] [HI_PPS] [SECS]
#
# env: SPORT CPORT TPORT BENCH PROBE LOGDIR (see bench_pi.sh), MAX_LOSS (0.02), ITER (7)
set -uo pipefail
NAME=$1; SBIN=$2; CBIN=$3; COMMON=$4; SARGS=$5; CARGS=$6; SIZE=${7:-1300}; HI=${8:-120000}; SECS=${9:-4}
SPORT=${SPORT:-34096}; CPORT=${CPORT:-33333}; TPORT=${TPORT:-37777}
BENCH=${BENCH:-./udpbench}; PROBE=${PROBE:-./udp_probe.py}; LOGDIR=${LOGDIR:-/tmp/udp2raw-bench}
MAX_LOSS=${MAX_LOSS:-0.02}; ITER=${ITER:-7}
# optional CPU pinning per process (e.g. SERVER_CPUS=0-3 CLIENT_CPUS=4-7 GEN_CPUS=8-9)
S_PIN=${SERVER_CPUS:+taskset -c $SERVER_CPUS}; C_PIN=${CLIENT_CPUS:+taskset -c $CLIENT_CPUS}; G_PIN=${GEN_CPUS:+taskset -c $GEN_CPUS}
mkdir -p "$LOGDIR"
pids=()
cleanup() { for p in "${pids[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done; pids=(); sleep 0.6; }
trap cleanup EXIT
cpu_ticks() { awk '{print $14+$15}' "/proc/$1/stat" 2>/dev/null || echo 0; }
sys_ticks() { awk 'NR==1{print $2+$3+$4, $7+$8}' /proc/stat; }
temp() { awk '{printf "%.1f", $1/1000}' /sys/class/thermal/thermal_zone0/temp 2>/dev/null; }

$S_PIN $SBIN -s -l 127.0.0.1:$SPORT -r 127.0.0.1:$TPORT -k benchpw -a $COMMON $SARGS > "$LOGDIR/$NAME.server.log" 2>&1 & SPID=$!; pids+=($SPID)
sleep 0.6
$C_PIN $CBIN -c -l 127.0.0.1:$CPORT -r 127.0.0.1:$SPORT -k benchpw -a $COMMON $CARGS > "$LOGDIR/$NAME.client.log" 2>&1 & CPID=$!; pids+=($CPID)
for _ in $(seq 1 200); do grep -q client_ready "$LOGDIR/$NAME.client.log" 2>/dev/null && break; sleep 0.1; done
if ! grep -q client_ready "$LOGDIR/$NAME.client.log"; then echo "NDR $NAME | client never became ready"; exit 1; fi
sleep 0.5
python3 "${PROBE%/*}/udp_echo.py" 127.0.0.1 $TPORT & EPID=$!; pids+=($EPID)
sleep 0.3
PROBE_RES=$(python3 "$PROBE" 127.0.0.1 $CPORT 500 1000 2 0.98 2>&1 | tail -1 | sed 's/^probe: //')
kill $EPID 2>/dev/null; wait $EPID 2>/dev/null
sleep 0.3

HZ=$(getconf CLK_TCK)
try_rate() { # RATE -> sets STEADY SCPU CCPU SYSB SYSQ
    local rate=$1
    $G_PIN $BENCH sink 127.0.0.1 $TPORT $((SECS + 2)) > "$LOGDIR/$NAME.sink.log" 2>&1 & local sink=$!; pids+=($sink)
    sleep 0.4
    read B0 Q0 < <(sys_ticks); local S0=$(cpu_ticks $SPID) C0=$(cpu_ticks $CPID) T0=$(date +%s.%N)
    $G_PIN $BENCH blast 127.0.0.1 $CPORT $SECS $SIZE $rate > "$LOGDIR/$NAME.blast.log" 2>&1
    local T1=$(date +%s.%N) S1=$(cpu_ticks $SPID) C1=$(cpu_ticks $CPID); read B1 Q1 < <(sys_ticks)
    wait $sink 2>/dev/null
    local DT=$(awk "BEGIN{print $T1-$T0}")
    SCPU=$(awk "BEGIN{printf \"%.0f\", ($S1-$S0)/$HZ/$DT*100}")
    CCPU=$(awk "BEGIN{printf \"%.0f\", ($C1-$C0)/$HZ/$DT*100}")
    SYSB=$(awk "BEGIN{printf \"%.0f\", ($B1-$B0)/$HZ/$DT*100}")
    SYSQ=$(awk "BEGIN{printf \"%.0f\", ($Q1-$Q0)/$HZ/$DT*100}")
    # exact counts: everything the sink received (it runs 2 s longer than the blast) vs sent
    RECV=$(grep -h '^sink:' "$LOGDIR/$NAME.sink.log" | sed 's/.*packets=\([0-9]*\).*/\1/')
    SENT=$(grep -h '^blast:' "$LOGDIR/$NAME.blast.log" | sed 's/.*packets=\([0-9]*\).*/\1/')
    OFFERED=$(grep -h '^blast:' "$LOGDIR/$NAME.blast.log" | sed 's/.*pps=\([0-9]*\).*/\1/')
    STEADY=$(awk "BEGIN{printf \"%.0f\", ${RECV:-0}/$SECS}")
}

lo=0; hi=$HI; best=0; best_line=""
for _ in $(seq 1 "$ITER"); do
    rate=$(( (lo + hi) / 2 ))
    try_rate $rate
    loss=$(awk "BEGIN{ if (${SENT:-0}>0) printf \"%.4f\", 1 - ${RECV:-0}/$SENT; else print 1 }")
    ok=$(awk "BEGIN{print ($loss <= $MAX_LOSS) ? 1 : 0}")
    echo "  ndr-iter $NAME rate=$rate offered=$OFFERED sent=$SENT recv=$RECV loss=$loss server_cpu=${SCPU}% client_cpu=${CCPU}% sys_busy=${SYSB}% irq=${SYSQ}%"
    if [ "$ok" = 1 ]; then
        lo=$rate; best=$STEADY
        best_line="server_cpu=${SCPU}% client_cpu=${CCPU}% sys_busy=${SYSB}% sys_irq=${SYSQ}%"
    else
        hi=$rate
    fi
    sleep 1
done
MBPS=$(awk "BEGIN{printf \"%.0f\", $best*$SIZE*8/1e6}")
WARN=$(grep -h -c -E "dropped|overloaded|rst==1" "$LOGDIR/$NAME.client.log" "$LOGDIR/$NAME.server.log" | paste -sd+ | bc)
echo "NDR $NAME | ndr_pps=$best mbps=$MBPS size=$SIZE | $best_line (of $(nproc)00%) | probe: $PROBE_RES | warnlines=$WARN temp=$(temp)C"
