#!/bin/bash
# Fixed-rate efficiency test for one udp2raw configuration over loopback: offer RATE pps
# for SECS seconds and report loss plus each daemon's user and system CPU (user = the
# daemon's own work: crypto, parsing, framing; system = kernel work done in its syscalls,
# including loopback delivery of what it sends). Runs as root on the box under test.
#
#   bench_fixed.sh NAME SERVER_BIN CLIENT_BIN "COMMON" "SERVER ARGS" "CLIENT ARGS" RATE [SIZE] [SECS] [BURST]
set -uo pipefail
NAME=$1; SBIN=$2; CBIN=$3; COMMON=$4; SARGS=$5; CARGS=$6; RATE=$7; SIZE=${8:-1300}; SECS=${9:-8}; BURST=${10:-8}
SPORT=${SPORT:-34096}; CPORT=${CPORT:-33333}; TPORT=${TPORT:-37777}
BENCH=${BENCH:-./udpbench}; LOGDIR=${LOGDIR:-/tmp/udp2raw-bench}
mkdir -p "$LOGDIR"
pids=()
cleanup() { for p in "${pids[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done; pids=(); sleep 0.6; }
trap cleanup EXIT
ticks() { awk '{print $14, $15}' "/proc/$1/stat" 2>/dev/null || echo "0 0"; }
sys_ticks() { awk 'NR==1{print $2+$3+$4, $7+$8}' /proc/stat; }

$SBIN -s -l 127.0.0.1:$SPORT -r 127.0.0.1:$TPORT -k benchpw -a $COMMON $SARGS > "$LOGDIR/$NAME.server.log" 2>&1 & SPID=$!; pids+=($SPID)
sleep 0.6
$CBIN -c -l 127.0.0.1:$CPORT -r 127.0.0.1:$SPORT -k benchpw -a $COMMON $CARGS > "$LOGDIR/$NAME.client.log" 2>&1 & CPID=$!; pids+=($CPID)
for _ in $(seq 1 200); do grep -q client_ready "$LOGDIR/$NAME.client.log" 2>/dev/null && break; sleep 0.1; done
if ! grep -q client_ready "$LOGDIR/$NAME.client.log"; then echo "FIXED $NAME | client never became ready"; exit 1; fi
sleep 0.8
$BENCH sink 127.0.0.1 $TPORT $((SECS + 2)) > "$LOGDIR/$NAME.sink.log" 2>&1 & SINK=$!; pids+=($SINK)
sleep 0.4
HZ=$(getconf CLK_TCK)
read SU0 SS0 < <(ticks $SPID); read CU0 CS0 < <(ticks $CPID); read B0 Q0 < <(sys_ticks); T0=$(date +%s.%N)
$BENCH blast 127.0.0.1 $CPORT $SECS $SIZE $RATE $BURST > "$LOGDIR/$NAME.blast.log" 2>&1
T1=$(date +%s.%N); read SU1 SS1 < <(ticks $SPID); read CU1 CS1 < <(ticks $CPID); read B1 Q1 < <(sys_ticks)
wait $SINK 2>/dev/null
DT=$(awk "BEGIN{print $T1-$T0}")
pct() { awk "BEGIN{printf \"%.0f\", ($2-$1)/$HZ/$DT*100}"; }
RECV=$(grep -h '^sink:' "$LOGDIR/$NAME.sink.log" | sed 's/.*packets=\([0-9]*\).*/\1/')
SENT=$(grep -h '^blast:' "$LOGDIR/$NAME.blast.log" | sed 's/.*packets=\([0-9]*\).*/\1/')
OFFERED=$(grep -h '^blast:' "$LOGDIR/$NAME.blast.log" | sed 's/.*pps=\([0-9]*\).*/\1/')
LOSS=$(awk "BEGIN{ if (${SENT:-0}>0) printf \"%.4f\", 1 - ${RECV:-0}/$SENT; else print 1 }")
WARN=$(grep -h -c -E "dropped|overloaded|rst==1" "$LOGDIR/$NAME.client.log" "$LOGDIR/$NAME.server.log" | paste -sd+ | bc)
echo "FIXED $NAME | rate=$RATE offered=$OFFERED burst=$BURST size=$SIZE sent=$SENT recv=$RECV loss=$LOSS | server user=$(pct $SU0 $SU1)% sys=$(pct $SS0 $SS1)% | client user=$(pct $CU0 $CU1)% sys=$(pct $CS0 $CS1)% | sys_busy=$(pct $B0 $B1)% sys_irq=$(pct $Q0 $Q1)% | warnlines=$WARN"
