#!/bin/bash
# Run one udp2raw configuration over loopback and measure one-direction throughput
# (udpbench blast -> client udp port -> raw tunnel -> server -> udpbench sink) plus the CPU
# consumed by each daemon and by the whole system. Runs as root on the box under test.
#
#   bench_pi.sh NAME SERVER_BIN CLIENT_BIN "COMMON ARGS" "SERVER ARGS" "CLIENT ARGS" [SECONDS] [SIZE] [MAX_PPS]
#
# env: SPORT (tunnel port, 34096) CPORT (client udp port, 33333) TPORT (sink port, 37777)
#      BENCH (udpbench binary, ./udpbench) PROBE (udp_probe.py) LOGDIR (/tmp/udp2raw-bench)
set -uo pipefail
NAME=$1; SBIN=$2; CBIN=$3; COMMON=$4; SARGS=$5; CARGS=$6; SECS=${7:-10}; SIZE=${8:-1300}; MAXPPS=${9:-0}
SPORT=${SPORT:-34096}; CPORT=${CPORT:-33333}; TPORT=${TPORT:-37777}
BENCH=${BENCH:-./udpbench}; PROBE=${PROBE:-./udp_probe.py}; LOGDIR=${LOGDIR:-/tmp/udp2raw-bench}
mkdir -p "$LOGDIR"
pids=()
cleanup() { for p in "${pids[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done; pids=(); sleep 0.6; }
trap cleanup EXIT

cpu_ticks() { awk '{print $14+$15}' "/proc/$1/stat" 2>/dev/null || echo 0; }   # utime+stime of all threads
sys_ticks() { awk 'NR==1{print $2+$3+$4, $5+$6, $7+$8}' /proc/stat; }             # busy(user+nice+sys) idle(idle+iowait) irq(irq+softirq)
temp() { awk '{printf "%.1f", $1/1000}' /sys/class/thermal/thermal_zone0/temp 2>/dev/null; }

$SBIN -s -l 127.0.0.1:$SPORT -r 127.0.0.1:$TPORT -k benchpw -a $COMMON $SARGS > "$LOGDIR/$NAME.server.log" 2>&1 & SPID=$!; pids+=($SPID)
sleep 0.6
$CBIN -c -l 127.0.0.1:$CPORT -r 127.0.0.1:$SPORT -k benchpw -a $COMMON $CARGS > "$LOGDIR/$NAME.client.log" 2>&1 & CPID=$!; pids+=($CPID)
for _ in $(seq 1 200); do grep -q client_ready "$LOGDIR/$NAME.client.log" 2>/dev/null && break; sleep 0.1; done
if ! grep -q client_ready "$LOGDIR/$NAME.client.log"; then echo "RESULT $NAME | client never became ready"; exit 1; fi
sleep 0.5

# correctness first: 500 datagrams on 2 convs must echo back (needs an echo server on TPORT)
python3 "${PROBE%/*}/udp_echo.py" 127.0.0.1 $TPORT & EPID=$!; pids+=($EPID)
sleep 0.3
PROBE_RES=$(python3 "$PROBE" 127.0.0.1 $CPORT 500 1000 2 0.98 2>&1 | tail -1)
kill $EPID 2>/dev/null; wait $EPID 2>/dev/null
sleep 0.3

# throughput: sink behind the server, blast into the client
$BENCH sink 127.0.0.1 $TPORT $((SECS + 2)) > "$LOGDIR/$NAME.sink.log" 2>&1 & SINK=$!; pids+=($SINK)
sleep 0.5
T_BEFORE=$(temp)
read B0 I0 Q0 < <(sys_ticks); S0=$(cpu_ticks $SPID); C0=$(cpu_ticks $CPID); T0=$(date +%s.%N)
$BENCH blast 127.0.0.1 $CPORT $SECS $SIZE $MAXPPS > "$LOGDIR/$NAME.blast.log" 2>&1
T1=$(date +%s.%N); S1=$(cpu_ticks $SPID); C1=$(cpu_ticks $CPID); read B1 I1 Q1 < <(sys_ticks)
T_AFTER=$(temp)
wait $SINK 2>/dev/null
HZ=$(getconf CLK_TCK); NCPU=$(nproc)
DT=$(awk "BEGIN{print $T1-$T0}")
SCPU=$(awk "BEGIN{printf \"%.0f\", ($S1-$S0)/$HZ/$DT*100}")
CCPU=$(awk "BEGIN{printf \"%.0f\", ($C1-$C0)/$HZ/$DT*100}")
SYSB=$(awk "BEGIN{printf \"%.0f\", ($B1-$B0)/$HZ/$DT*100}")
SYSQ=$(awk "BEGIN{printf \"%.0f\", ($Q1-$Q0)/$HZ/$DT*100}")
# steady-state pps: average of the per-second samples excluding the 2 s ramp-up and the last second
STEADY=$(grep "^t=" "$LOGDIR/$NAME.sink.log" | awk '{sub("pps=","",$2); print $2}' | sed '1,2d;$d' | awk '{s+=$1; n++} END{if(n>0) printf "%.0f", s/n; else print 0}')
MBPS=$(awk "BEGIN{printf \"%.0f\", $STEADY*$SIZE*8/1e6}")
WARN=$(grep -h -c -E "dropped|overloaded|rst==1" "$LOGDIR/$NAME.client.log" "$LOGDIR/$NAME.server.log" | paste -sd+ | bc)
echo "RESULT $NAME | steady_pps=$STEADY mbps=$MBPS size=$SIZE | server_cpu=${SCPU}% client_cpu=${CCPU}% sys_busy=${SYSB}% sys_irq=${SYSQ}% (of ${NCPU}00%) | $(grep -h '^blast:' "$LOGDIR/$NAME.blast.log") | $(grep -h '^sink:' "$LOGDIR/$NAME.sink.log") | probe: $PROBE_RES | warnlines=$WARN temp=${T_BEFORE}->${T_AFTER}C"
