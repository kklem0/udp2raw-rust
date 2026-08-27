#!/bin/bash
# Syscall profile of udp2raw builds at a fixed offered rate over loopback (root, Linux).
# For each NAME=BIN: (1) user/sys CPU and context switches of the client and server daemons
# at RATE pps; (2) count and total kernel time of every syscall type of each daemon, from the
# tracefs raw_syscalls tracepoints (no ptrace overhead) for TRACE_SECS seconds at TRACE_RATE.
# Socket-buffer limits, governor and the trace buffer are set for the run and restored.
#   ./sysprof_pi.sh NAME=BIN [NAME=BIN...]
# With PERF=1 (needs `perf`, override the binary with PERF_BIN): a run sampling both daemons
# (cpu-clock, call graphs) at RATE with the report (top symbols per daemon) in
# LOGDIR/NAME_perf.report, and a run with PMU counters per daemon (cycles, instructions,
# L1/L2 misses) printed inline.
# env: RATE (10000) SECS (5) TRACE_RATE (5000) TRACE_SECS (3) BURST (64) THREADS (0) NO_TRACE (unset) PERF (unset)
#      COMMON ("--log-level 4 --fix-gro") BENCH (./udpbench2) LOGDIR (./logs-sysprof)
#      SERVER_CPUS / CLIENT_CPUS / GEN_CPUS: optional taskset pinning (e.g. 1 / 2 / 3)
set -uo pipefail
RATE=${RATE:-10000}; SECS=${SECS:-5}; TRACE_RATE=${TRACE_RATE:-5000}; TRACE_SECS=${TRACE_SECS:-3}; BURST=${BURST:-64}; THREADS=${THREADS:-0}
COMMON=${COMMON:-"--log-level 4 --fix-gro"}; BENCH=${BENCH:-./udpbench2}; LOGDIR=${LOGDIR:-$PWD/logs-sysprof}
SPORT=${SPORT:-34096}; CPORT=${CPORT:-33333}; TPORT=${TPORT:-37777}
PERF_BIN=${PERF_BIN:-perf}
S_PIN=${SERVER_CPUS:+taskset -c $SERVER_CPUS}; C_PIN=${CLIENT_CPUS:+taskset -c $CLIENT_CPUS}; G_PIN=${GEN_CPUS:+taskset -c $GEN_CPUS}
TR=/sys/kernel/tracing; [ -d $TR/events/raw_syscalls ] || TR=/sys/kernel/debug/tracing
[ -d $TR/events/raw_syscalls ] || TR=""
mkdir -p "$LOGDIR"; HZ=$(getconf CLK_TCK)
OLD_RMEM=$(sysctl -n net.core.rmem_max); OLD_WMEM=$(sysctl -n net.core.wmem_max)
OLD_GOV=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo "")
OLD_BUF=$([ -n "$TR" ] && cut -d' ' -f1 $TR/buffer_size_kb || echo "")   # "7 (expanded: 1408)" -> 7
pids=()
restore() {
    for p in "${pids[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
    if [ -n "$TR" ]; then echo 0 > $TR/tracing_on; echo 0 > $TR/events/raw_syscalls/enable; echo > $TR/set_event_pid; echo > $TR/trace; [ -n "$OLD_BUF" ] && echo "$OLD_BUF" > $TR/buffer_size_kb; fi
    sysctl -w net.core.rmem_max="$OLD_RMEM" net.core.wmem_max="$OLD_WMEM" >/dev/null 2>&1
    if [ -n "$OLD_GOV" ]; then for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo "$OLD_GOV" > "$g" 2>/dev/null; done; fi
    sleep 0.5
    echo "# restored rmem_max=$(sysctl -n net.core.rmem_max) wmem_max=$(sysctl -n net.core.wmem_max) governor=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null) trace_buffer_kb=$([ -n "$TR" ] && cat $TR/buffer_size_kb) tracing_on=$([ -n "$TR" ] && cat $TR/tracing_on)"
    echo "# leftover bench processes: $(pgrep -a -f 'udpbench|udp_echo|udp_probe|/bench/udp2raw' | wc -l); udp2raw processes: $(pgrep -a udp2raw | paste -sd';')"
}
trap restore EXIT
sysctl -w net.core.rmem_max=16777216 net.core.wmem_max=16777216 >/dev/null
for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo performance > "$g" 2>/dev/null; done
stat2() { awk '{print $14, $15}' /proc/$1/stat; }
ctx() { awk '/ctxt_switches/{printf "%s ", $2}' /proc/$1/status; }
sysname() { # aarch64 (generic) syscall numbers
    case $1 in 22) echo epoll_pwait;; 63) echo read;; 64) echo write;; 73) echo ppoll;; 98) echo futex;; 113) echo clock_gettime;;
        206) echo sendto;; 207) echo recvfrom;; 211) echo sendmsg;; 212) echo recvmsg;; 243) echo recvmmsg;; 269) echo sendmmsg;; *) echo "nr$1";; esac; }
run_case() { # NAME BIN MODE RATE SECS  (measures the middle SECS-2 seconds of a SECS blast)
    local name=$1 bin=$2 mode=$3 rate=$4 secs=$5
    $S_PIN $bin -s -l 127.0.0.1:$SPORT -r 127.0.0.1:$TPORT -k benchpw -a $COMMON --threads $THREADS > "$LOGDIR/$name.server.log" 2>&1 & local SP=$!; pids+=($SP)
    sleep 0.6
    $C_PIN $bin -c -l 127.0.0.1:$CPORT -r 127.0.0.1:$SPORT -k benchpw -a $COMMON --threads $THREADS > "$LOGDIR/$name.client.log" 2>&1 & local CP=$!; pids+=($CP)
    for _ in $(seq 1 100); do grep -q client_ready "$LOGDIR/$name.client.log" 2>/dev/null && break; sleep 0.1; done
    grep -q client_ready "$LOGDIR/$name.client.log" || { echo "$name: client never ready"; kill $SP $CP; pids=(); return; }
    sleep 0.5
    $G_PIN $BENCH sink 127.0.0.1 $TPORT $((secs + 2)) > "$LOGDIR/$name.sink.log" 2>&1 & local SK=$!; pids+=($SK)
    sleep 0.3
    $G_PIN $BENCH blast 127.0.0.1 $CPORT $secs 1300 $rate $BURST > "$LOGDIR/$name.blast.log" 2>&1 & local BL=$!; pids+=($BL)
    sleep 1
    if [ $mode = trace ]; then echo > $TR/trace; printf '%s\n%s\n' $SP $CP > $TR/set_event_pid; echo 1 > $TR/events/raw_syscalls/enable; echo 1 > $TR/tracing_on; fi
    local PERFPID=""
    if [ $mode = perf ]; then $PERF_BIN record -e cpu-clock -F 1999 -g -o "$LOGDIR/$name.perf.data" -p $SP,$CP > "$LOGDIR/$name.perf.log" 2>&1 & PERFPID=$!; pids+=($PERFPID); sleep 0.5; fi
    local STATPIDS=()
    if [ $mode = stat ]; then
        local ev=cycles,instructions,L1-dcache-load-misses,l2d_cache_refill,cache-misses,context-switches
        $PERF_BIN stat -e $ev -p $SP -o "$LOGDIR/$name.stat.server" 2>/dev/null & STATPIDS+=($!)
        $PERF_BIN stat -e $ev -p $CP -o "$LOGDIR/$name.stat.client" 2>/dev/null & STATPIDS+=($!)
        pids+=("${STATPIDS[@]}"); sleep 0.5
    fi
    read -r su0 ss0 < <(stat2 $SP); read -r cu0 cs0 < <(stat2 $CP); local sx0=$(ctx $SP) cx0=$(ctx $CP) t0=$(date +%s.%N)
    sleep $((secs - 2))
    local t1=$(date +%s.%N); read -r su1 ss1 < <(stat2 $SP); read -r cu1 cs1 < <(stat2 $CP); local sx1=$(ctx $SP) cx1=$(ctx $CP)
    if [ $mode = trace ]; then echo 0 > $TR/tracing_on; echo 0 > $TR/events/raw_syscalls/enable; echo > $TR/set_event_pid; cat $TR/trace > "$LOGDIR/$name.trace"; echo > $TR/trace; fi
    if [ -n "$PERFPID" ]; then kill -INT $PERFPID; wait $PERFPID 2>/dev/null; fi
    for t in "${STATPIDS[@]:-}"; do [ -n "$t" ] && kill -INT $t 2>/dev/null; done
    for t in "${STATPIDS[@]:-}"; do [ -n "$t" ] && wait $t 2>/dev/null; done
    wait $BL $SK 2>/dev/null
    kill $SP $CP 2>/dev/null; wait $SP $CP 2>/dev/null; pids=(); sleep 0.5
    local dt=$(awk "BEGIN{print $t1-$t0}")
    pct() { awk "BEGIN{printf \"%.0f\", ($2-$1)/$HZ/$dt*100}"; }
    sw() { awk "BEGIN{split(\"$1\",a,\" \");split(\"$2\",b,\" \");printf \"%dv+%dnv\", b[1]-a[1], b[2]-a[2]}"; }
    local sent=$(sed -n 's/.*packets=\([0-9]*\).*/\1/p' "$LOGDIR/$name.blast.log" | head -1) recv=$(sed -n 's/^sink:.*packets=\([0-9]*\).*/\1/p' "$LOGDIR/$name.sink.log")
    echo "$name | $mode rate=$rate sent=$sent recv=$recv | server user=$(pct $su0 $su1)% sys=$(pct $ss0 $ss1)% ctx=$(sw "$sx0" "$sx1") | client user=$(pct $cu0 $cu1)% sys=$(pct $cs0 $cs1)% ctx=$(sw "$cx0" "$cx1") | $(printf %.1f $dt)s"
    if [ $mode = trace ]; then
        for side in server:$SP client:$CP; do
            awk -v pid="${side#*:}" -v side="${side%%:*}" -v dt="$dt" '
                function nr_ts(   nr, ts) { nr=$0; sub(/.*NR /,"",nr); sub(/[^0-9].*/,"",nr); ts=$0; sub(/: sys_.*/,"",ts); sub(/.* /,"",ts); NR_=nr; TS_=ts }
                $0 ~ "-"pid" +\\[" && /sys_enter: NR/ { nr_ts(); t0[NR_]=TS_ }
                $0 ~ "-"pid" +\\[" && /sys_exit: NR/  { nr_ts(); if (NR_ in t0) { n[NR_]++; s[NR_]+=TS_-t0[NR_]; delete t0[NR_] } }
                END { for (nr in n) printf "  %-6s nr=%s calls=%d us/call=%.1f in-syscall=%.1f%%\n", side, nr, n[nr], s[nr]/n[nr]*1e6, s[nr]/dt*100 }' "$LOGDIR/$name.trace" \
            | sort -t= -k3 -rn | head -7 | while read -r l; do nr=$(echo "$l" | sed 's/.*nr=\([0-9]*\).*/\1/'); echo "$l" | sed "s/nr=$nr /$(sysname $nr) /"; done
        done
        echo "  (trace: $(wc -l < "$LOGDIR/$name.trace") lines, $(grep -c 'LOST' "$LOGDIR/$name.trace") lost-event markers; in-syscall = wall time inside the syscall incl. preemption; epoll = sleeping)"
    fi
    if [ $mode = stat ]; then
        for side in server client; do
            awk -v side=$side -v pk=$(( (recv > 0 ? recv : 1) )) '/^ +[0-9,]+ +[a-zA-Z]/ { gsub(",", "", $1); v[$2]=$1 }
                END { printf "  %-6s per packet: cycles=%.0f instr=%.0f IPC=%.2f L1d-miss=%.0f L2-refill=%.0f cache-miss=%.0f ctxsw=%.2f\n", side, v["cycles"]/pk, v["instructions"]/pk, v["instructions"]/v["cycles"], v["L1-dcache-load-misses"]/pk, v["l2d_cache_refill"]/pk, v["cache-misses"]/pk, v["context-switches"]/pk }' "$LOGDIR/$name.stat.$side"
        done
        echo "  (per packet = counter / packets received by the sink during the whole blast; the counters cover the middle $((secs - 2)) s, so scale by ~$secs/$((secs - 2)))"
    fi
    if [ $mode = perf ]; then
        $PERF_BIN report -i "$LOGDIR/$name.perf.data" --stdio --no-children --sort comm,sym -g none --percent-limit 0.8 2>/dev/null | grep -v -E "^#|^$" > "$LOGDIR/$name.perf.report"
        echo "  perf: $(grep -c . "$LOGDIR/$name.perf.report") symbols >= 0.8% in $LOGDIR/$name.perf.report ($($PERF_BIN report -i "$LOGDIR/$name.perf.data" --stdio --header-only 2>/dev/null | grep -o 'sample.*' | head -1))"
    fi
}
echo "# $(date -Is) host=$(hostname) kernel=$(uname -r) rate=$RATE secs=$SECS trace_rate=$TRACE_RATE trace_secs=$TRACE_SECS burst=$BURST threads=$THREADS common='$COMMON' tracefs=${TR:-none} pin=${SERVER_CPUS:-}/${CLIENT_CPUS:-}/${GEN_CPUS:-}"
[ -n "$TR" ] && echo 8192 > $TR/buffer_size_kb
for spec in "$@"; do
    name=${spec%%=*}; bin=${spec#*=}
    echo "## $name = $bin ($(md5sum < "$bin" | cut -c1-8))"
    run_case "${name}_cpu" "$bin" cpu "$RATE" "$SECS"
    [ -n "$TR" ] && [ -z "${NO_TRACE:-}" ] && run_case "${name}_trace" "$bin" trace "$TRACE_RATE" "$((TRACE_SECS + 2))"
    if [ -n "${PERF:-}" ] && command -v "$PERF_BIN" >/dev/null; then
        run_case "${name}_stat" "$bin" stat "$RATE" "$SECS"
        run_case "${name}_perf" "$bin" perf "$RATE" "$SECS"
    fi
done
