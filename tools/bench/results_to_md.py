#!/usr/bin/env python3
"""Turn `RESULT ...` lines from bench_pi.sh / run_matrix_pi.sh into a markdown table.
    tools/bench/results_to_md.py results.txt [baseline_name]"""
import re
import sys

rows = []
for line in open(sys.argv[1]):
    if not line.startswith("RESULT "):
        continue
    name = line.split()[1]
    g = lambda k: (re.search(k + r"=(-?[0-9.]+)", line) or [None, "?"])[1]
    probe = "ok" if "ratio=1.0000" in line else ("FAIL" if "probe:" in line else "?")
    rows.append((name, int(g("steady_pps")), int(g("mbps")), g("size"), g("server_cpu"), g("client_cpu"), g("sys_busy"), g("sys_irq"), probe, (re.search(r"temp=([0-9.]+->[0-9.]+)", line) or [None, "?"])[1]))
base = None
if len(sys.argv) > 2:
    for r in rows:
        if r[0] == sys.argv[2]:
            base = r[1]
print("| case | steady pps | Mbit/s | size | server CPU | client CPU | system busy / irq (of 400%) | probe | temp °C |" + (" vs baseline |" if base else ""))
print("|---|---:|---:|---:|---:|---:|---|---|---|" + ("---:|" if base else ""))
for r in rows:
    rel = f" {r[1] / base:.2f}× |" if base else ""
    print(f"| {r[0]} | {r[1]:,} | {r[2]} | {r[3]} | {r[4]}% | {r[5]}% | {r[6]}% / {r[7]}% | {r[8]} | {r[9]} |{rel}")
