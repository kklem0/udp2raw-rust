#!/usr/bin/env python3
"""Continuously probe a UDP echo tunnel and bound its longest packet-loss run.

Usage:
    continuous_udp_probe.py HOST PORT DURATION INTERVAL REPLY_GRACE MAX_LOSS_GAP MIN_RATIO

Each scheduled datagram carries a unique sequence and deterministic body.  The result is based on
the longest consecutive run of scheduled packets that did not return intact, rather than a
single successful probe after a reconnect.  This makes short namespace tests sensitive to
recurring hidden outages while tolerating the one bounded interruption explicitly allowed
for an attended cutover.
"""

import select
import socket
import struct
import sys
import time


if len(sys.argv) != 8:
    print(__doc__.strip(), file=sys.stderr)
    sys.exit(2)

host = sys.argv[1]
port = int(sys.argv[2])
duration = float(sys.argv[3])
interval = float(sys.argv[4])
reply_grace = float(sys.argv[5])
max_loss_gap = float(sys.argv[6])
min_ratio = float(sys.argv[7])
if duration <= 0 or interval <= 0 or reply_grace < 0 or max_loss_gap < 0:
    raise SystemExit("duration/interval must be positive and grace/gap non-negative")
if not 0.0 <= min_ratio <= 1.0:
    raise SystemExit("min_ratio must be between zero and one")

family = socket.AF_INET6 if ":" in host else socket.AF_INET
sock = socket.socket(family, socket.SOCK_DGRAM)
sock.setblocking(False)

expected = {}
received = set()
corrupt = 0


def drain():
    global corrupt
    while True:
        try:
            body, _ = sock.recvfrom(65535)
        except BlockingIOError:
            return
        if len(body) < 8:
            corrupt += 1
            continue
        seq = struct.unpack("!Q", body[:8])[0]
        if expected.get(seq) == body:
            received.add(seq)
        else:
            corrupt += 1


started = time.monotonic()
ends = started + duration
next_send = started
seq = 0
print(
    f"continuous probe started: duration={duration:.2f}s interval={interval:.3f}s "
    f"max_loss_gap={max_loss_gap:.2f}s",
    flush=True,
)

while True:
    now = time.monotonic()
    while now >= next_send and next_send < ends:
        payload = struct.pack("!Q", seq) + bytes([seq & 0xFF]) * 56
        expected[seq] = payload
        try:
            sock.sendto(payload, (host, port))
        except (BlockingIOError, OSError):
            # The scheduled packet remains absent from `received` and counts as loss.
            pass
        seq += 1
        next_send += interval
        now = time.monotonic()
    drain()
    now = time.monotonic()
    if now >= ends:
        break
    wait = min(0.02, max(0.0, next_send - now))
    select.select([sock], [], [], wait)

grace_deadline = time.monotonic() + reply_grace
while time.monotonic() < grace_deadline and len(received) < seq:
    remaining = max(0.0, grace_deadline - time.monotonic())
    select.select([sock], [], [], min(0.02, remaining))
    drain()

longest_run = 0
run = 0
for packet in range(seq):
    if packet in received:
        longest_run = max(longest_run, run)
        run = 0
    else:
        run += 1
longest_run = max(longest_run, run)
ratio = len(received) / seq if seq else 1.0
loss_gap = longest_run * interval
print(
    f"continuous probe: sent={seq} received={len(received)} corrupt={corrupt} "
    f"ratio={ratio:.4f} longest_loss_run={longest_run} max_loss_gap={loss_gap:.3f}s",
    flush=True,
)

sys.exit(0 if corrupt == 0 and ratio >= min_ratio and loss_gap <= max_loss_gap else 1)
