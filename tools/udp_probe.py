#!/usr/bin/env python3
"""Send numbered datagrams through a tunnel to an echo server and verify the echoes.

    tools/udp_probe.py host port count size [flows] [min_ratio]

Uses `flows` independent source sockets (= tunnel convs). Echoes are drained while
sending so the probe's own socket buffers never overflow. Exit status 0 when at least
`min_ratio` of the datagrams came back intact.
"""
import os
import socket
import sys
import time

SO_RCVBUFFORCE = 33  # linux; needs CAP_NET_ADMIN, falls back to SO_RCVBUF

host, port = sys.argv[1], int(sys.argv[2])
count, size = int(sys.argv[3]), int(sys.argv[4])
flows = int(sys.argv[5]) if len(sys.argv) > 5 else 2
min_ratio = float(sys.argv[6]) if len(sys.argv) > 6 else 0.99
fam = socket.AF_INET6 if ":" in host else socket.AF_INET
socks = []
for _ in range(flows):
    s = socket.socket(fam, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, SO_RCVBUFFORCE, 16 * 1024 * 1024)
    except OSError:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16 * 1024 * 1024)
    s.setblocking(False)
    socks.append(s)

sent = {}
got = set()
corrupt = 0


def drain():
    global corrupt
    progressed = False
    for f, s in enumerate(socks):
        while True:
            try:
                data, _ = s.recvfrom(65535)
            except BlockingIOError:
                break
            progressed = True
            i = int.from_bytes(data[:4], "big")
            if sent.get((f, i)) == data:
                got.add((f, i))
            else:
                corrupt += 1
    return progressed


t0 = time.time()
for i in range(count):
    f = i % flows
    payload = i.to_bytes(4, "big") + os.urandom(max(0, size - 4))
    sent[(f, i)] = payload
    while True:
        try:
            socks[f].sendto(payload, (host, port))
            break
        except BlockingIOError:
            drain()
            time.sleep(0.0005)
    if i % 20 == 19:
        drain()
        time.sleep(0.0005)  # ~40k pps, keeps loopback queues sane
deadline = time.time() + 5.0
while len(got) < count and time.time() < deadline:
    if not drain():
        time.sleep(0.01)
elapsed = time.time() - t0
ratio = len(got) / count if count else 1.0
print(f"probe: sent={count} received={len(got)} corrupt={corrupt} size={size} flows={flows} ratio={ratio:.4f} elapsed={elapsed:.2f}s")
sys.exit(0 if ratio >= min_ratio and corrupt == 0 else 1)
