#!/usr/bin/env python3
"""One-direction UDP throughput smoke test.

    tools/udp_bench.py sink  bind_ip port seconds        # counts what arrives, prints Mbit/s and pps
    tools/udp_bench.py blast host port seconds size      # sends as fast as python can
"""
import os
import socket
import sys
import time

SO_RCVBUFFORCE = 33
SO_SNDBUFFORCE = 32


def force_buf(s, opt_force, opt, size):
    try:
        s.setsockopt(socket.SOL_SOCKET, opt_force, size)
    except OSError:
        s.setsockopt(socket.SOL_SOCKET, opt, size)


mode = sys.argv[1]
if mode == "sink":
    ip, port, seconds = sys.argv[2], int(sys.argv[3]), float(sys.argv[4])
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_DGRAM)
    force_buf(s, SO_RCVBUFFORCE, socket.SO_RCVBUF, 16 * 1024 * 1024)
    s.bind((ip, port))
    s.settimeout(0.5)
    n = 0
    b = 0
    first = None
    last = None
    end = time.time() + seconds
    while time.time() < end:
        try:
            data = s.recv(65535)
        except socket.timeout:
            continue
        now = time.time()
        if first is None:
            first = now
        last = now
        n += 1
        b += len(data)
    dur = (last - first) if first and last and last > first else 1e-9
    print(f"sink: packets={n} bytes={b} duration={dur:.2f}s pps={n / dur:.0f} mbps={b * 8 / dur / 1e6:.1f}")
else:
    host, port, seconds, size = sys.argv[2], int(sys.argv[3]), float(sys.argv[4]), int(sys.argv[5])
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_DGRAM)
    force_buf(s, SO_SNDBUFFORCE, socket.SO_SNDBUF, 16 * 1024 * 1024)
    s.connect((host, port))
    payload = os.urandom(size)
    n = 0
    end = time.time() + seconds
    t0 = time.time()
    while time.time() < end:
        try:
            s.send(payload)
            n += 1
        except (BlockingIOError, InterruptedError):
            pass
        except OSError:
            time.sleep(0.001)
    dur = time.time() - t0
    print(f"blast: packets={n} size={size} duration={dur:.2f}s pps={n / dur:.0f} mbps={n * size * 8 / dur / 1e6:.1f}")
