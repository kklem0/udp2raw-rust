#!/usr/bin/env python3
"""Receive and deliberately discard UDP datagrams: udp_sink.py [bind_ip] port."""

import socket
import sys


if len(sys.argv) == 2:
    bind_ip, port = "127.0.0.1", int(sys.argv[1])
else:
    bind_ip, port = sys.argv[1], int(sys.argv[2])

family = socket.AF_INET6 if ":" in bind_ip else socket.AF_INET
sock = socket.socket(family, socket.SOCK_DGRAM)
sock.bind((bind_ip, port))
while True:
    sock.recvfrom(65535)
