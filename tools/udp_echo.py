#!/usr/bin/env python3
"""UDP echo server: tools/udp_echo.py [bind_ip] port"""
import socket
import sys

if len(sys.argv) == 2:
    ip, port = "127.0.0.1", int(sys.argv[1])
else:
    ip, port = sys.argv[1], int(sys.argv[2])
fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
s = socket.socket(fam, socket.SOCK_DGRAM)
s.bind((ip, port))
while True:
    data, peer = s.recvfrom(65535)
    s.sendto(data, peer)
