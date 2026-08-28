#!/usr/bin/env python3
"""Minimal DNS stub for the integration tests: answers A queries from an answers file that
is re-read for every query, so a test can move a name while the client runs.

    dns_stub.py BIND_IP PORT ANSWERS_FILE

ANSWERS_FILE lines: "<name> <ipv4> [ttl]" (repeat the name for several records),
"<name> NXDOMAIN" or "<name> SERVFAIL"; names not in the file get NXDOMAIN; queries for
other types than A get an empty NOERROR (NODATA). UDP only, no truncation. Every query is
logged to stderr as "<time> query <name> type <n> from <ip> -> <answer>".
"""
import socket
import struct
import sys
import time


def parse_name(data, off):
    labels = []
    while True:
        length = data[off]
        off += 1
        if length == 0:
            break
        if length & 0xC0:
            raise ValueError("compressed name in question")
        labels.append(data[off:off + length].decode("ascii"))
        off += length
    return ".".join(labels), off


def load(path):
    table = {}
    try:
        with open(path) as f:
            for line in f:
                parts = line.split()
                if not parts or parts[0].startswith("#"):
                    continue
                table.setdefault(parts[0].rstrip(".").lower(), []).append(parts[1:])
    except FileNotFoundError:
        pass
    return table


def main():
    bind_ip, port, path = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind_ip, port))
    while True:
        data, peer = sock.recvfrom(4096)
        try:
            qid, flags, qd, _an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
            name, off = parse_name(data, 12)
            qtype, _qclass = struct.unpack("!HH", data[off:off + 4])
            off += 4
        except Exception as e:  # noqa: BLE001
            sys.stderr.write(f"{time.time():.3f} bad query from {peer}: {e}\n")
            continue
        question = data[12:off]
        entries = load(path).get(name.lower(), [])
        rcode, answers, ancount, desc = 0, b"", 0, []
        if not entries:
            rcode, desc = 3, ["NXDOMAIN"]
        for e in entries:
            if e[0].upper() == "NXDOMAIN":
                rcode, answers, ancount, desc = 3, b"", 0, ["NXDOMAIN"]
                break
            if e[0].upper() == "SERVFAIL":
                rcode, answers, ancount, desc = 2, b"", 0, ["SERVFAIL"]
                break
            if qtype == 1:
                ttl = int(e[1]) if len(e) > 1 else 30
                answers += struct.pack("!HHHIH", 0xC00C, 1, 1, ttl, 4) + socket.inet_aton(e[0])
                ancount += 1
                desc.append(f"{e[0]}/{ttl}")
        header = struct.pack("!HHHHHH", qid, 0x8000 | (flags & 0x0100) | 0x0080 | rcode, 1, ancount, 0, 0)
        sock.sendto(header + question + answers, peer)
        sys.stderr.write(f"{time.time():.3f} query {name} type {qtype} from {peer[0]} -> {' '.join(desc) or 'NODATA'}\n")
        sys.stderr.flush()


if __name__ == "__main__":
    main()
