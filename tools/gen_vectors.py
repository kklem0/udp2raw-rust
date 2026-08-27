#!/usr/bin/env python3
"""Regenerate tests/data/vectors.txt from the ORIGINAL C++ udp2raw implementation.

Usage:
    tools/cpp_harness/build.sh /path/to/udp2raw-cpp      # builds tools/cpp_harness/build/harness
    tools/gen_vectors.py tools/cpp_harness/build/harness tests/data/vectors.txt

Record format (one per line, hex fields, "-" for empty):
    CFG <role> <cipher> <auth> <password_hex> <cfb_legacy>
    KEY <name> <hex>
    GROXOR <hex>
    ECB <in16> <encrypted_with_cipher_key_encrypt> <decrypted_with_cipher_key_decrypt>
    ENC <plain> <ciphertext|ERR>            my_encrypt by <role>
    XDEC <ciphertext> <plain|ERR>           my_decrypt by the OPPOSITE role
    TDEC <tampered_ciphertext> <plain|ERR>  my_decrypt by the opposite role of a corrupted packet
"""
import itertools
import random
import subprocess
import sys

harness = sys.argv[1]
out_path = sys.argv[2]
rng = random.Random(20260827)

LENS = [0, 1, 15, 16, 17, 33, 100, 1401, 1801]
CIPHERS = ["none", "xor", "aes128cbc", "aes128cfb"]
AUTHS = ["none", "md5", "crc32", "simple", "hmac_sha1"]
BASE_PW = "secret key"
EXTRA_PW = {
    ("aes128cbc", "md5"): "p@ss w0rd 123",
    ("aes128cfb", "hmac_sha1"): "p@ss w0rd 123",
    ("xor", "simple"): "p@ss w0rd 123",
}


def run(role, cipher, auth, pw, cfb_old, cmds):
    if not cmds:
        return []
    p = subprocess.run(
        [harness, role, cipher, auth, pw, "0", str(cfb_old)],
        input="\n".join(cmds) + "\n",
        capture_output=True,
        text=True,
        check=True,
    )
    lines = p.stdout.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    assert len(lines) == len(cmds) + 4 * cmds.count("keys"), (cmds, lines)
    return lines


def h(b):
    return b.hex() if b else "-"


def norm(s):
    return s if s == "ERR" else (s or "-")


lines = []
for cipher, auth in itertools.product(CIPHERS, AUTHS):
    pws = [BASE_PW] + ([EXTRA_PW[(cipher, auth)]] if (cipher, auth) in EXTRA_PW else [])
    cfb_olds = [0, 1] if cipher == "aes128cfb" else [0]
    for pw in pws:
        for cfb_old in cfb_olds:
            plains = [bytes(rng.getrandbits(8) for _ in range(n)) for n in LENS]
            if cipher == "aes128cfb":
                # the C++ asserts len>=16 on the cipher input; with MAC-then-encrypt the
                # tag makes short inputs long enough, with encrypt-then-MAC it does not.
                min_len = 16 if auth == "hmac_sha1" else max(0, 16 - {"none": 0, "md5": 16, "crc32": 4, "simple": 8}[auth])
                plains = [p for p in plains if len(p) >= min_len]
            for role, other in (("client", "server"), ("server", "client")):
                cmds = ["keys", "groxor", "ecbenc 000102030405060708090a0b0c0d0e0f", "ecbdec 000102030405060708090a0b0c0d0e0f"]
                cmds += ["enc " + p.hex() for p in plains]
                res = run(role, cipher, auth, pw, cfb_old, cmds)
                lines.append(f"CFG {role} {cipher} {auth} {pw.encode().hex()} {cfb_old}")
                for kl in res[0:5]:
                    name, val = kl.split()
                    lines.append(f"KEY {name} {val}")
                lines.append(f"GROXOR {res[5]}")
                lines.append(f"ECB 000102030405060708090a0b0c0d0e0f {res[6]} {res[7]}")
                encs = res[8:]
                xcmds = []
                tam = []
                for p, c in zip(plains, encs):
                    lines.append(f"ENC {h(p)} {norm(c)}")
                    if c != "ERR":
                        xcmds.append("dec " + c)
                        if c:
                            b = bytearray(bytes.fromhex(c))
                            b[len(b) // 2] ^= 0x55
                            tam.append(bytes(b).hex())
                xres = run(other, cipher, auth, pw, cfb_old, xcmds)
                for cmd, r in zip(xcmds, xres):
                    lines.append(f"XDEC {norm(cmd[4:])} {norm(r)}")
                tres = run(other, cipher, auth, pw, cfb_old, ["dec " + t for t in tam])
                for t, r in zip(tam, tres):
                    lines.append(f"TDEC {t} {norm(r)}")

with open(out_path, "w") as f:
    f.write("\n".join(lines) + "\n")
print(f"wrote {len(lines)} records to {out_path}")
