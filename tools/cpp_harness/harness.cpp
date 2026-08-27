// Golden-vector harness: links the ORIGINAL udp2raw C++ sources (built with -DUDP2RAW_MP so it
// compiles on macOS) and exposes my_init_keys / my_encrypt / my_decrypt / gro helpers on stdin.
//
//   usage: harness <client|server> <cipher> <auth> <password> <fix_gro 0|1> [cfb_old 0|1]
//   stdin lines:
//     keys              -> prints derived keys (hex)
//     enc <hex>         -> hex(my_encrypt(bytes)) | ERR
//     dec <hex>         -> hex(my_decrypt(bytes)) | ERR
//     ecbenc <hex16>    -> aes_ecb_encrypt1 (cipher_key_encrypt)
//     ecbdec <hex16>    -> aes_ecb_decrypt1 (cipher_key_decrypt)
//     groxor            -> hex(gro_xor[0..256])
// One key configuration per process (the C++ caches AES key schedules in statics).
#include "common.h"
#include "encrypt.h"
#include "log.h"
#include <string>
#include <iostream>

extern char normal_key[];
extern unsigned char hmac_key_encrypt[];
extern unsigned char hmac_key_decrypt[];
extern unsigned char cipher_key_encrypt[];
extern unsigned char cipher_key_decrypt[];

static std::string hex(const unsigned char *p, int n) {
    static const char *d = "0123456789abcdef";
    std::string s;
    for (int i = 0; i < n; i++) { s += d[p[i] >> 4]; s += d[p[i] & 15]; }
    return s;
}
static int unhex(const std::string &h, char *out) {
    int n = 0;
    for (size_t i = 0; i + 1 < h.size(); i += 2) {
        auto v = [](char c) { return c <= '9' ? c - '0' : (c | 32) - 'a' + 10; };
        out[n++] = (char)((v(h[i]) << 4) | v(h[i + 1]));
    }
    return n;
}
int main(int argc, char **argv) {
    if (argc < 6) { fprintf(stderr, "bad args\n"); return 2; }
    log_level = 0;
    enable_log_color = 0;
    int is_client = std::string(argv[1]) == "client";
    std::string c = argv[2], a = argv[3];
    if (c == "none") cipher_mode = cipher_none; else if (c == "xor") cipher_mode = cipher_xor;
    else if (c == "aes128cbc") cipher_mode = cipher_aes128cbc; else if (c == "aes128cfb") cipher_mode = cipher_aes128cfb;
    else { fprintf(stderr, "bad cipher\n"); return 2; }
    if (a == "none") auth_mode = auth_none; else if (a == "md5") auth_mode = auth_md5; else if (a == "crc32") auth_mode = auth_crc32;
    else if (a == "simple") auth_mode = auth_simple; else if (a == "hmac_sha1") auth_mode = auth_hmac_sha1;
    else { fprintf(stderr, "bad auth\n"); return 2; }
    g_fix_gro = atoi(argv[5]);
    if (argc >= 7) aes128cfb_old = atoi(argv[6]);
    my_init_keys(argv[4], is_client);
    std::string line;
    static char in[70000], out[70000];
    while (std::getline(std::cin, line)) {
        size_t sp = line.find(' ');
        std::string cmd = line.substr(0, sp), arg = sp == std::string::npos ? "" : line.substr(sp + 1);
        if (cmd == "keys") {
            printf("normal_key %s\n", hex((unsigned char *)normal_key, 16).c_str());
            printf("cipher_key_encrypt %s\n", hex(cipher_key_encrypt, 64).c_str());
            printf("cipher_key_decrypt %s\n", hex(cipher_key_decrypt, 64).c_str());
            printf("hmac_key_encrypt %s\n", hex(hmac_key_encrypt, 64).c_str());
            printf("hmac_key_decrypt %s\n", hex(hmac_key_decrypt, 64).c_str());
        } else if (cmd == "groxor") {
            printf("%s\n", hex((unsigned char *)gro_xor, 256).c_str());
        } else if (cmd == "enc" || cmd == "dec") {
            int len = unhex(arg, in);
            int r = cmd == "enc" ? my_encrypt(in, out, len) : my_decrypt(in, out, len);
            if (r != 0) printf("ERR\n"); else printf("%s\n", hex((unsigned char *)out, len).c_str());
        } else if (cmd == "ecbenc" || cmd == "ecbdec") {
            unhex(arg, in);
            if (cmd == "ecbenc") aes_ecb_encrypt1(in); else aes_ecb_decrypt1(in);
            printf("%s\n", hex((unsigned char *)in, 16).c_str());
        } else {
            printf("ERR\n");
        }
        fflush(stdout);
    }
    return 0;
}
