// udpbench.c — low-overhead UDP traffic generator and sink (sendmmsg / recvmmsg), so the
// load generator does not steal the CPU we are trying to measure.
//
//   udpbench blast <host> <port> <seconds> <size> [max_pps]
//   udpbench sink  <bind_ip> <port> <seconds>
//
// The sink prints one line per second ("t=<n> pps=<n>") and a final summary.
// Build: gcc -O2 -o udpbench udpbench.c
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define BATCH 64
#define MAXPKT 65536

static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static int make_addr(const char *ip, int port, struct sockaddr_storage *ss, socklen_t *len) {
    memset(ss, 0, sizeof(*ss));
    if (strchr(ip, ':')) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)ss;
        a->sin6_family = AF_INET6;
        a->sin6_port = htons(port);
        if (inet_pton(AF_INET6, ip, &a->sin6_addr) != 1) return -1;
        *len = sizeof(*a);
        return AF_INET6;
    }
    struct sockaddr_in *a = (struct sockaddr_in *)ss;
    a->sin_family = AF_INET;
    a->sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &a->sin_addr) != 1) return -1;
    *len = sizeof(*a);
    return AF_INET;
}

static void set_buf(int fd, int opt, int opt_force, int size) {
    if (setsockopt(fd, SOL_SOCKET, opt_force, &size, sizeof(size)) != 0)
        setsockopt(fd, SOL_SOCKET, opt, &size, sizeof(size));
}

static int blast(int argc, char **argv) {
    if (argc < 6) return 2;
    const char *host = argv[2];
    int port = atoi(argv[3]);
    double seconds = atof(argv[4]);
    int size = atoi(argv[5]);
    long max_pps = argc > 6 ? atol(argv[6]) : 0;
    struct sockaddr_storage ss;
    socklen_t slen;
    int fam = make_addr(host, port, &ss, &slen);
    if (fam < 0) { fprintf(stderr, "bad address\n"); return 2; }
    int fd = socket(fam, SOCK_DGRAM, 0);
    set_buf(fd, SO_SNDBUF, SO_SNDBUFFORCE, 16 << 20);
    if (connect(fd, (struct sockaddr *)&ss, slen) != 0) { perror("connect"); return 1; }
    static unsigned char payload[MAXPKT];
    for (int i = 0; i < size; i++) payload[i] = (unsigned char)(rand() & 0xff);
    struct mmsghdr msgs[BATCH];
    struct iovec iov[BATCH];
    memset(msgs, 0, sizeof(msgs));
    for (int i = 0; i < BATCH; i++) {
        iov[i].iov_base = payload;
        iov[i].iov_len = size;
        msgs[i].msg_hdr.msg_iov = &iov[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }
    double t0 = now(), deadline = t0 + seconds;
    long sent = 0, eagain = 0;
    while (1) {
        double t = now();
        if (t >= deadline) break;
        if (max_pps > 0) {
            long allowed = (long)((t - t0) * max_pps) - sent;
            if (allowed < BATCH) { usleep(50); continue; }
        }
        int n = sendmmsg(fd, msgs, BATCH, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == ENOBUFS || errno == EINTR) { eagain++; usleep(100); continue; }
            perror("sendmmsg");
            break;
        }
        sent += n;
    }
    double dur = now() - t0;
    printf("blast: packets=%ld size=%d duration=%.2fs pps=%.0f mbps=%.1f enobufs=%ld\n", sent, size, dur, sent / dur, sent * (double)size * 8 / dur / 1e6, eagain);
    return 0;
}

static int sink(int argc, char **argv) {
    if (argc < 5) return 2;
    const char *ip = argv[2];
    int port = atoi(argv[3]);
    double seconds = atof(argv[4]);
    struct sockaddr_storage ss;
    socklen_t slen;
    int fam = make_addr(ip, port, &ss, &slen);
    if (fam < 0) { fprintf(stderr, "bad address\n"); return 2; }
    int fd = socket(fam, SOCK_DGRAM, 0);
    set_buf(fd, SO_RCVBUF, SO_RCVBUFFORCE, 32 << 20);
    if (bind(fd, (struct sockaddr *)&ss, slen) != 0) { perror("bind"); return 1; }
    struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    static unsigned char bufs[BATCH][2048];
    struct mmsghdr msgs[BATCH];
    struct iovec iov[BATCH];
    memset(msgs, 0, sizeof(msgs));
    for (int i = 0; i < BATCH; i++) {
        iov[i].iov_base = bufs[i];
        iov[i].iov_len = sizeof(bufs[i]);
        msgs[i].msg_hdr.msg_iov = &iov[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }
    double t0 = now(), deadline = t0 + seconds, next_report = t0 + 1.0;
    long total = 0, bytes = 0, sec_pkts = 0, sec = 0;
    double first = 0, last = 0;
    while (1) {
        double t = now();
        if (t >= deadline) break;
        if (t >= next_report) {
            sec++;
            printf("t=%ld pps=%ld\n", sec, sec_pkts);
            fflush(stdout);
            sec_pkts = 0;
            next_report += 1.0;
        }
        int n = recvmmsg(fd, msgs, BATCH, 0, NULL);
        if (n <= 0) continue;
        t = now();
        if (first == 0) first = t;
        last = t;
        total += n;
        sec_pkts += n;
        for (int i = 0; i < n; i++) bytes += msgs[i].msg_len;
    }
    double active = last > first ? last - first : 1e-9;
    printf("sink: packets=%ld bytes=%ld active=%.2fs pps=%.0f mbps=%.1f\n", total, bytes, active, total / active, bytes * 8.0 / active / 1e6);
    return 0;
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "blast") == 0) return blast(argc, argv);
    if (argc >= 2 && strcmp(argv[1], "sink") == 0) return sink(argc, argv);
    fprintf(stderr, "usage: udpbench blast <host> <port> <seconds> <size> [max_pps]\n       udpbench sink <bind_ip> <port> <seconds>\n");
    return 2;
}
