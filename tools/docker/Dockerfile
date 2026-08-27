# Linux build + end-to-end test environment (arm64 or amd64).
#   docker build -t udp2raw-rust-dev tools/docker
#   docker run --rm -it --cap-add NET_RAW --cap-add NET_ADMIN \
#       -v "$PWD":/work -v /path/to/udp2raw-cpp:/cpp udp2raw-rust-dev tools/docker/e2e.sh
FROM rust:1-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
        g++ make libpcap-dev iptables iproute2 tcpdump procps python3 ca-certificates iperf3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /work
