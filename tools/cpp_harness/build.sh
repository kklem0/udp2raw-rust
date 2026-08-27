#!/bin/sh
# Build the golden-vector harness against the ORIGINAL udp2raw C++ sources.
#   tools/cpp_harness/build.sh /path/to/udp2raw    (the wangyu-/udp2raw checkout)
# Uses the multi-platform (-DUDP2RAW_MP, libpcap) build so it also compiles on macOS.
set -e
CPP="${1:?usage: build.sh /path/to/udp2raw-cpp}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/build"
mkdir -p "$OUT"
echo 'const char *gitversion = "harness";' > "$OUT/git_version.h"
CXX="${CXX:-c++}"
SRCS="lib/md5.cpp lib/pbkdf2-sha1.cpp lib/pbkdf2-sha256.cpp encrypt.cpp log.cpp network.cpp common.cpp connection.cpp misc.cpp fd_manager.cpp client.cpp server.cpp lib/aes_faster_c/aes.cpp lib/aes_faster_c/backend.cpp lib/aes_faster_c/wrapper.cpp my_ev.cpp"
OBJS=""
for f in $SRCS; do
  o="$OUT/$(echo "$f" | tr '/' '_').o"
  (cd "$CPP" && "$CXX" -std=c++11 -O2 -w -I. -I"$OUT" -isystem libev -DUDP2RAW_MP -c "$f" -o "$o")
  OBJS="$OBJS $o"
done
"$CXX" -std=c++11 -O2 -w -I"$CPP" -I"$OUT" -isystem "$CPP/libev" -DUDP2RAW_MP -c "$HERE/harness.cpp" -o "$OUT/harness.o"
"$CXX" -o "$OUT/harness" "$OUT/harness.o" $OBJS -lpcap -lpthread
echo "built $OUT/harness"
