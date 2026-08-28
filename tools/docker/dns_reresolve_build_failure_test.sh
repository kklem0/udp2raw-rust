#!/bin/bash
# Fast regression for dns_reresolve_test.sh's build gate. This intentionally runs before any
# namespace operation and therefore needs neither Linux network namespaces nor root.
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd)
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/udp2raw-dns-build-failure.XXXXXXXX")
cleanup() {
    case ${TEST_ROOT:-} in
        "${TMPDIR:-/tmp}"/udp2raw-dns-build-failure.*) rm -rf -- "$TEST_ROOT" ;;
    esac
}
trap cleanup EXIT

FAKE_BIN=$TEST_ROOT/bin
SHARED_TARGET=$TEST_ROOT/named-target-volume
mkdir -p "$FAKE_BIN" "$SHARED_TARGET/release"
CARGO_MARKER=$TEST_ROOT/cargo-called
SETUP_MARKER=$TEST_ROOT/namespace-setup-reached
STALE_MARKER=$TEST_ROOT/stale-binary-ran
OUTPUT=$TEST_ROOT/output.log

# These marker variables deliberately expand when each generated fixture runs.
# shellcheck disable=SC2016
printf '%s\n' \
    '#!/bin/sh' \
    ': > "$FAKE_CARGO_MARKER"' \
    'echo "injected compiler failure" >&2' \
    'exit 97' > "$FAKE_BIN/cargo"
chmod +x "$FAKE_BIN/cargo"

# Any attempt to reach namespace setup is a regression.
# shellcheck disable=SC2016
printf '%s\n' \
    '#!/bin/sh' \
    ': > "$FAKE_SETUP_MARKER"' \
    'exit 98' > "$FAKE_BIN/ip"
chmod +x "$FAKE_BIN/ip"

# Model the stale executable left in a named Cargo target volume. The main harness must never
# select or execute it, even though it is executable and Cargo fails.
# shellcheck disable=SC2016
printf '%s\n' \
    '#!/bin/sh' \
    ': > "$FAKE_STALE_MARKER"' \
    'exit 0' > "$SHARED_TARGET/release/udp2raw"
chmod +x "$SHARED_TARGET/release/udp2raw"

set +e
PATH="$FAKE_BIN:$PATH" \
FAKE_CARGO_MARKER=$CARGO_MARKER \
FAKE_SETUP_MARKER=$SETUP_MARKER \
FAKE_STALE_MARKER=$STALE_MARKER \
DNS_RERESOLVE_WORKDIR=$REPO_ROOT \
CARGO_TARGET_DIR=$SHARED_TARGET \
bash "$SCRIPT_DIR/dns_reresolve_test.sh" > "$OUTPUT" 2>&1
status=$?
set -e

if [ "$status" -eq 0 ]; then
    echo "FAIL: injected Cargo failure returned success" >&2
    cat "$OUTPUT" >&2
    exit 1
fi
[ -e "$CARGO_MARKER" ] || { echo "FAIL: fake Cargo was not invoked" >&2; exit 1; }
[ ! -e "$SETUP_MARKER" ] || { echo "FAIL: namespace setup ran after the failed build" >&2; exit 1; }
[ ! -e "$STALE_MARKER" ] || { echo "FAIL: stale named-volume binary was executed" >&2; exit 1; }
[ -x "$SHARED_TARGET/release/udp2raw" ] || { echo "FAIL: stale fixture was unexpectedly removed" >&2; exit 1; }
grep -q "cargo build failed; namespace setup was not started" "$OUTPUT" || {
    echo "FAIL: harness did not report the build gate" >&2
    cat "$OUTPUT" >&2
    exit 1
}
if grep -q '^== setup$' "$OUTPUT"; then
    echo "FAIL: harness reached namespace setup output" >&2
    cat "$OUTPUT" >&2
    exit 1
fi

echo "PASS: failed fresh build stopped before namespace setup and ignored stale artifact"
