#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

test_fail() {
    printf 'release-arm64-test: %s\n' "$*" >&2
    exit 1
}

array_has() {
    local wanted=$1 item
    shift
    for item in "$@"; do
        test "$item" = "$wanted" && return 0
    done
    return 1
}

volume_source() {
    local wanted=$1 volume source destination _ignored
    shift
    for volume in "$@"; do
        IFS=: read -r source destination _ignored <<< "$volume"
        if test "$destination" = "$wanted"; then
            printf '%s\n' "$source"
            return 0
        fi
    done
    return 1
}

fake_docker_run() {
    local user_arg='' network_arg='' image='' target_volume='' cargo_volume='' has_read_only=0
    # Bash 3.2 with nounset treats expansion of an empty array as an unset variable. A harmless
    # empty sentinel keeps the fake runtime portable to the system Bash shipped by macOS.
    local -a volumes=('') container_env=('') command_args=()
    while (($#)); do
        case "$1" in
            --rm) shift ;;
            --read-only) has_read_only=1; shift ;;
            --platform|--tmpfs) shift 2 ;;
            --network) network_arg=$2; shift 2 ;;
            --user) user_arg=$2; shift 2 ;;
            --env) container_env+=("$2"); shift 2 ;;
            --volume) volumes+=("$2"); shift 2 ;;
            --*) test_fail "fake docker does not understand run option $1" ;;
            *)
                image=$1
                shift
                command_args=("$@")
                break
                ;;
        esac
    done

    test "$image" = "$UDP2RAW_RELEASE_TEST_IMAGE_ID" ||
        test_fail "container run used mutable image reference $image"
    test "$has_read_only" = 1 || test_fail "container run lacks --read-only"
    test "$user_arg" = "$UDP2RAW_RELEASE_TEST_EXPECTED_USER" ||
        test_fail "container run lacks the invoking uid/gid"
    array_has HOME=/tmp "${container_env[@]}" || test_fail "container HOME is not writable tmpfs"
    test "${#command_args[@]}" -gt 0 || test_fail "container run lacks a command"

    case "${command_args[0]}:${command_args[1]:-}" in
        cargo:fetch)
            array_has CARGO_HOME=/cargo "${container_env[@]}" ||
                test_fail "fetch lacks its writable Cargo home"
            cargo_volume="$(volume_source /cargo "${volumes[@]}")" ||
                test_fail "fetch lacks the Cargo cache mount"
            printf 'locked dependency cache\n' > "$cargo_volume/fetched"
            ;;
        cargo:build)
            test "$network_arg" = none || test_fail "release build is not offline"
            target_volume="$(volume_source /target "${volumes[@]}")" ||
                test_fail "build lacks its target mount"
            mkdir -p "$target_volume/aarch64-unknown-linux-musl/release"
            printf '#!/bin/sh\nprintf "fake udp2raw\\n"\n' \
                > "$target_volume/aarch64-unknown-linux-musl/release/udp2raw"
            chmod 0755 "$target_volume/aarch64-unknown-linux-musl/release/udp2raw"
            ;;
        bash:*)
            test "$network_arg" = none || test_fail "verification/tool run is not offline"
            if volume_source /artifact "${volumes[@]}" >/dev/null 2>&1; then
                test "${UDP2RAW_RELEASE_TEST_FAIL_PHASE:-}" != verify || return 79
            else
                printf '%s\n' \
                    'rustc 1.85.1 (fixture)' \
                    'cargo 1.85.1 (fixture)' \
                    'cc (fixture) 1.0' \
                    'GNU readelf (fixture) 1.0' \
                    '/rustlib/aarch64-unknown-linux-musl/lib'
            fi
            ;;
        *) test_fail "unexpected container command ${command_args[*]}" ;;
    esac
}

fake_docker() {
    printf '%q ' "$@" >> "$UDP2RAW_RELEASE_TEST_DOCKER_LOG"
    printf '\n' >> "$UDP2RAW_RELEASE_TEST_DOCKER_LOG"
    case "${1:-}:${2:-}" in
        buildx:build)
            local snapshot_dockerfile='' arg
            shift 2
            while (($#)); do
                arg=$1
                shift
                if test "$arg" = --file; then
                    snapshot_dockerfile=$1
                    shift
                fi
            done
            test -n "$snapshot_dockerfile" || test_fail "build lacks --file"
            test "$snapshot_dockerfile" != "$UDP2RAW_RELEASE_TEST_LIVE_DOCKERFILE" ||
                test_fail "builder read the live Dockerfile"
            case "$snapshot_dockerfile" in
                */udp2raw-arm64-release.*/src/tools/release/Dockerfile.arm64-static) ;;
                *) test_fail "builder did not use the immutable commit snapshot" ;;
            esac
            ! grep -Eq '^[[:space:]]*#[[:space:]]*syntax=' "$snapshot_dockerfile" ||
                test_fail "Dockerfile uses a remote syntax frontend"
            grep -Eq '^FROM[[:space:]]+[^[:space:]]+@sha256:[0-9a-f]{64}$' \
                "$snapshot_dockerfile" || test_fail "base image is not digest-pinned"
            ;;
        image:inspect)
            local inspect_format=
            shift 2
            while (($#)); do
                case "$1" in
                    --format) inspect_format=$2; shift 2 ;;
                    *) shift ;;
                esac
            done
            case "$inspect_format" in
                '{{.Id}}') printf '%s\n' "$UDP2RAW_RELEASE_TEST_IMAGE_ID" ;;
                '{{.Os}}/{{.Architecture}}') printf 'linux/arm64\n' ;;
                *) test_fail "unexpected image inspect format $inspect_format" ;;
            esac
            ;;
        run:*)
            shift
            fake_docker_run "$@"
            ;;
        *) test_fail "unexpected docker command $*" ;;
    esac
}

fake_sha256sum() {
    local file=${1:?}
    if test "${UDP2RAW_RELEASE_TEST_CORRUPT_FINAL:-0}" = 1; then
        case "$file" in
            "$UDP2RAW_RELEASE_TEST_CORRUPT_BUNDLE"/udp2raw-*-arm64-static)
                if test ! -e "$UDP2RAW_RELEASE_TEST_CORRUPT_MARKER"; then
                    printf 'post-rename corruption\n' >> "$file"
                    : > "$UDP2RAW_RELEASE_TEST_CORRUPT_MARKER"
                fi
                ;;
        esac
    fi
    case "$UDP2RAW_RELEASE_TEST_REAL_SHA_MODE" in
        sha256sum) "$UDP2RAW_RELEASE_TEST_REAL_SHA_TOOL" "$file" ;;
        shasum) "$UDP2RAW_RELEASE_TEST_REAL_SHA_TOOL" -a 256 "$file" ;;
        *) test_fail "unknown real SHA-256 mode" ;;
    esac
}

case "${0##*/}" in
    docker)
        test "${UDP2RAW_RELEASE_TEST_FAKE_TOOLS:-0}" = 1 || test_fail "fake docker not enabled"
        fake_docker "$@"
        exit
        ;;
    sha256sum)
        test "${UDP2RAW_RELEASE_TEST_FAKE_TOOLS:-0}" = 1 || test_fail "fake sha256sum not enabled"
        fake_sha256sum "$@"
        exit
        ;;
esac

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source_root="$(cd "$script_dir/../.." && pwd -P)"
test_tmp="$(mktemp -d "${TMPDIR:-/tmp}/udp2raw-release-test.XXXXXXXX")"
cleanup_test() {
    case "$test_tmp" in
        "${TMPDIR:-/tmp}"/udp2raw-release-test.*) rm -rf -- "$test_tmp" ;;
    esac
}
trap cleanup_test EXIT

if command -v sha256sum >/dev/null 2>&1; then
    real_sha_tool="$(command -v sha256sum)"
    real_sha_mode=sha256sum
else
    real_sha_tool="$(command -v shasum)"
    real_sha_mode=shasum
fi

fixture_repo="$test_tmp/repo"
fake_bin="$test_tmp/bin"
docker_log="$test_tmp/docker.log"
mkdir -p "$fixture_repo/tools/release" "$fake_bin"
cp "$script_dir/build_arm64_static.sh" "$fixture_repo/tools/release/"
cp "$script_dir/Dockerfile.arm64-static" "$fixture_repo/tools/release/"
cp "$source_root/.dockerignore" "$fixture_repo/"
printf '# fixture lockfile\nversion = 4\n' > "$fixture_repo/Cargo.lock"
chmod 0755 "$fixture_repo/tools/release/build_arm64_static.sh"
git -C "$fixture_repo" init -q
git -C "$fixture_repo" config user.name release-test
git -C "$fixture_repo" config user.email release-test.invalid
git -C "$fixture_repo" config commit.gpgsign false
git -C "$fixture_repo" add .
git -C "$fixture_repo" commit -q -m fixture

ln -s "$script_dir/build_arm64_static_test.sh" "$fake_bin/docker"
ln -s "$script_dir/build_arm64_static_test.sh" "$fake_bin/sha256sum"

fixture_commit="$(git -C "$fixture_repo" rev-parse HEAD)"
fixture_tree="$(git -C "$fixture_repo" rev-parse 'HEAD^{tree}')"
fixture_short="$(git -C "$fixture_repo" rev-parse --short=12 HEAD)"
artifact_name="udp2raw-${fixture_short}-arm64-static"
attestation_name="${artifact_name}.attestation.txt"
bundle_name="${artifact_name}.release"
fake_image_id="sha256:1111111111111111111111111111111111111111111111111111111111111111"

run_fixture() {
    env \
        PATH="$fake_bin:$PATH" \
        UDP2RAW_RELEASE_TEST_FAKE_TOOLS=1 \
        UDP2RAW_RELEASE_TEST_IMAGE_ID="$fake_image_id" \
        UDP2RAW_RELEASE_TEST_EXPECTED_USER="$(id -u):$(id -g)" \
        UDP2RAW_RELEASE_TEST_DOCKER_LOG="$docker_log" \
        UDP2RAW_RELEASE_TEST_LIVE_DOCKERFILE="$fixture_repo/tools/release/Dockerfile.arm64-static" \
        UDP2RAW_RELEASE_TEST_REAL_SHA_TOOL="$real_sha_tool" \
        UDP2RAW_RELEASE_TEST_REAL_SHA_MODE="$real_sha_mode" \
        UDP2RAW_RELEASE_TEST_FAIL_PHASE="${UDP2RAW_RELEASE_TEST_FAIL_PHASE:-}" \
        UDP2RAW_RELEASE_TEST_CORRUPT_FINAL="${UDP2RAW_RELEASE_TEST_CORRUPT_FINAL:-0}" \
        UDP2RAW_RELEASE_TEST_CORRUPT_BUNDLE="${UDP2RAW_RELEASE_TEST_CORRUPT_BUNDLE:-}" \
        UDP2RAW_RELEASE_TEST_CORRUPT_MARKER="${UDP2RAW_RELEASE_TEST_CORRUPT_MARKER:-}" \
        "$fixture_repo/tools/release/build_arm64_static.sh" "$1"
}

real_sha_file() {
    case "$real_sha_mode" in
        sha256sum) "$real_sha_tool" "$1" | awk '{print $1}' ;;
        shasum) "$real_sha_tool" -a 256 "$1" | awk '{print $1}' ;;
    esac
}

output_dir="$test_tmp/out"
run_fixture "$output_dir" > "$test_tmp/success.out"
bundle_dir="$output_dir/$bundle_name"
artifact="$bundle_dir/$artifact_name"
attestation="$bundle_dir/$attestation_name"
test -x "$artifact" || test_fail "successful run lacks its artifact"
test -f "$attestation" || test_fail "successful run lacks its attestation"
test -f "$bundle_dir/SHA256SUMS" || test_fail "successful run lacks SHA256SUMS"
grep -Fx "format=udp2raw-rust-arm64-attestation-v2" "$attestation" >/dev/null
grep -Fx "source_commit=$fixture_commit" "$attestation" >/dev/null
grep -Fx "source_tree=$fixture_tree" "$attestation" >/dev/null
grep -Fx "builder_image_id=$fake_image_id" "$attestation" >/dev/null
grep -Fx "builder_platform=linux/arm64" "$attestation" >/dev/null
grep -Fx "artifact_sha256=$(real_sha_file "$artifact")" "$attestation" >/dev/null
while read -r expected_hash filename; do
    test "$(real_sha_file "$bundle_dir/$filename")" = "$expected_hash" ||
        test_fail "checksum mismatch for $filename"
done < "$bundle_dir/SHA256SUMS"
test -z "$(find "$output_dir" -maxdepth 1 \
    \( -name '.*.staging.*' -o -name '.*.publish.lock' \) -print)" ||
    test_fail "successful publication left staging or lock state"

# A rebuild of the same commit must not alter an already consumable bundle.
artifact_before="$(real_sha_file "$artifact")"
attestation_before="$(real_sha_file "$attestation")"
if run_fixture "$output_dir" > "$test_tmp/no-clobber.out" 2>&1; then
    test_fail "second publication unexpectedly overwrote the bundle"
fi
test "$(real_sha_file "$artifact")" = "$artifact_before" || test_fail "artifact was overwritten"
test "$(real_sha_file "$attestation")" = "$attestation_before" ||
    test_fail "attestation was overwritten"

# Dirty source must be rejected before Docker is invoked.
docker_lines_before="$(wc -l < "$docker_log" | tr -d ' ')"
printf 'untracked\n' > "$fixture_repo/untracked-source"
if run_fixture "$test_tmp/out-dirty" > "$test_tmp/dirty.out" 2>&1; then
    test_fail "dirty source was accepted"
fi
docker_lines_after="$(wc -l < "$docker_log" | tr -d ' ')"
test "$docker_lines_before" = "$docker_lines_after" || test_fail "dirty build invoked Docker"
rm -- "$fixture_repo/untracked-source"

# A pre-publication verification failure must leave no consumable final bundle.
UDP2RAW_RELEASE_TEST_FAIL_PHASE=verify
export UDP2RAW_RELEASE_TEST_FAIL_PHASE
if run_fixture "$test_tmp/out-verify-fail" > "$test_tmp/verify-fail.out" 2>&1; then
    test_fail "injected verification failure unexpectedly succeeded"
fi
unset UDP2RAW_RELEASE_TEST_FAIL_PHASE
test ! -e "$test_tmp/out-verify-fail/$bundle_name" ||
    test_fail "verification failure left a consumable bundle"

# Corrupt the artifact on the first post-rename hash. The script must move the whole bundle back
# under a hidden failed name before it exits.
corrupt_output="$test_tmp/out-corrupt"
mkdir -p "$corrupt_output"
corrupt_output="$(cd "$corrupt_output" && pwd -P)"
corrupt_bundle="$corrupt_output/$bundle_name"
UDP2RAW_RELEASE_TEST_CORRUPT_FINAL=1
UDP2RAW_RELEASE_TEST_CORRUPT_BUNDLE="$corrupt_bundle"
UDP2RAW_RELEASE_TEST_CORRUPT_MARKER="$test_tmp/corrupted"
export UDP2RAW_RELEASE_TEST_CORRUPT_FINAL UDP2RAW_RELEASE_TEST_CORRUPT_BUNDLE
export UDP2RAW_RELEASE_TEST_CORRUPT_MARKER
if run_fixture "$corrupt_output" > "$test_tmp/corrupt.out" 2>&1; then
    test_fail "post-rename corruption unexpectedly succeeded"
fi
unset UDP2RAW_RELEASE_TEST_CORRUPT_FINAL UDP2RAW_RELEASE_TEST_CORRUPT_BUNDLE
unset UDP2RAW_RELEASE_TEST_CORRUPT_MARKER
test ! -e "$corrupt_bundle" || test_fail "corrupt final bundle remained consumable"
failed_count="$(find "$corrupt_output" -maxdepth 1 -type d \
    -name ".${bundle_name}.failed.*" | wc -l | tr -d ' ')"
test "$failed_count" = 1 || test_fail "corrupt bundle was not quarantined exactly once"
test ! -e "$corrupt_output/.${bundle_name}.publish.lock" ||
    test_fail "corrupt publication left its lock"

printf 'release-arm64-test: all checks passed\n'
