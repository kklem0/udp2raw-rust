#!/usr/bin/env bash
set -Eeuo pipefail

umask 022

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
dockerfile_rel=tools/release/Dockerfile.arm64-static
target_triple=aarch64-unknown-linux-musl

die() {
    printf 'release-arm64: %s\n' "$*" >&2
    exit 1
}

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

require_clean_commit() {
    local expected_commit=$1 current_commit worktree_state
    current_commit="$(git -C "$repo_dir" rev-parse --verify 'HEAD^{commit}')" ||
        die "cannot resolve HEAD"
    test "$current_commit" = "$expected_commit" ||
        die "HEAD changed during the release (expected $expected_commit, found $current_commit)"
    worktree_state="$(git -C "$repo_dir" status --porcelain=v1 \
        --untracked-files=all --ignore-submodules=none)" ||
        die "cannot inspect the source worktree"
    test -z "$worktree_state" ||
        die "the source worktree must exactly match HEAD; commit the reviewed source first"
}

command -v docker >/dev/null 2>&1 || die "docker is required"
command -v git >/dev/null 2>&1 || die "git is required"
command -v tar >/dev/null 2>&1 || die "tar is required"
command -v mktemp >/dev/null 2>&1 || die "mktemp is required"

commit="$(git -C "$repo_dir" rev-parse --verify 'HEAD^{commit}')" || die "cannot resolve HEAD"
require_clean_commit "$commit"
tree="$(git -C "$repo_dir" rev-parse "${commit}^{tree}")"
short_commit="$(git -C "$repo_dir" rev-parse --short=12 "$commit")"
source_date_epoch="$(git -C "$repo_dir" show -s --format=%ct "$commit")"
output_arg="${1:-$repo_dir/dist}"
artifact_name="udp2raw-${short_commit}-arm64-static"
attestation_name="${artifact_name}.attestation.txt"
bundle_name="${artifact_name}.release"
builder_tag="udp2raw-rust-arm64-builder:${short_commit}"
container_user="$(id -u):$(id -g)"

release_tmp="$(mktemp -d "${TMPDIR:-/tmp}/udp2raw-arm64-release.XXXXXXXX")"
publish_stage=
publish_lock=
publish_lock_owned=0
cleanup() {
    if test -n "${publish_stage:-}" && test -d "$publish_stage"; then
        case "${publish_stage##*/}" in
            ".${bundle_name}.staging."*) rm -rf -- "$publish_stage" ;;
        esac
    fi
    if test "${publish_lock_owned:-0}" = 1 && test -n "${publish_lock:-}" &&
        test -d "$publish_lock"; then
        rmdir -- "$publish_lock" 2>/dev/null || true
    fi
    case "$release_tmp" in
        "${TMPDIR:-/tmp}"/udp2raw-arm64-release.*) rm -rf -- "$release_tmp" ;;
    esac
}
trap cleanup EXIT

mkdir -p "$release_tmp/src" "$release_tmp/cargo-seed" \
    "$release_tmp/cargo-a" "$release_tmp/cargo-b" \
    "$release_tmp/target-a" "$release_tmp/target-b" "$release_tmp/verify"
git -C "$repo_dir" archive --format=tar "$commit" | tar -xf - -C "$release_tmp/src"
require_clean_commit "$commit"

snapshot_dockerfile="$release_tmp/src/$dockerfile_rel"
snapshot_lockfile="$release_tmp/src/Cargo.lock"
test -r "$snapshot_dockerfile" || die "commit $commit does not contain $dockerfile_rel"
test -r "$snapshot_lockfile" || die "commit $commit does not contain Cargo.lock"
from_count="$(awk '/^FROM[[:space:]]/ { count++ } END { print count + 0 }' \
    "$snapshot_dockerfile")"
test "$from_count" = 1 || die "$dockerfile_rel must contain exactly one FROM instruction"
base_image="$(awk '/^FROM[[:space:]]/ { print $2 }' "$snapshot_dockerfile")"
if [[ ! "$base_image" =~ ^[^[:space:]]+@sha256:[0-9a-f]{64}$ ]]; then
    die "$dockerfile_rel must pin its base image by sha256 manifest digest"
fi
lock_sha256="$(sha256_file "$snapshot_lockfile")"
dockerfile_sha256="$(sha256_file "$snapshot_dockerfile")"

printf '== build pinned linux/arm64 builder from commit snapshot\n'
docker buildx build --load --platform linux/arm64 \
    --file "$snapshot_dockerfile" --tag "$builder_tag" "$release_tmp/src"
builder_image_id="$(docker image inspect --format '{{.Id}}' "$builder_tag")"
if [[ ! "$builder_image_id" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    die "docker returned an invalid builder image ID: $builder_image_id"
fi
builder_platform="$(docker image inspect --format '{{.Os}}/{{.Architecture}}' \
    "$builder_image_id")"
test "$builder_platform" = linux/arm64 ||
    die "builder image has platform $builder_platform, expected linux/arm64"

printf '== fetch locked dependencies into the seed cache\n'
docker run --rm --platform linux/arm64 --read-only \
    --tmpfs /tmp:rw,nosuid,nodev \
    --user "$container_user" \
    --env HOME=/tmp \
    --env CARGO_HOME=/cargo \
    --env CARGO_TARGET_DIR=/tmp/target \
    --volume "$release_tmp/src:/src:ro" \
    --volume "$release_tmp/cargo-seed:/cargo" \
    "$builder_image_id" \
    cargo fetch --locked --target "$target_triple"

cp -a "$release_tmp/cargo-seed/." "$release_tmp/cargo-a/"
cp -a "$release_tmp/cargo-seed/." "$release_tmp/cargo-b/"

build_once() {
    local label=$1 cargo_home=$2 target_dir=$3
    printf '== offline build %s\n' "$label"
    docker run --rm --platform linux/arm64 --network none --read-only \
        --tmpfs /tmp:rw,nosuid,nodev \
        --user "$container_user" \
        --env HOME=/tmp \
        --env CARGO_HOME=/cargo \
        --env CARGO_TARGET_DIR=/target \
        --env CARGO_INCREMENTAL=0 \
        --env SOURCE_DATE_EPOCH="$source_date_epoch" \
        --env RUSTFLAGS="--remap-path-prefix=/src=." \
        --volume "$release_tmp/src:/src:ro" \
        --volume "$cargo_home:/cargo" \
        --volume "$target_dir:/target" \
        "$builder_image_id" \
        cargo build --release --locked --offline --target "$target_triple"
}

build_once A "$release_tmp/cargo-a" "$release_tmp/target-a"
build_once B "$release_tmp/cargo-b" "$release_tmp/target-b"

binary_a="$release_tmp/target-a/$target_triple/release/udp2raw"
binary_b="$release_tmp/target-b/$target_triple/release/udp2raw"
test -x "$binary_a" || die "build A did not produce $binary_a"
test -x "$binary_b" || die "build B did not produce $binary_b"
sha_a="$(sha256_file "$binary_a")"
sha_b="$(sha256_file "$binary_b")"
test "$sha_a" = "$sha_b" ||
    die "reproducibility failure: build A $sha_a, build B $sha_b"

cp "$binary_a" "$release_tmp/verify/udp2raw"
chmod 0755 "$release_tmp/verify/udp2raw"

printf '== verify ELF and built-in unit tests\n'
docker run --rm --platform linux/arm64 --network none --read-only \
    --tmpfs /tmp:rw,nosuid,nodev \
    --user "$container_user" \
    --env HOME=/tmp \
    --volume "$release_tmp/verify:/artifact:ro" \
    "$builder_image_id" bash -o pipefail -ceu '
        file /artifact/udp2raw
        readelf -h /artifact/udp2raw > /tmp/elf-header
        grep -Eq "Class:[[:space:]]+ELF64" /tmp/elf-header
        grep -Eq "Machine:[[:space:]]+AArch64" /tmp/elf-header
        readelf -l /artifact/udp2raw > /tmp/program-headers
        if grep -q INTERP /tmp/program-headers; then
            echo "unexpected ELF interpreter" >&2
            exit 1
        fi
        readelf -d /artifact/udp2raw > /tmp/dynamic-section 2>&1
        if grep -q NEEDED /tmp/dynamic-section; then
            echo "unexpected dynamic dependency" >&2
            exit 1
        fi
        /artifact/udp2raw --unit-test
    '

tool_versions="$(docker run --rm --platform linux/arm64 --network none --read-only \
    --tmpfs /tmp:rw,nosuid,nodev \
    --user "$container_user" \
    --env HOME=/tmp \
    --env TARGET_TRIPLE="$target_triple" \
    "$builder_image_id" bash -o pipefail -ceu '
        rustc -vV
        cargo -V
        cc --version | sed -n "1p"
        readelf --version | sed -n "1p"
        rustc --print target-libdir --target "$TARGET_TRIPLE"
    ')"

# Building from the immutable archive makes later edits unable to affect the artifact. Requiring
# the same clean commit again prevents a release from being published while its reviewed source
# has changed underneath the operator.
require_clean_commit "$commit"

mkdir -p -- "$output_arg"
output_dir="$(cd "$output_arg" && pwd -P)"
bundle_dir="$output_dir/$bundle_name"
publish_lock="$output_dir/.${bundle_name}.publish.lock"
if ! mkdir -- "$publish_lock"; then
    die "another publication holds $publish_lock; inspect it before removing a stale lock"
fi
publish_lock_owned=1
if test -e "$bundle_dir" || test -L "$bundle_dir"; then
    die "refusing to overwrite existing release bundle $bundle_dir"
fi

# Staging is on the output filesystem, so the final directory rename is atomic during ordinary
# process execution. A normal failure removes it via the EXIT trap; a process crash or interruption
# can leave only a hidden staging directory and lock, not a final partial bundle. This does not
# claim sudden-power-loss durability because the release files and directory are not explicitly
# synchronized with fsync.
publish_stage="$(mktemp -d "$output_dir/.${bundle_name}.staging.XXXXXXXX")"
install -m 0755 "$binary_a" "$publish_stage/$artifact_name"
published_sha256="$(sha256_file "$publish_stage/$artifact_name")"
test "$published_sha256" = "$sha_a" ||
    die "staged artifact hash $published_sha256 differs from verified build hash $sha_a"
artifact_size="$(wc -c < "$publish_stage/$artifact_name" | tr -d ' ')"

cat > "$publish_stage/$attestation_name" <<EOF
format=udp2raw-rust-arm64-attestation-v2
source_snapshot=git-archive
source_commit=$commit
source_tree=$tree
source_date_epoch=$source_date_epoch
cargo_lock_sha256=$lock_sha256
builder_base=$base_image
builder_dockerfile_sha256=$dockerfile_sha256
builder_image_id=$builder_image_id
builder_platform=$builder_platform
target=$target_triple
build_command=cargo build --release --locked --offline --target $target_triple
build_network=none
cargo_incremental=0
rustflags=--remap-path-prefix=/src=.
double_build_sha256=$sha_a
artifact_sha256=$published_sha256
artifact_name=$artifact_name
artifact_size=$artifact_size
bundle_name=$bundle_name
elf_class=ELF64
elf_machine=AArch64
elf_interpreter=none
elf_needed=none
unit_test=passed
tool_versions_begin
$tool_versions
tool_versions_end
EOF
chmod 0644 "$publish_stage/$attestation_name"
attestation_sha256="$(sha256_file "$publish_stage/$attestation_name")"
printf '%s  %s\n%s  %s\n' \
    "$published_sha256" "$artifact_name" \
    "$attestation_sha256" "$attestation_name" \
    > "$publish_stage/SHA256SUMS"
chmod 0644 "$publish_stage/SHA256SUMS"
chmod 0755 "$publish_stage"
checksums_sha256="$(sha256_file "$publish_stage/SHA256SUMS")"

# Re-read both staged files after the manifest is complete. This detects destination corruption
# before the single atomic publication point.
test "$(sha256_file "$publish_stage/$artifact_name")" = "$published_sha256" ||
    die "staged artifact changed before publication"
test "$(sha256_file "$publish_stage/$attestation_name")" = "$attestation_sha256" ||
    die "staged attestation changed before publication"

stage_basename="${publish_stage##*/}"
mv -- "$publish_stage" "$bundle_dir"
if test -d "$bundle_dir/$stage_basename"; then
    publish_stage="$bundle_dir/$stage_basename"
    die "release destination appeared during publication; no bundle was overwritten"
fi
publish_stage=

quarantine_bundle() {
    local reason=$1 failed_dir
    failed_dir="$output_dir/.${bundle_name}.failed.${stage_basename##*.}.${BASHPID:-$$}"
    if test -e "$failed_dir" || test -L "$failed_dir"; then
        die "$reason; cannot quarantine because $failed_dir already exists"
    fi
    if mv -- "$bundle_dir" "$failed_dir"; then
        die "$reason; quarantined the non-consumable bundle at $failed_dir"
    fi
    die "$reason; failed to quarantine $bundle_dir"
}

if ! final_artifact_sha256="$(sha256_file "$bundle_dir/$artifact_name")"; then
    quarantine_bundle "published artifact could not be hashed"
fi
test "$final_artifact_sha256" = "$published_sha256" ||
    quarantine_bundle "published artifact failed its final hash check"
if ! final_attestation_sha256="$(sha256_file "$bundle_dir/$attestation_name")"; then
    quarantine_bundle "published attestation could not be hashed"
fi
test "$final_attestation_sha256" = "$attestation_sha256" ||
    quarantine_bundle "published attestation failed its final hash check"
if ! final_checksums_sha256="$(sha256_file "$bundle_dir/SHA256SUMS")"; then
    quarantine_bundle "published checksum manifest could not be hashed"
fi
test "$final_checksums_sha256" = "$checksums_sha256" ||
    quarantine_bundle "published checksum manifest failed its final hash check"
rmdir -- "$publish_lock"
publish_lock_owned=0
publish_lock=

printf 'release-arm64: bundle=%s\n' "$bundle_dir"
printf 'release-arm64: artifact=%s\n' "$bundle_dir/$artifact_name"
printf 'release-arm64: sha256=%s\n' "$published_sha256"
printf 'release-arm64: attestation=%s\n' "$bundle_dir/$attestation_name"
printf 'release-arm64: checksums=%s\n' "$bundle_dir/SHA256SUMS"
