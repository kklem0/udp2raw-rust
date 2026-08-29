# Reproducible static ARM64 release

Production Raspberry Pi deployments use one baseline AArch64 binary on both Pi 4 and Pi 5.
Do not build with `target-cpu=native` or a global `+aes`: runtime dispatch selects hardware AES
where available and the portable backend otherwise.

The release builder is pinned to Rust 1.85.1 and the immutable official
`rust:1.85.1-bookworm` multi-architecture manifest. The Dockerfile has no remotely resolved
syntax frontend. Its `linux/arm64` image installs Rust's self-contained
`aarch64-unknown-linux-musl` target without installing mutable operating-system packages. The
final compilations run offline and without a writable container root filesystem.

From a clean, reviewed commit:

```sh
tools/release/build_arm64_static.sh
```

The script:

1. resolves one commit, requires the worktree to match it before snapshot and publication, and
   archives that immutable commit rather than reading live source during the build;
2. takes the Dockerfile and `Cargo.lock` from that same archive, builds the pinned ARM64 image,
   validates its platform, and uses its captured image ID for every container run;
3. fetches the locked dependency graph as the invoking uid into a disposable seed cache;
4. performs two offline release builds in separate target and Cargo directories and requires
   identical SHA-256 digests;
5. verifies ELF64/AArch64, no `INTERP`, no `NEEDED`, and the built-in `--unit-test` result; and
6. re-hashes a staged copy, writes its provenance and checksums, then atomically publishes one
   versioned release directory under `dist/`.

For commit `<short-commit>`, the only consumable output is the complete directory
`dist/udp2raw-<short-commit>-arm64-static.release/`. It contains the executable, its text
attestation, and `SHA256SUMS`. The directory does not become visible under that final name until
all three files are complete and rechecked, and an existing final directory is never overwritten.
Verify the bundle before copying or deploying it:

```sh
cd dist/udp2raw-<short-commit>-arm64-static.release
sha256sum -c SHA256SUMS                 # Linux
# shasum -a 256 -c SHA256SUMS           # macOS
```

A normal pre-publication failure removes its hidden staging directory and publication lock. After
the atomic rename, the script re-hashes all three final files; a failure moves the entire directory
back to a hidden `.udp2raw-<short-commit>-arm64-static.release.failed.*` quarantine before exiting.
A process crash or interruption can leave
`.udp2raw-<short-commit>-arm64-static.release.staging.*` and
`.udp2raw-<short-commit>-arm64-static.release.publish.lock` under `dist/`, but not a final partial
bundle during ordinary process execution: the final rename occurs only after the binary,
attestation, and manifest were verified in staging. An interruption immediately after that rename
can leave the complete preverified final bundle and a stale lock, so consumers must still check
`SHA256SUMS`. This is process-crash/interruption safety, not sudden-power-loss or storage-failure
durability: the release files and containing directory are not explicitly `fsync`ed. After
confirming that no release process is running, review any `.failed.*` quarantine, remove stale
hidden remnants, and retry. Do not remove or replace an existing final bundle implicitly; review
it first.

The attestation records the immutable source commit/tree/time, archived `Cargo.lock` and builder
Dockerfile hashes, base manifest and selected builder image ID/platform, tool versions, exact
target/command/environment, artifact size and SHA-256, ELF properties, and self-test result. It is
an unsigned build record: authenticate or sign the bundle through the release channel before
treating it as third-party provenance.

The focused non-network regression test uses a fake container runtime to check snapshot binding,
image-ID use, non-root cache setup, no-clobber publication, and attestation/checksum consistency:

```sh
tools/release/build_arm64_static_test.sh
```

Before deployment, additionally run the ordinary unit/e2e suites and smoke the exact artifact
on both a Pi 4 and Pi 5. Verify `--unit-test`, the reported runtime AES backend, no `SIGILL`, and
protocol interoperability. A build attestation is not a site rollout acceptance record.
