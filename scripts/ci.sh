#!/bin/sh
# One-command verification: formatting, lints, tests, release build.
#
# --locked everywhere: CI verifies the LOCKFILE we ship; accidental
# dependency drift fails here instead of shipping.
#
# Platform honesty: cfg-gated code only compiles on its platform, so
# "green" is per-platform — each cfg(target_os) block is invisible to
# the other platform's run (learned when v0.6.1 shipped "CI green"
# with macOS broken). The echo below keeps that in every log's face;
# cross-platform changes need a run on each platform before "green"
# is claimed anywhere.
set -eu
cd "$(dirname "$0")/.."
echo "== platform: $(uname -s)/$(uname -m) (cfg-gated code for other platforms is NOT compiled here) =="
echo "== fmt =="; cargo fmt --check
echo "== clippy =="; cargo clippy --locked --all-targets -- -D warnings
echo "== msrv =="
# rust-version in the workspace manifest is enforced by cargo on every
# build already; this step verifies the declared floor by compiling on
# the actual MSRV toolchain (installed on demand via rustup).
MSRV=$(sed -n 's/^rust-version = "\(.*\)"/\1/p' Cargo.toml | head -1)
if [ -n "$MSRV" ]; then
    rustup toolchain install "$MSRV" --profile minimal >/dev/null 2>&1 || true
    if rustup run "$MSRV" cargo --version >/dev/null 2>&1; then
        cargo "+$MSRV" check --locked --workspace
    else
        echo "MSRV toolchain $MSRV unavailable (offline?) — cargo still enforces rust-version on this build"
    fi
fi
echo "== rustdoc =="; RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps --workspace
echo "== semver =="
# cargo-semver-checks compares the public API of HEAD against the
# previous tag — a silent breaking change to a lib crate fails here.
# Skipped (with a notice) when the tool is not installed.
if command -v cargo-semver-checks >/dev/null 2>&1; then
    PREV_TAG=$(git tag --sort=-v:refname | grep -v "^$(git describe --tags --exact-match 2>/dev/null || true)$" | head -1 || true)
    if [ -n "$PREV_TAG" ]; then
        cargo semver-checks check-release --workspace --baseline-rev "$PREV_TAG"
    else
        echo "no baseline tag found — semver check skipped"
    fi
else
    echo "cargo-semver-checks not installed — API drift check skipped"
fi
echo "== probe inventory =="; sh scripts/check-probe-inventory.sh
echo "== test =="; cargo test --locked
echo "== release =="; cargo build --locked --release
echo "OK"
