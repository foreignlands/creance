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
echo "== probe inventory =="; sh scripts/check-probe-inventory.sh
echo "== test =="; cargo test --locked
echo "== release =="; cargo build --locked --release
echo "OK"
