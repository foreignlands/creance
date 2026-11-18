#!/bin/sh
# One-command verification: formatting, lints, tests, release build.
set -eu
cd "$(dirname "$0")/.."
echo "== fmt =="; cargo fmt --check
echo "== clippy =="; cargo clippy --all-targets -- -D warnings
echo "== test =="; cargo test
echo "== release =="; cargo build --release
echo "OK"
