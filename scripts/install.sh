#!/bin/sh
# creance installer — build and install into ~/.local/bin (or $PREFIX).
# Fetches the bundled mihomo core when missing. Idempotent.
set -eu
cd "$(dirname "$0")/.."

PREFIX="${PREFIX:-$HOME/.local}"
BIN_DIR="$PREFIX/bin"
mkdir -p "$BIN_DIR"

# Toolchain: prefer system cargo, fall back to the repo-local one.
if ! command -v cargo >/dev/null 2>&1; then
    if [ -x .toolchain/cargo/bin/cargo ]; then
        export RUSTUP_HOME="$PWD/.toolchain/rustup" \
               CARGO_HOME="$PWD/.toolchain/cargo" \
               PATH="$PWD/.toolchain/cargo/bin:$PATH"
    else
        echo "error: cargo not found (install rustup or run inside the repo)" >&2
        exit 1
    fi
fi

echo "== building creance (release) =="
cargo build --release
install -m 0755 target/release/creance "$BIN_DIR/creance"

# Bundled core: creance looks next to the binary and in ../proxy-core/
# (core_path's second candidate), so the prefix layout must match it.
CORE_DIR="$(dirname "$BIN_DIR")/proxy-core"
if [ ! -x "$CORE_DIR/mihomo" ] && [ -x target/proxy-core/mihomo ]; then
    mkdir -p "$CORE_DIR"
    install -m 0755 target/proxy-core/mihomo "$CORE_DIR/mihomo"
    echo "note: installed target/proxy-core/mihomo -> $CORE_DIR"
    echo "      (if it is missing, run: scripts/fetch-proxy-core.sh first)"
fi

echo
echo "installed: $BIN_DIR/creance $("$BIN_DIR/creance" version)"
case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) echo "note: add $BIN_DIR to PATH" ;;
esac
echo "next: creance init && creance doctor"
