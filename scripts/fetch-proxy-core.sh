#!/bin/sh
# Fetch the bundled mihomo core for development builds.
#
# core_path() looks next to the creance binary and in ../proxy-core/, so a dev
# checkout installs it at target/proxy-core/mihomo. Release bundles ship the
# core inside the app; this script is not needed there.
#
# The default version is PINNED and its assets' sha256 are recorded below
# (self-recorded on first pin, 2026-11-21, against v1.19.34 — mihomo
# publishes no per-asset checksums). An override (arg or MIHOMO_VERSION)
# has no recorded hash: the script says so loudly and skips verification.
#
# Usage: scripts/fetch-proxy-core.sh [version]
set -eu

repo=MetaCubeX/mihomo
pinned=v1.19.34
os=$(uname -s | tr '[:upper:]' '[:lower:]') # darwin / linux
case "$(uname -m)" in
    arm64 | aarch64) arch=arm64 ;;
    x86_64) arch=amd64 ;;
    *)
        echo "unsupported architecture: $(uname -m)" >&2
        exit 1
        ;;
esac

# Supported targets only: macOS Apple Silicon and Ubuntu x86_64.
case "$os-$arch" in
    darwin-arm64 | linux-amd64) ;;
    *)
        echo "unsupported platform: $os-$arch (creance targets macOS arm64 and Ubuntu x86_64)" >&2
        exit 1
        ;;
esac

# sha256 of the release .gz assets, recorded at pin time (full asset
# names — case matches the whole string, a bare "darwin-arm64-…" would
# never fire).
checksum_for() {
    case "$1" in
        mihomo-darwin-arm64-v1.19.34)  echo 1a7a20eca63fbbaec90137717465bfde488d0db2a3a79b8fadebf9b2545b6e4c ;;
        mihomo-linux-amd64-v1.19.34)   echo 223fab877e5795ce780ba39902e5f0b1113c1256ae244a7160f1165e017e9ccc ;;
        *) return 1 ;;
    esac
}

sha256_of() {
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d' ' -f1
    else
        sha256sum "$1" | cut -d' ' -f1
    fi
}

version=${1:-${MIHOMO_VERSION:-$pinned}}
[ -n "$version" ] || {
    echo "cannot determine the mihomo version" >&2
    exit 1
}

out=target/proxy-core
mkdir -p "$out"
asset="mihomo-$os-$arch-$version"
url="https://github.com/$repo/releases/download/$version/$asset.gz"
echo "fetching $url"
# Land on a temp name, verify, THEN move into place — a half-download
# corpse must never shadow a working core (F-034 discipline).
tmp="$out/.mihomo.download.$$"
trap 'rm -f "$tmp"' EXIT
curl -fsSL -o "$tmp" "$url"

if expected=$(checksum_for "$asset"); then
    actual=$(sha256_of "$tmp")
    if [ "$actual" != "$expected" ]; then
        echo "checksum mismatch for $asset" >&2
        echo "  expected $expected" >&2
        echo "  actual   $actual" >&2
        exit 1
    fi
    echo "sha256 verified: $expected"
else
    echo "WARNING: no recorded checksum for $asset — SKIPPING verification" >&2
fi

gunzip -c "$tmp" >"$out/mihomo.new" && mv "$out/mihomo.new" "$out/mihomo"
chmod +x "$out/mihomo"
"$out/mihomo" -v
echo "installed at $out/mihomo ($version)"
