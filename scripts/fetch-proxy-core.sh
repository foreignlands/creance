#!/bin/sh
# Fetch the bundled mihomo core for development builds.
#
# CorePath looks next to the cage binary and in ../proxy-core/, so a dev
# checkout installs it at target/proxy-core/mihomo. Release bundles ship the
# core inside the app; this script is not needed there.
#
# Usage: scripts/fetch-proxy-core.sh [version]
#   MIHOMO_VERSION=v1.19.13 scripts/fetch-proxy-core.sh   (pin a version)
set -eu

repo=MetaCubeX/mihomo
os=$(uname -s | tr '[:upper:]' '[:lower:]') # darwin / linux
case "$(uname -m)" in
    arm64 | aarch64) arch=arm64 ;;
    x86_64) arch=amd64 ;;
    *)
        echo "unsupported architecture: $(uname -m)" >&2
        exit 1
        ;;
esac

version=${1:-${MIHOMO_VERSION:-}}
if [ -z "$version" ]; then
    version=$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" |
        sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p')
fi
[ -n "$version" ] || {
    echo "cannot determine the latest mihomo version; pass one or set MIHOMO_VERSION" >&2
    exit 1
}

out=target/proxy-core
mkdir -p "$out"
url="https://github.com/$repo/releases/download/$version/mihomo-$os-$arch-$version.gz"
echo "fetching $url"
curl -fsSL "$url" | gunzip >"$out/mihomo"
chmod +x "$out/mihomo"
"$out/mihomo" -v
echo "installed at $out/mihomo"
