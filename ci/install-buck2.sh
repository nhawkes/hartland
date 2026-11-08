#!/usr/bin/env bash
# Installs the pinned buck2 into a per-user cache and prints its path.
# The release publishes no checksum, so the pin is trust-on-first-use.
set -euo pipefail
version="2026-10-15"
sha256="dc39a4702492333b46dcfa17129481b41f4820bb415e4efd437f70ef33ba451d"
url="https://github.com/facebook/buck2/releases/download/${version}/buck2-x86_64-unknown-linux-musl.zst"

dir="${XDG_CACHE_HOME:-$HOME/.cache}/hartland/buck2-${version}"
bin="$dir/buck2"
if [ ! -x "$bin" ]; then
    command -v zstd >/dev/null || { sudo apt-get update -q && sudo apt-get install -qy zstd; } >&2
    mkdir -p "$dir"
    tmp="$(mktemp "$dir/download.XXXXXX")"
    trap 'rm -f "$tmp"' EXIT
    curl -fsSL --retry 3 -o "$tmp" "$url"
    echo "$sha256  $tmp" | sha256sum -c --quiet - >&2
    zstd -dqf "$tmp" -o "$bin.new"
    chmod +x "$bin.new"
    mv "$bin.new" "$bin"
fi
echo "$bin"
