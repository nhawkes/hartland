#!/usr/bin/env bash
# Fetches every pinned_git source of a project into a store for
# `hartland sources serve`: with the seed zig, or with gix (in hartland) where
# zig fails. Fetching happens here, outside any build action; buck2 then
# downloads each canonical archive by sha256.
#
# Usage: fetch-sources.sh <repo root> <store> <zig>
# Uses `buck2` and `hartland` from PATH unless BUCK2 / HARTLAND are set.
set -euo pipefail
root="$1"; store="$2"; zig="$3"
buck2="${BUCK2:-buck2}"; hartland="${HARTLAND:-hartland}"

sources="$(cd "$root" && "$buck2" uquery 'kind(pinned_git, //...)' \
    --output-attribute url --output-attribute commit --output-attribute sha256 \
    --output-attribute zig_hash --json)"
python3 -c '
import json, sys
for label, a in sorted(json.load(sys.stdin).items()):
    print("\t".join([label, a["url"], a["commit"], a["sha256"], a.get("zig_hash") or ""]))
' <<<"$sources" |
while IFS=$'\t' read -r label url commit sha256 zig_hash; do
    args=(--dir "$store" --url "$url" --commit "$commit" --sha256 "$sha256" --zig "$zig")
    [ -n "$zig_hash" ] && args+=(--zig-hash "$zig_hash")
    # Prints the sha256, Zig's hash of the tree (for pinning zig_hash) and
    # how it was fetched (zig or gix).
    fetched="$("$hartland" sources fetch "${args[@]}")"
    echo "fetch-sources: $label $fetched" >&2
done
