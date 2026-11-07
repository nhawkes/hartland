#!/usr/bin/env bash
# Run zig with every @response-file flattened to a single level.
# buck2's prelude nests argsfiles (@a containing @b); `zig cc` rejects that.
# It also confines zig's caches to the action's scratch space, so nothing is
# read from or written to $HOME (sandboxed and remote actions have no usable one).
# Usage: zig-flatten.sh <zig> <args...>
set -uo pipefail
zig="$1"; shift
scratch="${BUCK_SCRATCH_PATH:-${TMPDIR:-/tmp}}"
mkdir -p "$scratch"
tmpdir="$(mktemp -d "$scratch/zig.XXXXXX")"
tmpdir="$(cd "$tmpdir" && pwd)"
trap 'rm -rf "$tmpdir"' EXIT
export ZIG_GLOBAL_CACHE_DIR="$tmpdir/global-cache"
export ZIG_LOCAL_CACHE_DIR="$tmpdir/local-cache"

expand() {
    local line
    while IFS= read -r line || [ -n "$line" ]; do
        if [[ "$line" == @* && -f "${line:1}" ]]; then
            expand "${line:1}"
        else
            printf '%s\n' "$line"
        fi
    done < "$1"
}

n=0
args=()
for a in "$@"; do
    if [[ "$a" == @* && -f "${a:1}" ]]; then
        n=$((n + 1))
        expand "${a:1}" > "$tmpdir/$n.rsp"
        args+=("@$tmpdir/$n.rsp")
    else
        args+=("$a")
    fi
done

"$zig" "${args[@]}"
