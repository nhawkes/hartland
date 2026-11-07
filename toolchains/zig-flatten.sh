#!/usr/bin/env bash
# Run zig with every @response-file flattened to a single level.
# buck2's prelude nests argsfiles (@a containing @b); `zig cc` rejects that.
# Usage: zig-flatten.sh <zig> <args...>
set -uo pipefail
zig="$1"; shift
tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/zigrsp.XXXXXX")"
trap 'rm -rf "$tmpdir"' EXIT

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
