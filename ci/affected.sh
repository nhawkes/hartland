#!/usr/bin/env bash
# Prints the CI targets affected by the commits between <base-rev> and HEAD.
# Run from the project root. Changes inside git submodules are expanded to the
# files changed within them. If the diff cannot be worked out, prints every
# CI target rather than guess.
# Usage: hartland/ci/affected.sh <base-rev> [buck2]
set -euo pipefail
base_rev="$1"
buck2="${2:-buck2}"

everything() {
    echo "affected: $1; selecting every ci target" >&2
    exec "$buck2" bxl hartland//ci/affected.bxl:affected -- --file .buckconfig
}

base="$(git merge-base HEAD "$base_rev")" || everything "no merge base with $base_rev"

submodules=()
if [ -f .gitmodules ]; then
    while read -r _ path; do submodules+=("$path"); done \
        < <(git config -f .gitmodules --get-regexp '^submodule\..*\.path$' || true)
fi

files=()
while IFS= read -r f; do
    is_sub=""
    for s in "${submodules[@]}"; do [ "$f" = "$s" ] && is_sub=1; done
    if [ -z "$is_sub" ]; then
        files+=("$f")
        continue
    fi
    old="$(git rev-parse -q --verify "$base:$f" 2>/dev/null)" || everything "submodule $f added"
    new="$(git rev-parse -q --verify "HEAD:$f" 2>/dev/null)" || everything "submodule $f removed"
    git -C "$f" cat-file -e "$old^{commit}" 2>/dev/null \
        || git -C "$f" fetch -q origin "$old" \
        || everything "cannot fetch $f@$old"
    while IFS= read -r g; do files+=("$f/$g"); done \
        < <(git -C "$f" diff --name-only --no-renames "$old" "$new")
done < <(git diff --name-only --no-renames "$base" HEAD)

[ "${#files[@]}" -gt 0 ] || exit 0
args=()
for f in "${files[@]}"; do args+=(--file "$f"); done
exec "$buck2" bxl hartland//ci/affected.bxl:affected -- "${args[@]}"
