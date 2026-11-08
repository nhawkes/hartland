#!/usr/bin/env bash
# CI entry point, run from the project root.
#   hartland/ci/run.sh pr     lint, then build and test targets affected since origin/main
#   hartland/ci/run.sh all    lint, then build and test every ci target
# Uses BuildBuddy remote execution when BUILDBUDDY_API_KEY is set (trusted
# runs only); otherwise builds locally.
set -euo pipefail
mode="${1:?usage: run.sh pr|all}"

git submodule update --init --recursive
buck2="$(hartland/ci/install-buck2.sh)"
PATH="$(dirname "$buck2"):$PATH"
export PATH

flags=()
if [ -n "${BUILDBUDDY_API_KEY:-}" ]; then
    flags+=("@mode/remote")
    echo "ci: BuildBuddy remote execution" >&2
else
    echo "ci: BUILDBUDDY_API_KEY not set; building locally" >&2
fi

echo "ci: lint" >&2
buck2 bxl hartland//lint/pins.bxl:lint
hartland/lint/test.sh

case "$mode" in
    pr)
        git fetch -q origin main
        targets="$(hartland/ci/affected.sh FETCH_HEAD buck2)"
        ;;
    all)
        targets="$(buck2 bxl hartland//ci/affected.bxl:affected -- --file .buckconfig)"
        ;;
    *) echo "unknown mode: $mode" >&2; exit 2 ;;
esac

mapfile -t list < <(grep -v '^#' <<<"$targets" | grep . || true)
grep '^#' <<<"$targets" >&2 || true
if [ "${#list[@]}" -eq 0 ]; then
    echo "ci: nothing affected" >&2
    exit 0
fi
printf 'ci: %s\n' "${list[@]}" >&2
buck2 build "${flags[@]}" "${list[@]}"
buck2 test "${flags[@]}" "${list[@]}"
