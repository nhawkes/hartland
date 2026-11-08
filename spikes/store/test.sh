#!/usr/bin/env bash
# Usage: test.sh <hartland> <jwks.json> <results-dir>
set -uo pipefail
h="$(realpath "$1")"; jwks="$(realpath "$2")"; out="$3"
mkdir -p "$out"; out="$(realpath "$out")"
exec > >(tee "$out/log.txt") 2>&1
work="$(mktemp -d)"; cd "$work"
addr=http://127.0.0.1:8981
run="$GITHUB_RUN_ID"
fail=0
check() { if "$@"; then echo "PASS: $*"; else echo "FAIL: $*"; fail=1; fi; }

wf="$GITHUB_REPOSITORY/.github/workflows/spike-store.yml"
printf '{"builders":[{"workflow":"%s","commits":["%s"]}]}\n' "$wf" "$GITHUB_SHA" > trust.json
printf '{"builders":[{"workflow":"%s","commits":["0000000000000000000000000000000000000000"]}]}\n' "$wf" > distrust.json

serve() { # dir keyring [write]
    local extra=()
    [ -n "${3:-}" ] && extra=(--write "$REPO")
    "$h" proxy serve --dir "$1" --listen 127.0.0.1:8981 --registry ghcr.io --read "$REPO" \
        --keyring "$2" --jwks "$jwks" --publish-every 3600 "${extra[@]}" &
    pid=$!
    for _ in $(seq 50); do (exec 3<>/dev/tcp/127.0.0.1/8981) 2>/dev/null && return 0; sleep 0.2; done
    echo "proxy did not start"; return 1
}
stop() { kill -TERM "$pid"; wait "$pid"; }

echo "== write: store a result, publish on SIGTERM"
serve w trust.json write
check "$h" proxy ac-put --addr $addr --action "w-$run"
stop

echo "== read: fresh proxy, trusting keyring"
serve r1 trust.json
check "$h" proxy ac-get --addr $addr --action "w-$run" --expect found
good=$("$h" proxy ac-get --addr $addr --action "w-$run" | cut -d' ' -f1)
forged=$("$h" proxy ac-get --addr $addr --action "forged-$run" | cut -d' ' -f1)
stop

echo "== forge: copy the signed entry to another action's tag"
check "$h" oci retag --registry ghcr.io --repo "$REPO" --from "$good" --to "$forged"
serve r2 trust.json
check "$h" proxy ac-get --addr $addr --action "forged-$run" --expect missing
stop

echo "== trust: keyring that does not trust this workflow commit"
serve r3 distrust.json
check "$h" proxy ac-get --addr $addr --action "w-$run" --expect missing
stop

echo "summary: $([ $fail -eq 0 ] && echo ALL PASS || echo FAILURES)" | tee "$out/summary.txt"
exit $fail
