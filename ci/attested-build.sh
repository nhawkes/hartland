#!/usr/bin/env bash
# Attested build, run by hartland's reusable workflow (.github/workflows/build.yml)
# on a GitHub-hosted runner. Every path to trusted code comes from the
# hartland checkout at the builder's own commit (job_workflow_sha), never from
# the caller.
#
# Usage: attested-build.sh <hartland-dir> <caller-dir> <targets> <results-dir>
#
# Three uids:
#   runner     the proxy: holds the OIDC request credentials, signs results
#   hlbuild    buck2: no sudo, no credentials; cannot read runner's processes
#   hlsandbox  each action, via bwrap: empty root, no network, no /home
set -euo pipefail
hl="$(realpath "$1")"; caller="$(realpath "$2")"; targets="$3"; out="$4"
mkdir -p "$out"; out="$(realpath "$out")"
log() { echo "attest: $*" | tee -a "$out/summary.txt" >&2; }

: "${ACTIONS_ID_TOKEN_REQUEST_URL:?needs id-token: write}"
: "${REGISTRY_USER:?}" "${REGISTRY_PASSWORD:?}" "${BUILDER_SHA:?}" "${GITHUB_REPOSITORY_OWNER:?}"
namespace="${GITHUB_REPOSITORY_OWNER,,}/hartland-cache"
builder="nhawkes/hartland/.github/workflows/build.yml"

log "builder $builder@$BUILDER_SHA for $GITHUB_REPOSITORY@$GITHUB_SHA; cache ghcr.io/$namespace"

# Tools, from the trusted checkout only.
(cd "$hl/cli" && cargo build --locked --release -q)
hartland="$hl/cli/target/release/hartland"
buck2="$("$hl/ci/install-buck2.sh")"
"$hartland" sandbox setup
id hlbuild >/dev/null 2>&1 || sudo useradd --create-home --shell /usr/sbin/nologin hlbuild

# Trust: results signed by this builder at this commit (and any listed in
# hartland's keys/builders.json, if present).
work="$(mktemp -d)"
python3 - "$builder" "$BUILDER_SHA" "$hl/keys/builders.json" > "$work/keyring.json" <<'PY'
import json, os, sys
wf, sha, extra = sys.argv[1:4]
commits = [sha]
if os.path.exists(extra):
    for b in json.load(open(extra)).get("builders", []):
        if b["workflow"] == wf:
            commits += [c for c in b["commits"] if c not in commits]
print(json.dumps({"builders": [{"workflow": wf, "commits": commits}]}))
PY

# First tier (Actions cache) and promotion: everything from the default
# branch goes to the registry; elsewhere only first-tier results reused.
registry_args=(--registry ghcr.io --read "$namespace" --keyring "$work/keyring.json" --jwks "$hl/keys/github-actions-jwks.json")
promote=none
if [ -n "${HARTLAND_L1:-}" ]; then
    mkdir -p "$HARTLAND_L1"
    registry_args+=(--l1 "$HARTLAND_L1")
    promote=reused
    [ "${GITHUB_REF:-}" = "refs/heads/${DEFAULT_BRANCH:-main}" ] && promote=all
    log "first tier $HARTLAND_L1 ($(find "$HARTLAND_L1/batches" -name '*.envelope' 2>/dev/null | wc -l) batches restored); promote $promote"
fi

serve() { # store-dir promote [--write ns]
    local dir="$1" policy="$2"; shift 2
    local policy_args=()
    [ -n "${HARTLAND_L1:-}" ] && policy_args=(--promote "$policy")
    "$hartland" proxy serve --dir "$dir" --listen 127.0.0.1:8980 --execute sandbox \
        "${registry_args[@]}" "${policy_args[@]}" --publish-every 3600 "$@" \
        >>"$out/proxy.log" 2>&1 &
    proxy=$!
    for _ in $(seq 100); do (exec 3<>/dev/tcp/127.0.0.1/8980) 2>/dev/null && return 0; sleep 0.2; done
    log "proxy did not start"; return 1
}

# buck2 runs as hlbuild in a copy of the caller's checkout it owns, with the
# attested settings forced regardless of the caller's own config.
build() { # label
    # Under hlbuild's home: $work is private to the runner uid.
    local tree="/home/hlbuild/build-$1"
    sudo rm -rf "$tree" && sudo cp -a "$caller" "$tree"
    sudo cp "$caller/mode/attested.bcfg" "$tree/.buckconfig.local" 2>/dev/null || true
    sudo tee -a "$tree/.buckconfig.local" >/dev/null <<'CFG'

[hartland]
remote_execution = true
remote_only = true

[buck2_re_client]
engine_address = 127.0.0.1:8980
action_cache_address = 127.0.0.1:8980
cas_address = 127.0.0.1:8980
tls = false
CFG
    sudo chown -R hlbuild:hlbuild "$tree"
    sudo install -o hlbuild -m 0755 "$buck2" /home/hlbuild/buck2
    # shellcheck disable=SC2086
    sudo -u hlbuild env -i HOME=/home/hlbuild PATH=/usr/bin:/bin \
        sh -c "cd '$tree' && /home/hlbuild/buck2 build $targets" 2>&1 | tee "$out/build-$1.log" \
        | grep -E 'BUILD|Cache hits|Commands' >&2 || true
    sudo -u hlbuild sh -c "cd '$tree' && /home/hlbuild/buck2 kill" >/dev/null 2>&1 || true
    grep -q 'BUILD SUCCEEDED' "$out/build-$1.log"
}

log "phase 1: build, execute in the sandbox, sign, publish"
serve "$work/store1" "$promote" --write "$namespace"
build first && log "first build succeeded" || { log "first build FAILED"; kill -TERM "$proxy"; wait "$proxy" || true; exit 1; }

# Package attestations: one signed statement per target, binding its output
# files to the source repository and commit (checked against the token's own
# claims by verifiers).
log "package attestations"
pkgs="$out/packages"; mkdir -p "$pkgs"
sudo -u hlbuild env -i HOME=/home/hlbuild PATH=/usr/bin:/bin \
    sh -c "cd /home/hlbuild/build-first && /home/hlbuild/buck2 build $targets --materializations=all --show-full-json-output" \
    2>/dev/null > "$work/outputs.json" || log "could not list outputs"
python3 - "$work/outputs.json" > "$work/outputs.tsv" <<'PY'
import json, sys
for label, path in sorted(json.load(open(sys.argv[1])).items()):
    print(f"{label}\t{path}")
PY
n=0
while IFS=$'\t' read -r label path; do
    [ -n "$label" ] || continue
    if [ ! -f "$path" ]; then log "skip $label: output is not a single file"; continue; fi
    n=$((n + 1)); name="$(basename "$path")"; dir="$pkgs/$n"; mkdir -p "$dir"
    cp "$path" "$dir/$name"
    printf '%s\n' "$label" > "$dir/target.txt"
    "$hartland" attest package --target "$label" --repository "$GITHUB_REPOSITORY" --commit "$GITHUB_SHA" \
        --output "$name=$dir/$name" --out "$dir/attestation.json" 2>&1 | tee -a "$out/summary.txt" >&2
done < "$work/outputs.tsv"
cp "$work/keyring.json" "$out/keyring.json"

kill -TERM "$proxy"; wait "$proxy" || true
grep -E 'signed new results|queued|publish failed' "$out/proxy.log" | tee -a "$out/summary.txt" >&2 || true

# Registry promotion runs in the background from here: nothing below needs
# it, and it is waited for only before the first tier is saved.
promoter=
if [ -n "${HARTLAND_L1:-}" ]; then
    "$hartland" proxy promote --dir "$work/store-promote" "${registry_args[@]}" --write "$namespace" \
        >"$out/promote.log" 2>&1 &
    promoter=$!
fi

log "phase 2: fresh proxy, empty store: everything must come from signed entries"
serve "$work/store2" none
build second && log "second build succeeded" || log "second build FAILED"
grep -E 'Cache hits|Commands' "$out/build-second.log" | sed 's/^.*\] //' | tee -a "$out/summary.txt" >&2 || true
kill -TERM "$proxy"; wait "$proxy" || true

if [ -n "$promoter" ]; then
    if wait "$promoter"; then log "registry promotion done"; else log "registry promotion FAILED (queued again next run)"; fi
    grep -E 'promoted|registry updated|ERROR' "$out/promote.log" | tail -3 | tee -a "$out/summary.txt" >&2 || true
fi
