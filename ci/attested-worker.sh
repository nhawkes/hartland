#!/usr/bin/env bash
# A dispatched worker, run by hartland's reusable workflow (role: worker) on a
# GitHub-hosted runner. Joins the coordinator named in the dispatch inputs,
# runs the actions it sends in the sandbox, signs the results with its own
# certified key, and leaves after a minute without work.
#
# Usage: attested-worker.sh <hartland-dir>
#
# Two uids: runner (this process: OIDC credentials, signs) and hlsandbox
# (each action, via bwrap: empty root, no network, no /home).
set -euo pipefail
hl="$(realpath "$1")"
: "${ACTIONS_ID_TOKEN_REQUEST_URL:?needs id-token: write}"
: "${BUILDER_SHA:?}" "${COORDINATOR:?}" "${COORDINATOR_RUN:?}"
builder="nhawkes/hartland/.github/workflows/build.yml"
echo "worker: builder $builder@$BUILDER_SHA for coordinator $COORDINATOR (run $COORDINATOR_RUN)" >&2

(cd "$hl/cli" && cargo build --locked --release -q)
hartland="$hl/cli/target/release/hartland"
work="$(mktemp -d)"
python3 "$hl/ci/make-keyring.py" "$builder" "$BUILDER_SHA" "$hl/keys/builders.json" > "$work/keyring.json"

"$hartland" proxy worker --dir "$work/store" --coordinator "$COORDINATOR" --coordinator-run "$COORDINATOR_RUN" \
    --keyring "$work/keyring.json" --jwks "$hl/keys/github-actions-jwks.json" \
    --execute sandbox --slots "$(nproc)" --idle 60
