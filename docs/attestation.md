# Attested builds

Status: design, not yet implemented. Unverified assumptions are marked (?).

## Goals

- Anyone may add packages to the repository; nothing is trusted for being in git.
- Consumers decide what to trust with a keyring. Trust never crosses an
  attestation boundary: a build only uses results attested by a builder in
  the keyring.
- Users pay for their own compute and storage. Hartland hosts nothing.
- Trust is anchored in GitHub, not in the user who triggered the build.

## Two kinds of build

**Everyday builds** (local, or on the user's own BuildBuddy account) are plain
buck2. No proxy, no signing, nothing uploaded to GitHub.

**Attested builds** run only on GitHub-hosted runners, in the user's own
repository (a fork of hartland-packages), by calling Hartland's reusable
workflow pinned to a commit. The user's Actions minutes and registry storage
pay for them.

## The trusted builder

A keyring entry names a builder, not a person:

    github-hosted runner + job_workflow_ref = nhawkes/hartland/.github/workflows/build.yml@<commit>

Verification checks the OIDC claims `job_workflow_ref` (our pinned workflow)
and `runner_environment == github-hosted`. Self-hosted runners can run the same
workflow and obtain valid tokens, so the second check is essential.

Callers cannot add steps to a reusable workflow; workflow inputs are minimal
and recorded in the attestation.

## Signing: GitHub OIDC tokens as signatures

A job requests an OIDC token whose audience is the digest of a statement:

    aud = "hartland-attest:sha256:<digest of batch statement>"

The token is a JWT signed by GitHub, binding the workflow identity, repository,
commit and runner environment to that digest. It is verified against GitHub's
published JWKS; Hartland keeps an archive of GitHub's public keys so that old
tokens remain verifiable after key rotation. No Sigstore, Rekor or timestamp
authority is involved.

## Isolation: build actions must never reach the signer

Build actions are user-controlled code (their BUCK files, patches, scripts).
Anything that can request an OIDC token can choose its audience, so it could
sign a forged result. Therefore the worker (our pinned code):

- reads `ACTIONS_ID_TOKEN_REQUEST_URL` / `_TOKEN` at startup, keeps them only in
  its own memory, and scrubs them from every environment it passes on;
- runs each action as a separate unprivileged uid without sudo, in its own
  namespaces: no network, no view of the worker process, fresh scratch
  directory. Ubuntu 24.04 runners block unprivileged user namespaces
  (AppArmor), so root creates the namespaces and drops to the sandbox uid:
  `sudo unshare --net --pid --mount --ipc --uts --fork --mount-proc setpriv
  --reuid=<sandbox> --regid=<sandbox> --clear-groups --no-new-privs
  --inh-caps=-all --bounding-set=-all`. The mount namespace still needs a
  read-only root and per-action scratch (not yet built);
- signs only digests it computed itself from the CAS.

## Cache

Every action result from an attested build is uploaded to the caller's own
GitHub container registry namespace (`ghcr.io/<owner>/hartland/...`):

- CAS blobs are OCI blobs (content-addressed by sha256, so unforgeable).
- An action-cache entry is a small manifest tagged with the action digest,
  pointing at the output blobs.
- Each job signs one batch statement listing every (action digest, result
  digest) pair it produced; the signature (the JWT) is stored in the registry
  alongside the entries, as an OCI referrer or via cosign-style tag fallback
  (? GHCR referrers support).

Attested builds read only cache entries whose batch statement is signed by a
trusted builder. Because trust is in the builder, entries from any user's
namespace are equally good: the cache is shared, and each builder pays for
what they stored. Discovery is by the namespaces of keyring users for now; a
global index is out of scope.

Results from everyday builds may be uploaded unsigned, but attested builds
never read them.

## Attestations

The final attestation for a package covers its whole closure: the package's
input hash (pinned sources, BUCK files, patches, toolchain) and the output
digest of every transitive dependency, all produced within trusted-builder
runs. It is signed the same way and stored in the registry next to the
package, optionally also in GitHub's attestations store (?).

Divergent results for the same action digest from two trusted builders prove
a hermeticity bug and are reported.

## Scale-out

Within an attested build, the proxy schedules actions onto worker jobs in the
same workflow run. Hosted runners accept no inbound connections, so workers
dial out to a rendezvous the user provides (e.g. their own Tailscale tailnet
with ephemeral keys) (?). Simpler first step: one job per package group,
ordered by buck2's dependency graph, local execution plus the verified cache.

## Findings (spike/oidc branch, private repo, ubuntu-24.04 runner)

- A token with `aud = hartland-attest:sha256:<hex>` is issued, verifies
  against GitHub's JWKS, and rejects a wrong audience. Claims include
  `runner_environment: github-hosted`, `job_workflow_ref`,
  `job_workflow_sha`, `repository`, `sha`, `run_id`.
- Tokens live 300 s; the signature still verifies after expiry (signature-only
  check), so they serve as durable signatures. JWKS held 4 keys: archive them.
- As the default `runner` uid, three processes' environments expose
  `ACTIONS_ID_TOKEN_REQUEST_TOKEN`; a separate uid sees none, has no sudo,
  and cannot read the runner's home.
- The root-created jail gives: sandbox uid, all capability sets empty,
  NoNewPrivs=1, network unreachable, only its own PIDs visible, no token,
  sudo refused. Launch overhead is about 7.6 ms per action.
- Alternative: `sysctl kernel.apparmor_restrict_unprivileged_userns=0`, then
  `bwrap --unshare-all` as the sandbox uid, also works.
- Private-repo runners: 2 cores, 7 GB RAM, ~14 GB free disk.
- Called from hartland-packages, a reusable workflow in hartland pinned by
  commit gets a token with `job_workflow_ref =
  nhawkes/hartland/.github/workflows/<file>@<commit>` and `job_workflow_sha`
  equal to that commit, while `repository`, `workflow_ref` and `sha` name the
  caller. So the verifier pins the builder by `job_workflow_ref` +
  `job_workflow_sha` + `runner_environment`, independent of who called it.
  (Private repositories need hartland's Actions "Access" setting to allow
  repositories owned by the user.)

## Open questions

1. Actions concurrency limits and terms of use for long-lived worker jobs.

## Settled

- GHCR (private package, pushed from Actions with GITHUB_TOKEN):
  - No OCI referrers API (`/v2/<repo>/referrers/<digest>` returns 404
    MANIFEST_UNKNOWN), though manifests with `subject` are accepted. So the
    signature is carried by annotation + layer on the entry itself.
  - Small blobs: ~1.1 s each sequentially (HEAD + POST + PUT); with 16 in
    parallel, ~92 ms each effective (300 in 28 s). No failures, no
    rate-limit headers seen. Existence checks 35–185 ms each.
  - Blob GET is a 307 to pkg-containers.githubusercontent.com; one early
    read failed, later reads succeeded: retry reads.
  - Manifests by tag round-trip byte for byte; anonymous reads of a private
    package get 401.

- Sandbox on a hosted runner (`hartland sandbox run`, bubblewrap as uid
  hlsandbox, empty tmpfs root): with OIDC credentials present in the
  worker's environment, the action ran as uid 1002, saw no token, root held
  only work/proc/dev/tmp, no /home, no sudo, network unreachable, 2 visible
  PIDs, inputs and declared env present, no scratch left behind.
- bubblewrap is not preinstalled on ubuntu-24.04 runners; `sandbox setup`
  installs it from Ubuntu's archive. TODO: ship a pinned static bwrap.
- End to end: a batch signed in Actions (`hartland attest sign`) verifies
  locally (`hartland attest verify`) against the archived JWKS with a keyring
  trusting that workflow at that commit, and is rejected by one that does not.

- buck2 local execution with a remote cache: `CommandExecutorConfig(
  local_enabled = True, remote_enabled = False, remote_cache_enabled = True,
  allow_cache_uploads = True)` is a distinct executor in buck2
  (`RemoteEnabledExecutor::Local`): actions run locally, the RE action cache
  is queried, and local results are uploaded. Source:
  app/buck2_build_api/src/interpreter/rule_defs/command_executor_config.rs.
