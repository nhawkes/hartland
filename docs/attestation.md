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

    aud = "hartland-attest:sha256:<digest of batch statement>"   (?)

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
  directory (? whether hosted runners allow this without root);
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

## Open questions

1. Can an OIDC token be requested with an arbitrary audience string of this
   form, and how long is it valid?
2. Can a hosted runner unshare namespaces and drop to another uid?
3. GHCR: referrers API, rate limits, behaviour with many small blobs.
4. buck2 executor settings for local execution with a remote cache.
5. Actions concurrency limits and terms of use for long-lived worker jobs.
