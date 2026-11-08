# Scale-out

Status: design, with the connectivity spike done.

## Problem

An attested build of LLVM is too much for one 2-core hosted runner. Hosted
runners accept no inbound connections, and GitHub documents no way for
jobs in a run to reach each other, so workers need a way to meet.

## Spike: iroh between hosted runners (run 42512379973)

`spikes/iroh`, workflow `spike-iroh.yml`: two jobs in one run.

- **Rendezvous:** the listener published its endpoint address and an OIDC
  token with `aud = hartland-peer:<endpoint key>` to a run-specific GHCR
  tag; the connector found it after 0.6 s.
- **Mutual authentication with OIDC alone:** each side verified the
  other's token against the archived JWKS and a keyring trusting only
  `spike-iroh.yml` at the run's commit, on a GitHub-hosted runner, in the
  same run, bound to the peer's endpoint key. Both succeeded. No account,
  no secret.
- **Path:** the connection opened through n0's public relays (RTT 209 ms;
  the two runners used different relays, east and west US) and switched
  to a direct, hole-punched UDP path within 0.3 s (RTT 49 ms). Every later
  sample was direct.
- **Throughput:** 256 MiB on one QUIC stream in 11.4 s, about 187 Mbit/s
  (23 MB/s), direct.
- **Cost:** one build job, two peer jobs of a few minutes each.

So the public relays are needed only to set up connections, which is the
use n0's free tier is meant for.

## Spike: dispatched worker, chain of keys (runs 42520929962, 42521154304)

The coordinator job (a push run) bound an iroh endpoint and requested one
OIDC token with `aud = hartland-key:<its key>`, a certificate for the key.
It dispatched the worker run (`workflow_dispatch` with `GITHUB_TOKEN` and
`actions: write`) with its key and run id as inputs.

- The worker dialled the coordinator by key alone (address found through
  n0's DNS) in 155 ms, and checked its certificate: builder workflow at the
  commit, GitHub-hosted, same repository, the run named in its inputs.
- The coordinator checked the worker's certificate (builder, hosted, same
  repository), that its `event_name` was `workflow_dispatch`, and the
  worker's signature, by its certified key, over membership of this
  coordinator. All passed.
- Claims of the dispatched run: `event_name: workflow_dispatch`, `actor:
  github-actions[bot]`, its own `run_id`, the dispatched ref. Nothing in
  the token links it to the coordinator's run, so the membership signature
  is what binds a worker to a build.
- Path: relayed for the first moment, direct from 1.3 s (RTT 19 ms; both in
  the same region this time); 64 MiB at about 420 Mbit/s.
- `workflow_dispatch` needs the workflow file on the default branch; the
  run uses the file from the ref it is dispatched to (a stub on hartland's
  `main` registers the spike).

## Design

- **Coordinator:** the job running buck2 and the signing proxy. It hands
  each action to a free worker over iroh instead of running it itself.
- **Workers:** jobs of the same pinned builder workflow, started by the
  coordinator's workflow run. Each runs actions in its own sandbox (same
  three-uid separation), signs its results with its own OIDC token, and
  returns them. The coordinator verifies worker signatures before using a
  result, exactly as for cached results.
- **Chain of keys:** each job holds one Ed25519 key, which is also its iroh
  endpoint key, certified once by an OIDC token (`aud =
  hartland-key:<key>`). The coordinator dispatches workers with its key;
  a worker checks the coordinator's certificate, and joins by signing
  membership of that key; the coordinator checks the worker's certificate
  (trusted builder, hosted runner, same repository, dispatched) and the
  signature. Workers sign result batches with their key, attaching their
  certificate: a new envelope signature kind, alongside the existing one.
- **Inputs:** workers fetch blobs from the shared tiers (Actions cache,
  GHCR) where they can, and from the coordinator's CAS over iroh
  otherwise: one direct stream moved 23 MB/s, so large source trees
  should not all come through the coordinator.
- **No idle compute:** the coordinator dispatches a worker only while
  buck2 has more runnable actions than its workers can take, and a worker
  exits after a short idle period with no work. Every job has a hard time
  limit.
- **Limits:** 20 concurrent jobs on the Free plan, 40 on Pro (queued beyond
  that); minutes are free for public repositories.

## Open

- Several streams per worker for input transfer, if 23 MB/s per stream is
  the limit.
