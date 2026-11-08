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

## Design

- **Coordinator:** the job running buck2 and the signing proxy. It hands
  each action to a free worker over iroh instead of running it itself.
- **Workers:** jobs of the same pinned builder workflow, started by the
  coordinator's workflow run. Each runs actions in its own sandbox (same
  three-uid separation), signs its results with its own OIDC token, and
  returns them. The coordinator verifies worker signatures before using a
  result, exactly as for cached results.
- **Rendezvous and trust:** as in the spike. Tokens bind each peer's
  endpoint key; peers must be the trusted builder at a keyring commit, on a
  hosted runner, in the same run.
- **Inputs:** workers fetch blobs from the shared tiers (Actions cache,
  GHCR) where they can, and from the coordinator's CAS over iroh
  otherwise: one direct stream moved 23 MB/s, so large source trees
  should not all come through the coordinator.
- **No idle compute:** the coordinator asks for workers only while buck2
  has more runnable actions than it can run, and a worker exits after a
  short idle period with no work. Every job has a hard time limit.
- **Limits:** 20 concurrent jobs on the Free plan, 40 on Pro (queued beyond
  that); minutes are free for public repositories.

## Open

- How the coordinator starts workers mid-run (a fixed matrix sized from
  the plan, or a dispatch it triggers itself), so that none sit idle.
- Several streams per worker for input transfer, if 23 MB/s per stream is
  the limit.
