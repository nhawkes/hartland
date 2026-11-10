# Handover (9 November 2026, 23:45 UTC)

(Paths starting `pkg/`, `ci/pin-builder.sh` and `.buckconfig` are in
hartland-packages; the rest are in this repository.)

Hartland: a Linux distribution built from pinned upstream sources with buck2,
hermetic, seeded by Zig, on musl, with builds attested on GitHub-hosted
runners. Two repositories, both on branch `claude/p0-hermeticity` (`main`
holds only dispatch stubs; see below):

- `nhawkes/hartland` (public): rules cell `hartland//`, the Rust CLI
  `hartland` (`cli/`), the trusted builder workflow, docs.
- `nhawkes/hartland-packages` (private): the buck2 root, packages, CI caller.
  hartland is a submodule at `./hartland`.

Read first: `docs/design.md` (the agreed design and where we differ),
`docs/attestation.md`, `docs/scale-out.md`, and
the bootstrap plan artifact (https://claude.ai/artifact/RFiDeJWBagxhp5iUm7yXrK).

## Principles (the user holds these firmly)

1. Everything derived from pinned sources is produced inside the build
   graph, as actions. Nothing generated is committed (no file lists, no
   CMake output, no generated headers).
2. Actions run only tools the graph built from pinned source, plus the seeds
   (Zig, busybox). No host tools; never the `hartland` CLI (infrastructure
   vouches, it never builds).
3. Native buckification, no coarse fallbacks: no CMake/Ninja/Makefile runs.
   A package's build is Starlark we write and commit; source files are
   discovered in the build by dynamic actions (pattern: `pkg/musl/musl.bzl`).
   Configure results are written by our rules.
4. Upstream's own interfaces; no sed; patches case by case, made to survive
   version bumps, caught by tests when wrong.
5. Rust: type-driven (parse, don't validate), no type aliases, use crates,
   no `unsafe` (`#![forbid(unsafe_code)]`), lock-free state (papaya,
   atomics), tracing for logs.
6. Don't waste compute: idle workers leave; jobs have hard limits.
7. To force a rebuild use a cache seed (`[hartland] cache_seed` in
   `.buckconfig`, changes every action digest), never a special mode.

Commits: `git -c user.name="Nathan Hawkes" -c user.email=nhawkes99@gmail.com`.
Pointer-only bumps in hartland-packages: add `[skip ci]` (any other push to
`claude/p0-hermeticity` runs a full attested build). To move the builder pin
use `ci/pin-builder.sh`: it adds the outgoing builder to
`hartland/keys/builders.json` first, otherwise the new builder refuses (and
rebuilds) everything its predecessor signed.

## State

Done and verified in CI:
- musl 1.2.5 from source; its file list discovered in the build (dynamic
  action); byte-identical to the earlier committed-list build.
- libc-test against our musl in the build (`//pkg/libc-test`): 418 tests,
  402 pass, 11 expected failures (musl 1.2.5 bugs, each also failing against
  Zig's musl), 4 `NEEDS_BIN_SH` (not enforced until the sandbox has a
  /bin/sh from pinned busybox), 1 unchecked (root vs non-root).
- Attestation: GitHub OIDC tokens; certified keys (one token certifies an
  Ed25519 key, which then signs batches: envelope kind
  `hartland-certified-key-v0`); keyring of builder commits; two-tier signed
  cache (Actions cache, then GHCR), background promotion.
- Scale-out: the coordinator dispatches worker runs (`workflow_dispatch`)
  only while actions wait; workers join over iroh by a chain of keys, start
  from the coordinator's certified CLI binary, prefetch input trees, wait
  for a direct path, sign their own batches, leave after 60 s idle. Last
  run: 4 workers took 444 of 1,122 actions, all direct, phase 1 in 1 m 54 s.

LLVM 23.1.5, stage 1 (built by the Zig seed):
- `d1df3a1`: llvm-min-tblgen, llvm-tblgen, clang-tblgen, LLVMCore. Attested
  in CI (run 42710029429): 5 workers, fresh-proxy rebuild 100% (4,315).
- `b0731bd` (pushed to `claude/p0-hermeticity`, CI result pending at
  writing): the rest of llvm/lib, clang (26 libraries, `pkg/clang`), lld
  (all five drivers, `pkg/lld`), llvm-ar, clang's resource headers,
  compiler-rt builtins (`//pkg/compiler-rt:builtins`, 173 sources = CMake's
  x86_64 selection). Locally: clang compiles C; our clang + lld + musl link
  a static C program that runs.

Toolchains (`rules/c.bzl`, `toolchains/BUCK` in hartland-packages):
- Rules never name a compiler; they take `CcToolchainInfo` (cc, cxx, ar,
  env, runtime) from `toolchains//:cc` (hosted C: our musl),
  `toolchains//:cc-freestanding` (no libc: musl itself, compiler-rt) or
  `toolchains//:cc-cxx` (C++ with the C++ library: LLVM). Each selects on
  `hartland//cfg:stage1`.
- Stage 0 (default): `zig_cc_toolchain`. Stage 1 (`buck2 build -m
  hartland//cfg:stage1 ...`): `clang_cc_toolchain`, our clang/lld/llvm-ar
  as exec deps, so always the previous stage's build (no cycle); hosted:
  `--sysroot` our musl, `-rtlib=compiler-rt` from a resource dir assembled
  in the build; cc-cxx adds our libc++ (`-nostdinc++ -isystem`, archives
  via `-Wl,`; lld resolves archives in any order).
- Introducing it changed no stage-0 command line (no rebuild).
- Verified locally in stage 1: musl and compiler-rt (objects say clang
  23.1.5); libc-test identical to stage 0 (402 pass, same 11 XFAIL);
  libunwind/libc++abi/libc++ (`pkg/libunwind`, `pkg/libcxxabi`,
  `pkg/libcxx`, shared `pkg/runtimes/runtimes.bzl`) with their smoke test
  (exceptions, threads, filesystem); llvm-tblgen built by our clang against
  our libc++, runs.
- Stage 1 builds clang, lld, llvm-ar (2,407 actions): clang compiled by our
  clang against our libc++.
- **Fixed point** (`-m hartland//cfg:stage2 //pkg/clang:clang`, 4,066
  actions): clang built by the stage-2 compiler is byte-identical to clang
  built by the stage-1 compiler (sha256 68fe3d97...). Toolchain stage 2's
  tools are `staged(..., stage = "stage1")` (`rules/stage.bzl`).

## In flight / next

0. Git-pinned sources (`pinned_git`, `hartland sources fetch|serve`,
   `ci/fetch-sources.sh`): fetched outside actions by the seed's
   `zig fetch`, archived canonically (format v1, `cli/src/sources.rs`),
   served on 127.0.0.1:8981. libc-test uses it (repo.or.cz blocks HTTP
   snapshot downloads, not git). Caveat: Zig 0.17.1 drops the executable
   bit from its cache and hash; the archive takes it from the temporary
   checkout `zig fetch` leaves behind (a Zig bug we depend on). Revisit on
   the next Zig, or verify the bit another way.
1. Done (hartland-packages d4fa708, run of 10 Nov 08:33-09:16 UTC): CI
   builds stage 0, stage 1 and the fixed point (`//pkg/bootstrap`:
   `staged` stage-1 builds and `fixed-point`, which fails unless the
   stage-2 clang equals the stage-1 clang). 21,117 actions, 9,731 run by 8
   workers; fresh-proxy rebuild 100% (21,325). The runner frees its
   preinstalled SDKs first (free disk 8.9 -> 25+ GB).
4. Then Linux From Scratch-level packages, built in stage 1+.
5. busybox 1.37.0 from source (`pkg/busybox`, merged 61099ca): Kconfig
   evaluated and Kbuild applied in Starlark, upstream's helper tools built
   and run in the graph; generated headers and the 575-object set match a
   reference `make` build; upstream testsuite 954 pass / 27 fail (25 also
   fail against glibc; 2 musl behaviour), not yet enforced. Next: make it
   toolchains//:sh in place of the TOFU seed (a later stage, since the
   seed builds it).
6. Local (unsandboxed) builds inherit the daemon's environment beyond PATH
   (e.g. SHELL); attested builds do not (bwrap --clearenv). Fixing it in
   `sh_run` changes every shell action digest: fold it into the next change
   that rebuilds everything anyway.
7. Smaller: sandbox `/bin/sh` from pinned busybox (unblocks 4 libc-test
   tests); nm/abidiff checks against upstream; libunwind/libc++abi keep
   upstream's assertions (`-D_DEBUG`), embedding buck-out paths; pinned
   static bwrap; GHCR index write races; `hartland verify` for consumers.

## Practical notes

- Session GitHub proxy: no Actions API writes, no repo settings; results
  are read from branches (`attest-results`, `attest-workers/<run>`) and
  `gh api .../check-runs`. Making hartland-packages public (Settings) would
  make Actions minutes free.
- `main` in both repos holds `workflow_dispatch` stubs (allowed by the
  user): GitHub only dispatches workflows present on the default branch.
- buck2 binary: install with `hartland/ci/install-buck2.sh` (pinned).
  Local remote-execution checks: `hartland proxy serve --dir ... --listen
  127.0.0.1:8980 --execute unprivileged` with `mode/attested.bcfg` copied to
  `.buckconfig.local` (and `buck2 kill`).
- Disk is the constraint locally (~13 GB free); keep one buck-out (a stage-0
  and a stage-1 LLVM build together take ~12 GB).
