# Hartland design

The design agreed on 7 November 2026, recovered from the session that
started the project, with what has changed since. Build on these decisions;
change them only deliberately, and record the change here.

## Agreed design

- **Repositories:** `hartland` (CLI, source VFS, buck2 rules cell) and
  `hartland-packages` (cell `packages`: packages and OS bundles), split like
  nix and nixpkgs.
- **Build:** buck2, every package natively buckified (kernel, libc and
  compiler included) by per-package generators, written by cheap AI, that
  cover only the subset each package uses. Results are verified against
  upstream: symbols (nm), ABI (abidiff) and upstream test suites. No coarse
  fallbacks such as running a package's own build system as one action.
- **Configuration:** buck2 configuration modifiers for coarse axes (arch,
  libc, optimisation, bootstrap stage); labels on targets (ci, release, os).
- **Seed:** Zig, fetched by sha256, builds our musl, compiler-rt and libc++,
  then LLVM stage 1; LLVM stage 2 is built by stage 1 (fixed point).
- **Sources:** a lazy FUSE VFS is the only view of sources, in development
  and in CI.
  - L0: the upstream tarball, sha256-pinned in `pins.lock`, its tree in the
    CAS.
  - L1: committed patches.
  - L2: local edits, saved as patches.
  - A fake Watchman socket tells buck2 about changes.
  - Listings are metadata-only, so evaluating BUCK files fetches no content.
  - Generated BUCK files list sources explicitly: no globs.
- **Store:** relocatable `<digest>-name/` directories with `$ORIGIN`-style
  relative paths (after fzakaria's "One store, two frontends"); packages are
  installed into the store and linked into Nix-style profiles and
  generations as symlink forests.
- **OS:** antlir2-style features (install, user, unit, etc, firewall port,
  pam, kernel module, ...), system-level aggregators and parameterised
  bundle functions. No NixOS-style options or fixpoint layer. A host is a
  `system(...)` target in the user's own repository. Images are
  composefs/EROFS with a UKI per generation, boot counting and rollback.
- **Rejected:** a separate ingest service, Bazel inside buck2, an options
  "sugar" layer. An RE proxy was rejected at first; see below.

Open questions at the time: init system, hash algorithm, signing, whether
buck2 can take file digests from the VFS without reading content, and FUSE
in CI machines.

## Changed since

- **Where builds run and what is trusted.** Attested builds run on
  GitHub-hosted runners through Hartland's reusable workflow; results are
  signed with GitHub OIDC tokens and cached in GHCR behind the Actions
  cache (see `attestation.md`). BuildBuddy remains optional for everyday
  builds.
- **RE proxy.** Adopted after all, as the signing executor for attested
  builds: only results of actions it ran in its own sandbox can be signed.
- **Signing** is settled: GitHub OIDC tokens, keyrings of trusted builder
  commits.
- **Sources** are tarballs or git commits. A project without release
  tarballs (or whose host blocks automated downloads) is pinned by commit
  with `pinned_git`. The commit is fetched outside every action, by
  `hartland sources fetch` running the seed Zig's package manager
  (`ci/fetch-sources.sh`), and served on localhost by `hartland sources
  serve`, from which buck2's own downloader fetches it like any pinned
  file. The pin is the sha256 of the tree's canonical archive (an
  uncompressed ustar with fixed metadata; the format is specified and
  versioned in `cli/src/sources.rs`), next to Zig's own hash of the tree.

## Not yet following the design

- **No source VFS yet.** `pinned_archive` unpacks tarballs into buck2 output
  directories, and rules reach into them by path projection. Patches are
  build steps, not an L1 layer.
- **musl's file list** is no longer committed. A busybox action lists the
  unpacked tree, and a dynamic action applies musl's Makefile selection
  rules (written in Starlark in `pkg/musl/musl.bzl`) and declares one
  compile per source. That puts the selection inside the build graph rather
  than in a generated BUCK file over the VFS. It is verified against
  upstream's test suite, libc-test (`pkg/libc-test`, built the same way:
  its Makefile's selection in Starlark, one action per compile, link and
  test run), with a committed list of expected failures; static binaries
  only, as there is no dynamic loader yet. Not yet with nm or abidiff.
