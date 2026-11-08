# Hartland

The Hartland tool: CLI, source VFS, and the `hartland` buck2 rules cell
(`pinned_archive`, configuration constraints, and later features/system rules).

Package definitions live in `hartland-packages`.

## Modifying upstream

Packages build pinned, unmodified upstream sources. Any change on top of them
is judged by two outcomes, not by the method used:

1. **Survive version bumps.** A modification should need as little rework as
   possible when upstream moves.
2. **Be caught when wrong.** More important: a change that misapplies, matches
   nothing, breaks behaviour, or is no longer needed must fail the build or a
   test, not pass silently.

Flags, generated headers, shims, output fixups, unified diffs, AST rewrites
and tests are all acceptable; choose per package. Two things are fixed: no
text-substitution edits (`sed` and similar), which fail silently, and every
modification runs as a Buck action under the pinned tools.

What the infrastructure does to support this:

- Every modification carries a check that fails when it is wrong: a package
  test, a symbol or ABI check, an expected match count, or a diff that refuses
  to apply. The package chooses which.
- A version bump rebuilds the package and its reverse dependencies and runs
  their tests before merge.
- Where cheap, a test shows the modification is still needed, by failing
  against unmodified upstream. When upstream fixes the issue, that test passes
  without us and the modification can go.
