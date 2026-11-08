"""A pinned shell for build actions, so nothing depends on the host OS.

The prelude's genrule hard-codes `/usr/bin/env bash` and its http_archive runs
`/bin/sh` with the host's tar. Hartland actions instead run a pinned static
busybox, exposed as a directory of applet links that becomes the whole PATH.
"""

ShellInfo = provider(fields = {
    # Directory of applet links (sh, sed, tar, ...), all pointing at busybox.
    "bin": provider_field(Artifact),
})

# Applets exposed on PATH. Everything else in busybox stays unreachable, which
# keeps what scripts can depend on explicit.
BUSYBOX_APPLETS = [
    "[", "awk", "basename", "bzip2", "cat", "chmod", "cmp", "cp", "cut", "date",
    "dd", "diff", "dirname", "echo", "egrep", "env", "expr", "false", "find",
    "grep", "gzip", "head", "install", "ln", "ls", "mkdir", "mktemp", "mv", "od",
    "patch", "printf", "pwd", "readlink", "realpath", "rm", "rmdir", "sed",
    "sh", "sha256sum", "sleep", "sort", "stat", "tail", "tar", "tee", "test",
    "touch", "tr", "true", "uniq", "unzip", "wc", "xargs", "xz",
]

def _busybox_shell_impl(ctx: AnalysisContext) -> list[Provider]:
    busybox = ctx.attrs.busybox[DefaultInfo].default_outputs[0]
    # busybox picks the applet from argv[0], so each link's name is the tool.
    bin = ctx.actions.symlinked_dir("bin", {a: busybox for a in BUSYBOX_APPLETS})
    return [DefaultInfo(default_output = bin), ShellInfo(bin = bin)]

busybox_shell = rule(
    impl = _busybox_shell_impl,
    attrs = {"busybox": attrs.dep()},
)

_PROLOGUE = """set -eu
set -o pipefail
export PATH="$PWD/$HARTLAND_SH_BIN"
unset HARTLAND_SH_BIN
"""

def sh_action(
        ctx: AnalysisContext,
        shell: ShellInfo,
        script: str,
        env: dict[str, typing.Any],
        hidden: list[typing.Any],
        category: str,
        identifier: [str, None] = None):
    """Runs `script` under the pinned shell, with only its applets on PATH."""
    full_env = dict(env)
    full_env["HARTLAND_SH_BIN"] = cmd_args(shell.bin)
    ctx.actions.run(
        cmd_args(shell.bin.project("sh"), "-c", _PROLOGUE + script, hidden = [shell.bin] + hidden),
        env = full_env,
        category = category,
        identifier = identifier,
    )

def _sh_genrule_impl(ctx: AnalysisContext) -> list[Provider]:
    out = ctx.actions.declare_output(ctx.attrs.out)
    srcs = ctx.attrs.srcs
    env = {k: cmd_args(v) for k, v in ctx.attrs.env.items()}
    env["OUT"] = out.as_output()
    env["SRCS"] = cmd_args(srcs, delimiter = " ")
    # $OUT and $SRCS are made absolute so scripts may cd freely.
    script = """OUT="$PWD/$OUT"
_s=; for _f in $SRCS; do _s="$_s $PWD/$_f"; done; SRCS="${_s# }"; unset _s _f
mkdir -p "$(dirname "$OUT")"
""" + ctx.attrs.cmd
    sh_action(ctx, ctx.attrs._sh[ShellInfo], script, env, srcs, "sh_genrule")
    return [DefaultInfo(default_output = out)]

# genrule replacement: runs `cmd` under the pinned busybox shell. Inputs arrive
# as $SRCS (space-separated, absolute); write the result to $OUT.
sh_genrule = rule(
    impl = _sh_genrule_impl,
    attrs = {
        "cmd": attrs.string(),
        "env": attrs.dict(attrs.string(), attrs.arg(), default = {}),
        "labels": attrs.list(attrs.string(), default = []),
        "out": attrs.string(),
        "srcs": attrs.list(attrs.source(), default = []),
        "_sh": attrs.default_only(attrs.exec_dep(default = "toolchains//:sh", providers = [ShellInfo])),
    },
)

def _program_test_impl(ctx: AnalysisContext) -> list[Provider]:
    exe = ctx.attrs.program[DefaultInfo].default_outputs[0]
    out = ctx.actions.declare_output(ctx.label.name + ".log")
    script = """
"$PWD/$PROGRAM" {args} > "$OUT" 2>&1 || {{ rc=$?; cat "$OUT" >&2; echo "test failed with exit status $rc" >&2; exit 1; }}
""".format(args = " ".join(['"{}"'.format(a) for a in ctx.attrs.args]))
    sh_action(
        ctx,
        ctx.attrs._sh[ShellInfo],
        script,
        env = {"OUT": out.as_output(), "PROGRAM": cmd_args(exe)},
        hidden = [exe],
        category = "program_test",
    )
    return [DefaultInfo(default_output = out)]

# A test as a build action: runs `program` in the action sandbox and fails the
# build if it exits non-zero. Its log is an ordinary output, so attested
# builds execute, cache and sign test results like everything else.
program_test = rule(
    impl = _program_test_impl,
    attrs = {
        "args": attrs.list(attrs.string(), default = []),
        "labels": attrs.list(attrs.string(), default = []),
        "program": attrs.dep(),
        "_sh": attrs.default_only(attrs.exec_dep(default = "toolchains//:sh", providers = [ShellInfo])),
    },
)
