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

def sh_run(
        actions: AnalysisActions,
        shell: ShellInfo,
        script: str,
        env: dict[str, typing.Any],
        hidden: list[typing.Any],
        category: str,
        identifier: [str, None] = None,
        args: list[typing.Any] = []):
    """Runs `script` under the pinned shell, with only its applets on PATH,
    and `args` as its positional parameters ("$@"). Takes `actions` rather
    than a context, so dynamic actions can use it."""
    full_env = dict(env)
    full_env["HARTLAND_SH_BIN"] = cmd_args(shell.bin)
    actions.run(
        cmd_args(shell.bin.project("sh"), "-c", _PROLOGUE + script, "sh", args, hidden = [shell.bin] + hidden),
        env = full_env,
        category = category,
        identifier = identifier,
    )

def sh_action(
        ctx: AnalysisContext,
        shell: ShellInfo,
        script: str,
        env: dict[str, typing.Any],
        hidden: list[typing.Any],
        category: str,
        identifier: [str, None] = None):
    """sh_run with a rule's context."""
    sh_run(ctx.actions, shell, script, env, hidden, category, identifier)

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

_PROGRAM_TEST = """
rc=0
"$@" > "$OUT" 2>&1 || rc=$?
case "$EXPECT:$rc" in
  pass:0|fail:[1-9]*|either:*) ;;
  fail:0)
    cat "$OUT" >&2
    echo "$NAME: expected to fail, but passed; drop it from the expected failures" >&2
    exit 1 ;;
  *)
    cat "$OUT" >&2
    echo "$NAME: test failed with exit status $rc" >&2
    exit 1 ;;
esac
"""

def program_test_action(
        actions: AnalysisActions,
        shell: ShellInfo,
        name: str,
        cmd: cmd_args,
        out: OutputArtifact,
        expect: str = "pass"):
    """Runs `cmd` (a program and its arguments), writing its output to `out`.
    With `expect` "pass" the action fails if the command exits non-zero;
    with "fail", if it exits zero: a known failure that starts passing must
    be noticed, so the expectation can be dropped. "either" records the
    output whatever the outcome, for tests whose result depends on the
    machine running them."""
    if expect not in ["pass", "fail", "either"]:
        fail("expect must be pass, fail or either, got " + expect)
    sh_run(
        actions,
        shell,
        _PROGRAM_TEST,
        env = {
            "EXPECT": expect,
            "NAME": name,
            "OUT": out,
        },
        hidden = [],
        category = "program_test",
        identifier = name,
        args = [cmd],
    )

def _program_test_impl(ctx: AnalysisContext) -> list[Provider]:
    exe = ctx.attrs.program[DefaultInfo].default_outputs[0]
    out = ctx.actions.declare_output(ctx.label.name + ".log")
    program_test_action(ctx.actions, ctx.attrs._sh[ShellInfo], str(ctx.label.raw_target()), cmd_args(exe, ctx.attrs.args), out.as_output())
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
