"""Compiling C straight from an unpacked source tree with the seed zig.

Each source is compiled from a projection of the pinned source tree, so
nothing is copied into the repository and the prelude's C++ machinery is not
involved. `tree_c` takes an explicit source list; packages that discover their
sources inside the build (from a dynamic action) call the action-level helpers
`tree_c_includes`, `tree_c_compile` and `tree_c_archive` directly.
"""

TreeObjectsInfo = provider(fields = {
    # name (source path with the extension replaced by .o) -> object artifact
    "objects": provider_field(dict[str, Artifact]),
})

def tree_c_obj_name(src: str) -> str:
    """The object name for a source path: its extension replaced by .o."""
    base = src.rsplit(".", 1)[0]
    return base + ".o"

def _parent(p):
    return p.rsplit("/", 1)[0] if "/" in p else ""

def tree_c_includes(tree: Artifact, gen: [Artifact, None], include_dirs: list[str]) -> list[cmd_args]:
    """-I flags for one ordered list of "tree:<dir>" (inside the source tree)
    and "gen:<dir>" (inside the `gen` directory) entries. Order matters: it
    decides which header wins."""
    includes = []
    for inc in include_dirs:
        kind, _, path = inc.partition(":")
        if kind == "tree":
            base = tree
        elif kind == "gen" and gen:
            base = gen
        else:
            fail("include_dirs entries are tree:<dir> or gen:<dir> (with `generated`), got " + inc)
        includes.append(cmd_args(base.project(path) if path else base, format = "-I{}"))
    return includes

def tree_c_compile(
        actions: AnalysisActions,
        zig: typing.Any,
        tree: Artifact,
        src: str,
        flags: list[str],
        includes: list[cmd_args],
        hidden: list[Artifact],
        target: str,
        input_dirs: list[str]) -> Artifact:
    """Compiles `src` (a path inside `tree`) to obj/<src stem>.o. `hidden` is
    the tree plus any generated header directory. With `input_dirs`, the
    action gets only those tree directories, the source's own directory and
    (for arch subdirectories) its parent instead of the whole tree: far
    smaller remote inputs."""
    out = actions.declare_output("obj", tree_c_obj_name(src))
    if input_dirs:
        d = _parent(src)
        dirs = {x: None for x in list(input_dirs) + [d, _parent(d)] if x}
        hidden = [h for h in hidden if h != tree] + [tree.project(x) for x in dirs]
    actions.run(
        cmd_args(
            zig,
            "cc",
            "-target",
            target,
            "-c",
            tree.project(src),
            "-o",
            out.as_output(),
            flags,
            includes,
            hidden = hidden,
        ),
        category = "cc",
        identifier = src,
    )
    return out

def tree_c_archive(actions: AnalysisActions, zig: typing.Any, out: OutputArtifact, name: str, objects: dict[str, Artifact]):
    """Archives `objects` into `out`, members in sorted name order."""
    argsfile = actions.write("{}.objects".format(name), [objects[k] for k in sorted(objects)])
    actions.run(
        cmd_args(zig, "ar", "rcs", out, cmd_args(argsfile, format = "@{}"), hidden = objects.values()),
        category = "ar",
    )

def _tree_c_impl(ctx: AnalysisContext) -> list[Provider]:
    zig = ctx.attrs._zig[RunInfo]
    tree = ctx.attrs.tree[DefaultInfo].default_outputs[0]
    gen = ctx.attrs.generated[DefaultInfo].default_outputs[0] if ctx.attrs.generated else None
    includes = tree_c_includes(tree, gen, ctx.attrs.include_dirs)
    hidden = [tree] + ([gen] if gen else [])

    objects = {}
    for src in ctx.attrs.srcs:
        flags = list(ctx.attrs.cflags) + list(ctx.attrs.src_flags.get(src, []))
        objects[tree_c_obj_name(src)] = tree_c_compile(ctx.actions, zig, tree, src, flags, includes, hidden, ctx.attrs.target, ctx.attrs.input_dirs)

    providers = [TreeObjectsInfo(objects = objects)]
    if ctx.attrs.archive:
        lib = ctx.actions.declare_output(ctx.attrs.archive)
        tree_c_archive(ctx.actions, zig, lib.as_output(), ctx.attrs.archive, objects)
        providers.append(DefaultInfo(default_output = lib, sub_targets = {
            k: [DefaultInfo(default_output = v)]
            for k, v in objects.items()
        }))
    else:
        providers.append(DefaultInfo(default_outputs = [objects[k] for k in sorted(objects)], sub_targets = {
            k: [DefaultInfo(default_output = v)]
            for k, v in objects.items()
        }))
    return providers

# Compiles `srcs` (paths inside `tree`) and optionally archives them.
tree_c = rule(
    impl = _tree_c_impl,
    attrs = {
        "archive": attrs.option(attrs.string(), default = None),
        "cflags": attrs.list(attrs.string(), default = []),
        # A target producing a directory of generated headers.
        "generated": attrs.option(attrs.dep(), default = None),
        "include_dirs": attrs.list(attrs.string(), default = []),
        # If set, each compile gets only these tree directories (plus the
        # source's own) as inputs instead of the whole tree.
        "input_dirs": attrs.list(attrs.string(), default = []),
        "labels": attrs.list(attrs.string(), default = []),
        "src_flags": attrs.dict(attrs.string(), attrs.list(attrs.string()), default = {}),
        "srcs": attrs.list(attrs.string()),
        "target": attrs.string(default = "x86_64-linux-musl"),
        "tree": attrs.dep(),
        "_zig": attrs.default_only(attrs.exec_dep(default = "toolchains//:zig", providers = [RunInfo])),
    },
)

def _sysroot_c_binary_impl(ctx: AnalysisContext) -> list[Provider]:
    zig = ctx.attrs._zig[RunInfo]
    sysroot = ctx.attrs.sysroot[DefaultInfo].default_outputs[0]
    target = ["-target", ctx.attrs.target]
    objects = []
    for src in ctx.attrs.srcs:
        obj = ctx.actions.declare_output("obj", src.short_path + ".o")
        ctx.actions.run(
            cmd_args(
                zig,
                "cc",
                target,
                "-nostdinc",
                cmd_args(sysroot.project("include"), format = "-isystem{}"),
                ctx.attrs.cflags,
                "-c",
                src,
                "-o",
                obj.as_output(),
                hidden = [sysroot],
            ),
            category = "cc",
            identifier = src.short_path,
        )
        objects.append(obj)
    exe = ctx.actions.declare_output(ctx.label.name)
    lib = sysroot.project("lib")
    ctx.actions.run(
        cmd_args(
            zig,
            "cc",
            target,
            "-static",
            "-nostdlib",
            lib.project("crt1.o"),
            lib.project("crti.o"),
            objects,
            lib.project("libc.a"),
            lib.project("crtn.o"),
            ctx.attrs.ldflags,
            "-o",
            exe.as_output(),
            hidden = [sysroot],
        ),
        category = "link",
    )
    return [DefaultInfo(default_output = exe), RunInfo(args = [exe])]

# A static executable linked against a libc sysroot (no zig-bundled libc):
# crt1.o crti.o <objects> libc.a crtn.o, compiled with -nostdinc.
sysroot_c_binary = rule(
    impl = _sysroot_c_binary_impl,
    attrs = {
        "cflags": attrs.list(attrs.string(), default = ["-O2"]),
        "labels": attrs.list(attrs.string(), default = []),
        "ldflags": attrs.list(attrs.string(), default = []),
        "srcs": attrs.list(attrs.source()),
        "sysroot": attrs.dep(),
        "target": attrs.string(default = "x86_64-linux-musl"),
        "_zig": attrs.default_only(attrs.exec_dep(default = "toolchains//:zig", providers = [RunInfo])),
    },
)
