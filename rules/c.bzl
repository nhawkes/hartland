"""Compiling C straight from an unpacked source tree.

Each source is compiled from a projection of the pinned source tree, so
nothing is copied into the repository and the prelude's C++ machinery is not
involved. `tree_c` takes an explicit source list; packages that discover their
sources inside the build (from a dynamic action) call the action-level helpers
`tree_c_includes`, `tree_c_compile` and `tree_c_archive` directly, and
programs built against a libc sysroot the same way use `sysroot_c_compile`
and `sysroot_c_link`.

C++ (`.cpp`, `.cc`, `.cxx` sources) compiles with `zig c++`, which brings
Zig's bundled libc++ headers. C++ code is built against a `zig_libc`: a
libc installation (our musl, kernel headers, crt objects) that zig is pointed
at through a libc paths file in `ZIG_LIBC`, so zig neither uses its own
bundled musl nor looks at the host. `tree_cxx_link` links against it.

Rules do not name a compiler: they take a `CcToolchainInfo` from
toolchains//:cc (hosted: compiles and links against our libc) or
toolchains//:cc-freestanding (no libc: musl itself, crt objects), so the
bootstrap stage decides which compiler builds what. The seed is
`zig_cc_toolchain`.
"""

TreeObjectsInfo = provider(fields = {
    # name (source path with the extension replaced by .o) -> object artifact
    "objects": provider_field(dict[str, Artifact]),
})

def tree_c_obj_name(src: str) -> str:
    """The object name for a source path: its extension replaced by .o."""
    base = src.rsplit(".", 1)[0]
    return base + ".o"

_CXX_EXTS = ["cpp", "cc", "cxx"]

ZigLibcInfo = provider(fields = {
    # The libc paths file zig reads from $ZIG_LIBC.
    "file": provider_field(Artifact),
    # The installation it names: include/ and lib/.
    "root": provider_field(Artifact),
})

def zig_libc_env(libc: ZigLibcInfo) -> dict[str, typing.Any]:
    """The action environment that makes zig use `libc`."""
    return {"ZIG_LIBC": cmd_args(libc.file, hidden = [libc.root])}

CcToolchainInfo = provider(fields = {
    # The compiler driver for C and assembly sources (flags follow).
    "cc": provider_field(cmd_args),
    # The compiler driver for C++ sources and for links.
    "cxx": provider_field(cmd_args),
    # The archiver, run as <ar> rcs <archive> <objects>.
    "ar": provider_field(cmd_args),
    # Environment for every compile and link (zig: the libc it uses).
    "env": provider_field(dict[str, typing.Any]),
    # The compiler's runtime library, which a -nostdlib link names itself
    # after libc (zig links its own regardless).
    "runtime": provider_field(list[Artifact]),
})

def _zig_cc_toolchain_impl(ctx: AnalysisContext) -> list[Provider]:
    zig = ctx.attrs.zig[RunInfo]
    env = zig_libc_env(ctx.attrs.libc[ZigLibcInfo]) if ctx.attrs.libc else {}
    return [
        DefaultInfo(),
        CcToolchainInfo(
            cc = cmd_args(zig, "cc"),
            cxx = cmd_args(zig, "c++"),
            ar = cmd_args(zig, "ar"),
            env = env,
            runtime = [],
        ),
    ]

# The seed toolchain: zig cc / zig c++ / zig ar. With `libc`, compiles and
# links use that libc installation (hosted); without, only what each action
# passes itself (freestanding: -nostdinc and explicit include directories).
zig_cc_toolchain = rule(
    impl = _zig_cc_toolchain_impl,
    attrs = {
        "libc": attrs.option(attrs.dep(providers = [ZigLibcInfo]), default = None),
        "zig": attrs.exec_dep(providers = [RunInfo]),
    },
    is_toolchain_rule = True,
)

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
        cc: CcToolchainInfo,
        tree: Artifact,
        src: str,
        flags: list[str],
        includes: list[cmd_args],
        hidden: list[Artifact],
        target: str,
        input_dirs: list[str]) -> Artifact:
    """Compiles `src` (a path inside `tree`) to obj/<src stem>.o, as C++ for
    C++ extensions and C (or assembly) otherwise. `hidden` is
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
            cc.cxx if src.rsplit(".", 1)[-1] in _CXX_EXTS else cc.cc,
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
        env = cc.env,
        category = "cc",
        identifier = src,
    )
    return out

def tree_c_archive(actions: AnalysisActions, cc: CcToolchainInfo, out: OutputArtifact, name: str, objects: dict[str, Artifact]):
    """Archives `objects` into `out`, members in sorted name order."""
    argsfile = actions.write("{}.objects".format(name), [objects[k] for k in sorted(objects)])
    actions.run(
        cmd_args(cc.ar, "rcs", out, cmd_args(argsfile, format = "@{}"), hidden = objects.values()),
        category = "ar",
    )

def tree_cxx_link(
        actions: AnalysisActions,
        cc: CcToolchainInfo,
        out: OutputArtifact,
        objects: list[Artifact],
        archives: list[Artifact],
        flags: list[str],
        target: str,
        whole_archives: list[Artifact] = []):
    """Links a static C++ executable against the toolchain's libc and C++
    library (the seed: Zig's libc++).
    `archives` must be in link order (dependents before dependencies);
    `whole_archives` are linked entirely, like objects (for code that only
    registers itself through static constructors).
    `flags` should carry the optimisation level: zig builds libc++ for the
    link in the mode it implies (no -O means Debug, with UBSan traps)."""
    whole = ["-Wl,--whole-archive"] + whole_archives + ["-Wl,--no-whole-archive"] if whole_archives else []
    argsfile = actions.write("link.args", objects + whole + archives)
    actions.run(
        cmd_args(
            cc.cxx,
            "-target",
            target,
            "-static",
            flags,
            cmd_args(argsfile, format = "@{}"),
            "-o",
            out,
            hidden = objects + whole_archives + archives,
        ),
        env = cc.env,
        category = "link",
    )

def _zig_libc_impl(ctx: AnalysisContext) -> list[Provider]:
    root = ctx.attrs.root[DefaultInfo].default_outputs[0]
    # Paths are relative to the action's working directory (the project
    # root), where zig resolves them.
    file = ctx.actions.write(
        "libc.txt",
        cmd_args(
            cmd_args("include_dir=", root.project("include"), delimiter = ""),
            cmd_args("sys_include_dir=", root.project("include"), delimiter = ""),
            cmd_args("crt_dir=", root.project("lib"), delimiter = ""),
            # Where zig looks for crtbegin.o and crtend.o.
            cmd_args("cc_dir=", root.project("lib"), delimiter = ""),
            "msvc_lib_dir=",
            "kernel32_lib_dir=",
            "darwin_sdk_dir=",
        ),
    )
    return [DefaultInfo(default_output = file, other_outputs = [root]), ZigLibcInfo(file = file, root = root)]

# A libc installation for zig: `root` holds include/ (libc and kernel
# headers) and lib/ (crt1.o crti.o crtn.o crtbegin.o crtend.o libc.a and the
# empty libm.a etc. that musl installs).
zig_libc = rule(
    impl = _zig_libc_impl,
    attrs = {"root": attrs.dep()},
)

def _tree_c_impl(ctx: AnalysisContext) -> list[Provider]:
    cc = ctx.attrs._cc[CcToolchainInfo]
    tree = ctx.attrs.tree[DefaultInfo].default_outputs[0]
    gen = ctx.attrs.generated[DefaultInfo].default_outputs[0] if ctx.attrs.generated else None
    includes = tree_c_includes(tree, gen, ctx.attrs.include_dirs)
    hidden = [tree] + ([gen] if gen else [])

    objects = {}
    for src in ctx.attrs.srcs:
        flags = list(ctx.attrs.cflags) + list(ctx.attrs.src_flags.get(src, []))
        objects[tree_c_obj_name(src)] = tree_c_compile(ctx.actions, cc, tree, src, flags, includes, hidden, ctx.attrs.target, ctx.attrs.input_dirs)

    providers = [TreeObjectsInfo(objects = objects)]
    if ctx.attrs.archive:
        lib = ctx.actions.declare_output(ctx.attrs.archive)
        tree_c_archive(ctx.actions, cc, lib.as_output(), ctx.attrs.archive, objects)
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
        "_cc": attrs.default_only(attrs.toolchain_dep(default = "toolchains//:cc-freestanding", providers = [CcToolchainInfo])),
    },
)

def sysroot_c_cmd(cc: CcToolchainInfo, sysroot: Artifact, target: str) -> cmd_args:
    """The C compiler for `target` against the headers of `sysroot` only
    (-nostdinc; no compiler-bundled libc headers)."""
    return cmd_args(
        cc.cc,
        "-target",
        target,
        "-nostdinc",
        cmd_args(sysroot.project("include"), format = "-isystem{}"),
        hidden = [sysroot],
    )

def sysroot_c_compile(
        actions: AnalysisActions,
        cc: CcToolchainInfo,
        sysroot: Artifact,
        src: Artifact,
        out: OutputArtifact,
        flags: list[typing.Any],
        hidden: list[Artifact],
        target: str,
        identifier: str):
    """Compiles `src` to `out` with sysroot_c_cmd."""
    actions.run(
        cmd_args(sysroot_c_cmd(cc, sysroot, target), flags, "-c", src, "-o", out, hidden = hidden),
        category = "cc",
        identifier = identifier,
    )

def sysroot_c_link(
        actions: AnalysisActions,
        cc: CcToolchainInfo,
        sysroot: Artifact,
        objects: list[typing.Any],
        out: OutputArtifact,
        ldflags: list[typing.Any],
        target: str,
        identifier: [str, None] = None):
    """Links a static executable from `objects` (objects or archives) and the
    sysroot's libc: crt1.o crti.o <objects> libc.a crtn.o."""
    lib = sysroot.project("lib")
    actions.run(
        cmd_args(
            cc.cc,
            "-target",
            target,
            "-static",
            "-nostdlib",
            lib.project("crt1.o"),
            lib.project("crti.o"),
            objects,
            lib.project("libc.a"),
            cc.runtime,
            lib.project("crtn.o"),
            ldflags,
            "-o",
            out,
            hidden = [sysroot],
        ),
        category = "link",
        identifier = identifier,
    )

def _sysroot_c_binary_impl(ctx: AnalysisContext) -> list[Provider]:
    cc = ctx.attrs._cc[CcToolchainInfo]
    sysroot = ctx.attrs.sysroot[DefaultInfo].default_outputs[0]
    objects = []
    for src in ctx.attrs.srcs:
        obj = ctx.actions.declare_output("obj", src.short_path + ".o")
        sysroot_c_compile(ctx.actions, cc, sysroot, src, obj.as_output(), ctx.attrs.cflags, [], ctx.attrs.target, src.short_path)
        objects.append(obj)
    exe = ctx.actions.declare_output(ctx.label.name)
    sysroot_c_link(ctx.actions, cc, sysroot, objects, exe.as_output(), ctx.attrs.ldflags, ctx.attrs.target)
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
        "_cc": attrs.default_only(attrs.toolchain_dep(default = "toolchains//:cc", providers = [CcToolchainInfo])),
    },
)

def _clang_cc_toolchain_impl(ctx: AnalysisContext) -> list[Provider]:
    clang = ctx.attrs.clang[RunInfo]
    triple = ctx.attrs.triple
    # <resource dir>: include/ (clang/lib/Headers) and, hosted, the
    # per-target runtime directory (LLVM_ENABLE_PER_TARGET_RUNTIME_DIR, the
    # Linux default) with compiler-rt's builtins and crt objects.
    resource = {"include": ctx.attrs.resource_headers[DefaultInfo].default_outputs[0]}
    # Every link uses our lld, which picks its flavour from argv[0]: the
    # driver runs it as ld.lld.
    ld = ctx.actions.symlinked_dir("ld", {"ld.lld": ctx.attrs.lld[DefaultInfo].default_outputs[0]})
    flags = [cmd_args(ld.project("ld.lld"), format = "--ld-path={}")]
    rt = ctx.attrs.compiler_rt
    if ctx.attrs.sysroot:
        lib = "lib/" + triple + "/"
        resource[lib + "libclang_rt.builtins.a"] = rt["builtins"]
        resource[lib + "clang_rt.crtbegin.o"] = rt["crtbegin"]
        resource[lib + "clang_rt.crtend.o"] = rt["crtend"]
        flags += [
            cmd_args(ctx.attrs.sysroot[DefaultInfo].default_outputs[0], format = "--sysroot={}"),
            "-rtlib=compiler-rt",
        ]
    cxx_flags = []
    if ctx.attrs.cxx_headers:
        # Our libc++ in place of a toolchain-bundled one: its headers ahead
        # of the libc's (-isystem precedes the system directories), its
        # archives on every link (lld resolves archives in any order).
        headers = ctx.attrs.cxx_headers[DefaultInfo].default_outputs[0]
        cxx_flags = [
            "-nostdinc++",
            cmd_args(headers.project("include/c++/v1"), format = "-isystem{}"),
            "-nostdlib++",
        ] + [cmd_args(d[DefaultInfo].default_outputs[0], format = "-Wl,{}") for d in ctx.attrs.cxx_libs]
    resource_dir = ctx.actions.symlinked_dir("resource", resource)
    # The link flags are unused in compiles, which -Werror would reject.
    driver = cmd_args(
        clang,
        cmd_args(resource_dir, format = "-resource-dir={}"),
        "--start-no-unused-arguments",
        flags,
        "--end-no-unused-arguments",
    )
    return [
        DefaultInfo(),
        CcToolchainInfo(
            cc = driver,
            # Without cxx_headers, callers bring -nostdinc++ and a library
            # (the runtimes themselves are built this way).
            cxx = cmd_args(
                driver,
                "--driver-mode=g++",
                "--start-no-unused-arguments",
                cxx_flags,
                "--end-no-unused-arguments",
            ) if cxx_flags else cmd_args(driver, "--driver-mode=g++"),
            ar = cmd_args(ctx.attrs.ar[RunInfo]),
            env = {},
            runtime = [rt["builtins"]] if ctx.attrs.sysroot else [],
        ),
    ]

# A toolchain of our own clang. The tools are exec deps, configured for the
# execution platform, which carries no bootstrap stage: they are always the
# previous stage's build, so selecting this toolchain for a stage does not
# make clang depend on itself. With `sysroot` (and `compiler_rt`) it is
# hosted: links use our musl and compiler-rt; without, freestanding.
# Links always use our lld.
clang_cc_toolchain = rule(
    impl = _clang_cc_toolchain_impl,
    attrs = {
        "ar": attrs.exec_dep(providers = [RunInfo]),
        "clang": attrs.exec_dep(providers = [RunInfo]),
        # builtins, crtbegin, crtend -> artifacts (compiler-rt's outputs).
        "compiler_rt": attrs.dict(attrs.string(), attrs.source(), default = {}),
        # The C++ standard library: an installed header tree (include/c++/v1)
        # and its archives (libc++, libc++abi, libunwind).
        "cxx_headers": attrs.option(attrs.dep(), default = None),
        "cxx_libs": attrs.list(attrs.dep(), default = []),
        "lld": attrs.exec_dep(providers = [RunInfo]),
        "resource_headers": attrs.dep(),
        "sysroot": attrs.option(attrs.dep(), default = None),
        "triple": attrs.string(default = "x86_64-unknown-linux-musl"),
    },
    is_toolchain_rule = True,
)
