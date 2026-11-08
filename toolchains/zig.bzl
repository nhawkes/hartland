"""Zig seed toolchain: no shell, no host tools, no $HOME.

`zig_seed` takes an unpacked Zig release and builds `zig-wrap` with it.
`cxx_zig_toolchain` is the prelude's toolchain of the same name with its
generated `zig_cc.sh`-style shell scripts replaced by direct invocations.
The prelude is dual-licensed MIT / Apache-2.0 (Meta Platforms, Inc.).
"""

load(
    "@prelude//cxx:cxx_toolchain_types.bzl",
    "BinaryUtilitiesInfo",
    "CCompilerInfo",
    "CxxCompilerInfo",
    "CxxInternalTools",
    "LinkerInfo",
    "LinkerType",
    "ShlibInterfacesMode",
    "StripFlagsInfo",
    "cxx_toolchain_infos",
)
load("@prelude//cxx:headers.bzl", "HeaderMode")
load("@prelude//linking:link_info.bzl", "LinkStyle")
load("@prelude//toolchains/cxx/zig:defs.bzl", "ZigDistributionInfo")

def _zig_seed_impl(ctx: AnalysisContext) -> list[Provider]:
    release = ctx.attrs.release[DefaultInfo].default_outputs[0]
    zig = cmd_args(release.project("zig"), hidden = [release])
    src = ctx.attrs._wrapper_src[DefaultInfo].default_outputs[0]

    # Build the wrapper with the seed zig itself: no shell, no libc.
    wrapper = ctx.actions.declare_output("zig-wrap")
    cache = ctx.actions.declare_output("zig-wrap-cache", dir = True)
    global_cache = ctx.actions.declare_output("zig-wrap-global-cache", dir = True)
    ctx.actions.run(
        cmd_args(
            zig,
            "build-exe",
            src,
            "-OReleaseSafe",
            # Exec platforms are x86_64 Linux; baseline keeps the output host-independent.
            "-target",
            "x86_64-linux",
            "-mcpu",
            "baseline",
            "-fstrip",
            "--cache-dir",
            cache.as_output(),
            "--global-cache-dir",
            global_cache.as_output(),
            cmd_args(wrapper.as_output(), format = "-femit-bin={}"),
        ),
        category = "zig_wrap",
    )

    return [
        DefaultInfo(default_output = release),
        RunInfo(args = cmd_args(wrapper, zig)),
        ZigDistributionInfo(version = ctx.attrs.version, arch = ctx.attrs.arch, os = ctx.attrs.os),
    ]

# An unpacked Zig release (pinned_archive with strip_prefix), runnable through
# zig-wrap: nested argsfiles flattened, caches kept in the action's scratch space.
zig_seed = rule(
    impl = _zig_seed_impl,
    attrs = {
        "arch": attrs.string(),
        "os": attrs.string(),
        "release": attrs.dep(),
        "version": attrs.string(),
        "_wrapper_src": attrs.default_only(attrs.dep(default = "hartland//toolchains:zig_wrap.zig")),
    },
)

def _cxx_zig_toolchain_impl(ctx: AnalysisContext) -> list[Provider]:
    dist = ctx.attrs.distribution[ZigDistributionInfo]
    if dist.os != "linux":
        fail("hartland cxx_zig_toolchain targets Linux only, got {}".format(dist.os))
    zig = ctx.attrs.distribution[RunInfo]
    target = ["-target", ctx.attrs.target] if ctx.attrs.target else []

    def tool(sub):
        return RunInfo(args = cmd_args(zig, sub))

    # Binary utilities not in the zig distribution fail loudly rather than
    # silently reaching for host binaries.
    missing = RunInfo(args = ["/hartland/no-such-tool"])

    return [ctx.attrs.distribution[DefaultInfo]] + cxx_toolchain_infos(
        internal_tools = ctx.attrs._cxx_internal_tools[CxxInternalTools],
        platform_name = dist.arch,
        c_compiler_info = CCompilerInfo(
            compiler = tool("cc"),
            compiler_type = "clang",
            # Hermetic actions: safe to share through a remote cache.
            allow_cache_upload = True,
            compiler_flags = cmd_args(target, ctx.attrs.c_compiler_flags),
            preprocessor_flags = cmd_args(ctx.attrs.c_preprocessor_flags),
        ),
        cxx_compiler_info = CxxCompilerInfo(
            compiler = tool("c++"),
            compiler_type = "clang",
            allow_cache_upload = True,
            compiler_flags = cmd_args(target, ctx.attrs.cxx_compiler_flags),
            preprocessor_flags = cmd_args(ctx.attrs.cxx_preprocessor_flags),
        ),
        linker_info = LinkerInfo(
            archiver = tool("ar"),
            archiver_type = "gnu",
            archiver_supports_argfiles = True,
            archive_objects_locally = False,
            binary_extension = "",
            generate_linker_maps = False,
            link_binaries_locally = False,
            link_libraries_locally = False,
            link_style = LinkStyle(ctx.attrs.link_style),
            link_weight = 1,
            linker = tool("c++"),
            linker_flags = cmd_args(target, ctx.attrs.linker_flags),
            object_file_extension = "o",
            shlib_interfaces = ShlibInterfacesMode("disabled"),
            shared_dep_runtime_ld_flags = [],
            shared_library_name_default_prefix = "lib",
            shared_library_name_format = "{}.so",
            shared_library_versioned_name_format = "{}.so.{}",
            static_dep_runtime_ld_flags = [],
            static_library_extension = "a",
            static_pic_dep_runtime_ld_flags = [],
            independent_shlib_interface_linker_flags = [],
            type = LinkerType("gnu"),
            use_archiver_flags = True,
            is_pdb_generated = False,
        ),
        binary_utilities_info = BinaryUtilitiesInfo(
            dwp = None,
            nm = missing,
            objcopy = tool("objcopy"),
            ranlib = tool("ranlib"),
            strip = missing,
        ),
        header_mode = HeaderMode("symlink_tree_only"),
        strip_flags_info = StripFlagsInfo(
            strip_debug_flags = None,
            strip_non_global_flags = None,
            strip_all_flags = None,
        ),
    )

cxx_zig_toolchain = rule(
    impl = _cxx_zig_toolchain_impl,
    attrs = {
        "c_compiler_flags": attrs.list(attrs.arg(), default = []),
        "c_preprocessor_flags": attrs.list(attrs.arg(), default = []),
        "cxx_compiler_flags": attrs.list(attrs.arg(), default = []),
        "cxx_preprocessor_flags": attrs.list(attrs.arg(), default = []),
        "distribution": attrs.exec_dep(providers = [RunInfo, ZigDistributionInfo]),
        "link_style": attrs.enum(LinkStyle.values(), default = "static"),
        "linker_flags": attrs.list(attrs.arg(), default = []),
        "target": attrs.option(attrs.string(), default = None),
        "_cxx_internal_tools": attrs.default_only(attrs.dep(providers = [CxxInternalTools], default = "prelude//cxx/tools:internal_tools")),
    },
    is_toolchain_rule = True,
)
