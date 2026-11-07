"""Zig seed toolchain helpers."""

load("@prelude//toolchains/cxx/zig:defs.bzl", "ZigDistributionInfo")

def _flattening_zig_impl(ctx: AnalysisContext) -> list[Provider]:
    dist = ctx.attrs.distribution
    script = ctx.attrs._flatten[DefaultInfo].default_outputs[0]
    return [
        dist[DefaultInfo],
        dist[ZigDistributionInfo],
        RunInfo(args = cmd_args("bash", script, dist[RunInfo])),
    ]

# Wraps a zig_distribution so nested buck2 argsfiles are flattened before zig sees them.
flattening_zig = rule(
    impl = _flattening_zig_impl,
    attrs = {
        "distribution": attrs.exec_dep(providers = [RunInfo, ZigDistributionInfo]),
        "_flatten": attrs.default_only(attrs.dep(default = "hartland//toolchains:zig-flatten.sh")),
    },
)
