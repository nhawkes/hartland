"""Bootstrap stages: a target built at a given stage.

`hartland//cfg:stage` selects which toolchain compiles a target (see
toolchains//:cc). A stage-n toolchain needs the stage-(n-1) build of clang,
lld and llvm-ar: `staged` is that target, configured at another stage.
"""

def _stage_transition_impl(platform: PlatformInfo, refs: struct, attrs: struct) -> PlatformInfo:
    value = getattr(refs, attrs.stage)[ConstraintValueInfo]
    constraints = dict(platform.configuration.constraints)
    constraints[value.setting.label] = value
    return PlatformInfo(
        label = platform.label,
        configuration = ConfigurationInfo(constraints = constraints, values = platform.configuration.values),
    )

_stage_transition = transition(
    impl = _stage_transition_impl,
    refs = {
        "stage0": "hartland//cfg:stage0",
        "stage1": "hartland//cfg:stage1",
        "stage2": "hartland//cfg:stage2",
    },
    attrs = ["stage"],
)

def _staged_impl(ctx: AnalysisContext) -> list[Provider]:
    actual = ctx.attrs.actual
    providers = [actual[DefaultInfo]]
    if RunInfo in actual:
        providers.append(actual[RunInfo])
    return providers

# `actual` built at bootstrap stage `stage` (stage0, stage1 or stage2).
staged = rule(
    impl = _staged_impl,
    attrs = {
        "actual": attrs.dep(),
        "stage": attrs.enum(["stage0", "stage1", "stage2"]),
    },
    cfg = _stage_transition,
)
