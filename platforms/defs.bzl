"""Hartland execution platforms.

Remote execution properties are fixed here, in code, not taken from target
attributes, so no package can turn the network back on (the hermeticity lint
rejects network properties anywhere in attributes). Only the container image is
configurable, and it must be pinned by digest.
"""

load("@prelude//cfg/exec_platform:marker.bzl", "get_exec_platform_marker")

_HEX = "0123456789abcdef"

# BuildBuddy platform properties for every remote action.
_REMOTE_PROPERTIES = {
    "OSFamily": "Linux",
    "Arch": "amd64",
    # No network inside actions; all bytes enter through pinned downloads.
    "dockerNetwork": "off",
    "workload-isolation-type": "oci",
    # A fresh runner for every action: nothing leaks between builds.
    "recycle-runner": "false",
}

def _check_image(image: str):
    ref, sep, digest = image.partition("@sha256:")
    if not sep or not ref.startswith("docker://"):
        fail("container_image must be docker://<ref>@sha256:<digest>, got {}".format(image))
    if len(digest) != 64 or [c for c in digest.elems() if c not in _HEX]:
        fail("container_image digest must be 64 lowercase hex characters, got {}".format(digest))

def _platform(ctx, name, cfg, remote):
    if remote:
        _check_image(ctx.attrs.container_image)
        props = dict(_REMOTE_PROPERTIES)
        props["container-image"] = ctx.attrs.container_image
        # remote_only (attested builds): nothing runs locally, so no build
        # code shares a uid with the signing proxy, and nothing is uploaded
        # from the client: the proxy only vouches for actions it executed.
        remote_only = ctx.attrs.remote_only
        executor = CommandExecutorConfig(
            # Otherwise local stays enabled for actions marked local_only.
            local_enabled = not remote_only,
            remote_enabled = True,
            remote_cache_enabled = True,
            allow_cache_uploads = not remote_only,
            remote_execution_properties = props,
            remote_execution_use_case = "buck2-default",
            use_windows_path_separators = False,
        )
    elif ctx.attrs.remote_cache:
        # Local execution, remote cache: the hartland proxy (or any REAPI
        # cache) is queried first and local results are uploaded to it.
        executor = CommandExecutorConfig(
            local_enabled = True,
            remote_enabled = False,
            remote_cache_enabled = True,
            allow_cache_uploads = True,
            remote_execution_use_case = "buck2-default",
            use_windows_path_separators = False,
        )
    else:
        executor = CommandExecutorConfig(
            local_enabled = True,
            remote_enabled = False,
            use_windows_path_separators = False,
        )
    return ExecutionPlatformInfo(label = name, configuration = cfg, executor_config = executor)

def _impl(ctx: AnalysisContext) -> list[Provider]:
    constraints = dict()
    constraints.update(ctx.attrs.cpu_configuration[ConfigurationInfo].constraints)
    constraints.update(ctx.attrs.os_configuration[ConfigurationInfo].constraints)
    cfg = ConfigurationInfo(constraints = constraints, values = {})
    name = ctx.label.raw_target()
    platform = _platform(ctx, name, cfg, ctx.attrs.remote)
    return [
        DefaultInfo(),
        platform,
        PlatformInfo(label = str(name), configuration = cfg),
        ExecutionPlatformRegistrationInfo(
            platforms = [platform],
            exec_marker_constraint = get_exec_platform_marker(),
        ),
    ]

hartland_execution_platform = rule(
    impl = _impl,
    attrs = {
        "container_image": attrs.string(default = ""),
        "cpu_configuration": attrs.dep(providers = [ConfigurationInfo]),
        "os_configuration": attrs.dep(providers = [ConfigurationInfo]),
        "remote": attrs.bool(default = False),
        "remote_cache": attrs.bool(default = False),
        "remote_only": attrs.bool(default = False),
    },
)
