"""Hash-pinned downloads: the only way external bytes enter a Hartland build.

Every pin must carry a sha256. sha1-only pins and unpinned URLs are rejected at
load time. Archives are unpacked with the pinned busybox, never the host's tar.
"""

load(":sh.bzl", "ShellInfo", "sh_action")

_HEX = "0123456789abcdef"

def _check(name, urls, sha256, mirrors, kwargs):
    if "sha1" in kwargs:
        fail("{}: sha1 pins are not allowed; use sha256".format(name))
    if not sha256:
        fail("{}: sha256 is required".format(name))
    if len(sha256) != 64:
        fail("{}: sha256 must be 64 hex characters, got {}".format(name, len(sha256)))
    for c in sha256.elems():
        if c not in _HEX:
            fail("{}: sha256 must be lowercase hex".format(name))
    if not urls:
        fail("{}: at least one upstream url is required".format(name))
    if len(mirrors + urls) != 1:
        # buck2's download_file takes a single URL.
        fail("{}: exactly one url is supported for now (mirrors not yet implemented)".format(name))

def _basename(url):
    return url.split("?")[0].split("/")[-1]

def _pinned_file_impl(ctx: AnalysisContext) -> list[Provider]:
    url = ctx.attrs.urls[0]
    out = ctx.actions.declare_output(ctx.attrs.out or _basename(url))
    ctx.actions.download_file(out.as_output(), url, sha256 = ctx.attrs.sha256, is_executable = ctx.attrs.executable, size_bytes = ctx.attrs.size_bytes)
    providers = [DefaultInfo(default_output = out)]
    if ctx.attrs.executable:
        providers.append(RunInfo(args = [out]))
    return providers

_pinned_file = rule(
    impl = _pinned_file_impl,
    attrs = {
        "executable": attrs.bool(default = False),
        "out": attrs.option(attrs.string(), default = None),
        "sha256": attrs.string(),
        # With the size, buck2 skips its HEAD request before downloading:
        # needed for servers that refuse HEAD (gitweb snapshots do).
        "size_bytes": attrs.option(attrs.int(), default = None),
        "urls": attrs.list(attrs.string()),
    },
)

_UNPACK = """
mkdir -p "$OUT"
tmp="$PWD/$BUCK_SCRATCH_PATH/unpack"
rm -rf "$tmp"; mkdir -p "$tmp"
case "$ARCHIVE" in
  *.tar.xz|*.txz)   xz -dc "$ARCHIVE" | tar -x -f - -C "$tmp" ;;
  *.tar.gz|*.tgz)   gzip -dc "$ARCHIVE" | tar -x -f - -C "$tmp" ;;
  *.tar.bz2|*.tbz2) bzip2 -dc "$ARCHIVE" | tar -x -f - -C "$tmp" ;;
  *.tar)            tar -x -f "$ARCHIVE" -C "$tmp" ;;
  *.zip)            unzip -q "$ARCHIVE" -d "$tmp" ;;
  *) echo "pinned_archive: unsupported archive type: $ARCHIVE" >&2; exit 1 ;;
esac
src="$tmp${STRIP_PREFIX:+/$STRIP_PREFIX}"
[ -d "$src" ] || { echo "pinned_archive: strip_prefix not found: $STRIP_PREFIX" >&2; exit 1; }
for f in "$src"/* "$src"/.[!.]* "$src"/..?*; do
  [ -e "$f" ] || [ -L "$f" ] || continue
  mv "$f" "$OUT"/
done
rm -rf "$tmp"
"""

def _pinned_archive_impl(ctx: AnalysisContext) -> list[Provider]:
    url = ctx.attrs.urls[0]
    archive = ctx.actions.declare_output("archive", _basename(url))
    ctx.actions.download_file(archive.as_output(), url, sha256 = ctx.attrs.sha256, size_bytes = ctx.attrs.size_bytes)
    out = ctx.actions.declare_output(ctx.label.name, dir = True)
    sh_action(
        ctx,
        ctx.attrs._sh[ShellInfo],
        _UNPACK,
        env = {
            "ARCHIVE": cmd_args(archive),
            "OUT": out.as_output(),
            "STRIP_PREFIX": ctx.attrs.strip_prefix or "",
        },
        hidden = [archive],
        category = "pinned_archive",
    )
    return [DefaultInfo(default_output = out)]

_pinned_archive = rule(
    impl = _pinned_archive_impl,
    attrs = {
        "sha256": attrs.string(),
        # See _pinned_file.
        "size_bytes": attrs.option(attrs.int(), default = None),
        "strip_prefix": attrs.option(attrs.string(), default = None),
        "urls": attrs.list(attrs.string()),
        "_sh": attrs.default_only(attrs.exec_dep(default = "toolchains//:sh", providers = [ShellInfo])),
    },
)

def pinned_archive(name, urls, sha256, mirrors = [], **kwargs):
    """Download and unpack an archive, verified by sha256."""
    _check(name, urls, sha256, mirrors, kwargs)
    _pinned_archive(name = name, urls = mirrors + urls, sha256 = sha256, **kwargs)

def pinned_file(name, urls, sha256, mirrors = [], **kwargs):
    """Download a single file, verified by sha256."""
    _check(name, urls, sha256, mirrors, kwargs)
    _pinned_file(name = name, urls = mirrors + urls, sha256 = sha256, **kwargs)
