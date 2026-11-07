"""Hash-pinned downloads: the only way external bytes enter a Hartland build.

Every pin must carry a sha256. sha1-only pins and unpinned URLs are rejected at
load time. Mirrors are tried before upstream URLs.
"""

_HEX = "0123456789abcdef"

def _check(name, sha256, kwargs):
    if "sha1" in kwargs:
        fail("{}: sha1 pins are not allowed; use sha256".format(name))
    if not sha256:
        fail("{}: sha256 is required".format(name))
    if len(sha256) != 64:
        fail("{}: sha256 must be 64 hex characters, got {}".format(name, len(sha256)))
    for c in sha256.elems():
        if c not in _HEX:
            fail("{}: sha256 must be lowercase hex".format(name))

def pinned_archive(name, urls, sha256, mirrors = [], **kwargs):
    """Download and unpack an archive, verified by sha256."""
    _check(name, sha256, kwargs)
    if not urls:
        fail("{}: at least one upstream url is required".format(name))
    native.http_archive(
        name = name,
        urls = mirrors + urls,
        sha256 = sha256,
        **kwargs
    )

def pinned_file(name, urls, sha256, mirrors = [], **kwargs):
    """Download a single file, verified by sha256."""
    _check(name, sha256, kwargs)
    if not urls:
        fail("{}: at least one upstream url is required".format(name))
    native.http_file(
        name = name,
        urls = mirrors + urls,
        sha256 = sha256,
        **kwargs
    )
