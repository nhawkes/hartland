"""CMake's configure_file(), in Starlark, for packages that build with CMake.

Upstream's `*.cmake` / `*.in` templates stay the source of truth; the values
CMake would have computed at configure time are written in Starlark by the
package (reviewed, committed) instead of being probed by running CMake. A
dynamic action reads each template from the unpacked tree and expands it:

  #cmakedefine VAR rest     -> #define VAR rest     or  /* #undef VAR */
  #cmakedefine01 VAR        -> #define VAR 1        or  #define VAR 0
  ${VAR} and @VAR@          -> the value (only @VAR@ with at_only)
A value may also be a file's contents (`file_values`: CMake's file(READ ...)
into a variable), read from the tree in the same dynamic action.

Truthiness is CMake's: "", 0, OFF, NO, FALSE, N, IGNORE, NOTFOUND and
*-NOTFOUND are false. Unlike CMake, a variable the template uses but `values`
does not set fails the build instead of expanding to nothing, so a version
bump that adds configuration is caught rather than silently defaulted.
"""

_FALSE = ["", "0", "OFF", "NO", "FALSE", "N", "IGNORE", "NOTFOUND"]
_IDENT = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_"

def _truthy(v: str) -> bool:
    u = v.upper()
    return u not in _FALSE and not u.endswith("-NOTFOUND")

def _is_ident(s: str) -> bool:
    if not s:
        return False
    for c in s.elems():
        if c not in _IDENT:
            return False
    return True

def _lookup(name: str, values: dict[str, str], template: str) -> str:
    if name not in values:
        fail("{}: no value for CMake variable {}".format(template, name))
    return values[name]

def _expand(line: str, values: dict[str, str], at_only: bool, template: str) -> str:
    """Replaces ${VAR} (unless at_only) and @VAR@ in one line."""
    out = ""
    rest = line
    for _ in range(len(line) + 1):
        if not rest:
            break
        d = -1 if at_only else rest.find("${")
        a = rest.find("@")
        if d < 0 and a < 0:
            out += rest
            break
        if d >= 0 and (a < 0 or d < a):
            end = rest.find("}", d + 2)
            name = rest[d + 2:end] if end >= 0 else ""
            if _is_ident(name):
                out += rest[:d] + _lookup(name, values, template)
                rest = rest[end + 1:]
            else:
                out += rest[:d + 2]
                rest = rest[d + 2:]
        else:
            end = rest.find("@", a + 1)
            name = rest[a + 1:end] if end >= 0 else ""
            if _is_ident(name):
                out += rest[:a] + _lookup(name, values, template)
                rest = rest[end + 1:]
            else:
                # A lone @ (an e-mail address, a doc comment): kept as is.
                out += rest[:a + 1]
                rest = rest[a + 1:]
    return out

def _directive(line: str):
    """For a `#cmakedefine` or `#cmakedefine01` line: (the text up to and
    including `#` and any blanks after it, kind, rest after the directive),
    else None."""
    stripped = line.lstrip(" \t")
    if not stripped.startswith("#"):
        return None
    body = stripped[1:].lstrip(" \t")
    for kind in ["cmakedefine01", "cmakedefine"]:
        if body.startswith(kind) and body[len(kind):len(kind) + 1] in [" ", "\t"]:
            return (line[:len(line) - len(body)], kind, body[len(kind):].lstrip(" \t"))
    return None

def cmake_configure(text: str, values: dict[str, str], at_only: bool = False, template: str = "template") -> str:
    """Expands one template the way configure_file() does."""
    lines = []
    for line in text.split("\n"):
        d = None if at_only else _directive(line)
        if d == None:
            lines.append(_expand(line, values, at_only, template))
            continue
        indent, kind, rest = d
        var = rest
        tail = ""
        for i in range(len(rest)):
            if rest[i] in [" ", "\t"]:
                var = rest[:i]
                tail = rest[i:]
                break
        on = _truthy(_lookup(var, values, template))
        if kind == "cmakedefine01":
            lines.append("{}define {} {}".format(indent, var, "1" if on else "0"))
        elif on:
            lines.append("{}define {}{}".format(indent, var, _expand(tail, values, False, template)))
        else:
            lines.append("/* #undef {} */".format(var))
    return "\n".join(lines)

def _configure_impl(
        actions: AnalysisActions,
        templates: dict[str, ArtifactValue],
        values: dict[str, str],
        file_values: dict[str, ArtifactValue],
        at_only: list[str],
        out: OutputArtifact) -> list[Provider]:
    values = dict(values)
    for name, f in file_values.items():
        if name in values:
            fail("{} is set both as a value and as a file's contents".format(name))
        values[name] = f.read_string()
    files = {}
    for path, template in templates.items():
        text = cmake_configure(template.read_string(), values, path in at_only, path)
        files[path] = actions.write(path, text)
    actions.copied_dir(out, files)
    return []

_configure = dynamic_actions(
    impl = _configure_impl,
    attrs = {
        "at_only": dynattrs.value(list[str]),
        "file_values": dynattrs.dict(str, dynattrs.artifact_value()),
        "out": dynattrs.output(),
        "templates": dynattrs.dict(str, dynattrs.artifact_value()),
        "values": dynattrs.value(dict[str, str]),
    },
)

def _cmake_configure_files_impl(ctx: AnalysisContext) -> list[Provider]:
    tree = ctx.attrs.tree[DefaultInfo].default_outputs[0]
    out = ctx.actions.declare_output(ctx.label.name, dir = True)
    ctx.actions.dynamic_output_new(_configure(
        templates = {path: tree.project(src) for path, src in ctx.attrs.files.items()},
        values = ctx.attrs.values,
        file_values = {name: tree.project(src) for name, src in ctx.attrs.file_values.items()},
        at_only = ctx.attrs.at_only,
        out = out.as_output(),
    ))
    return [DefaultInfo(default_output = out)]

# A directory of configured files: `files` maps each output path to its
# template, a path inside `tree`. Outputs listed in `at_only` are expanded as
# configure_file(... @ONLY) does. `file_values` maps a variable to a file in
# `tree` whose contents it holds (file(READ <file> <variable>)).
cmake_configure_files = rule(
    impl = _cmake_configure_files_impl,
    attrs = {
        "at_only": attrs.list(attrs.string(), default = []),
        "file_values": attrs.dict(attrs.string(), attrs.string(), default = {}),
        "files": attrs.dict(attrs.string(), attrs.string()),
        "labels": attrs.list(attrs.string(), default = []),
        "tree": attrs.dep(),
        "values": attrs.dict(attrs.string(), attrs.string()),
    },
)
