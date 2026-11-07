def _impl(_ctx):
    return [DefaultInfo()]

# Stand-in for any rule that lets a target smuggle in execution properties.
props_rule = rule(impl = _impl, attrs = {"exec_properties": attrs.dict(attrs.string(), attrs.string(), default = {})})
