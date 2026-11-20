# Minimal excerpt (the tool-construction-and-registration method) reproduced
# under the Apache License 2.0 from PrefectHQ/fastmcp,
# src/fastmcp/server/providers/openapi/provider.py, commit
# 53dab031e4fed759d4f271bd5266d041a106c8ce
# (https://github.com/PrefectHQ/fastmcp).
#
# Reproduced here, together with components_excerpt.py, as a real-world
# regression fixture for mcp-safeguard's entrypoints.py shape H,
# `registry_subscript_assignment`, resolution step 2 (the ONE-HOP local
# -constructor-call case, see bench/SDK_VOCAB_AND_TRUNCATION_FIX_STATUS.md
# section 1). `tool = OpenAPITool(...)` is a local variable bound to a
# class constructor call, then `self._tools[tool.name] = tool` registers it
# by dict-key subscript assignment -- `OpenAPITool` itself (and its own
# `run` method, the real handler) is defined in a SIBLING file
# (components_excerpt.py here, `components.py` in the real repo), which is
# exactly why this shape's resolution deliberately searches across every
# parsed file in the repo for this one step, not just the registration
# call's own file.
from __future__ import annotations

from fastmcp.server.providers.openapi.components import OpenAPITool


class OpenAPIProvider:
    def _create_openapi_tool(self, route, name, tags):
        """Create and register an OpenAPITool."""
        tool_name = self._get_unique_name(name, "tool")

        tool = OpenAPITool(
            client=self._client,
            route=route,
            director=self._director,
            name=tool_name,
            description=route.description,
            parameters=route.flat_param_schema,
        )

        if self._mcp_component_fn is not None:
            self._mcp_component_fn(route, tool)

        self._tools[tool.name] = tool
