# Minimal excerpt (class declaration + constructor + the `run` handler
# method's own signature and opening body) reproduced under the Apache
# License 2.0 from PrefectHQ/fastmcp,
# src/fastmcp/server/providers/openapi/components.py, commit
# 53dab031e4fed759d4f271bd5266d041a106c8ce
# (https://github.com/PrefectHQ/fastmcp).
#
# Sibling fixture to provider_excerpt.py -- see that file's header for the
# real registration shape this pair reproduces
# (entrypoints.py shape H, resolution step 2). `run` is the real target's
# own actual handler method, one of `_CLASS_HANDLER_METHODS`
# (execute/run/call/handle/invoke), defined DIRECTLY in this class.
from __future__ import annotations

from fastmcp.tools.tool import Tool, ToolResult


class OpenAPITool(Tool):
    """Tool implementation for OpenAPI endpoints."""

    def __init__(self, client, route, director, name, description, parameters):
        super().__init__(name=name, description=description, parameters=parameters)
        self._client = client
        self._route = route
        self._director = director

    def __repr__(self) -> str:
        return f"OpenAPITool(name={self.name!r}, method={self._route.method}, path={self._route.path})"

    async def run(self, arguments: dict) -> ToolResult:
        """Execute the HTTP request using RequestDirector."""
        base_url = str(self._client.base_url) or "http://localhost"
        request = self._director.build(self._route, arguments, base_url)
        return await self._client.send(request)
