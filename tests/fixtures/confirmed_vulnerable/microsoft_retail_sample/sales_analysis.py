# Minimal excerpt (2 of ~15 functions, reformatted for brevity) reproduced under
# the MIT License from microsoft/MCP-Server-and-PostgreSQL-Sample-Retail,
# mcp_server/sales_analysis.py, commit 1b6e188622fe413d9a882d6224be8bb23a537a44
# (https://github.com/microsoft/MCP-Server-and-PostgreSQL-Sample-Retail).
# Copyright (c) Microsoft Corporation. MIT License.
#
# Reproduced here as a real-world regression fixture for mcp-safeguard's
# SRC-017 rule (see tests/test_benchmark_confirmed_vulnerable.py). This is a
# genuine, independently-confirmed vulnerability: the ONLY access-control
# mechanism on this MCP server is the caller-supplied `x-rls-user-id` header
# read here, with no authentication anywhere in the request path -- and the
# default value used when the header is simply omitted is hardcoded in the
# project's own shipped RLS policies as an "all stores" bypass. Live-verified
# during this project's own disclosure campaign against the real shipped
# sample data: omitting the header (or sending any non-UUID garbage value)
# returned all 50,000 customer records instead of one store's ~20,000.
# Disclosed to Microsoft; not yet publicly fixed as of this fixture's date.

from typing import Optional


def get_header(ctx, header_name: str) -> Optional[str]:
    """Extract a specific header from the request context."""

    request = ctx.request_context.request
    if request is not None and hasattr(request, "headers"):
        headers = request.headers
        if headers:
            header_value = headers.get(header_name)
            if header_value is not None:
                if isinstance(header_value, bytes):
                    return header_value.decode("utf-8")
                return str(header_value)

    return None


def get_rls_user_id(ctx) -> str:
    """Get the Row Level Security User ID from the request context."""

    rls_user_id = get_header(ctx, "x-rls-user-id")
    if rls_user_id is None:
        # Default to a placeholder if not provided
        rls_user_id = "00000000-0000-0000-0000-000000000000"
    return rls_user_id
