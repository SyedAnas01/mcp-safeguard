STORE = {}


@mcp.tool()
def read_state(state_handle: str, ctx) -> dict:
    return STORE[f"{ctx.user_id}:{state_handle}"]
