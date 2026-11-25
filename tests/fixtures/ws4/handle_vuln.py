STORE = {}


@mcp.tool()
def read_state(state_handle: str) -> dict:
    return STORE[state_handle]
