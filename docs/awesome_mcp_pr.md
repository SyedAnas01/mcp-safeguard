# PR for awesome-mcp-servers

**Title:** Add mcp-safeguard — security scanner for MCP servers

---

**Description:**

This PR adds **mcp-safeguard** to the Security Tools section of the awesome-mcp-servers list.

**What it does:**
mcp-safeguard is an MCP server that scans other MCP servers for security vulnerabilities. It detects prompt injection patterns in tool definitions, credential leaks in server configurations, exposed admin endpoints, and tool poisoning risks. Findings are CVSS-scored with remediation guidance.

**Why it belongs here:**
- It is itself an MCP server (FastMCP-based)
- It works directly with Claude Desktop and Cursor via standard MCP integration
- It addresses security concerns unique to the MCP ecosystem (tool description injection, tool poisoning)
- MIT licensed, actively maintained, 50+ tests

**Links:**
- GitHub: https://github.com/mcp-safeguard/mcp-safeguard
- PyPI: https://pypi.org/project/mcp-safeguard/
- License: MIT

**Proposed entry:**

```markdown
## Security

- [mcp-safeguard](https://github.com/mcp-safeguard/mcp-safeguard) - Security scanner for MCP servers. Detects prompt injection in tool definitions, credential leaks, exposed endpoints, and tool poisoning risks. Generates CVSS-scored HTML reports.
```
