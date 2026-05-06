# Hacker News Post

**Title:** Show HN: mcp-shield – Security scanner for MCP servers (prompt injection, credential leaks, tool poisoning)

---

**Body:**

Hey HN,

I built mcp-shield — an open-source security scanner for MCP (Model Context Protocol) servers. Think of it as Snyk or Semgrep, but specifically for the attack surfaces that MCP introduces.

**The problem it solves:**

MCP servers expose AI agents to real-world systems: filesystems, databases, APIs, code execution. That creates new attack surfaces that traditional AppSec tools don't cover:

1. **Prompt injection via tool descriptions** — A tool's description field is read by the LLM and can contain hidden instructions ("ignore previous instructions", zero-width character steganography, identity hijacking directives). These bypass the model's safety training by arriving through the "trusted" tool definition channel.

2. **Credential exposure in server configs** — Claude Desktop and Cursor configs are JSON files that frequently contain hardcoded API keys. I've seen OpenAI keys, Anthropic keys, AWS credentials, and database URLs in plain text in MCP configs shared publicly.

3. **Exposed admin/debug endpoints** — MCP servers are often FastAPI or Express apps where the developer forgot to disable `/debug`, `/docs`, `/metrics`, or `/actuator` before deployment.

4. **Tool poisoning** — Third-party MCP tools can be designed to look benign but silently exfiltrate data or suppress logging. The description says "search files" but also does something else.

**What mcp-shield does:**

- Detects 15+ prompt injection patterns via regex analysis of tool definitions
- Identifies 17 credential leak patterns (AWS keys, JWT tokens, private keys, etc.)
- Probes 28 sensitive endpoint paths and 12 dangerous ports
- Scores every tool's blast radius (0–10) and permission risk
- Generates CVSS-scored findings with remediation guidance
- Produces HTML + JSON reports for audit trails

**It's an MCP server itself**, which means you add it to your Claude Desktop config and use it directly from Claude's chat interface.

**Tech stack:** Python, FastMCP, Prometheus, OpenTelemetry, Pydantic.

**Caveats:**
- Endpoint scanning is restricted to localhost/allowlisted hosts by default (SSRF protection)
- No runtime instrumentation yet — this is static analysis + probe-based detection
- v0.1.0 — more rules and transport-level scanning coming

GitHub: https://github.com/mcp-shield/mcp-shield
PyPI: pip install mcp-shield

Happy to discuss the threat model or specific detection rules. What attack surfaces am I missing?
