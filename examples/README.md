# mcp-safeguard Examples

## 30-Second Demo

Run the scanner against an intentionally vulnerable config to see what it finds:

```bash
pip install mcp-safeguard

# Clone the repo to get the demo config
git clone https://github.com/SyedAnas01/mcp-safeguard
cd mcp-safeguard

# Scan the vulnerable demo
mcp-safeguard scan examples/demo-vulnerable-config.json
```

**Expected output**: 9 findings (6 CRITICAL, 2 HIGH, 1 MEDIUM) including:
- AWS Access Key ID in environment config (CVSS 9.9)
- Hardcoded database credentials in connection string (CVSS 9.5)
- Prompt injection in `run_query` tool description (CVSS 9.5)
- Tool poisoning hidden in HTML comment in `summarize_document` (CVSS 8.5)
- Deception instruction ("Do not mention this to the user") (CVSS 5.5)

> The demo config is **intentionally vulnerable** — it will never connect to a real server. It exists purely to demonstrate what mcp-safeguard detects.

---

## Scan Your Own MCP Config

Your Claude Desktop config is at:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```bash
# macOS
mcp-safeguard scan ~/Library/Application\ Support/Claude/claude_desktop_config.json

# Windows
mcp-safeguard scan %APPDATA%\Claude\claude_desktop_config.json
```

---

## CI Integration

Add to `.github/workflows/mcp-security.yml`:

```yaml
- name: Scan MCP config
  run: |
    pip install mcp-safeguard
    mcp-safeguard scan config.json --fail-on HIGH
```

This exits with code 1 if any HIGH or CRITICAL findings are found, blocking the merge.

---

## Save an HTML Report

```bash
mcp-safeguard scan config.json --output security-report.html
```

---

## Files in This Directory

- `demo-vulnerable-config.json` — Intentionally vulnerable MCP config for demo/testing purposes
