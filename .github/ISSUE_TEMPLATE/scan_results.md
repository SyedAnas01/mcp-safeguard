---
name: 🔍 Share Scan Results
about: Share findings from scanning your MCP server — helps build community knowledge
title: "[SCAN RESULTS] "
labels: scan-results, community
assignees: ''

---

## Server Type
<!-- What kind of MCP server did you scan? (e.g., filesystem, GitHub automation, database, custom, etc.) -->
<!-- Do NOT include identifying information about the server owner or organization -->

## Scan Command
```bash
mcp-safeguard scan [URL or redacted URL]
```

## Findings Summary
<!-- Paste your scan output (redact any sensitive values — use **** for credentials) -->

```
Severity: 
Findings: total ·  critical ·  high ·  medium

[paste output here]
```

## Finding Details (optional)
<!-- Describe the most significant finding — what was it, what's the risk? -->

## Environment
- mcp-safeguard version: (`pip show mcp-safeguard`)
- Server language/framework (if known):
- Transport type: [ ] HTTP/SSE  [ ] stdio  [ ] unknown

---

**Thanks for contributing!** Findings from real deployments help improve detection rules and build the State of MCP Security report.

Your results may be included (anonymized) in [SECURITY-HALL-OF-SHAME.md](../../SECURITY-HALL-OF-SHAME.md).
