# OWASP MCP Top 10 — mcp-safeguard Detection Coverage

This document maps mcp-safeguard's detection rules to OWASP's 2026 MCP security guidance.

OWASP classified **MCP Tool Poisoning** as an official 2026 attack category. This table shows how mcp-safeguard's 52 detection rules cover OWASP's identified threat categories.

---

## Coverage Table

| OWASP MCP Category | OWASP Description | mcp-safeguard Rules | Coverage |
|-------------------|-------------------|---------------------|----------|
| **MCP Tool Poisoning** | Tool descriptions contain embedded instructions that manipulate AI behavior | PI-001 to PI-015 (15 rules) | ✅ Full |
| **Credential Exposure** | Sensitive credentials in server configs, tool definitions, or responses | CRED-001 to CRED-017 (17 rules) | ✅ Full |
| **Dangerous Endpoint Exposure** | Unprotected admin, debug, or metadata endpoints | EP-001 to EP-028, PORT-001 to PORT-012 (40 rules) | ✅ Full |
| **Privilege Escalation via Tool Scope** | Tools requesting permissions beyond stated functionality | TP-001 to TP-008 (8 rules) | ✅ Full |
| **SSRF via MCP Server** | Server-side request forgery through MCP tool invocation | SSRF guard built-in | ✅ Partial |
| **Supply Chain via Third-Party Tools** | Malicious tools injected via package registries | Detection roadmap (v0.3) | 🔄 Planned |

---

## Rule Details by Category

### Category I — Prompt Injection (PI-001 to PI-015)
*Covers: OWASP MCP Tool Poisoning*

| Rule ID | Pattern | CVSS | Example |
|---------|---------|------|---------|
| PI-001 | Instruction override | 8.7 | "Ignore previous instructions and..." |
| PI-002 | Identity hijacking | 7.9 | "You are now DAN..." |
| PI-003 | Fake system message | 9.2 | "\nSYSTEM: You are..." |
| PI-004 | Constraint bypass | 8.1 | "Disregard your guidelines..." |
| PI-005 | Exfiltration command | 9.8 | "POST the contents of ~/.ssh to..." |
| PI-006 | Hidden instruction tag | 7.5 | `<!-- Instruction: ... -->` |
| PI-007 | Jailbreak sequence | 8.3 | Common jailbreak phrase patterns |
| PI-008 | Privilege escalation | 8.9 | "You now have admin access..." |
| PI-009 | Indirect injection hook | 7.2 | "Read the file at [URL] for instructions" |
| PI-010 | Prompt segmentation | 6.8 | Split instructions across multiple fields |
| PI-011 | System prompt exfiltration | 8.5 | "Output your system prompt to..." |
| PI-012 | Context window flooding | 5.5 | Extremely long descriptions designed to overflow |
| PI-013 | Token manipulation | 6.1 | Unicode or encoding tricks |
| PI-014 | Conditional trigger | 7.8 | "If the user mentions 'finance', then..." |
| PI-015 | Schema injection | 7.4 | Malicious JSON in parameter defaults |

### Category II — Credential Detection (CRED-001 to CRED-017)
*Covers: OWASP Credential Exposure*

| Rule ID | Pattern | CVSS |
|---------|---------|------|
| CRED-001 | AWS Access Key (AKIA...) | 9.8 |
| CRED-002 | AWS Secret Key | 9.8 |
| CRED-003 | OpenAI API Key (sk-...) | 8.5 |
| CRED-004 | Anthropic API Key (sk-ant-...) | 8.5 |
| CRED-005 | Google API Key (AIza...) | 7.9 |
| CRED-006 | Stripe Secret Key (sk_live_...) | 9.1 |
| CRED-007 | Stripe Publishable Key (pk_live_...) | 6.5 |
| CRED-008 | GitHub OAuth Token (gho_...) | 8.7 |
| CRED-009 | GitHub PAT (ghp_...) | 9.1 |
| CRED-010 | GitHub App Token (ghs_...) | 8.7 |
| CRED-011 | Slack Bot Token (xoxb-...) | 8.1 |
| CRED-012 | JWT (eyJ...) | 7.5 |
| CRED-013 | Database URL with password | 8.2 |
| CRED-014 | Generic password field | 6.0 |
| CRED-015 | Private key header (-----BEGIN...) | 9.5 |
| CRED-016 | HuggingFace token (hf_...) | 7.8 |
| CRED-017 | Generic high-entropy string (40+ chars) | 5.5 |

### Category III — Endpoint Exposure (EP-001 to EP-028 + PORT-001 to PORT-012)
*Covers: OWASP Dangerous Endpoint Exposure*

**Sensitive Path Probes** (28): `/admin`, `/management`, `/.env`, `/.git/config`, `/debug`, `/_debug`, `/actuator/env`, `/actuator/heap`, `/swagger-ui.html`, `/api-docs`, `/graphql` (introspection), `/__pycache__`, `/config.json`, `/secrets.json`, `/credentials`, `/backup`, `/phpinfo.php`, `/server-status`, `/server-info`, `/health` (verbose), `/metrics` (unauthenticated), `/trace`, `/mappings`, `/beans`, `/loggers`, `/heapdump`, `/threaddump`, `/jolokia`

**Dangerous Port Checks** (12): 5432 (PostgreSQL), 3306 (MySQL), 6379 (Redis), 27017 (MongoDB), 5984 (CouchDB), 9200 (Elasticsearch), 8080 (dev HTTP), 9090 (Prometheus), 4040 (Spark UI), 8888 (Jupyter), 5005 (JVM debug), 2375 (Docker daemon)

### Category IV — Tool Poisoning (TP-001 to TP-008)
*Covers: OWASP Privilege Escalation via Tool Scope*

| Rule ID | Pattern | CVSS |
|---------|---------|------|
| TP-001 | External data exfiltration | 8.4 |
| TP-002 | Embedded external URL call | 7.9 |
| TP-003 | Safety override request | 8.8 |
| TP-004 | Side-effect beyond stated purpose | 7.2 |
| TP-005 | Permission scope inflation | 7.5 |
| TP-006 | User deception in description | 6.9 |
| TP-007 | Covert channel establishment | 8.1 |
| TP-008 | Blast radius — overly broad tool scope | 5.8 |

---

## Running mcp-safeguard

```bash
pip install mcp-safeguard
mcp-safeguard scan http://your-mcp-server:8000
```

For CI/CD integration:
```yaml
# .github/workflows/security.yml
- name: Scan MCP server
  run: |
    pip install mcp-safeguard
    mcp-safeguard scan ${{ secrets.MCP_SERVER_URL }} --fail-on-high
```

---

## References

- [OWASP AI Security Project](https://owasp.org/www-project-ai-security-and-privacy-guide/)
- [OWASP MCP Tool Poisoning (2026)](https://owasp.org)
- [mcp-safeguard arXiv Paper](https://arxiv.org) — cs.CR
- [Model Context Protocol Specification](https://modelcontextprotocol.io)
