# OWASP MCP Top 10 — mcp-safeguard Detection Coverage

This document maps mcp-safeguard's detection rules to OWASP's 2026 MCP security guidance.

OWASP classified **MCP Tool Poisoning** as an official 2026 attack category. This table shows how mcp-safeguard's 146 detection rules — prompt injection (15), credentials (31), tool poisoning (11), SSRF (3), OAuth scope risk (7), and source-audit (34) — plus 29 endpoint path probes and 12 dangerous-port checks cover OWASP's identified threat categories. This count is generated from the code itself (the `security://rules` MCP resource) rather than hand-maintained here.

---

## Coverage Table

| OWASP MCP Category | OWASP Description | mcp-safeguard Rules | Coverage |
|-------------------|-------------------|---------------------|----------|
| **MCP Tool Poisoning** | Tool descriptions contain embedded instructions that manipulate AI behavior | PI-001 to PI-015 (15 rules) | ✅ Full |
| **Credential Exposure** | Sensitive credentials in server configs, tool definitions, or responses | CRED-001 to CRED-028 (31 rules) | ✅ Full |
| **Dangerous Endpoint Exposure** | Unprotected admin, debug, or metadata endpoints | 29 path probes + PORT-001 to PORT-012 (41 checks) | ✅ Full |
| **Privilege Escalation via Tool Scope** | Tools requesting permissions beyond stated functionality | TP-001 to TP-011 (11 rules) | ✅ Full |
| **SSRF via MCP Server** | Server-side request forgery through MCP tool invocation | SS-001 to SS-003 (3 rules) | ✅ Full |
| **Supply Chain via Third-Party Tools** | Malicious tools injected via package registries | Detection roadmap | 🔄 Planned |

---

## Rule Details by Category

Every table below was generated directly from the rule definitions in
`src/mcp_safeguard/scanner/*.py` (IDs, titles, CVSS scores) — not
hand-written independently of the code — specifically to close the gap the
earlier version of this document had: several rows here previously listed
rule IDs, CVSS scores, and endpoint paths/ports that did not exist anywhere
in the actual scanner (a fabricated `SS-004`, a `TP-001..008` table with
invented titles that didn't match the real TP-001..011, endpoint paths like
`/graphql`/`/jolokia` absent from the real path list). If this table and the
source code ever disagree again, the source code is correct — re-derive this
file from it rather than trusting this prose.

### Category I — Prompt Injection (PI-001 to PI-015)
*Covers: OWASP MCP Tool Poisoning*

| Rule ID | Pattern | CVSS |
|---------|---------|------|
| PI-001 | Instruction Override Attempt | 9.3 |
| PI-002 | Identity Hijacking Pattern | 8.1 |
| PI-003 | Fake System Message Injection | 7.8 |
| PI-004 | Constraint Bypass Attempt | 9.1 |
| PI-005 | Hidden Instruction Tag | 8.5 |
| PI-006 | System Prompt Exfiltration | 7.5 |
| PI-007 | Deception Instruction | 5.5 |
| PI-008 | Encoded Instruction Obfuscation | 5.8 |
| PI-009 | Conditional Trigger Instruction | 5.2 |
| PI-010 | Code Execution Prompt | 8.0 |
| PI-011 | Data Exfiltration Instruction | 9.5 |
| PI-012 | Template Injection Pattern | 5.0 |
| PI-013 | Comment-Hidden Instruction | 4.8 |
| PI-014 | Zero-Width Character Steganography | 7.2 |
| PI-015 | Forced Tool Call Instruction | 6.0 |

### Category II — Credential Detection (CRED-001 to CRED-028)
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
| CRED-018 | Stripe credential in environment (by name) | 8.5 |
| CRED-019 | OpenAI credential in environment (by name) | 8.5 |
| CRED-020 | Anthropic credential in environment (by name) | 8.5 |
| CRED-021 | Twilio credential in environment (by name) | 7.5 |
| CRED-022 | SendGrid credential in environment (by name) | 7.5 |
| CRED-023 | Slack credential in environment (by name) | 7.5 |
| CRED-024 | GitHub credential in environment (by name) | 8.0 |
| CRED-025 | AWS credential in environment (by name) | 9.5 |
| CRED-026 | Hugging Face credential in environment (by name) | 8.0 |
| CRED-027 | Replicate credential in environment (by name) | 8.5 |
| CRED-028 | Cohere credential in environment (by name) | 8.0 |

CRED-018–020 are also matched by *value* shape under CRED-003–005 above;
the "(by name)" rows fire on the env-var key name instead, catching a
credential even when its value doesn't match the expected format.

### Category III — Endpoint Exposure (29 path probes + EP-PORT-001 to EP-PORT-012)
*Covers: OWASP Dangerous Endpoint Exposure*

**Sensitive Path Probes** (29, rules EP-001–013): `/admin`, `/admin/`, `/_admin` (EP-001, Exposed Admin Panel, 8.0) · `/debug`, `/debug/`, `/__debug__` (EP-002, Exposed Debug Endpoint, 7.5) · `/health`, `/healthz`, `/ready` (EP-003, Health Endpoint, 2.0) · `/metrics`, `/_metrics` (EP-004, Prometheus Metrics Exposed, 5.5) · `/docs`, `/swagger`, `/swagger-ui`, `/redoc` (EP-005, API Docs Exposed, 3.5) · `/openapi.json` (EP-006, OpenAPI Schema Exposed, 4.5) · `/config`, `/env` (EP-007, Config/Env Endpoint Exposed, 8.0) · `/.env` (EP-008, Environment File Exposed, 9.5 — CRITICAL) · `/mcp` (EP-009, MCP Endpoint, verify auth, 2.5) · `/sse`, `/ws` (EP-010, SSE/WebSocket Endpoint, verify auth, 4.5) · `/actuator`, `/actuator/env`, `/actuator/heapdump` (EP-011, Spring Actuator Exposed, up to 9.8 — CRITICAL) · `/version`, `/_version` (EP-012, Version Disclosure, 3.0) · `/trace`, `/pprof` (EP-013, Trace/Profiler Exposed, up to 7.5). Response bodies from any live path are also pattern-matched for stack traces, exception dumps, and leaked secrets (EP-RESP-001–005), escalating severity when found.

**Dangerous Port Checks** (12, rules EP-PORT-001–012): 22 SSH (5.0) · 23 Telnet (8.0) · 2375 Docker API unauthenticated (10.0 — CRITICAL) · 2376 Docker API TLS (7.5) · 4040 Ngrok Inspection UI (5.5) · 5000 Development Server (5.0) · 5432 PostgreSQL (8.0) · 6379 Redis (9.0) · 8080 HTTP Alt/Dev Server (3.5) · 8443 HTTPS Alt (3.0) · 9200 Elasticsearch (9.5 — CRITICAL) · 27017 MongoDB (8.5).

### Category IV — Tool Poisoning (TP-001 to TP-011)
*Covers: OWASP Privilege Escalation via Tool Scope*

| Rule ID | Pattern | CVSS |
|---------|---------|------|
| TP-001 | Hidden Side-Effect in Benign Tool | 8.0 |
| TP-002 | Covert Operation Descriptor | 8.5 |
| TP-003 | Instruction to Suppress Logging | 9.0 |
| TP-004 | Explicitly Covert Tool Action | 9.5 |
| TP-005 | Silent Data Exfiltration Descriptor | 9.8 |
| TP-006 | Deceptive Tool Description | 8.8 |
| TP-007 | Forced Tool Chain Trigger | 6.0 |
| TP-008 | User Awareness Suppression | 9.5 |
| TP-009 | Hidden Instruction Tag in Tool Description | 9.0 |
| TP-010 | Instruction to Conceal Action from User | 8.0 |
| TP-011 | Read Sensitive File Then Pass As Argument | 9.5 |

### Category V — SSRF Detection (SS-001 to SS-003)
*Covers: OWASP SSRF via MCP Server*

| Rule ID | Pattern |
|---------|---------|
| SS-001 | Unconstrained URL parameter with no allowlist/blocklist protection |
| SS-002 | Redirect-following URL fetch with no revalidation |
| SS-003 | Missing scheme restriction on a URL-fetching tool |

### Category VI — Source-Level Audit (SRC-001 to SRC-034)
*Covers: multiple categories above, at the source-code level rather than the
config/tool-definition level — see `scan-source` in README.md for the full
per-rule table. Includes SRC-021 (missing authentication on the MCP
transport itself), the single most common real bug shape this project's
disclosure campaign found. Not run by default (`scan`); invoked explicitly via
`scan-source`, since it needs the server's actual repository, not just its
config.*

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
- mcp-safeguard arXiv preprint — *in preparation* (cs.CR)
- [Model Context Protocol Specification](https://modelcontextprotocol.io)
