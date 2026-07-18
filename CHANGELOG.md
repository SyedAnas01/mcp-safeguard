# Changelog

All notable changes to mcp-safeguard are documented here.

## [0.3.0] - 2026-05-22
### Added
- **SSRF detection module** (`ssrf_scanner.py`): 4 new rules for Server-Side Request Forgery
  - `SS-001` — URL parameter with no allowlist/blocklist protection (CVSS 7.5 HIGH)
  - `SS-002` — Blind URL fetch with no scope restriction in description (CVSS 7.5–8.5 HIGH)
  - `SS-003` — Redirect following without revalidation risk (CVSS 6.5 MEDIUM)
  - `SS-004` — Non-HTTP scheme accepted (`file://`, `gopher://`, `dict://`) (CVSS 6.5 MEDIUM)
- SSRF rules detect vulnerable patterns across MCP fetch/scrape tools:
  - Any tool accepting unconstrained `url`, `uri`, `endpoint`, `webhook`, `callback` parameters
  - Tools describing themselves as fetching arbitrary user-supplied URLs
  - Tools that follow HTTP redirects without revalidating the destination
- Detection covers CVE class: cloud IAM credential exfiltration via prompt injection on AWS/GCP/Azure
- Motivated by empirical study of 195 public MCP fetch/scrape servers (9.2% confirmed SSRF via runtime verification)

## [0.2.0] - 2026-05-15
### Added
- **Tool Poisoning detection** (8 new rules): Identifies malicious tool definitions that masquerade as legitimate MCP tools
- **CVSS-aligned severity scoring**: Every finding now includes Critical/High/Medium/Low/Info severity with CVSS base score estimates
- **Structured JSON output**: `--output json` flag for CI/CD integration
- **Markdown report generation**: `--output markdown` for GitHub Actions summaries
- **Batch scanning**: Scan multiple servers in one invocation with `--targets-file`
- `mcp-safeguard` now operates as an MCP server itself (dog-fooding security)

### Changed
- Prompt injection rules expanded from 12 to 15 patterns (PI-001–PI-015)
- Credential exposure patterns expanded to 25 (added JWT, Bearer token, OAuth patterns)
- Endpoint exposure probes: 28 probes + 12 port checks (was 20+8)
- CLI interface redesigned for better UX

### Fixed
- False positive reduction in PI-007 (base64-encoded content detection)
- Path traversal detection now handles Windows-style paths

## [0.1.0] - 2026-04-28
### Added
- Initial release with 3 detection categories
- Prompt injection detection (12 rules)  
- Credential exposure scanning (18 patterns)
- Endpoint exposure probing (20 probes)
- CVSS scoring foundation
- pip-installable package (`pip install mcp-safeguard`)
- CLI: `mcp-safeguard scan --target <path>`

## [Unreleased] - Coming in 0.4.0
- **New credential detection rules**:
  - `CRED-027`: Replicate API token detection (`r8_` prefix pattern, CVSS 8.5 HIGH)
  - `CRED-028`: Cohere API key detection (CVSS 8.0 HIGH)
  - Env var name detection for Replicate and Cohere credentials
- Scan over MCP stdio transport directly
- GitHub Actions workflow template
- VS Code extension for real-time MCP security hints
- Semgrep rule export
