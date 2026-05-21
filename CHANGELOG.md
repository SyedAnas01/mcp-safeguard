# Changelog

All notable changes to mcp-shield are documented here.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] — 2026-05-21

### Added
- **Standalone CLI** (`mcp-safeguard scan <config.json>`) — no AI client required
  - Scans Claude Desktop config format (`mcpServers` JSON) and raw tool definition arrays
  - Colored terminal output with CVSS scores and remediation steps
  - `--severity` flag to filter findings by minimum severity
  - `--fail-on` flag for CI/CD integration (exits non-zero if severity threshold breached)
  - `--output <file>` flag for HTML or JSON report files
  - `--format json` flag for machine-readable output
- **Demo vulnerable config** (`examples/demo-vulnerable-config.json`) for testing and demos
- **Examples directory** with usage documentation

### Changed
- `mcp-safeguard` command now runs the CLI scanner (was: MCP server runner)
- `mcp-shield` command continues to run the MCP server

## [0.1.0] — 2026-05-06

### Added
- Initial public release of mcp-shield
- `scan_mcp_server` tool — full security scan of an MCP server URL
- `scan_tool_definitions` tool — prompt injection + poisoning analysis
- `check_auth_config` tool — credential and OAuth scope auditing
- `check_endpoint_exposure` tool — admin panel and dangerous port detection
- `generate_security_report` tool — JSON, HTML, and text report formats
- `get_scan_history` tool — list past scans with severity scores
- `compare_scans` tool — regression detection between scan pairs
- 15 prompt injection detection rules (PI-001 through PI-015)
- 4 schema-level injection risk rules (PI-SCH-001 through PI-SCH-004)
- 17 credential leak patterns (CRED-001 through CRED-017)
- 7 OAuth scope risk rules (OAUTH-001 through OAUTH-007)
- 28 sensitive endpoint paths probed
- 12 dangerous port checks
- Blast radius and permission risk scoring (0–10) for every tool
- 8 tool poisoning detection rules (TP-001 through TP-008)
- CVSS-style scoring for all findings
- SSRF protection — only localhost and allowlisted hosts can be scanned
- Token bucket rate limiter per client
- API key and Bearer token authentication
- Structured JSON audit logging for all scan events
- Prometheus metrics: scan counts, vulnerability counts, CVSS histogram, latency
- OpenTelemetry tracing integration
- Streamlit real-time dashboard
- `security://reports/{scan_id}` resource
- `security://rules` resource — all active detection rules
- `security://dashboard` resource — aggregate statistics
- `security_audit_prompt` — guided full audit workflow
- `remediation_prompt` — step-by-step fix guides for 5 vulnerability types
- HTML report generation with severity-color-coded tables
- Multi-stage Docker build with non-root user
- Docker Compose stack: mcp-shield + Prometheus + Grafana + Streamlit
- GitHub Actions CI: lint, test (Python 3.11 + 3.12), build, Docker
- GitHub Actions publish workflow (PyPI + Docker Hub on release)
- 50+ test cases across 4 test modules

[Unreleased]: https://github.com/SyedAnas01/mcp-safeguard/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/SyedAnas01/mcp-safeguard/releases/tag/v0.2.0
[0.1.0]: https://github.com/SyedAnas01/mcp-safeguard/releases/tag/v0.1.0
