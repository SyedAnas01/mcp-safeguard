# Changelog

All notable changes to mcp-safeguard are documented here.

## [0.6.0] - 2026-09-02

### Fixed — 3 critical bugs found by a full line-by-line code audit
- **`scan_for_tool_poisoning` crashed on `"description": null`** — `tool.get("description", "")`
  only supplies the default when the key is *absent*; a tool with the valid JSON
  `"description": null` reached `re.search()` with `None` and raised `TypeError`,
  taking down the whole CLI scan (and, via `scan_mcp_server`'s broad exception
  handler, silently discarding every other finding for the target).
- **`scan_mcp_server`'s tool-fetch path had no SSRF/DNS-rebinding protection** — the
  exact vulnerability class this tool exists to detect in *other* servers. `validate_url()`
  alone only rejects a literal private/metadata IP; a caller-supplied hostname that
  *resolves* to one reached `_fetch_tools_via_mcp`/the httpx fallback completely
  unguarded, with any caller-supplied `auth_token` attached. Now resolves the target
  host and rejects private/reserved/metadata addresses before connecting.
- **Stored XSS in the tool's own HTML reports** — a scanned server's tool name (fully
  attacker-controlled when scanning a hostile/compromised server) was interpolated
  unescaped into both `generate_html_report()` (MCP server + on-disk reports) and the
  CLI's `--output report.html` writer.

### Fixed — other real bugs from the same audit
- `Dockerfile`'s `CMD` used `python -m fastmcp run ...`, which doesn't exist for the
  pinned fastmcp version (`fastmcp` ships a console script, not a `__main__`) —
  the container couldn't start as shipped. Registered a real `/health` route and
  fixed the healthcheck to actually check the response status.
- `endpoint_scanner.py`'s `.local`/`.internal` hostname suffix bypassed the SSRF
  allowlist entirely (EP-SSRF-001's own blind spot) — removed; the DNS-rebinding
  guard now also checks the full RFC1918/ULA range, not just link-local + metadata.
- Rate limiting and audit logging were keyed by a static env-var placeholder shared
  by every caller, not the real per-API-key identity `_check_auth()` already
  computed — one caller could exhaust the shared bucket for everyone else, and
  audit logs couldn't attribute actions to the actual caller. Auth failures are
  now also logged and counted (`auth_failures` metric was defined but never
  incremented).
- `_SENSITIVE_ENV_NAMES` (11 real credential rules — CRED-018..028, including
  Hugging Face/Replicate/Cohere) was defined *inside* `scan_for_credentials()`,
  invisible to introspection — hoisted to module level.
- `--output`/`--format json` printed the banner and status lines to stdout too,
  so `scan-source . --format json > baseline.json` silently produced invalid
  JSON. Machine-readable formats now own stdout exclusively; status moves to stderr.

### Added — 8 new source-audit rules (`SRC-013`..`SRC-020`)
Each is derived from a real bug shape this project's own disclosure campaign found
repeatedly across unrelated MCP servers — not a hypothetical:
- `SRC-013` — TLS certificate verification disabled (`verify=False`, `ssl.CERT_NONE`, etc.)
- `SRC-014` — OAuth `redirect_uri` used in a redirect with no allowlist check anywhere
  in the file (authorization-code interception, RFC 9700 §4.1.1) — the single most
  common real vulnerability this campaign found, including two confirmed government
  MCP servers and a live-verified production auth bypass (Emporia Energy)
- `SRC-015` — inbound `Authorization` header re-forwarded to an outbound request
  (token passthrough — forbidden outright by the MCP spec's Security Best Practices)
- `SRC-016` — a write/destructive-capability flag gates only the tool-*list* response
  with no matching gate near the tool-*call* dispatcher (hides discovery, not
  execution — the exact bug found in a production crypto-custody MCP server)
- `SRC-017` — an HTTP header value used directly as an authorization/tenant-scoping
  identity with no authentication check anywhere in the file (found giving full,
  unauthenticated database access in a Microsoft sample MCP server)
- `SRC-018` — real path traversal: a joined path used in a file operation with no
  realpath+containment check, replacing the earlier "parameter is named 'path'" heuristic
- `SRC-019` — unescaped shell interpolation, broader-recall companion to `SRC-009`
  that doesn't require repo-wide corroboration (43% of MCP CVEs filed in early 2026
  were shell/exec injection — the single largest real-world MCP vulnerability class)
- `SRC-020` — unencoded value in a URL query string (the statically-detectable root
  cause behind HTTP Parameter Pollution)

`SRC-014` and `SRC-017` were each fixed at least once *after* being validated against
the real vulnerable source they were derived from (not just their own synthetic unit
test) — see the benchmark below and the rules' comments in `source_scanner.py` for
what the first version missed.

### Added — SARIF output, suppressions, baseline
- `--format sarif` / `--output results.sarif` emits SARIF 2.1.0 for `scan` and
  `scan-source`, for GitHub code scanning (`github/codeql-action/upload-sarif`) and
  any other SARIF-consuming CI.
- Inline suppression for `scan-source`: `# safeguard: ignore[SRC-013] reason` (or
  `// ...`) on the flagged line, `ignore[*]` for all rules on that line.
- `--baseline <file>` for `scan-source`: adopt today's findings once
  (`scan-source . --format json > baseline.json`), then only fail CI on genuinely
  new ones — the standard way a team adopts a scanner on an existing codebase.

### Added — a real-world benchmark, not just synthetic tests
- `tests/test_benchmark_confirmed_vulnerable.py` scans a fixture reproduced (with
  attribution, MIT license) from an actual, independently-confirmed vulnerable MCP
  server and asserts the right rule fires at the right file:line and severity. Most
  security scanners' test suites only prove a rule matches its own hand-written
  fixture; this proves at least one rule survives contact with real production code.

### Changed
- `credential_scanner.py`: `_SENSITIVE_ENV_NAMES` moved to module level (see Fixed).
- `security://rules` resource now includes the `ssrf` and `source_audit` categories
  (previously omitted entirely — the live rule count was undercounted by 20).
- README.md and OWASP-ALIGNMENT.md rule counts and per-category tables corrected
  to match the actual code (previous numbers were stale/wrong in several places —
  e.g. OWASP-ALIGNMENT.md's Tool Poisoning and SSRF tables listed rule IDs, titles,
  and even a `SS-004` rule that didn't exist anywhere in the codebase).

## [0.5.0] - 2026-09-01
### Added
- **8 new source-audit rules** (`SRC-005`..`SRC-012`) closing the gap between what a
  manual line-by-line audit catches and what the automated `scan-source` rules
  (SRC-001..004) catch. Each targets a bug *class*, generalized from a real
  vulnerability found in a specific MCP-related repo during that audit, not a
  one-off check for that repo:
  - `SRC-005` — an `--auth-token`/`AUTH_TOKEN` flag is parsed and referenced (e.g.
    printed in a startup warning) but nothing in the file actually gates the
    network listener on it — the server starts serving regardless (CVSS 7.5 HIGH)
  - `SRC-006` — a client-supplied resource ID (`chat_id`/`session_id`/`conversation_id`/
    `connection_id`/`room_id`) keys shared server-side state (a `*History`/`*Store`/
    `*Session`/`*Cache`/`*Memory` constructor) with no ownership check on that
    specific ID in the file (CVSS 7.5 HIGH)
  - `SRC-007` — a "detect destructive"/`is_readonly`-style classifier that is
    actually used to gate execution recognizes only statement-type syntax
    (keyword/AST-node matching), not side-effecting function calls, so a
    syntactically-safe statement wrapping a call like `setval()` slips through
    (CVSS 7.5 HIGH)
  - `SRC-008` — a create/update mutation trusts a client-supplied ownership field
    (`user_id`/`owner_id`/`account_id`/`tenant_id`) instead of deriving it from the
    authenticated session server-side (CVSS 8.1 HIGH)
  - `SRC-009` — a variable is interpolated unescaped into a shell string passed to
    `exec`/`system`, flagged **only** when the same repository already has a safer
    argv/quoting pattern (`shellQuote`, `escapeShellArg`, `shlex.quote`, `execFile`,
    `spawn`) elsewhere — the inconsistency is the signal (CVSS 8.1 HIGH)
  - `SRC-010` — a credential/private-key file write has no permission-hardening call
    near it, flagged **only** when the same repo hardens permissions on some other
    file write (CVSS 5.5 MEDIUM)
  - `SRC-011` — an SSRF guard validates a resolved IP once, but the actual outbound
    call is a separate call that re-resolves the original URL string instead of
    connecting to the pinned IP — a DNS-rebinding TOCTOU window (CVSS 7.5 HIGH)
  - `SRC-012` — a manifest/lockfile parser drops entries matching a sentinel value
    (unresolved version, empty/None field) before the list reaches a security
    consumer, logging the drop only at debug level — invisible to an operator at
    default log levels (CVSS 5.5 MEDIUM)
- `SRC-009` and `SRC-010` are intentionally scoped: they only fire when the same
  repository demonstrates elsewhere that it already knows the safer pattern. This
  trades recall for a much lower false-positive rate.
- `SRC-007` requires evidence that the classifier's result actually gates execution
  somewhere in the file (an `if`/`raise`/`return`/`deny`/`block`/`reject` on its call),
  not just that a function with a safety-sounding name exists — this is a direct
  guard against conflating "there is a type classifier" with "the type classifier is
  a security control," the exact overclaim shape a manual audit has to catch by hand.
- Like SRC-001..004, these are regex/text-proximity heuristics over source, not a
  type-aware or dataflow analysis. Findings are leads to confirm by reading the
  cited file and line, not proofs — the false-positive risk is highest for SRC-006
  and SRC-008, which only see ownership/derivation checks within the same file (a
  check enforced in a shared middleware or decorator elsewhere in the repo will not
  be seen, and would read as a finding here).
- `.rs` (Rust) and `.swift` source files are now scanned (previously `.go`, `.py`,
  `.ts`, `.js`, `.cs` only), needed for `SRC-005`'s Rust example and `SRC-010`'s
  Swift example.
- 17 new unit tests (`tests/test_source_scanner_new_rules.py`), one trigger + one
  non-trigger fixture per rule, plus two extra non-trigger fixtures for `SRC-007`
  specifically targeting false-positive resistance.

## [0.4.0] - 2026-08-20
### Added
- **Source-audit mode** (`source_scanner.py`) and new `scan-source` CLI command: 4 new
  rules that scan a server's actual source tree, not a config/tool-definition JSON.
  - `SRC-001` — Go `http.RoundTripper` re-applies `Authorization` on every hop with no
    `CheckRedirect` to strip it on a cross-host redirect (CVSS 6.5 MEDIUM)
  - `SRC-002` — Python `httpx` client with `follow_redirects=True` plus a bearer/
    Authorization header, the same failure as SRC-001 (CVSS 6.5 MEDIUM)
  - `SRC-003` — SQL read-only mode enforced by a string/prefix check only, with no
    database-level read-only transaction in the same file (CVSS 7.5 HIGH)
  - `SRC-004` — A server-held credential attached to a connection whose destination
    host is an interpolated, potentially caller-influenced variable (CVSS 7.5 HIGH)
- Validated against the published source of 14 official vendor MCP servers (Microsoft,
  Amazon, Google, GitHub, and others): 9 of 10 known instances correctly identified,
  zero findings on the 9 clean repositories in the same corpus.

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
