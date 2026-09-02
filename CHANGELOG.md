# Changelog

All notable changes to mcp-safeguard are documented here.

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
- Add `EP-029` detection for unauthenticated GraphQL schema introspection exposure.
- **New credential detection rules**:
  - `CRED-027`: Replicate API token detection (`r8_` prefix pattern, CVSS 8.5 HIGH)
  - `CRED-028`: Cohere API key detection (CVSS 8.0 HIGH)
  - Env var name detection for Replicate and Cohere credentials
- Scan over MCP stdio transport directly
- GitHub Actions workflow template
- VS Code extension for real-time MCP security hints
- Semgrep rule export
