# Changelog

All notable changes to mcp-safeguard are documented here.

## [0.8.0] - 2026-09-03

### Added — a first real precision measurement, plus 3 new rules (`SRC-032`..`034`) closing 3 of the 4 remaining Round 30 misses

This release does the two things flagged as open in 0.7.2's own notes: measure false-positive rate on
independently-confirmed-clean code (never done before), and close more of the Round 30 recall gap using
that same precision discipline in reverse — read the real missed vulnerable code, generalize the pattern,
validate against the real source, not a synthetic fixture.

**Precision, measured for the first time**: scanned 11 MCP-server repos independently verified clean during
this project's disclosure campaign (qdrant/mcp-server-qdrant, qdrant/mcp-for-docs, DeepL/deepl-mcp-server,
wix/wix-mcp, swiggy/swiggy-mcp-server-manifest, chargebee/agentkit, redis/mcp-redis, explorium-ai/mcp-explorium,
DIDA-AI/Dida-Hotel-MCP-Global, oilst/kraken-mcp, awslabs/iam-policy-autopilot). Before any fix, the rule set
(v0.7.3 plus this release's own new `SRC-021` widening) produced 12 findings; reading every one against the
actual cited file:line found 10 were genuine false positives, fixed with 5 surgical regex changes:

- `SRC-023`'s inline shape only confirmed a variable NAMED "...url..." sat near a fetch call, not that its
  value ever came from a caller — false-positived on chargebee/agentkit's API client (`url` built from an
  operator env var + a hardcoded per-call literal path) and oilst/kraken-mcp (`url = KRAKEN_BASE + url_path`,
  both hardcoded). Fixed by tracing the variable's own prior assignment(s) in the file and requiring at least
  one to show real caller-derived vocabulary before trusting the inline match; a bare function parameter with
  no local reassignment (the real ark-forge/Bybit-kaas shape) still fires unchanged.
- The same rule also matched inside a Rust doc comment (`/// Call browser fetch(url) and return ...`,
  awslabs/iam-policy-autopilot's WASM shim) — not executable code at all. Fixed by skipping a candidate whose
  own line starts with a comment marker and searching on for a real one.
- `SRC-026`'s bare-URL-literal alternative matched inside Rust `#[tokio::test]`/`#[rstest]` test functions
  (a client pointed at an intentionally-unreachable `http://127.0.0.1:1` to test connection-refused handling,
  and a parameterized test fixture string containing sample input for this tool's OWN source parser) —
  neither is this file's own server binding. Fixed by excluding a bare-URL match preceded by a
  `#[test]`/`#[tokio::test]`/`#[cfg(test)]`/`#[rstest]` attribute within ~800 chars.
- The same rule's host-assignment alternative stitched two unrelated things into a phantom bind statement in
  redis/mcp-redis: a `--url` CLI option's own help text describing a URI FORMAT (`user:pass@host:port/db`)
  contains the substring "host:", and an unrelated `--host` option's `default="127.0.0.1"` a few lines below
  landed inside the same match's 150-char lookahead window. Fixed by requiring the match not sit inside an
  open string literal (an odd quote count between the line start and the match).
- Widening `SRC-021`'s serve-call vocabulary for FastMCP's `mcp.run(transport=...)` idiom (below) newly
  matched DIDA-AI/Dida-Hotel-MCP-Global's thin entrypoint file, which delegates ALL tool registration — and,
  with it, the file's real per-request `Authorization`/`X-Secret-Key` check — to a separate module this
  same-file rule can't see. Fixed by requiring a file with no handler of its own (`@mcp.tool`/`@app.route`
  decorators, or `app.get(`/`app.post(`-style calls) and a `register_tools(mcp)`-shaped delegation call to be
  treated as inconclusive rather than a same-file absence of auth.

After all 5 fixes, the same 11 repos produce exactly 2 findings, both on DIDA-AI/Dida-Hotel-MCP-Global
(`SRC-026`: the server's `HOST` env var defaults to loopback with no Origin-header check in the same file;
`SRC-002`: its API client sets `follow_redirects=True` alongside a bearer `Authorization` header) — read
directly, both are genuine, if lower-severity, hardening gaps rather than false positives (the redirect
target and bind-override are both operator-configured, not attacker-controlled, so this is real
defense-in-depth advice, not an active exploit path).

**Recall**: re-measured Round 30 (10 confirmed findings from this project's own disclosure campaign) against
the CURRENT rule set before adding anything new — 6 of 10, not 0.7.0's "5 of 10": `SRC-031`, added in 0.7.2
specifically to close the trackmage gap, already accounts for the 6th. Reading the actual vulnerable code
behind the remaining 4 misses produced:

- `SRC-032` — a session id read from a client header (`mcp-session-id`) is used as a bracket-index lookup
  into an in-memory session store, with no check anywhere in the file that the session's stored owner matches
  the currently authenticated caller (Repliers-io/mcp-server: the per-request bearer token IS verified, but
  the looked-up session's `repliersApiKey` — captured from whoever ORIGINALLY created it — is reused for the
  current caller regardless).
- `SRC-033` — a caller-controlled boolean tool parameter (`simulate`/`dry_run`, defaulting to the safe
  value) is the sole gate before a real private-key signing/broadcast call, with no independent server-side
  confirmation anywhere in the file (nirholas/UCAI: every generated write-tool takes `simulate: bool = True`;
  flipping it is enough to move from a harmless simulation to an irreversible on-chain transfer).
- `SRC-034` — a FastAPI/Flask route decorator for a state-changing verb exists with no
  authentication-dependency vocabulary anywhere in the file. Deliberately does NOT require an in-file
  network-serve call the way `SRC-021` does: an importable ASGI `app` object commonly has no `.run()` call at
  all, served externally via a Dockerfile CMD — exactly why `SRC-021` missed
  microsoft/AKS-Lab-GitHubCopilot's `/invoke` endpoint (zero auth, runs an arbitrary agent goal), which this
  rule catches.
- `SRC-021` itself widened to recognize FastMCP's `mcp.run(transport="streamable-http"/"http"/"sse")` idiom
  (scoped to non-stdio transports only, so a bare `mcp.run()` or explicit `transport="stdio"` — neither
  network-exposed — is never matched) — closes the OTHER half of the same AKS-Lab repo's zero-auth MCP
  servers (`mcp.run(transport="streamable-http")` with no auth vocabulary anywhere in the file), which the
  original `.serve(`/`.listen(`/`uvicorn.run(`/`app.run(` vocabulary never covered for FastMCP's own idiom.

Each new/widened rule was validated against the REAL vulnerable source it was mined from, not a synthetic
fixture, and fires at the exact real file:line before any synthetic test was written. Round 30 coverage:
**6 of 10 → 9 of 10**, real and measured. The remaining miss, pedrobraiti/agentic-trading-mcp's
symbol-denylist bypass, is intentionally NOT covered by a new rule: the bug is a format mismatch between a
denylist built from raw config strings in one file (`policy.py`) and a BASE/QUOTE-normalized symbol compared
against it, built in a DIFFERENT file (`app.py`) — a genuinely cross-file dataflow fact this single-file
regex scanner has no way to see. Recorded as an honest, open gap rather than forced into a low-precision
same-file heuristic.

Re-ran the same 11 clean repos after adding the 3 new rules: no new false positives (still exactly the same
2 genuine Dida findings; `SRC-032`/`033`/`034` fire zero times on any of them).

146 rules total (up from 143). 227 tests passing (up from 214), ruff clean, clean self-scan.

## [0.7.3] - 2026-09-02

### Fixed — last 31 Dependabot alerts (55 → 0)

All 31 remaining alerts (after 0.7.1's bump of the 7 core-dependency CVEs) traced to a single
source: `streamlit`, pulled in only via the optional `[dashboard]` extra, not any code path the
scanner itself uses. GitPython (18 alerts) and Pillow (13 alerts) were both transitive deps of
`streamlit` alone — confirmed via the dependency graph, not assumed.

- `uv lock --upgrade-package gitpython --upgrade-package pillow --upgrade-package streamlit`
  resolved streamlit 1.57.0 → 1.63.0, which **dropped its GitPython dependency entirely**
  (eliminates all 18 GitPython alerts outright — no GitPython in the tree, no GitPython CVEs) and
  bumped Pillow 12.2.0 → 12.3.0.
- Verified against the actual alert data, not assumed: all 13 open Pillow advisories list
  `first_patched_version: 12.3.0` — the exact version now locked patches every one of them.
- Re-synced the environment to the real bumped versions (not just the lock file) and confirmed:
  `dashboard.py` and `streamlit` both still import cleanly at the new version (no breaking API
  changes hit), full test suite (214 tests) still passes, ruff clean.

Zero open Dependabot alerts as of this release.

## [0.7.2] - 2026-09-02

### Added — `SRC-031`, a credential passed as a URL query parameter on a GET request

Closes the last gap identified while measuring 0.7.0's Round 30 coverage: `trackmage-mcp-server`
sends its OAuth `client_id`/`client_secret` as `axios.get(url, { params: {...} })` on every server
startup and token-expiry refresh, instead of a POST body as RFC 6749 §3.2 requires — the secret
lands in every logging/caching layer that captures request URLs but not bodies (reverse-proxy/CDN/
WAF access logs, HTTP client debug logs, APM tools). This is a genuinely new, previously-uncovered
rule class, not a variant of `SRC-020` (that rule is about unencoded HTTP-Parameter-Pollution risk;
this one is about credential exposure specifically, regardless of encoding).

A first version matched on "a `params:`/`query:` object literal appears somewhere in the preceding
window" alone, which false-positived on `trackmage-mcp-server`'s own
`this.accessToken = response.data.access_token` a few lines *after* the params object that built the
request had already closed — reading a token back off the response, not building one. Window-based
proximity alone can't distinguish "still inside that object" from "object closed, something
unrelated followed a few lines later." Fixed with real brace-depth tracking from the params object's
own opening `{` up to the candidate credential key, so a match only counts if that object is
provably still open at that point. Re-verified against the real trackmage source: only the genuine
finding fires now.

143 rules total (up from 142). 214 tests passing (up from 211), ruff clean, clean self-scan.

### Validated — an internal semantic-audit methodology (not shipped in this package)

Separately from rule-mining: 6 blind adversarial code-reading passes (agent given only a target's
source + a general "does the code enforce what its own docs claim" methodology, not the known
answer) were run against the exact 6 Round 30 findings 0.7.0's regex rules don't catch — these are
business-logic/intent bugs (a denylist compared in the wrong value format, a safety flag that's
LLM-controlled with no real enforcement, a session ID never bound to its creator, credentials
matching an upstream API's own insecure contract) that are structurally different from the syntactic
patterns SRC-*/CRED-*/etc. can recognize. Initial blind run: 2 clean hits, 1 same-class hit, 3
misses. Two of the three misses were the same specific, fixable methodology bug (a real finding was
found and then self-refuted because the vulnerable behavior matched an upstream API's documented
contract, or because maintainers disclosed it as a known workshop trade-off — neither actually
eliminates the exposure). Fixing that calibration rule, plus adding explicit config-driven
(not just prose) claim extraction, and re-running blind: 6 of 6 now land correctly. This
methodology is intentionally NOT part of the published package or its "manual, not AI-powered"
positioning — it's an internal accelerant for this project's own paid audit work, kept in the
private o1a workspace, not this repo.

## [0.7.1] - 2026-09-02

### Fixed — adversarial self-review of mcp-safeguard's own code

0.7.0 hardened the tool's ability to *find* vulnerabilities in other MCP servers. This release
turns the same scrutiny on the tool itself: an independent adversarial pass whose only job was to
break mcp-safeguard's own SSRF guards, its own regex scanning, its own input handling — poke holes,
not review the design. Five real, verified findings came back; a sixth and seventh were found while
fixing the first. All seven are fixed, each with a working proof-of-concept confirming the bug
before the fix and confirming it's closed after, plus a regression test.

- **CRITICAL — IPv4-mapped/6to4 IPv6 SSRF bypass.** The private/reserved/metadata IP check
  (`input_validator.py`) matched an IPv6 address like `::ffff:169.254.169.254` against IPv6-only
  ranges, found no match, and allowed it — but a dual-stack socket resolves and connects that
  address to the real IPv4 `169.254.169.254` (the AWS/GCP metadata endpoint) underneath. Same blind
  spot for 6to4-encoded (`2002::/16`) addresses. Fixed with a new `_is_unsafe_ip()` helper that
  unwraps both forms to their real IPv4 address *before* checking, built on `ipaddress`'s own
  `.ipv4_mapped`/`.sixtofour` properties instead of hand-rolled range math. Loopback stays
  intentionally exempt (documented allowance for local MCP server testing). PoC: `http://[::ffff:
  169.254.169.254]/`, `http://[::ffff:10.0.0.5]/`, and `http://[2002:a9fe:a9fe::]/` (169.254.169.254
  in 6to4 form) were all previously **allowed**; all three are now **blocked**. `::ffff:127.0.0.1`
  correctly stays allowed.
- **Bonus, found while fixing the above — `validate_host()` never actually blocked private IPs.**
  `ValidationError` subclasses `ValueError`, so `raise ValidationError(...)` inside a `try` block
  immediately followed by `except ValueError:` was being silently caught by that same except clause
  and swallowed, falling through to hostname-format validation — which a dotted-decimal IP string
  passes fine. This function had never actually enforced its own private-IP block on any literal-IP
  input, in any released version. Fixed with the same `try/except/else` structure already used in
  `validate_url()`. PoC: `validate_host("192.168.1.1")` was previously **allowed**; now **blocked**.
- **HIGH — quadratic ReDoS in the `PI-005` prompt-injection regex, plus unbounded fetched-data
  size.** `PI-005`'s hidden-instruction-tag pattern used an unbounded `.*?` gap under `re.DOTALL`
  between an opening and closing tag; on adversarial input (many unclosed opening tags, no closing
  tag anywhere) this is quadratic — measured **6.0s on 624K characters** for the old pattern vs.
  **0.01s** for the fix (~550x), and the old pattern's cost only grows worse with input size. Fixed
  by bounding the gap to 500 characters, which real hidden-tag pairs never exceed. Separately, the
  two paths that fetch tool definitions over the network from a scan target
  (`_fetch_tools_via_mcp`, the httpx `/tools` fallback) had **no size limit at all** on what a target
  could return — unlike the `scan_tool_definitions` MCP tool, which already caps pasted JSON via
  `max_tool_descriptions_length`. A malicious or compromised scan target could return an
  arbitrarily large description and force every injection pattern to scan it in full, regardless of
  the regex fix. Closed with a new `_cap_string_fields()` helper applied to every tool definition
  fetched over the network, capping every string field (recursively, including nested schema
  strings) to the same limit the direct-paste path already enforces.
- **HIGH — 55 real Dependabot alerts**, including a documented HTTP-transport auth-bypass CVE in
  the pinned `mcp` SDK version. `uv.lock` had `mcp` pinned at `1.27.1`; bumped to `1.29.1` via `uv
  lock --upgrade-package` (proper dependency-graph resolution, not a hand-edited lock file) along
  with `starlette` (1.0.0 → 1.6.0), `pyjwt` (2.12.1 → 2.13.0), `joserfc` (1.6.5 → 1.7.5),
  `cryptography` (48.0.0 → 50.0.1), `python-multipart` (0.0.29 → 0.0.32), and `pydantic-settings`
  (2.14.1 → 2.15.0). Full test suite re-run against the actual bumped, locked versions (not just the
  ambient dev environment) — 205/205 passing, no breaking changes.
- **MEDIUM — missing type validation in `validate_tool_json`, and a second uncaught crash it didn't
  cover.** Well-formed JSON with a wrong-typed field (`description` as a number, `inputSchema` as a
  string) passed `validate_tool_json`'s checks (which only verified `isinstance(item, dict)` and the
  presence of `name`) and then crashed downstream in `analyze_tool_risk()` with an uncaught
  `AttributeError` — first on `input_schema.get(...)` when `inputSchema` wasn't a dict, and (found
  while writing the PoC) a **second, separate crash** on `description.strip()` when `description`
  wasn't a string. Fixed at both layers: `validate_tool_json` now rejects non-string `description`
  and non-dict `inputSchema` with a clear `ValidationError` instead of a stack trace, and
  `analyze_tool_risk()` itself now coerces (rather than crashes on) wrong-typed input as
  defense-in-depth — it's also reachable from `scan_mcp_server`'s network-fetch path, which doesn't
  go through `validate_tool_json` at all, since that data comes from the scan target, not a caller.
- **MEDIUM — uncaught `RecursionError` on deeply nested JSON.** `~10,000` levels of `[[[...]]]` or
  `{"a":{"a":...}}` nesting fits in about 60KB — comfortably under both `validate_tool_json`'s and
  `validate_config_json`'s default character-length caps — while still exhausting Python's call
  stack inside the JSON decoder and raising an uncaught `RecursionError`. Both functions now catch
  it and raise a clean `ValidationError` instead.

23 new regression tests added across `test_input_validator.py` (new file), `test_prompt_injection.py`,
`test_server.py`, and `test_tool_analyzer.py` — one confirming each bug's PoC stays fixed. 211 tests
passing (up from 188), ruff clean, self-scan of the tool's own source stays clean after every change.
No rule count change (these are validator/scanner-internals fixes, not new detection rules) — still
142 rules via `security://rules`.

## [0.7.0] - 2026-09-02

### Added — 9 more source-audit rules (`SRC-022`..`SRC-030`), mined from the full disclosure campaign backlog

Every rule added tonight so far (`SRC-013`..`SRC-021`) came from Round 30's fresh findings. This
release goes back through the *entire* campaign — 81 report files across every round — and turns
the remaining un-generalized real bug classes into rules, using nine parallel agents each held to
the same standard: derive the pattern from a real, already-confirmed finding, then actually run it
against the real vulnerable code (not a synthetic fixture) before calling it done.

**Every one of the nine initially got something wrong when checked against real code, and every one
was fixed before integration** — this is the expected cost of doing this properly, not a failure:

- `SRC-022` (SQL/SoQL injection) — the obvious first design (require `execute()` to directly wrap
  the interpolated string) matched *neither* real source finding it was derived from: both
  apple-health-mcp-server and cdc-places-mcp-server build the unsafe query fragment in one place and
  execute it in another. Redesigned around the actual structural signal (a comparison operator
  directly followed by a quoted, interpolated value) and re-verified against both real files.
- `SRC-014` and `SRC-017` (from earlier tonight) were also revisited and fixed here as part of the
  same integration pass — see their own entries below.
- `SRC-023` (unguarded outbound SSRF) — verified 3 of 4 real findings fire; the fourth (Inkeep
  agents) documents its vulnerable call chain by file:line/prose only, with no literal fetch-call
  code fence to regex-match, and is noted as uncovered rather than silently claimed.
- `SRC-024` (BOLA/missing resource-scope check) — shipped with an explicit lower-confidence label:
  it cannot recognize non-Python/TS handler shapes (confirmed: silent on a real C# finding it was
  also derived from), and a generic `authorize()`/`[Authorize]` call will suppress it even when that
  check never verifies ownership of the *specific* resource. Documented, not hidden.
- `SRC-025` (reflected XSS) — the interpolation-to-HTML-tag lookback window was first set too tight
  (measured against the real IBKR source: only an ~80-character margin) and widened before integration.
- `SRC-026` (loopback/Origin, DNS rebinding) — the first line-scoped version missed a real finding
  because the vulnerable assignment and the `"127.0.0.1"` literal it resolves to sit on different
  lines; widened to a cross-line window and re-verified. Also includes a bonus sub-case: an Origin
  check that exists but uses an unanchored wildcard regex (a real finding, fast-mcp), so a substring
  match like `evilexample.com` passes a check meant for `example.com`.
- `SRC-027` (OAuth scope, no role check) — a literal find/replace of `SRC-014`'s pattern (swap
  `redirect_uri` for `scope`) matched nothing against the real mcp-construction source, which reads
  `scope` via a framework context call and bracket notation, not the dotted-property shape
  `SRC-014` assumes. Both real shapes added and re-verified.
- `SRC-028` (unredacted error/PII logging) — an initial fixed-width forward window swept a
  *different*, safe, adjacent log line into the same finding, misattributing the location. Bounded
  to the rest of the offending line only, the same discipline `SRC-005`/`SRC-012` already use.
- `SRC-029` (plaintext credential persistence) — ships with a documented single-hop limitation
  (shared with `SRC-004`/`010`): the static-vs-runtime-origin check only inspects the immediate
  assignment, not a value routed through an intermediate variable first.
- `SRC-030` (CORS wildcard / disabled dev-server host check) — an unrelated word-boundary bug in the
  wildcard-quote alternative silently failed to match `origin: "*"` (a `\b` cannot match between two
  non-word characters) while still matching `origin: true`; fixed and re-verified against both forms.

### Fixed — issues surfaced only by integrating all nine together and re-running the tool on its own source
Dogfooding the finished tool against its own codebase (routine practice all through this hardening
pass) turned up real problems invisible to any single rule's isolated testing:
- 11 **self-referential false positives** — new rules' own doc comments and user-facing finding-text
  necessarily *describe* the patterns they detect, and several rules' example text (`= '{value}'`,
  `cors()`, `allowedHosts: true`, an `http://localhost:8000` docstring example) matched their own
  detection regex when the tool scanned its own source. Reworded every instance to describe the
  pattern without literally reproducing the trigger substring — same fix already applied to `SRC-013`
  earlier tonight, now applied consistently.
- **A real, pre-existing precision gap in `_SSRF_VALIDATE_CALL`** (the shared guard-name vocabulary
  `SRC-011` and the new `SRC-023` both rely on): its `\b` anchor never matches before a leading
  underscore (`_validate_url(`, `_is_ssrf_safe(` — extremely common Python private-helper style), and
  its vocabulary list didn't include several common real guard names. This caused `SRC-023` to
  false-positive on `endpoint_scanner.py`'s own, correctly-implemented SSRF guards
  (`_is_ssrf_safe`/`_resolves_to_unsafe_ip`) — fixed by dropping the anchor and broadening the
  vocabulary, which also improves `SRC-011`'s real-world recall on any codebase using this common
  naming style.
- **`SRC-026` false-positived on `server.py`'s own scan-target host extraction**
  (`host = parsed.hostname or "localhost"`) — that line parses a *scan target's* URL, it isn't this
  server declaring where it binds. Added an exclusion for `host = ...` assignments whose right-hand
  side parses an existing URL (`.hostname`, `urlparse(`), with a regression test.

### Validated end-to-end against the real campaign, not just unit tests
Beyond each rule's own validation, the finished set was swept across every locally-cloned Round 30
target (both confirmed-vulnerable and confirmed-clean) with zero further false positives, and
specifically re-checked against the two hardest real findings from earlier in the night:
`SRC-025` fires correctly on `ibkr-portfolio-builder-mcp`, `SRC-027` fires correctly on
`mcp-construction`, with **no cross-contamination** between the two repos. Coverage against the
Round 30 benchmark (10 confirmed findings, checked earlier tonight before this release) went from
**2 of 10 caught to 5 of 10** — real, measured, not asserted.

142 rules total (up from 133), live via `security://rules`. 188 tests passing (up from 169), ruff
clean, ships with a fully clean self-scan (all findings above were either fixed as real bugs or
resolved as genuine false positives — none suppressed to hide them).

## [0.6.1] - 2026-09-02

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

### Added — a 9th source-audit rule, `SRC-021`, validated end-to-end against a live campaign
- `SRC-021` — a network listener (HTTP/SSE) starts serving with **no inbound
  authentication check anywhere in the file** (excludes stdio transport,
  which isn't network-exposed). This turned out to be the single most common
  real bug shape the disclosure campaign found — more common than any other
  class — and was the one gap none of `SRC-001`..`020` covered.
  - The first version of this rule ("flag it if no auth-adjacent word
    appears *anywhere* in the file") **failed its own real-world validation**:
    every real integration server mentions "Authorization"/"Bearer"/"API_KEY"
    for its own *outbound* call to whatever backend it wraps — that's normal
    and says nothing about whether the MCP transport itself checks its
    callers. Rewritten to require the vocabulary to appear in an *inbound*
    shape (reading from the incoming request's headers, or a real named
    auth-check/middleware/provider), re-tested, and re-validated.
  - Caught and fixed two more real false positives in the same pass: a
    stdio-only MCP server (not network-exposed at all — excluded outright)
    and a server whose auth provider is wired in via `FastMCP(auth=...)`
    rather than a direct header read (the inbound-check vocabulary broadened
    to recognize framework-level auth-provider wiring, not just manual checks).
  - **End-to-end validated against a live, still-open campaign finding**:
    run against the real `codespar/mcp-dev-latam` monorepo, it found 115
    unauthenticated servers — matching, almost exactly, the 114 independently
    hand-verified during this campaign's own adversarial re-check the same
    night. Then swept across every other locally-cloned target from this
    campaign (both confirmed-vulnerable and confirmed-clean) with zero
    further false positives.

### Added — 8 source-audit rules from earlier the same night (`SRC-013`..`SRC-020`)
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
