# Security fixes: Taig Mac Carthy findings (2026-09-06)

Two vulnerabilities reported by external researcher Taig Mac Carthy, independently
re-verified with working reproductions against this repo at HEAD
`02f0ed5b2442b8ec713b3c3d8943fcbe01ec5a43` (v0.9.0), then fixed on branch
`fix/taig-ssrf-auth-2026-09-06`. Both are fixed and verified below. **Nothing in
this branch has been pushed, PR'd, or published to PyPI** — that remains a
separate, explicitly-gated decision.

## Bug 1 — DNS-rebinding SSRF in `scan_mcp_server`

**Where:** `src/mcp_safeguard/server.py` (`scan_mcp_server`, `_fetch_tools_via_mcp`,
the httpx `/tools` fallback), validator in `src/mcp_safeguard/security/input_validator.py`.

**The bug:** `scan_mcp_server` called `resolves_to_unsafe_ip(target_host)` to
validate the scan target's hostname, then proceeded to connect using the
**original hostname string** — via fastmcp's `Client` (which builds its own
`StreamableHttpTransport`/`SSETransport`) and, on fallback, a raw
`httpx.AsyncClient.get(f"{url}/tools")`. Both of those independently re-resolve
the hostname at connect time. An attacker-controlled DNS name can answer the
validation-time lookup with a public IP and every subsequent lookup with a
private/internal one (classic DNS-rebinding TOCTOU), turning the scanner into an
SSRF proxy into whatever network it runs on.

**The fix:** resolve the hostname exactly **once**, validate that resolved IP,
and pin every actual connection to that literal IP — never the hostname again.

- `input_validator.py` gains `resolve_pinned_ip(host) -> str`: does one
  `socket.getaddrinfo()` call, applies the same "reject if ANY resolved address
  is private/reserved/metadata" rule as the existing `resolves_to_unsafe_ip()`,
  and returns the first safe IP. `resolves_to_unsafe_ip()` itself is untouched
  (still used by `endpoint_scanner.py` and existing tests).
- `scan_mcp_server` now calls `resolve_pinned_ip(target_host)` once, up front,
  instead of `resolves_to_unsafe_ip(target_host)`, and threads the pinned IP
  through to both fetch paths.
- `_fetch_tools_via_mcp` now takes `pinned_ip`/`original_host` and connects to
  a URL with the host literal replaced by `pinned_ip` (`_pinned_connect_url`).
  An IP literal needs no DNS resolution, so there is no second, attacker-
  controllable lookup. TLS correctness is preserved via a custom
  `httpx.AsyncHTTPTransport` (`_PinnedSNITransport`) that pins SNI and
  certificate-hostname checking to `original_host` regardless of what the
  connection URL's host is (`extensions["sni_hostname"]`, verified against
  httpcore 1.x's actual connect code path — SNI/cert check reads
  `request.extensions["sni_hostname"]`, TCP connect reads the origin host from
  the URL). Host-header-based virtual hosting is preserved by explicitly
  setting `Host: original_host`.
- The httpx `/tools` fallback gets the same treatment: connects to the pinned
  IP with `extensions={"sni_hostname": target_host}` and an explicit `Host`
  header, keeping the existing `verify=settings.verify_scan_target_tls` kwarg
  in place (an existing test asserts on this directly).
- Both HTTP and SSE MCP transports are covered (transport class is chosen the
  same way fastmcp's own `infer_transport_type_from_url` does, by path suffix).

**Note on scope:** `endpoint_scanner.py`'s `scan_endpoints()` has a
structurally similar pattern (`_resolves_to_unsafe_ip(host)` then
`socket.create_connection((host, port))`, which re-resolves `host`
internally). This was **not** in scope for this fix (the report named
`scan_mcp_server` specifically) and was left untouched — flagging it here for
a separate look.

### Before/after reproduction (Bug 1)

Ran the supplied `repro_claim1_dns_rebind.py` and `repro_claim1b_unsafe_target.py`
against the real, unmodified code both before and after the fix (git-stashed the
fix to get a clean vulnerable baseline, then restored it).

**`repro_claim1_dns_rebind.py`** (rebinds connect-time resolution to a local
test double on `127.0.0.1`):

| | Before | After |
|---|---|---|
| Private test double received the scanner's request | **True** (`POST /`, `GET /tools`, both with `Host: rebind.attacker.test:<port>`) | **False** — nothing received |
| Scan result | `SSRF blocked` error: False; scan "succeeded" against the rebound target | `SSRF blocked` error: False; scan safely returns `"could not retrieve tool definitions from target"` — it connected only to the pinned (real, public) IP from the validation-time lookup, which nothing is listening on in this test |
| Script's own verdict | `CLAIM 1 CONFIRMED` | `CLAIM 1 NOT CONFIRMED` |

**`repro_claim1b_unsafe_target.py`** (rebinds connect-time resolution to a
genuine RFC1918 address, `10.13.13.13`, that `resolves_to_unsafe_ip()` would
reject — proves the gap reaches an address the validator itself considers
unsafe, not just the loopback address the first repro uses):

| | Before | After |
|---|---|---|
| `connect()` attempts intercepted toward `10.13.13.13` | **2** (`[('10.13.13.13', 9999), ('10.13.13.13', 9999)]`) | **0** — `[]` |
| Script's own verdict | `CONFIRMED: the connection layer dials the second (post-validation) DNS answer directly ... with no re-validation` | (no CONFIRMED line — `attempted=False`, so the vulnerable condition never occurs) |

## Bug 2 — Auth bypass on all 3 `@mcp.resource` handlers

**Where:** `src/mcp_safeguard/server.py` — `get_report_resource` (line ~862 pre-fix),
`get_rules_resource` (~880), `get_dashboard_resource` (~939).

**The bug:** `_check_auth()` was called by all 7 `@mcp.tool` functions but by
none of the 3 `@mcp.resource` handlers. When `MCP_SAFEGUARD_API_KEY` is
configured, an unauthenticated caller could not call `get_scan_history` (a
tool) but *could* read `security://reports/{scan_id}` (a resource) and get the
identical data — including credential findings — with zero authentication.
`security://rules` and `security://dashboard` had the same gap.

**The fix:** added the same `err, _client_id = _check_auth(); if err is not
None: return json.dumps(err)` guard used by the tools, adapted only for the
resources' `str` return type (tools return the error dict directly; resources
return a JSON string, matching the existing `except ValidationError` pattern
already used inside `get_report_resource`). `_check_auth()`'s use of
`get_http_headers()` from `fastmcp.server.dependencies` is not tool-specific —
it reads from ASGI-layer request context regardless of whether the calling
handler is a `@mcp.tool` or `@mcp.resource`, confirmed both by reading
`_check_auth`'s implementation and by the fixed repro below actually rejecting
the resource call the same way it rejects the tool call.

### Before/after reproduction (Bug 2)

Ran the supplied `repro_claim2_auth_bypass.py` (an unauthenticated call to the
gated tool `get_scan_history`, and to the resource `get_report_resource`, with
`MCP_SAFEGUARD_API_KEY` configured) before and after the fix.

| | Before | After |
|---|---|---|
| Tool call (`get_scan_history`) | Correctly rejected: `{'error': 'Authentication required.'}` | Same — unchanged |
| Resource call (`get_report_resource`) | **Leaked the full report** (target `http://internal-victim:9000`, `CRED-001` finding with `AKIA-REDACTED...`) unauthenticated | `{"error": "Authentication required."}` — correctly rejected, matching the tool's behavior |
| Script's own verdict | `CLAIM 2 CONFIRMED` | `CLAIM 2 NOT CONFIRMED` |

`get_rules_resource` and `get_dashboard_resource` were fixed identically and
covered by new regression tests (below); the supplied repro only exercised
`get_report_resource` directly.

## Test results

Test infra here is plain pytest (no Docker/testcontainers — checked
`pyproject.toml`, `tests/`, no `conftest.py`); ran each file individually with
no stalls.

- `tests/test_input_validator.py`: 15 original + 6 new (`TestResolvePinnedIp`)
  = **21 passed**
- `tests/test_server.py`: 43 original + 4 new (resource-auth regression tests)
  = **47 passed**
- `tests/test_mcp_protocol_client.py` (real in-process uvicorn MCP servers,
  end-to-end `scan_mcp_server` calls): 7 (existing tests updated for the new
  `_fetch_tools_via_mcp(url, pinned_ip, original_host, auth_token)` signature
  and the `resolve_pinned_ip`-based validation call) = **7 passed**
- `tests/test_ssrf_scanner.py`, `test_endpoint_scanner.py`: **15 passed**
  (unaffected — `endpoint_scanner.py` wasn't touched)
- Every other test file (`test_cli`, `test_credential_scanner`,
  `test_prompt_injection`, `test_report_generator`, `test_source_scanner*`,
  `test_suppression_and_sarif`, `test_tool_analyzer`, `test_version`,
  `test_benchmark_confirmed_vulnerable`, `test_benign_corpus`): **160 passed**

**Full suite: 250 passed, 0 failed, 0 skipped.**

`ruff check` on all changed files: clean. (`black --check` flags pre-existing
formatting drift on these same files even on the untouched baseline — a black
version mismatch unrelated to this change, left alone per "touch only what you
must".)

### New regression tests added

- `tests/test_input_validator.py::TestResolvePinnedIp` (6 tests): resolves a
  safe host, pins a literal public IP to itself, rejects a host resolving to
  an RFC1918 address, rejects if *any* of several resolved addresses is unsafe
  (mirrors `resolves_to_unsafe_ip`'s conservative rule), raises cleanly on
  resolution failure, and — the core regression — asserts `socket.getaddrinfo`
  is called **exactly once** for a given host.
- `tests/test_server.py` (4 tests): each of the 3 resources rejects an
  unauthenticated call when an API key is configured, plus one test
  confirming resources stay open when no API key is configured at all (no
  regression on the existing no-auth-configured behavior).

## PyPI — separate action still needed (not done here)

The installed PyPI package (0.4.0) is confirmed still exploitable for both
bugs — this is a release-process gap (PyPI is 5 minor versions behind the
`v0.9.0` source, so it predates even earlier hardening, let alone this fix),
not a code bug fixed by this branch. **A fresh PyPI release cutting in these
fixes (and everything else since 0.4.0) is now urgent** and must be done as
its own explicitly-approved action — no `twine upload` / `build` / publish
step was run as part of this work, per instructions.

## Branch

All changes committed locally to `fix/taig-ssrf-auth-2026-09-06`, based on
`main` at `02f0ed5b2442b8ec713b3c3d8943fcbe01ec5a43`. Not pushed to origin, no
PR opened.

Files changed:
- `src/mcp_safeguard/security/input_validator.py` — new `resolve_pinned_ip()`
- `src/mcp_safeguard/server.py` — pinned-IP connection for both `scan_mcp_server`
  fetch paths (`_PinnedSNITransport`, `_pinned_connect_url`,
  `_make_pinned_httpx_client_factory`, updated `_fetch_tools_via_mcp`); `_check_auth()`
  added to all 3 `@mcp.resource` handlers
- `tests/test_input_validator.py`, `tests/test_server.py` — new regression tests
- `tests/test_mcp_protocol_client.py` — updated 2 existing tests for the new
  `_fetch_tools_via_mcp` signature and `resolve_pinned_ip`-based validation
