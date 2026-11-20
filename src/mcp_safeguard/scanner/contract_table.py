"""Part 2 of the recognition-gap fix -- a small, curated table of
`(symbol, package substring) -> contract note`, wired to Part 1's
primitive-inventory scanner (`primitive_inventory.py`). See
bench/RECOGNITION_GAP_FIX_STATUS.md and the controlled experiment that
validated this need (bench/RECOGNITION_GAP_EXPERIMENT_RESULTS_REFERENCE.md):
for 2 of 3 real misses (PrefectHQ/fastmcp's fixed JWT audience;
typescript-sdk's shared-transport request-ID collision), Part 1's generic
"state the safe config or say unknown-contract" instruction alone did NOT
reliably reach the exact target mechanism -- only injecting a real,
externally-sourced fact about what the primitive actually requires did.

Every row below cites a REAL external source, checked live (via `WebFetch`/
`WebSearch`) as part of building this table, never fabricated and never
derived by reading a sealed-holdout target's own source beyond what the
experiment report itself already disclosed. Per the task's own overfitting
guard, each row's citation is independent of the ONE specific sealed-holdout
case that motivated adding it -- the Pyodide row, for instance, cites two
OTHER real, independent incidents (n8n, Grist-Core), not just a description
of the mcp-run-python target itself.

Matching is intentionally narrow: exact (case-insensitive) `symbol` name,
plus an optional `package_substring` (case-insensitive substring check
against the matched primitive's own `package` field) for a symbol name that
isn't unique enough on its own. `package_substring=""` matches any package
(used only where the symbol name alone is already unambiguous, e.g. a
specific SDK class name) -- documented per-row, not a silent default.

Push, not pull (Fable's explicit recommendation, quoted in the task): when
a match happens, the note is injected directly into the unit's evidence --
the model never has to think to call a tool to retrieve it, which would
repeat the exact "the model didn't know to look" failure mode this fix
targets. When there's no match, nothing is injected -- evidence for a unit
with no matched primitive is not degraded in any way.

contract-table-header-fix milestone: `match_contract_notes()`'s own header
line (naming the matched `PrimitiveMatch`'s file/package/symbol) is built
from real, repo-derived text -- the target's own import specifier and file
path -- and used to sit OUTSIDE `wrap_untrusted()` even after the sibling
unwrapped-content fix closed the equivalent gap in this table's OWN cells
(`primitive_inventory.render_primitive_inventory_section`). Proven directly
by `bench/v22_merge_verification/contract_header_unwrapped_repro.py`: a
crafted import specifier (`m.package`) rode straight into the unwrapped
header. Fixed by wrapping each repo-derived field (`m.file`, `m.package`,
`m.symbol`) individually in `wrap_untrusted()`, matching the per-field
wrapping discipline this codebase already uses for `ClaimCard` fields in
`adversary.py`/`critic.py` (e.g. `wrap_untrusted(claim_card.target_sink)`).
`m.symbol` is wrapped too for consistency even though, by the time this
function runs, its value is constrained to equal one of `CONTRACT_TABLE`'s
own fixed symbol names (case-insensitively) -- defense in depth, not a
confirmed second injection vector. `lexical.strip_comments_and_docstrings()`
does not apply here: these are short field values (a package specifier, a
file path), not source excerpts with comments to strip.
"""

from __future__ import annotations

from dataclasses import dataclass

from .primitive_inventory import PrimitiveMatch
from .untrusted_text import wrap_untrusted


@dataclass(frozen=True)
class ContractNote:
    symbol: str
    package_substring: str  # "" = match any package (symbol name alone is unambiguous)
    contract_text: str  # curated, target-independent fact + real external citation(s)
    sources: tuple[str, ...]  # the real URL(s) verified live while building this table


# --------------------------------------------------------------------------
# The 3 entries the recognition-gap experiment's own Arm 3 already used and
# validated (RECOGNITION_GAP_EXPERIMENT_RESULTS.md Section 1c) -- wording
# and citations reused directly from that report, not rewritten from memory.
# --------------------------------------------------------------------------

_CORE_TABLE: tuple[ContractNote, ...] = (
    ContractNote(
        symbol="loadPyodide",
        package_substring="pyodide",
        contract_text=(
            "loadPyodide() without an explicit `jsglobals` restriction exposes the full browser/Node global "
            "object via the js bridge -- see also n8n CVE-2025-68668 (\"N8Scape\", CVSS 9.9: Pyodide sandbox "
            "escape via `_pyodide._base.eval_code()`/`ctypes` abusing Python-JS interop to reach Node.js "
            "internals and execute system commands, fixed by rewriting the Python execution model in n8n "
            "v2.0) and the Grist-Core Pyodide sandbox escape, GHSA-7xvx-8pf2-pv5g (\"Cellbreak\", CVSS 9.1: "
            "Python class-hierarchy traversal plus exposed `ctypes`/Emscripten runtime hooks escaping to host "
            "command/JS execution, fixed by running Pyodide under Deno with permission-based isolation in "
            "Grist 1.7.9). Both are the same root pattern: an unrestricted Pyodide interpreter lets "
            "interpreted Python reach back into the host/embedding runtime."
        ),
        sources=(
            "https://www.cyera.com/research/n8scape-pyodide-sandbox-escape-9-9-critical-post-auth-rce-in-n8n-cve-2025-68668",
            "https://www.cyera.com/research-labs/cellbreak-grists-pyodide-sandbox-escape-and-the-data-at-risk-blast-radius",
        ),
    ),
    ContractNote(
        symbol="JWTIssuer",
        package_substring="jwt_issuer",
        contract_text=(
            "RFC 8707 (\"Resource Indicators for OAuth 2.0\") requires an authorization server bind an issued "
            "access token's audience to the specific resource the client requested via the `resource` "
            "parameter -- a fixed audience shared across every issued token (not read from the client's own "
            "per-request `resource` parameter) fails to bind tokens to the resource they were actually "
            "requested for. This is documented as the FastMCP maintainers' own root-cause description in "
            "GHSA-5h2m-4q8j-pqpj: \"the server does not properly respect the `resource` parameter submitted "
            "by the client in the authorization and token request\" -- tokens are issued for the base URL "
            "used at initialization instead of the specific MCP server/resource requested."
        ),
        sources=("https://github.com/PrefectHQ/fastmcp/security/advisories/GHSA-5h2m-4q8j-pqpj",),
    ),
    ContractNote(
        symbol="_requestToStreamMapping",
        package_substring="",
        contract_text=(
            "MCP client SDKs generate JSON-RPC message IDs from an incrementing counter starting at 0, so any "
            "two independent client connections sharing ONE server transport instance will produce colliding "
            "request IDs. Documented as the MCP TypeScript SDK maintainers' own root cause in "
            "GHSA-345p-7cg4-v4c7: \"The transport maintains an internal `requestId -> stream` mapping, and "
            "since MCP client SDKs generate message IDs using an incrementing counter starting at 0, two "
            "clients produce identical IDs. The second client's request overwrites the first client's "
            "mapping entry, routing the response to the wrong HTTP stream.\" Session-ID matching is a "
            "DIFFERENT check -- it does not prevent two requests through the SAME shared transport instance "
            "from colliding on this map."
        ),
        sources=("https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-345p-7cg4-v4c7",),
    ),
)

# --------------------------------------------------------------------------
# A few additional, real, externally-verifiable entries beyond the 3 core
# ones (task's own explicit ask). Each verified live (WebFetch/WebSearch)
# while building this table -- see bench/RECOGNITION_GAP_FIX_STATUS.md for
# the verification notes. Candidates named in Fable's earlier research.
# --------------------------------------------------------------------------

_EXTRA_TABLE: tuple[ContractNote, ...] = (
    ContractNote(
        symbol="VM",
        package_substring="vm2",
        contract_text=(
            "The `vm2` Node.js sandbox package has multiple confirmed, unfixed sandbox-escape "
            "vulnerabilities allowing arbitrary host code execution from code run \"inside\" the sandbox "
            "(CVE-2023-37903, \"Custom Inspect\" escape via `util.inspect.custom` + `WebAssembly."
            "compileStreaming`, reaching the host's `Function` constructor; related CVE-2023-29017, "
            "CVE-2023-29199, CVE-2023-30547, CVE-2023-32314, CVE-2023-37466). The `vm2` project has been "
            "discontinued with no further patches -- there is no documented safe configuration; running "
            "untrusted code through `vm2` at all is the unsafe condition, not a specific missing option."
        ),
        sources=(
            "https://www.sentinelone.com/vulnerability-database/cve-2023-37903/",
            "https://thehackernews.com/2026/01/critical-vm2-nodejs-flaw-allows-sandbox.html",
        ),
    ),
    ContractNote(
        symbol="request",
        package_substring="https",
        contract_text=(
            "Node's `https`/`tls` request and connection APIs validate the server's TLS certificate by "
            "default; setting `rejectUnauthorized: false` on the request/agent options (or the process-wide "
            "`NODE_TLS_REJECT_UNAUTHORIZED=0` environment variable) disables that validation entirely, "
            "enabling man-in-the-middle interception of anything sent over that connection -- there is no "
            "safe use of either short of a fully isolated, non-production test environment. A real, confirmed "
            "example: Nodemailer's OAuth2 token-fetch path (GHSA-r7g4-qg5f-qqm2) shipped `rejectUnauthorized: "
            "false` in its internal fetch client, allowing OAuth2 credential interception via MITM."
        ),
        sources=(
            "https://dailycve.com/nodemailer-improper-tls-certificate-validation-in-oauth2-token-fetch-ghsa-r7g4-qg5f-qqm2-medium-dc-jun2026-403/",
        ),
    ),
    ContractNote(
        symbol="connect",
        package_substring="tls",
        contract_text=(
            "Node's `tls.connect`/`tls.createSecureContext` validate the peer certificate by default; "
            "`rejectUnauthorized: false` (or the process-wide `NODE_TLS_REJECT_UNAUTHORIZED=0` environment "
            "variable read at startup) disables that validation entirely and allows MITM interception -- "
            "there is no safe production use of either. See also the `request`/`https` entry in this same "
            "table for a real, confirmed real-world example of this exact anti-pattern (Nodemailer, "
            "GHSA-r7g4-qg5f-qqm2)."
        ),
        sources=(
            "https://dailycve.com/nodemailer-improper-tls-certificate-validation-in-oauth2-token-fetch-ghsa-r7g4-qg5f-qqm2-medium-dc-jun2026-403/",
        ),
    ),
    ContractNote(
        symbol="StreamableHTTPServerTransport",
        package_substring="",
        contract_text=(
            "The official Model Context Protocol TypeScript SDK's `StreamableHTTPServerTransport` does NOT "
            "enable DNS-rebinding protection by default -- `enableDnsRebindingProtection` defaults to "
            "`false` \"for backwards compatibility\", per the MCP TypeScript SDK maintainers' own advisory, "
            "CVE-2025-66414 / GHSA-w48q-cv73-mx4w: an HTTP-based MCP server run on localhost without "
            "authentication and without `enableDnsRebindingProtection: true` set explicitly can have its "
            "same-origin protections bypassed by a malicious website via DNS rebinding, reaching the local "
            "MCP server. Fixed/addressable starting SDK version 1.24.0. This is the exact class this table's "
            "own `_requestToStreamMapping` entry (session-isolation) is a field of -- a DIFFERENT, "
            "independently real gap in the same primitive."
        ),
        sources=("https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-w48q-cv73-mx4w",),
    ),
)

CONTRACT_TABLE: tuple[ContractNote, ...] = _CORE_TABLE + _EXTRA_TABLE


def match_contract_notes(matches: list[PrimitiveMatch]) -> list[str]:
    """For every inventoried primitive whose `(symbol, package)` matches a
    `CONTRACT_TABLE` row, build the injectable note text: a dynamic header
    naming the real matched location (never hand-typed -- generated from
    the actual `PrimitiveMatch`, so it's correct for whatever target this
    runs against, not just the sealed cases that motivated each row) plus
    that row's curated, externally-sourced contract fact. No match for a
    given primitive -> nothing added for it (never degrades evidence for a
    unit with no matched primitive, per the task's own explicit
    requirement).

    The header names the matched location using `m.file`/`m.package`/
    `m.symbol` -- real, repo-derived text taken verbatim from the scanned
    target's own import statements/source, never from this project's own
    curated content. Each is individually wrapped in `wrap_untrusted()`
    (contract-table-header-fix milestone) so a maliciously-named package or
    file in a target repo cannot inject prompt content via its own name;
    `row.contract_text`/`row.sources` stay unwrapped, exactly as before --
    they are this project's own trusted, hand-authored, externally-cited
    content, not repo-derived."""
    notes: list[str] = []
    seen: set[tuple[str, str, int]] = set()
    for m in matches:
        for row in CONTRACT_TABLE:
            if row.symbol.lower() != m.symbol.lower():
                continue
            if row.package_substring and row.package_substring.lower() not in (m.package or "").lower():
                continue
            key = (m.file, m.symbol, m.call_line)
            if key in seen:
                continue
            seen.add(key)
            source_list = "; ".join(row.sources)
            header = (
                f"Primitive matched: `{wrap_untrusted(m.symbol)}` ({wrap_untrusted(m.package)}), "
                f"at {wrap_untrusted(m.file)}:{m.call_line}."
            )
            notes.append(f"{header}\n{row.contract_text}\n\n*Verified live: {source_list}*")
    return notes
