"""Tests for the recognition-gap-fix Part 2 contract table
(contract_table.py) and its wiring to Part 1's primitive-inventory scanner.
See that module's own docstring and bench/RECOGNITION_GAP_FIX_STATUS.md.
"""

from __future__ import annotations

from mcp_safeguard.scanner.contract_table import CONTRACT_TABLE, match_contract_notes
from mcp_safeguard.scanner.primitive_inventory import PrimitiveMatch


def _match(symbol, package, file="server.py", line=10):
    return PrimitiveMatch(
        file=file,
        import_line=1,
        call_line=line,
        package=package,
        symbol=symbol,
        call_snippet=f"{symbol}(...)",
        category="token-issuer-or-verifier",
        kind="call",
    )


def test_every_contract_table_row_has_a_real_citation():
    """Structural sanity check: no row is silently empty -- every entry
    carries curated contract text AND at least one real source URL."""
    assert len(CONTRACT_TABLE) >= 3
    for row in CONTRACT_TABLE:
        assert row.symbol
        assert row.contract_text.strip()
        assert len(row.sources) >= 1
        for src in row.sources:
            assert src.startswith("https://")


def test_matches_exact_symbol_and_package_substring():
    matches = [_match("loadPyodide", "pyodide")]
    notes = match_contract_notes(matches)
    assert len(notes) == 1
    assert "jsglobals" in notes[0]
    assert "loadPyodide" in notes[0]
    # contract-table-header-fix milestone: `m.file`/`m.call_line` are no
    # longer directly adjacent in the header text -- `m.file` is now
    # individually wrapped in `wrap_untrusted()`, so "server.py:10" is not
    # a contiguous substring any more. Check each piece separately instead.
    assert "server.py" in notes[0]
    assert ":10" in notes[0]


def test_no_match_when_symbol_unknown():
    matches = [_match("SomeUnrelatedThing", "some-package")]
    assert match_contract_notes(matches) == []


def test_no_match_when_package_substring_does_not_match():
    """`JWTIssuer` alone isn't enough -- the package must contain
    'jwt_issuer' too, or this could false-fire on an unrelated same-named
    class from a totally different codebase."""
    matches = [_match("JWTIssuer", "totally.unrelated.module")]
    assert match_contract_notes(matches) == []


def test_matches_when_package_substring_present():
    matches = [_match("JWTIssuer", "fastmcp.server.auth.jwt_issuer")]
    notes = match_contract_notes(matches)
    assert len(notes) == 1
    assert "RFC 8707" in notes[0]
    assert "GHSA-5h2m-4q8j-pqpj" in notes[0]


def test_empty_package_substring_matches_any_package():
    """The `_requestToStreamMapping` row has an empty `package_substring`
    -- it must match regardless of what's in the `package` field (this is
    the self-defined-primitive case, where package is a descriptive
    string, not a real module path)."""
    matches = [_match("_requestToStreamMapping", "(self-defined in this file, instance field of X)")]
    notes = match_contract_notes(matches)
    assert len(notes) == 1
    assert "GHSA-345p-7cg4-v4c7" in notes[0]


def test_no_matched_primitives_injects_nothing():
    assert match_contract_notes([]) == []


def test_dns_rebinding_row_fires_for_real_sdk_class_name():
    matches = [_match("StreamableHTTPServerTransport", "@modelcontextprotocol/sdk/server/streamableHttp.js")]
    notes = match_contract_notes(matches)
    assert len(notes) == 1
    assert "enableDnsRebindingProtection" in notes[0]
    assert "CVE-2025-66414" in notes[0]
