"""Tests for the SSRF scanner."""

from mcp_safeguard.scanner.ssrf_scanner import scan_for_ssrf


def test_url_param_with_only_format_uri_is_still_flagged():
    """
    A JSON-Schema `format` keyword (e.g. format: "uri") is a non-constraining
    annotation, not real protection — it must not be treated as sufficient
    to skip flagging an unconstrained URL parameter.
    """
    tools = [
        {
            "name": "fetch_page",
            "description": "Fetch the given url and return its contents.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "format": "uri"},
                },
                "required": ["url"],
            },
        }
    ]
    findings = scan_for_ssrf(tools)
    assert any(f.rule_id == "SS-001" for f in findings), (
        f"Expected an SS-001 finding despite format:'uri', got: {findings}"
    )


# --- SS-004: source-level metadata/JWKS/discovery fetch sink -----------------

from pathlib import Path

import pytest

from mcp_safeguard.scanner.ssrf_scanner import scan_source_for_metadata_ssrf

_FIX = Path(__file__).parent / "fixtures" / "ssrf_cimd"


def _scan(name: str):
    return scan_source_for_metadata_ssrf((_FIX / name).read_text(), name)


@pytest.mark.parametrize(
    "name,min_hits",
    [
        ("pos_cimd.ts", 1),
        ("pos_jwks.js", 2),
        ("pos_cimd.py", 2),
        ("pos_pyjwk.py", 1),
        ("pos_cimd.go", 2),
    ],
)
def test_ss004_flags_unguarded_metadata_fetch(name, min_hits):
    f = _scan(name)
    assert len(f) >= min_hits and all(x.rule_id == "SS-004" for x in f)
    assert all(x.severity.name == "HIGH" for x in f)


@pytest.mark.parametrize(
    "name",
    ["neg_guarded.ts", "neg_const.ts", "neg_guarded.py", "neg_const.py",
     "neg_guarded.go", "neg_const.go"],
)
def test_ss004_silent_on_guarded_or_constant(name):
    assert _scan(name) == []


def test_ss004_range_check_without_redirect_guard_is_medium():
    f = _scan("neg_redirect_bypass_pre.py")
    assert len(f) == 1 and f[0].severity.name == "MEDIUM"
    assert "redirect guard" in f[0].evidence


def test_ss004_ignores_commented_guard_and_unknown_language():
    src = "// TODO ssrf isPrivate check\nawait fetch(clientId);\n"
    assert len(scan_source_for_metadata_ssrf(src, "a.ts")) == 1
    assert scan_source_for_metadata_ssrf(src, "a.rb") == []
