"""Tests for the SSRF scanner."""

from mcp_shield.scanner.ssrf_scanner import scan_for_ssrf


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
