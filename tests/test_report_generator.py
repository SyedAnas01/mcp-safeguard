"""Tests for HTML report generation, in particular XSS-safety of interpolated
attacker-controlled fields (a scanned server's own tool names/target string)."""

from mcp_safeguard.scanner.prompt_injection import Severity
from mcp_safeguard.scanner.report_generator import (
    ScanSummary,
    SecurityReport,
    generate_html_report,
)
from mcp_safeguard.scanner.tool_analyzer import ToolRiskProfile

_XSS_PAYLOAD = "<script>alert(document.cookie)</script>"


def _empty_report(target: str, tool_risk_profiles: list[ToolRiskProfile]) -> SecurityReport:
    summary = ScanSummary(
        scan_id="test-scan-id",
        target=target,
        scan_time="2026-01-01T00:00:00Z",
        duration_ms=1.0,
        total_findings=0,
        critical_count=0,
        high_count=0,
        medium_count=0,
        low_count=0,
        info_count=0,
        overall_severity=Severity.INFO,
        overall_cvss=0.0,
        tools_scanned=len(tool_risk_profiles),
        categories_scanned=[],
    )
    return SecurityReport(
        summary=summary,
        injection_findings=[],
        credential_findings=[],
        endpoint_findings=[],
        tool_risk_profiles=tool_risk_profiles,
        tool_poisoning_findings=[],
    )


def test_html_report_escapes_malicious_tool_name():
    """A scanned server's tool name is fully attacker-controlled (that's the
    whole point of scanning untrusted/hostile servers) -- it must never reach
    the generated report as live HTML."""
    profile = ToolRiskProfile(
        tool_name=_XSS_PAYLOAD,
        blast_radius_score=1.0,
        permission_risk=1.0,
        overall_risk=1.0,
        risk_level=Severity.INFO,
        risk_factors=[_XSS_PAYLOAD],
        recommendations=[],
    )
    html = generate_html_report(_empty_report("http://localhost:8000", [profile]))
    assert _XSS_PAYLOAD not in html
    assert "&lt;script&gt;" in html


def test_html_report_escapes_malicious_target():
    """The scan target string (caller-supplied URL/path) is echoed into both
    <title> and the page body -- must be escaped in both places."""
    html = generate_html_report(_empty_report(f"http://x/{_XSS_PAYLOAD}", []))
    assert _XSS_PAYLOAD not in html
    assert html.count("&lt;script&gt;") >= 2  # once in <title>, once in the body
