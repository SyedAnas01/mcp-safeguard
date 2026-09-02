"""Tests for inline suppression comments (scan-source) and SARIF output."""

import json

from mcp_safeguard.scanner.report_generator import generate_sarif_report
from mcp_safeguard.scanner.source_scanner import scan_source_tree

# --- Inline suppression -----------------------------------------------------


def test_suppression_comment_silences_named_rule(tmp_path):
    (tmp_path / "client.py").write_text(
        '''
        import httpx

        async def fetch(url):
            async with httpx.AsyncClient(verify=False) as client:  # safeguard: ignore[SRC-013] internal dev cert
                return await client.get(url)
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-013" for f in findings), (
        f"Expected SRC-013 to be suppressed, got: {findings}"
    )


def test_suppression_comment_only_silences_named_rule_not_others(tmp_path):
    """A suppression naming one rule must not accidentally silence a
    DIFFERENT rule that also fires on the same line."""
    (tmp_path / "client.py").write_text(
        '''
        import httpx

        async def fetch(url):
            async with httpx.AsyncClient(verify=False) as client:  # safeguard: ignore[SRC-099]
                return await client.get(url)
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert any(f.rule_id == "SRC-013" for f in findings), (
        f"SRC-013 should still fire -- the suppression names a different rule, got: {findings}"
    )


def test_suppression_wildcard_silences_every_rule_on_that_line(tmp_path):
    (tmp_path / "client.py").write_text(
        '''
        import httpx

        async def fetch(url):
            async with httpx.AsyncClient(verify=False) as client:  # safeguard: ignore[*]
                return await client.get(url)
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-013" for f in findings)


def test_no_suppression_comment_does_not_affect_findings(tmp_path):
    (tmp_path / "client.py").write_text(
        '''
        import httpx

        async def fetch(url):
            async with httpx.AsyncClient(verify=False) as client:
                return await client.get(url)
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert any(f.rule_id == "SRC-013" for f in findings)


# --- SARIF output ------------------------------------------------------------


def test_sarif_report_is_valid_shape():
    findings = [
        {
            "rule_id": "SRC-013",
            "severity": "HIGH",
            "title": "TLS certificate verification disabled",
            "location": "client.py:5",
            "evidence": "verify=False",
            "cvss": 7.4,
            "remediation": "Never disable certificate verification.",
        }
    ]
    sarif = json.loads(generate_sarif_report(findings))

    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "mcp-safeguard"

    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert "SRC-013" in rule_ids

    result = run["results"][0]
    assert result["ruleId"] == "SRC-013"
    assert result["level"] == "error"  # HIGH maps to SARIF "error"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "client.py"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 5


def test_sarif_report_deduplicates_rule_catalog_entries():
    """Two findings for the same rule_id must produce one rules[] entry, not two."""
    findings = [
        {"rule_id": "SRC-013", "severity": "HIGH", "title": "t", "location": "a.py:1", "cvss": 7.4},
        {"rule_id": "SRC-013", "severity": "HIGH", "title": "t", "location": "b.py:2", "cvss": 7.4},
    ]
    sarif = json.loads(generate_sarif_report(findings))
    run = sarif["runs"][0]
    assert len(run["tool"]["driver"]["rules"]) == 1
    assert len(run["results"]) == 2


def test_sarif_report_handles_non_file_location_gracefully():
    """Config-scan findings use "tool:name.field" or "config" locations, not
    real file:line -- SARIF output must not crash on those, just skip a
    precise line number."""
    findings = [
        {"rule_id": "CRED-001", "severity": "CRITICAL", "title": "t", "location": "config", "cvss": 9.0},
    ]
    sarif = json.loads(generate_sarif_report(findings))
    result = sarif["runs"][0]["results"][0]
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "config"
