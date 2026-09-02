"""Tests for the CLI scanning entrypoint."""

import json

from mcp_safeguard.cli import _run_scan, _run_source_scan, _write_output


def test_scan_source_json_output_is_pure_json_on_stdout(tmp_path, capsys):
    """
    --format json must produce ONLY the JSON document on stdout -- the banner
    and status lines used to print unconditionally to stdout too, so
    `scan-source . --format json > baseline.json` silently produced a file
    that wasn't valid JSON (this is also how a real baseline file gets
    generated per the documented workflow, so this must actually work).
    """
    (tmp_path / "client.py").write_text(
        'import httpx\ndef f(u):\n    return httpx.get(u, verify=False)\n'
    )
    _run_source_scan(str(tmp_path), fmt="json")
    captured = capsys.readouterr()
    data = json.loads(captured.out)  # must not raise
    assert any(f["rule_id"] == "SRC-013" for f in data)
    assert captured.out.strip().startswith("[")


def test_scan_source_baseline_suppresses_previously_seen_findings(tmp_path, capsys):
    (tmp_path / "client.py").write_text(
        'import httpx\ndef f(u):\n    return httpx.get(u, verify=False)\n'
    )
    _run_source_scan(str(tmp_path), fmt="json")
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(capsys.readouterr().out)

    _run_source_scan(str(tmp_path), fmt="json", baseline=str(baseline_path))
    data = json.loads(capsys.readouterr().out)
    assert data == []


def test_write_output_html_escapes_finding_fields(tmp_path):
    """
    title/location/remediation/rule_id ultimately derive from a scanned
    server's own tool definitions (fully attacker-controlled when scanning a
    hostile server) -- --output report.html must not let them inject live
    HTML into the CLI's own report.
    """
    payload = "<script>alert(1)</script>"
    findings = [
        {
            "severity": "HIGH",
            "rule_id": payload,
            "title": payload,
            "location": payload,
            "cvss": 7.5,
            "remediation": payload,
        }
    ]
    out_path = tmp_path / "report.html"
    _write_output(findings, str(out_path), scanned=payload)

    html = out_path.read_text()
    assert payload not in html
    assert html.count("&lt;script&gt;") >= 5  # 4 finding fields + the scanned target


def test_realistic_mcp_servers_config_warns_tools_skipped(tmp_path, capsys):
    """
    A real Claude Desktop config's mcpServers entries never embed tool
    definitions inline (only command/args/env) — _extract_tools legitimately
    returns []. The CLI must warn on stderr that tool-based checks were
    skipped, rather than silently reporting a clean scan.
    """
    config = {"mcpServers": {"srv": {"command": "npx", "args": [], "env": {}}}}
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(config))

    _run_scan(str(config_path))

    captured = capsys.readouterr()
    assert "tool" in captured.err.lower()
    assert "skip" in captured.err.lower()
