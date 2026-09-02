"""Generate CVSS-style severity scores and formatted security reports."""

from __future__ import annotations

import html
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from mcp_safeguard import __version__

from .credential_scanner import CredentialFinding
from .endpoint_scanner import EndpointFinding
from .prompt_injection import InjectionFinding, Severity
from .ssrf_scanner import SSRFFinding
from .tool_analyzer import ToolPoisoningFinding, ToolRiskProfile


@dataclass
class ScanSummary:
    """High-level summary of a security scan."""

    scan_id: str
    target: str
    scan_time: str
    duration_ms: float
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    overall_severity: Severity
    overall_cvss: float
    tools_scanned: int
    categories_scanned: list[str]


@dataclass
class SecurityReport:
    """Complete security report for an MCP server scan."""

    summary: ScanSummary
    injection_findings: list[InjectionFinding]
    credential_findings: list[CredentialFinding]
    endpoint_findings: list[EndpointFinding]
    tool_risk_profiles: list[ToolRiskProfile]
    tool_poisoning_findings: list[ToolPoisoningFinding]
    ssrf_findings: list[SSRFFinding] = field(default_factory=list)
    raw_metadata: dict[str, Any] = field(default_factory=dict)


def _severity_order(s: Severity) -> int:
    """Numeric order for severity (higher = more severe)."""
    return {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}.get(s.value, 0)


def _count_by_severity(findings: list[Any]) -> dict[str, int]:
    """Count findings by severity field."""
    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = getattr(f, "severity", None)
        if sev:
            counts[sev.value] = counts.get(sev.value, 0) + 1
    return counts


def generate_scan_summary(
    target: str,
    injection_findings: list[InjectionFinding],
    credential_findings: list[CredentialFinding],
    endpoint_findings: list[EndpointFinding],
    tool_risk_profiles: list[ToolRiskProfile],
    tool_poisoning_findings: list[ToolPoisoningFinding],
    duration_ms: float,
    categories: list[str],
    ssrf_findings: list[SSRFFinding] | None = None,
) -> ScanSummary:
    """Build a ScanSummary from all finding collections."""
    all_findings: list[Any] = (
        injection_findings
        + credential_findings
        + endpoint_findings
        + tool_poisoning_findings
        + (ssrf_findings or [])
    )
    counts = _count_by_severity(all_findings)

    # Overall CVSS = max CVSS across all findings
    all_cvss = [getattr(f, "cvss_score", 0.0) for f in all_findings]
    overall_cvss = max(all_cvss) if all_cvss else 0.0

    # Determine overall severity
    if counts["CRITICAL"] > 0:
        overall_sev = Severity.CRITICAL
    elif counts["HIGH"] > 0:
        overall_sev = Severity.HIGH
    elif counts["MEDIUM"] > 0:
        overall_sev = Severity.MEDIUM
    elif counts["LOW"] > 0:
        overall_sev = Severity.LOW
    else:
        overall_sev = Severity.INFO

    return ScanSummary(
        scan_id=str(uuid.uuid4()),
        target=target,
        scan_time=datetime.now(UTC).isoformat(),
        duration_ms=round(duration_ms, 2),
        total_findings=len(all_findings),
        critical_count=counts["CRITICAL"],
        high_count=counts["HIGH"],
        medium_count=counts["MEDIUM"],
        low_count=counts["LOW"],
        info_count=counts["INFO"],
        overall_severity=overall_sev,
        overall_cvss=round(overall_cvss, 1),
        tools_scanned=len(tool_risk_profiles),
        categories_scanned=categories,
    )


def report_to_dict(report: SecurityReport) -> dict[str, Any]:
    """Serialize a SecurityReport to a plain dict for JSON output."""

    def to_serializable(obj: Any) -> Any:
        if hasattr(obj, "__dataclass_fields__"):
            return {k: to_serializable(v) for k, v in asdict(obj).items()}
        if isinstance(obj, Severity):
            return obj.value
        if isinstance(obj, list):
            return [to_serializable(i) for i in obj]
        if isinstance(obj, dict):
            return {k: to_serializable(v) for k, v in obj.items()}
        return obj

    return to_serializable(report)


def generate_html_report(report: SecurityReport) -> str:
    """
    Render a security report as a self-contained HTML page.

    Args:
        report: SecurityReport instance.

    Returns:
        Complete HTML string.
    """
    s = report.summary
    sev_colors = {
        "CRITICAL": "#dc2626",
        "HIGH": "#ea580c",
        "MEDIUM": "#d97706",
        "LOW": "#65a30d",
        "INFO": "#0284c7",
    }
    sev_color = sev_colors.get(s.overall_severity.value, "#6b7280")
    # s.target is the raw scan-target string the caller passed in (a URL or path)
    # and is echoed into both <title> and the page body below; escape it so a
    # crafted target string can't break out of the HTML it's embedded in.
    safe_target = html.escape(str(s.target))

    # Build findings table rows
    def finding_rows(findings: list[Any], columns: list[str]) -> str:
        rows = []
        for f in findings:
            sev_val = getattr(f, "severity", Severity.INFO).value
            color = sev_colors.get(sev_val, "#6b7280")
            row_cells = []
            for col in columns:
                val = getattr(f, col, "")
                if col == "severity":
                    row_cells.append(
                        f'<td><span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-size:12px">{val}</span></td>'
                    )
                elif col == "cvss_score":
                    row_cells.append(f'<td style="text-align:center;font-weight:bold">{val}</td>')
                else:
                    escaped = html.escape(str(val))[:200]
                    row_cells.append(f"<td>{escaped}</td>")
            rows.append(f"<tr>{''.join(row_cells)}</tr>")
        return (
            "\n".join(rows)
            if rows
            else '<tr><td colspan="10" style="text-align:center;color:#6b7280">No findings</td></tr>'
        )

    inj_rows = finding_rows(
        report.injection_findings,
        ["rule_id", "severity", "cvss_score", "title", "location", "evidence"],
    )
    cred_rows = finding_rows(
        report.credential_findings,
        ["rule_id", "severity", "cvss_score", "title", "location", "evidence"],
    )
    ep_rows = finding_rows(
        report.endpoint_findings,
        ["rule_id", "severity", "cvss_score", "title", "location", "evidence"],
    )
    poison_rows = finding_rows(
        report.tool_poisoning_findings,
        ["rule_id", "severity", "cvss_score", "title", "location", "evidence"],
    )

    # Tool risk table. tool_name and risk_factors come from the scanned server's
    # own tool definitions — fully attacker-controlled when scanning a hostile or
    # compromised MCP server, which is this tool's whole purpose — so they must
    # be escaped before interpolation, same as every other findings table above.
    tool_rows = []
    for tp in report.tool_risk_profiles:
        color = sev_colors.get(tp.risk_level.value, "#6b7280")
        safe_name = html.escape(str(tp.tool_name))
        safe_factors = "<br>".join(html.escape(str(rf)) for rf in tp.risk_factors[:3])
        tool_rows.append(
            f"<tr>"
            f"<td><strong>{safe_name}</strong></td>"
            f'<td><span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-size:12px">{tp.risk_level.value}</span></td>'
            f"<td style='text-align:center'>{tp.overall_risk}</td>"
            f"<td style='text-align:center'>{tp.blast_radius_score}</td>"
            f"<td style='text-align:center'>{tp.permission_risk}</td>"
            f"<td>{safe_factors}</td>"
            f"</tr>"
        )
    tool_table_rows = (
        "\n".join(tool_rows) if tool_rows else '<tr><td colspan="6">No tools scanned</td></tr>'
    )

    # Named `page`, not `html` -- the latter would shadow the `html` module
    # imported at the top of this file for escaping, and Python treats a name
    # assigned anywhere in a function as local for the WHOLE function, so every
    # `html.escape(...)` call above this point would raise UnboundLocalError.
    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>mcp-safeguard Security Report — {safe_target}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f8fafc; color: #1e293b; }}
  .header {{ background: #0f172a; color: white; padding: 24px 32px; }}
  .header h1 {{ font-size: 24px; font-weight: 700; }}
  .header p {{ opacity: 0.7; margin-top: 4px; font-size: 14px; }}
  .badge {{ display: inline-block; background: {sev_color}; color: white; padding: 4px 12px; border-radius: 20px; font-weight: 700; font-size: 18px; margin-top: 12px; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 24px 32px; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; margin: 24px 0; }}
  .stat-card {{ background: white; border-radius: 8px; padding: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); text-align: center; }}
  .stat-card .number {{ font-size: 32px; font-weight: 700; }}
  .stat-card .label {{ font-size: 13px; color: #64748b; margin-top: 4px; }}
  .section {{ background: white; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
  .section h2 {{ font-size: 18px; font-weight: 600; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 2px solid #e2e8f0; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ background: #f1f5f9; text-align: left; padding: 10px 12px; font-weight: 600; color: #475569; }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #e2e8f0; vertical-align: top; word-break: break-word; max-width: 300px; }}
  tr:hover td {{ background: #f8fafc; }}
  .footer {{ text-align: center; padding: 24px; color: #94a3b8; font-size: 13px; }}
</style>
</head>
<body>
<div class="header">
  <h1>🛡️ mcp-safeguard Security Report</h1>
  <p>Target: {safe_target} &nbsp;|&nbsp; Scan ID: {s.scan_id} &nbsp;|&nbsp; {s.scan_time}</p>
  <div class="badge">Overall: {s.overall_severity.value} (CVSS {s.overall_cvss})</div>
</div>

<div class="container">
  <div class="summary-grid">
    <div class="stat-card"><div class="number" style="color:#dc2626">{s.critical_count}</div><div class="label">Critical</div></div>
    <div class="stat-card"><div class="number" style="color:#ea580c">{s.high_count}</div><div class="label">High</div></div>
    <div class="stat-card"><div class="number" style="color:#d97706">{s.medium_count}</div><div class="label">Medium</div></div>
    <div class="stat-card"><div class="number" style="color:#65a30d">{s.low_count}</div><div class="label">Low</div></div>
    <div class="stat-card"><div class="number" style="color:#0284c7">{s.info_count}</div><div class="label">Info</div></div>
    <div class="stat-card"><div class="number">{s.total_findings}</div><div class="label">Total</div></div>
    <div class="stat-card"><div class="number">{s.tools_scanned}</div><div class="label">Tools</div></div>
    <div class="stat-card"><div class="number">{s.duration_ms:.0f}ms</div><div class="label">Scan Time</div></div>
  </div>

  <div class="section">
    <h2>🔴 Prompt Injection ({len(report.injection_findings)} findings)</h2>
    <table>
      <tr><th>Rule</th><th>Severity</th><th>CVSS</th><th>Title</th><th>Location</th><th>Evidence</th></tr>
      {inj_rows}
    </table>
  </div>

  <div class="section">
    <h2>🔑 Credential Exposure ({len(report.credential_findings)} findings)</h2>
    <table>
      <tr><th>Rule</th><th>Severity</th><th>CVSS</th><th>Title</th><th>Location</th><th>Evidence</th></tr>
      {cred_rows}
    </table>
  </div>

  <div class="section">
    <h2>🌐 Endpoint Exposure ({len(report.endpoint_findings)} findings)</h2>
    <table>
      <tr><th>Rule</th><th>Severity</th><th>CVSS</th><th>Title</th><th>Location</th><th>Evidence</th></tr>
      {ep_rows}
    </table>
  </div>

  <div class="section">
    <h2>☠️ Tool Poisoning ({len(report.tool_poisoning_findings)} findings)</h2>
    <table>
      <tr><th>Rule</th><th>Severity</th><th>CVSS</th><th>Title</th><th>Location</th><th>Evidence</th></tr>
      {poison_rows}
    </table>
  </div>

  <div class="section">
    <h2>⚖️ Tool Risk Profiles</h2>
    <table>
      <tr><th>Tool</th><th>Risk Level</th><th>Overall</th><th>Blast Radius</th><th>Perm Risk</th><th>Risk Factors</th></tr>
      {tool_table_rows}
    </table>
  </div>
</div>

<div class="footer">
  Generated by <strong>mcp-safeguard v{__version__}</strong> &mdash; <a href="https://github.com/SyedAnas01/mcp-safeguard">github.com/SyedAnas01/mcp-safeguard</a>
  &nbsp;|&nbsp; Scan duration: {s.duration_ms:.1f}ms &nbsp;|&nbsp; Scanned: {s.scan_time}
</div>
</body>
</html>"""
    return page


_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}


def generate_sarif_report(findings: list[dict[str, Any]]) -> str:
    """
    Render a flat findings list as a SARIF 2.1.0 log, for GitHub code scanning
    and any other SARIF-consuming CI system.

    Args:
        findings: List of finding dicts with rule_id, severity, title,
            location ("file:line" or "file:line-endline"), evidence, cvss,
            remediation -- the same shape the CLI's `scan`/`scan-source`
            commands already build internally.

    Returns:
        A SARIF 2.1.0 JSON document as a string.
    """
    # One ruleId can appear multiple times with different findings; SARIF
    # wants each rule described once in tool.driver.rules, referenced by id
    # from each result. Build the rule catalog from what's actually present
    # rather than a hardcoded list, so it never drifts from real findings.
    seen_rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for f in findings:
        rule_id = str(f.get("rule_id", "UNKNOWN"))
        severity = str(f.get("severity", "INFO")).upper()
        title = str(f.get("title", rule_id))
        location = str(f.get("location", ""))

        if rule_id not in seen_rules:
            seen_rules[rule_id] = {
                "id": rule_id,
                "name": title,
                "shortDescription": {"text": title},
                "fullDescription": {"text": title},
                "help": {"text": str(f.get("remediation", ""))},
                "properties": {
                    "security-severity": str(f.get("cvss", 0.0)),
                    "tags": ["security", "mcp-safeguard"],
                },
                "defaultConfiguration": {"level": _SARIF_LEVEL.get(severity, "warning")},
            }

        # location is "path:line" (source-audit) or "tool:name.field"/
        # "config" (config-scan modes, no real file/line to point at) --
        # only emit a physicalLocation when it parses as a real file:line.
        artifact_uri = location
        start_line = 1
        if ":" in location:
            path_part, _, line_part = location.rpartition(":")
            if path_part and line_part.split("-")[0].isdigit():
                artifact_uri = path_part
                start_line = int(line_part.split("-")[0])

        results.append({
            "ruleId": rule_id,
            "level": _SARIF_LEVEL.get(severity, "warning"),
            "message": {"text": f.get("evidence") or title},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": artifact_uri},
                    "region": {"startLine": max(1, start_line)},
                }
            }],
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "mcp-safeguard",
                    "version": __version__,
                    "informationUri": "https://github.com/SyedAnas01/mcp-safeguard",
                    "rules": list(seen_rules.values()),
                }
            },
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


def generate_text_report(report: SecurityReport) -> str:
    """Generate a plain-text summary report suitable for CLI output."""
    s = report.summary
    lines: list[str] = [
        "=" * 70,
        "  mcp-safeguard Security Report",
        "=" * 70,
        f"  Target:       {s.target}",
        f"  Scan ID:      {s.scan_id}",
        f"  Time:         {s.scan_time}",
        f"  Duration:     {s.duration_ms:.1f}ms",
        f"  Overall:      {s.overall_severity.value} (CVSS {s.overall_cvss})",
        "",
        "  Findings Summary:",
        f"    CRITICAL  {s.critical_count:>4}",
        f"    HIGH      {s.high_count:>4}",
        f"    MEDIUM    {s.medium_count:>4}",
        f"    LOW       {s.low_count:>4}",
        f"    INFO      {s.info_count:>4}",
        "    ─────────────────",
        f"    TOTAL     {s.total_findings:>4}",
        "",
    ]

    def section(title: str, findings: list[Any]) -> None:
        lines.append(f"  {'─'*60}")
        lines.append(f"  {title} ({len(findings)} findings)")
        lines.append(f"  {'─'*60}")
        for f in findings[:20]:  # Limit display
            sev = getattr(f, "severity", Severity.INFO).value
            cvss = getattr(f, "cvss_score", 0.0)
            rule_id = getattr(f, "rule_id", "")
            title_f = getattr(f, "title", "")
            loc = getattr(f, "location", "")
            lines.append(f"  [{sev:<8}] [{cvss:>4.1f}] {rule_id}: {title_f}")
            lines.append(f"           Location: {loc}")
            rem = getattr(f, "remediation", "")
            if rem:
                lines.append(f"           Fix: {rem[:100]}")
            lines.append("")
        if len(findings) > 20:
            lines.append(f"  ... and {len(findings) - 20} more findings.")
            lines.append("")

    section("Prompt Injection", report.injection_findings)
    section("Credential Exposure", report.credential_findings)
    section("Endpoint Exposure", report.endpoint_findings)
    section("Tool Poisoning", report.tool_poisoning_findings)

    lines.append("  Tool Risk Profiles:")
    lines.append(f"  {'─'*60}")
    for tp in report.tool_risk_profiles:
        lines.append(
            f"  {tp.tool_name:<30} {tp.risk_level.value:<8} "
            f"Overall:{tp.overall_risk:<5} BR:{tp.blast_radius_score}"
        )
    lines.append("")
    lines.append("=" * 70)
    lines.append(f"  Generated by mcp-safeguard v{__version__}")
    lines.append("=" * 70)
    return "\n".join(lines)
