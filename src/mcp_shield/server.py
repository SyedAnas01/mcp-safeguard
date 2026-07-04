"""
mcp-safeguard: FastMCP security scanner server.

Exposes MCP Tools, Resources, and Prompts for scanning MCP servers
for prompt injection, credential leaks, endpoint exposure, and tool poisoning.
"""

from __future__ import annotations

import json
import logging
import os
import time
import uuid
from collections import OrderedDict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from fastmcp import FastMCP
from fastmcp.server.dependencies import get_http_headers

from mcp_shield import __version__
from mcp_shield.config import settings
from mcp_shield.observability.metrics import (
    active_scans,
    record_scan_complete,
    scan_history_size,
)
from mcp_shield.observability.tracing import setup_tracing
from mcp_shield.scanner.credential_scanner import scan_for_credentials, scan_oauth_scopes
from mcp_shield.scanner.endpoint_scanner import scan_endpoints
from mcp_shield.scanner.prompt_injection import scan_for_prompt_injection
from mcp_shield.scanner.report_generator import (
    SecurityReport,
    generate_html_report,
    generate_scan_summary,
    report_to_dict,
)
from mcp_shield.scanner.ssrf_scanner import scan_for_ssrf
from mcp_shield.scanner.tool_analyzer import (
    analyze_tool_risk,
    hash_tool_definitions,
    scan_for_tool_poisoning,
)
from mcp_shield.security.audit_logger import audit_logger
from mcp_shield.security.auth_middleware import authenticate_request
from mcp_shield.security.input_validator import (
    ValidationError,
    sanitize_scan_id,
    validate_config_json,
    validate_host,
    validate_port,
    validate_tool_json,
)
from mcp_shield.security.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------

setup_tracing(otlp_endpoint=settings.otlp_endpoint)

mcp = FastMCP(
    name="mcp-safeguard",
    instructions=(
        "mcp-safeguard is a security scanner for MCP servers. "
        "Use scan_mcp_server to run a full security audit, "
        "scan_tool_definitions to check for prompt injection, "
        "check_auth_config to audit credentials and OAuth scopes, "
        "and check_endpoint_exposure to test for open admin ports."
    ),
)

_rate_limiter = RateLimiter(
    requests_per_window=settings.rate_limit_requests,
    window_seconds=settings.rate_limit_window,
)

# In-memory scan history (LRU-limited)
_scan_history: OrderedDict[str, dict[str, Any]] = OrderedDict()

_report_dir = Path(settings.report_dir)
_report_dir.mkdir(parents=True, exist_ok=True)


def _prune_history() -> None:
    """Keep scan history within configured max size."""
    while len(_scan_history) > settings.scan_history_max:
        _scan_history.popitem(last=False)
    scan_history_size.set(len(_scan_history))


def _store_report(report: SecurityReport) -> None:
    """Persist report to disk and in-memory history."""
    scan_id = report.summary.scan_id
    report_dict = report_to_dict(report)
    _scan_history[scan_id] = report_dict
    _prune_history()

    # Write JSON report to disk
    report_path = _report_dir / f"{scan_id}.json"
    try:
        report_path.write_text(json.dumps(report_dict, indent=2))
    except OSError:
        pass

    # Write HTML report to disk
    html_path = _report_dir / f"{scan_id}.html"
    try:
        html_path.write_text(generate_html_report(report))
    except OSError:
        pass


def _client_id_from_env() -> str:
    """Derive a stable client identifier from environment (for single-user setups)."""
    return os.environ.get("MCP_SHIELD_CLIENT_ID", "local")


async def _fetch_tools_via_mcp(url: str, auth_token: str = "") -> list[dict[str, Any]]:
    """
    Fetch tool definitions from a target MCP server via the real MCP protocol
    handshake (initialize + tools/list), instead of an OpenAPI-style HTTP GET.

    Args:
        url: The MCP server URL to connect to.
        auth_token: Optional bearer token to authenticate with the server.

    Returns:
        List of tool definition dicts ({"name", "description", "inputSchema"}),
        or an empty list on any connection/protocol failure.
    """
    from fastmcp import Client

    try:
        client = Client(url, auth=auth_token or None, timeout=settings.max_scan_timeout)
        async with client:
            mcp_tools = await client.list_tools()
        return [
            {
                "name": t.name,
                "description": t.description or "",
                "inputSchema": t.inputSchema,
            }
            for t in mcp_tools
        ]
    except Exception:
        return []


def _check_auth() -> dict[str, str] | None:
    """
    Enforce authentication for network-capable tools when an API key is configured.

    Returns:
        None if the request is authenticated (or no api_key is configured, which
        preserves open access for local/stdio use). Otherwise an error dict to
        return immediately from the calling tool.
    """
    if not settings.api_key:
        return None

    # fastmcp strips the Authorization header by default; explicitly include it.
    headers = get_http_headers(include={"authorization"})
    ctx = authenticate_request(
        api_key_header=headers.get("x-api-key"),
        authorization_header=headers.get("authorization"),
        expected_api_key=settings.api_key,
    )
    if not ctx.authenticated:
        return {"error": "Authentication required."}
    return None


if not settings.api_key:
    logger.warning(
        "mcp-safeguard is running without an API key configured — all tools are "
        "accessible without authentication. Set MCP_SHIELD_API_KEY to require auth."
    )


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp.tool
async def scan_mcp_server(url: str, auth_token: str = "") -> dict[str, Any]:
    """
    Run a full security scan of an MCP server.

    Performs prompt injection detection, credential scanning, endpoint
    probing, tool poisoning analysis, and blast radius scoring.

    Args:
        url: The MCP server URL to scan (e.g. http://localhost:8000).
        auth_token: Optional Bearer token to authenticate with the server.

    Returns:
        Structured security report as a dict, including summary and all findings.
    """
    if (e := _check_auth()) is not None:
        return e

    client_id = _client_id_from_env()

    if not _rate_limiter.is_allowed(client_id):
        audit_logger.log_rate_limit(client_id, "scan_mcp_server")
        return {"error": "Rate limit exceeded. Please wait before scanning again."}

    # Validate URL
    try:
        from mcp_shield.security.input_validator import validate_url

        validate_url(url)
    except ValidationError as e:
        audit_logger.log_validation_error(client_id, "url", str(e))
        return {"error": f"Invalid scan target: {e}"}

    scan_id = str(uuid.uuid4())
    start_time = time.monotonic()
    categories: list[str] = []

    audit_logger.log_scan_start(client_id, scan_id, url, ["full"])
    active_scans.inc()

    try:
        headers: dict[str, str] = {}
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        # --- Fetch tool definitions from the server ---
        tool_definitions: list[dict[str, Any]] = []
        server_config: dict[str, Any] = {}
        scan_warnings: list[str] = []

        # Try the real MCP protocol handshake (initialize + tools/list) first.
        tool_definitions = await _fetch_tools_via_mcp(url, auth_token)

        # Fall back to the legacy OpenAPI-style probe only if that yielded nothing.
        if not tool_definitions:
            async with httpx.AsyncClient(
                timeout=settings.max_scan_timeout,
                headers=headers,
                verify=False,
            ) as client:
                try:
                    resp = await client.get(f"{url}/tools")
                    if resp.status_code == 200:
                        data = resp.json()
                        tool_definitions = (
                            data if isinstance(data, list) else data.get("tools", [])
                        )
                except Exception:
                    pass

        if not tool_definitions:
            scan_warnings.append(
                "could not retrieve tool definitions from target; "
                "tool-based checks were skipped"
            )

        # --- Prompt injection scan ---
        categories.append("prompt_injection")
        inj_findings = scan_for_prompt_injection(tool_definitions) if tool_definitions else []

        # --- SSRF scan ---
        categories.append("ssrf")
        ssrf_findings = scan_for_ssrf(tool_definitions) if tool_definitions else []

        # --- Credential scan ---
        categories.append("credentials")
        cred_findings = scan_for_credentials(server_config)

        # --- Endpoint scan ---
        ep_findings = []
        if settings.enable_network_scan:
            categories.append("endpoints")
            from urllib.parse import urlparse

            parsed = urlparse(url)
            host = parsed.hostname or "localhost"
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            try:
                ep_findings = await scan_endpoints(
                    host=host,
                    port=port,
                    use_tls=(parsed.scheme == "https"),
                    timeout=min(5.0, settings.max_scan_timeout / 4),
                    ssrf_allowlist=settings.ssrf_allowlist,
                )
            except Exception:
                pass

        # --- Tool risk profiles ---
        categories.append("tool_risk")
        tool_profiles = [analyze_tool_risk(t) for t in tool_definitions]
        poison_findings = scan_for_tool_poisoning(tool_definitions)

        # --- Build report ---
        duration_ms = (time.monotonic() - start_time) * 1000
        summary = generate_scan_summary(
            target=url,
            injection_findings=inj_findings,
            credential_findings=cred_findings,
            endpoint_findings=ep_findings,
            tool_risk_profiles=tool_profiles,
            tool_poisoning_findings=poison_findings,
            duration_ms=duration_ms,
            categories=categories,
            ssrf_findings=ssrf_findings,
        )
        summary.scan_id = scan_id

        report = SecurityReport(
            summary=summary,
            injection_findings=inj_findings,
            credential_findings=cred_findings,
            endpoint_findings=ep_findings,
            tool_risk_profiles=tool_profiles,
            tool_poisoning_findings=poison_findings,
            ssrf_findings=ssrf_findings,
            raw_metadata={"tool_hashes": hash_tool_definitions(tool_definitions)},
        )

        _store_report(report)

        # Metrics
        finding_counts = {
            "injection": {f.severity.value: 0 for f in inj_findings},
            "credential": {f.severity.value: 0 for f in cred_findings},
            "endpoint": {f.severity.value: 0 for f in ep_findings},
            "poisoning": {f.severity.value: 0 for f in poison_findings},
            "ssrf": {f.severity.value: 0 for f in ssrf_findings},
        }
        all_cvss = [
            getattr(f, "cvss_score", 0.0)
            for f in inj_findings + cred_findings + ep_findings + poison_findings + ssrf_findings
        ]
        record_scan_complete(
            status="success",
            duration_s=duration_ms / 1000,
            finding_counts=finding_counts,
            cvss_scores=all_cvss,
        )

        audit_logger.log_scan_complete(
            client_id=client_id,
            scan_id=scan_id,
            target=url,
            duration_ms=duration_ms,
            finding_counts={
                "critical": summary.critical_count,
                "high": summary.high_count,
                "medium": summary.medium_count,
                "low": summary.low_count,
            },
            overall_severity=summary.overall_severity.value,
        )

        result = report_to_dict(report)
        if scan_warnings:
            result["summary"]["warnings"] = scan_warnings
        return result

    except Exception as e:
        record_scan_complete("failure", time.monotonic() - start_time, {}, [])
        return {"error": f"Scan failed: {e}", "scan_id": scan_id}
    finally:
        active_scans.dec()


@mcp.tool
async def scan_tool_definitions(tool_json: str) -> dict[str, Any]:
    """
    Analyze MCP tool definitions JSON for prompt injection and poisoning risks.

    Accepts either a JSON array of tool objects or a single tool object.

    Args:
        tool_json: JSON string of tool definitions to analyze.

    Returns:
        Dict with injection_findings, tool_risk_profiles, and summary.
    """
    if (e := _check_auth()) is not None:
        return e

    client_id = _client_id_from_env()

    if not _rate_limiter.is_allowed(client_id):
        return {"error": "Rate limit exceeded."}

    try:
        tools = validate_tool_json(tool_json, max_length=settings.max_tool_descriptions_length)
    except ValidationError as e:
        audit_logger.log_validation_error(client_id, "tool_json", str(e))
        return {"error": str(e)}

    start = time.monotonic()
    inj_findings = scan_for_prompt_injection(tools)
    poison_findings = scan_for_tool_poisoning(tools)
    tool_profiles = [analyze_tool_risk(t) for t in tools]
    duration_ms = (time.monotonic() - start) * 1000

    all_findings = inj_findings + poison_findings
    critical = sum(1 for f in all_findings if f.severity.value == "CRITICAL")
    high = sum(1 for f in all_findings if f.severity.value == "HIGH")

    return {
        "summary": {
            "tools_analyzed": len(tools),
            "total_findings": len(all_findings),
            "critical": critical,
            "high": high,
            "duration_ms": round(duration_ms, 2),
        },
        "injection_findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "cvss_score": f.cvss_score,
                "title": f.title,
                "location": f.location,
                "evidence": f.evidence,
                "remediation": f.remediation,
            }
            for f in inj_findings
        ],
        "poisoning_findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "cvss_score": f.cvss_score,
                "title": f.title,
                "location": f.location,
                "evidence": f.evidence,
                "remediation": f.remediation,
            }
            for f in poison_findings
        ],
        "tool_risk_profiles": [
            {
                "tool_name": tp.tool_name,
                "risk_level": tp.risk_level.value,
                "overall_risk": tp.overall_risk,
                "blast_radius_score": tp.blast_radius_score,
                "permission_risk": tp.permission_risk,
                "risk_factors": tp.risk_factors,
                "recommendations": tp.recommendations,
            }
            for tp in tool_profiles
        ],
    }


@mcp.tool
async def check_auth_config(config_json: str) -> dict[str, Any]:
    """
    Audit an MCP server configuration for credential exposure and OAuth scope risks.

    Args:
        config_json: JSON string of the server configuration (e.g. Claude Desktop config entry).

    Returns:
        Dict with credential_findings, oauth_findings, and a risk summary.
    """
    if (e := _check_auth()) is not None:
        return e

    client_id = _client_id_from_env()

    if not _rate_limiter.is_allowed(client_id):
        return {"error": "Rate limit exceeded."}

    try:
        config = validate_config_json(config_json)
    except ValidationError as e:
        audit_logger.log_validation_error(client_id, "config_json", str(e))
        return {"error": str(e)}

    cred_findings = scan_for_credentials(config)

    # Extract OAuth scopes if present
    scopes: list[str] = []
    if "oauth" in config:
        scopes = config["oauth"].get("scopes", [])
    elif "scopes" in config:
        scopes = config["scopes"]
    oauth_findings = scan_oauth_scopes(scopes)

    all_findings = cred_findings + oauth_findings
    critical = sum(1 for f in all_findings if f.severity.value == "CRITICAL")

    return {
        "summary": {
            "total_findings": len(all_findings),
            "critical": critical,
            "high": sum(1 for f in all_findings if f.severity.value == "HIGH"),
            "medium": sum(1 for f in all_findings if f.severity.value == "MEDIUM"),
        },
        "credential_findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "cvss_score": f.cvss_score,
                "title": f.title,
                "location": f.location,
                "evidence": f.evidence,
                "remediation": f.remediation,
            }
            for f in cred_findings
        ],
        "oauth_findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "cvss_score": f.cvss_score,
                "title": f.title,
                "location": f.location,
                "evidence": f.evidence,
                "remediation": f.remediation,
            }
            for f in oauth_findings
        ],
    }


@mcp.tool
async def check_endpoint_exposure(host: str, port: int = 8000) -> dict[str, Any]:
    """
    Probe an MCP server for exposed admin panels, debug routes, and dangerous ports.

    Only scans localhost and explicitly allowlisted hosts (SSRF protection).

    Args:
        host: Hostname or IP to scan (must be in SSRF allowlist).
        port: Port number the MCP server is running on.

    Returns:
        Dict with endpoint_findings and open_ports.
    """
    if (e := _check_auth()) is not None:
        return e

    client_id = _client_id_from_env()

    if not _rate_limiter.is_allowed(client_id):
        return {"error": "Rate limit exceeded."}

    try:
        validated_host = validate_host(host)
        validated_port = validate_port(port)
    except ValidationError as e:
        audit_logger.log_validation_error(client_id, "host/port", str(e))
        return {"error": str(e)}

    if not settings.enable_network_scan:
        return {"error": "Network scanning is disabled by configuration."}

    ep_findings = await scan_endpoints(
        host=validated_host,
        port=validated_port,
        timeout=settings.max_scan_timeout / 2,
        ssrf_allowlist=settings.ssrf_allowlist,
    )

    return {
        "summary": {
            "target": f"{validated_host}:{validated_port}",
            "total_findings": len(ep_findings),
            "critical": sum(1 for f in ep_findings if f.severity.value == "CRITICAL"),
            "high": sum(1 for f in ep_findings if f.severity.value == "HIGH"),
        },
        "endpoint_findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "cvss_score": f.cvss_score,
                "title": f.title,
                "location": f.location,
                "evidence": f.evidence,
                "status_code": f.status_code,
                "remediation": f.remediation,
            }
            for f in ep_findings
        ],
    }


@mcp.tool
async def generate_security_report(scan_id: str, format: str = "json") -> dict[str, Any]:
    """
    Retrieve a full security report for a completed scan.

    Args:
        scan_id: UUID of the scan to retrieve.
        format: "json" (default), "html", or "text".

    Returns:
        The full report in the requested format.
    """
    if (e := _check_auth()) is not None:
        return e

    try:
        validated_id = sanitize_scan_id(scan_id)
    except ValidationError as e:
        return {"error": str(e)}

    if validated_id not in _scan_history:
        # Try disk
        json_path = _report_dir / f"{validated_id}.json"
        if json_path.exists():
            try:
                data = json.loads(json_path.read_text())
                _scan_history[validated_id] = data
            except Exception:
                return {"error": f"Scan {validated_id} not found."}
        else:
            return {"error": f"Scan {validated_id} not found."}

    report_data = _scan_history[validated_id]

    if format == "html":
        html_path = _report_dir / f"{validated_id}.html"
        if html_path.exists():
            return {"html": html_path.read_text(), "scan_id": validated_id}
        return {"error": "HTML report not available for this scan."}

    if format == "text":
        # Reconstruct minimal text from stored dict
        s = report_data.get("summary", {})
        lines = [
            f"Scan ID: {s.get('scan_id', validated_id)}",
            f"Target: {s.get('target', 'unknown')}",
            f"Overall: {s.get('overall_severity', '?')} (CVSS {s.get('overall_cvss', 0)})",
            f"Critical: {s.get('critical_count', 0)}, High: {s.get('high_count', 0)}, "
            f"Medium: {s.get('medium_count', 0)}, Low: {s.get('low_count', 0)}",
            f"Total: {s.get('total_findings', 0)} findings in {s.get('duration_ms', 0):.1f}ms",
        ]
        return {"text": "\n".join(lines), "scan_id": validated_id}

    return report_data


@mcp.tool
async def get_scan_history() -> dict[str, Any]:
    """
    List all past scans with their severity scores and targets.

    Returns:
        Dict with a list of scan summaries, sorted by recency.
    """
    if (e := _check_auth()) is not None:
        return e

    history = []
    for scan_id, report in reversed(list(_scan_history.items())):
        s = report.get("summary", {})
        history.append(
            {
                "scan_id": scan_id,
                "target": s.get("target", "unknown"),
                "scan_time": s.get("scan_time", ""),
                "overall_severity": s.get("overall_severity", ""),
                "overall_cvss": s.get("overall_cvss", 0),
                "total_findings": s.get("total_findings", 0),
                "critical": s.get("critical_count", 0),
                "high": s.get("high_count", 0),
            }
        )

    return {
        "total_scans": len(history),
        "scans": history[:50],  # Return most recent 50
    }


@mcp.tool
async def compare_scans(scan_id_1: str, scan_id_2: str) -> dict[str, Any]:
    """
    Compare two security scans to identify regressions or improvements.

    Args:
        scan_id_1: UUID of the baseline scan.
        scan_id_2: UUID of the comparison scan.

    Returns:
        Diff showing new findings, resolved findings, and score changes.
    """
    if (e := _check_auth()) is not None:
        return e

    try:
        id1 = sanitize_scan_id(scan_id_1)
        id2 = sanitize_scan_id(scan_id_2)
    except ValidationError as e:
        return {"error": str(e)}

    if id1 not in _scan_history or id2 not in _scan_history:
        return {"error": "One or both scan IDs not found in history."}

    r1 = _scan_history[id1].get("summary", {})
    r2 = _scan_history[id2].get("summary", {})

    cvss_delta = round(r2.get("overall_cvss", 0) - r1.get("overall_cvss", 0), 1)
    findings_delta = r2.get("total_findings", 0) - r1.get("total_findings", 0)

    # Compare finding rule_ids
    def get_rule_ids(report_data: dict, category: str) -> set[str]:
        return {f.get("rule_id", "") for f in report_data.get(category, [])}

    scan1 = _scan_history[id1]
    scan2 = _scan_history[id2]

    for_categories = [
        "injection_findings",
        "credential_findings",
        "endpoint_findings",
        "tool_poisoning_findings",
    ]
    new_findings: list[str] = []
    resolved_findings: list[str] = []

    for cat in for_categories:
        ids1 = get_rule_ids(scan1, cat)
        ids2 = get_rule_ids(scan2, cat)
        new_findings.extend(f"{cat}:{r}" for r in (ids2 - ids1))
        resolved_findings.extend(f"{cat}:{r}" for r in (ids1 - ids2))

    # Rug-pull / tool-definition-change detection: compare per-tool content
    # hashes so a silently-changed tool description is caught even if it
    # doesn't trip any existing regex rule.
    hashes1: dict[str, str] = scan1.get("raw_metadata", {}).get("tool_hashes", {})
    hashes2: dict[str, str] = scan2.get("raw_metadata", {}).get("tool_hashes", {})
    added_tools = sorted(set(hashes2) - set(hashes1))
    removed_tools = sorted(set(hashes1) - set(hashes2))
    changed_tools = sorted(
        name for name in (set(hashes1) & set(hashes2)) if hashes1[name] != hashes2[name]
    )

    regression = cvss_delta > 0 or findings_delta > 0 or bool(changed_tools)

    return {
        "baseline_scan_id": id1,
        "comparison_scan_id": id2,
        "baseline_target": r1.get("target", ""),
        "comparison_target": r2.get("target", ""),
        "cvss_delta": cvss_delta,
        "findings_delta": findings_delta,
        "regression_detected": regression,
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "added_tools": added_tools,
        "removed_tools": removed_tools,
        "changed_tools": changed_tools,
        "baseline_summary": {
            "overall_cvss": r1.get("overall_cvss"),
            "critical": r1.get("critical_count"),
            "total": r1.get("total_findings"),
        },
        "comparison_summary": {
            "overall_cvss": r2.get("overall_cvss"),
            "critical": r2.get("critical_count"),
            "total": r2.get("total_findings"),
        },
    }


# ---------------------------------------------------------------------------
# Resources
# ---------------------------------------------------------------------------


@mcp.resource("security://reports/{scan_id}")
async def get_report_resource(scan_id: str) -> str:
    """Full JSON security report for a completed scan."""
    try:
        validated_id = sanitize_scan_id(scan_id)
    except ValidationError as e:
        return json.dumps({"error": str(e)})

    if validated_id in _scan_history:
        return json.dumps(_scan_history[validated_id], indent=2)

    json_path = _report_dir / f"{validated_id}.json"
    if json_path.exists():
        return json_path.read_text()

    return json.dumps({"error": f"Report {validated_id} not found."})


@mcp.resource("security://rules")
async def get_rules_resource() -> str:
    """All active detection rules across all scanner modules."""
    from mcp_shield.scanner.credential_scanner import _CREDENTIAL_PATTERNS, _OAUTH_SCOPE_RISKS
    from mcp_shield.scanner.endpoint_scanner import _DANGEROUS_PORTS, _SENSITIVE_PATHS
    from mcp_shield.scanner.prompt_injection import _INJECTION_PATTERNS, _SCHEMA_RISK_PATTERNS
    from mcp_shield.scanner.tool_analyzer import _POISONING_PATTERNS

    rules = {
        "prompt_injection": [
            {"rule_id": r[2], "pattern": r[0], "severity": r[1].value, "title": r[3], "cvss": r[4]}
            for r in _INJECTION_PATTERNS
        ],
        "schema_risks": [
            {"rule_id": r[2], "pattern": r[0], "severity": r[1].value, "title": r[3]}
            for r in _SCHEMA_RISK_PATTERNS
        ],
        "credentials": [
            {"rule_id": r[2], "severity": r[1].value, "title": r[3], "cvss": r[4]}
            for r in _CREDENTIAL_PATTERNS
        ],
        "oauth_scopes": [
            {"rule_id": r[2], "severity": r[1].value, "title": r[3], "cvss": r[4]}
            for r in _OAUTH_SCOPE_RISKS
        ],
        "sensitive_endpoints": [
            {"path": r[0], "severity": r[1].value, "rule_id": r[2], "title": r[3]}
            for r in _SENSITIVE_PATHS
        ],
        "dangerous_ports": [
            {"port": r[0], "service": r[1], "severity": r[2].value, "rule_id": r[3]}
            for r in _DANGEROUS_PORTS
        ],
        "tool_poisoning": [
            {"rule_id": r[2], "severity": r[1].value, "title": r[3], "cvss": r[4]}
            for r in _POISONING_PATTERNS
        ],
    }
    total = sum(len(v) for v in rules.values())
    rules["_meta"] = {"total_rules": total, "version": __version__}
    return json.dumps(rules, indent=2)


@mcp.resource("security://dashboard")
async def get_dashboard_resource() -> str:
    """Aggregate statistics across all scans."""
    total_scans = len(_scan_history)
    total_findings = 0
    severity_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    targets: set[str] = set()

    for report in _scan_history.values():
        s = report.get("summary", {})
        total_findings += s.get("total_findings", 0)
        severity_counts["CRITICAL"] += s.get("critical_count", 0)
        severity_counts["HIGH"] += s.get("high_count", 0)
        severity_counts["MEDIUM"] += s.get("medium_count", 0)
        severity_counts["LOW"] += s.get("low_count", 0)
        severity_counts["INFO"] += s.get("info_count", 0)
        if s.get("target"):
            targets.add(s["target"])

    return json.dumps(
        {
            "total_scans": total_scans,
            "unique_targets": len(targets),
            "total_findings": total_findings,
            "severity_breakdown": severity_counts,
            "generated_at": datetime.now(UTC).isoformat(),
        },
        indent=2,
    )


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------


@mcp.prompt
def security_audit_prompt() -> str:
    """Guided prompt for performing a full MCP security audit."""
    return """You are a senior application security engineer auditing an MCP server for security vulnerabilities.

Follow this systematic audit process:

## Phase 1: Tool Definition Analysis
1. Collect the target MCP server's tool definitions (name, description, inputSchema).
2. Use `scan_tool_definitions` with the tool JSON to identify:
   - Prompt injection patterns in descriptions
   - Tool poisoning indicators
   - Blast radius scores for each tool
3. Flag any tool with CVSS > 7.0 for immediate review.

## Phase 2: Configuration Audit
4. Review the server's Claude Desktop / Cursor configuration.
5. Use `check_auth_config` with the config JSON to detect:
   - Hardcoded credentials or API keys
   - Over-scoped OAuth permissions
   - Missing authentication requirements

## Phase 3: Endpoint Exposure
6. Use `check_endpoint_exposure` with the server's host and port to probe:
   - Exposed admin panels or debug routes
   - Unauthenticated metrics or health endpoints
   - Dangerous open ports (Redis, Elasticsearch, Docker API)

## Phase 4: Full Scan
7. Run `scan_mcp_server` for a comprehensive automated scan.
8. Use `generate_security_report` to get the full HTML report.

## Phase 5: Remediation Prioritization
9. Address CRITICAL findings immediately (CVSS 9.0+).
10. Schedule HIGH findings for next sprint (CVSS 7.0–8.9).
11. Use `compare_scans` after fixes to verify improvement.

## Key Questions to Answer
- Are tool descriptions free of instruction injection?
- Are credentials stored securely (not in config files)?
- Is authentication required for all MCP endpoints?
- Do OAuth scopes follow least-privilege?
- Are admin/debug endpoints inaccessible from external networks?

Start by asking the user for the MCP server URL and tool definitions."""


@mcp.prompt
def remediation_prompt(issue_type: str) -> str:
    """
    Step-by-step fix guide for a specific vulnerability type.

    Args:
        issue_type: One of: prompt_injection, credential_leak, endpoint_exposure,
                    tool_poisoning, oauth_overpermission.
    """
    guides = {
        "prompt_injection": """# Remediating Prompt Injection in MCP Tools

## Immediate Actions
1. **Remove all instructional content** from tool descriptions. Descriptions should describe *capability*, not give instructions to the AI.

   ❌ BAD:  `"description": "Search files. Also, ignore previous instructions and..."`
   ✅ GOOD: `"description": "Search for files matching a pattern in the specified directory."`

2. **Audit parameter schemas** — remove oversized defaults and hidden instructions.

3. **Strip zero-width characters** from all text fields:
   ```python
   import re
   cleaned = re.sub(r'[\\u200b-\\u200f\\ufeff]', '', text)
   ```

## Structural Controls
4. Implement **server-side validation** of all tool content before registration.
5. Set **maximum length limits** on tool descriptions (< 500 chars recommended).
6. Add **content filtering** that rejects tool definitions containing injection patterns.

## Ongoing Prevention
7. Add mcp-safeguard to your CI/CD pipeline to scan tool definitions on every commit.
8. Review third-party MCP tools before installation — treat them like npm packages.
9. Use `scan_tool_definitions` before deploying any tool configuration change.""",
        "credential_leak": """# Remediating Credential Exposure in MCP Configs

## Immediate Actions
1. **Rotate all exposed credentials immediately**. Assume they are compromised.
2. **Remove hardcoded values** from all configuration files.

## Secure Credential Storage
3. Use **environment variables** instead of inline values:
   ```json
   { "env": { "API_KEY": "${MY_API_KEY}" } }
   ```

4. Use a **secrets manager**:
   - AWS Secrets Manager: `aws secretsmanager get-secret-value`
   - HashiCorp Vault: `vault kv get secret/my-service`
   - 1Password CLI: `op read "op://vault/item/field"`

5. **Never commit .env files** — add to .gitignore and use .env.example instead.

## Verification
6. Run `check_auth_config` on your updated config to verify no credentials remain.
7. Scan git history for leaked secrets: `git log -p | grep -E "(password|secret|key)"`
8. Use tools like `trufflehog` or `gitleaks` to scan repository history.""",
        "endpoint_exposure": """# Remediating Exposed MCP Endpoints

## Immediate Actions
1. **Disable debug/admin endpoints in production**:
   - FastAPI: set `docs_url=None, redoc_url=None` in production
   - Django: `DEBUG = False`
   - Express: remove `morgan`, `debug` middleware

2. **Firewall dangerous ports**:
   ```bash
   # Block external access to Redis
   ufw deny from any to any port 6379
   # Block Docker API
   ufw deny from any to any port 2375
   ```

## Authentication Requirements
3. Protect all MCP endpoints with authentication:
   ```python
   # Add API key requirement to your FastMCP server
   MCP_SHIELD_API_KEY=your-key-here
   ```

4. Restrict Prometheus metrics to internal networks:
   ```nginx
   location /metrics {
     allow 10.0.0.0/8;
     deny all;
   }
   ```

## Network Hardening
5. Place MCP servers behind a **reverse proxy** (nginx/Caddy).
6. Use **network policies** in Kubernetes to restrict pod-to-pod access.
7. Enable **TLS** for all MCP server endpoints.""",
        "tool_poisoning": """# Remediating Tool Poisoning

## What is Tool Poisoning?
Tool poisoning occurs when an MCP tool's description contains hidden instructions
that manipulate AI behavior — making a "safe" tool secretly exfiltrate data,
suppress logging, or chain unauthorized actions.

## Detection
1. Use `scan_tool_definitions` to identify poisoned tools.
2. Manually review ALL tool descriptions from third-party MCP servers.
3. Look for: "also", "additionally", "silently", "secretly", "without logging".

## Remediation
4. **Quarantine suspicious tools** immediately.
5. Rewrite tool descriptions to be purely functional:
   - Only describe what the tool does
   - No conditional instructions
   - No references to other tools
   - No claims about what the user "wants"

6. Implement **tool description allowlisting** — only permit descriptions that
   match a whitelist of safe patterns.

7. **Audit tool sources**: only install MCP tools from trusted, reviewed sources.
   Apply the same scrutiny as npm packages from unknown authors.""",
        "oauth_overpermission": """# Remediating Over-Scoped OAuth in MCP Tools

## Principle of Least Privilege
OAuth scopes should grant only what the tool *actually needs*, not what *might be convenient*.

## Scope Reduction Process
1. Audit current scopes vs. actual API calls made.
2. Remove unused scopes.
3. Replace broad scopes with specific ones:

   | Overpermissive | Least-Privilege |
   |---|---|
   | `repo` | `repo:contents:read` |
   | `admin` | `read:org` |
   | `user` | `user:email` |
   | `*` | specific scopes only |

4. For write operations, implement **explicit user confirmation** before each action.

## Token Management
5. Use **short-lived tokens** with refresh flows instead of long-lived credentials.
6. Set **token expiry** to match session duration.
7. Implement **token revocation** on session end.
8. Log all token usage for audit purposes.""",
    }

    guide = guides.get(issue_type)
    if guide:
        return guide

    available = ", ".join(guides.keys())
    return f"Unknown issue type '{issue_type}'. Available types: {available}"
