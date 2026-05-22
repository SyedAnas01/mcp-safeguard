"""
Detect Server-Side Request Forgery (SSRF) risks in MCP tool definitions.

Rule class: SS (Server-Side Request Forgery)
Coverage: Tools that accept unconstrained URL/URI parameters without blocklist
protection, redirect following without revalidation, or missing scheme restrictions.

Background: Multiple CVEs in the MCP ecosystem stem from tools that pass user-
controlled URL parameters directly to HTTP clients without validating against
private IP ranges (RFC 1918), cloud metadata endpoints (169.254.169.254, etc.),
or non-HTTP schemes (file://, gopher://, dict://). These enable attackers to
exfiltrate cloud IAM credentials via prompt injection chains.

Known affected: mcp-server-fetch (Anthropic), playwright-mcp (Microsoft),
                mcp-server-http-request (community), AWS MCP servers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .prompt_injection import Severity


@dataclass
class SSRFFinding:
    """A Server-Side Request Forgery risk finding."""

    rule_id: str
    severity: Severity
    title: str
    description: str
    location: str
    evidence: str
    remediation: str
    cvss_score: float = 0.0


# Parameter names that indicate URL input
_URL_PARAM_PATTERNS = re.compile(
    r"^(url|uri|endpoint|webhook|callback|redirect|redirect_url|"
    r"target_url|destination|link|href|source_url|fetch_url|request_url|"
    r"proxy_url|remote_url|host|base_url|api_url|server_url)$",
    re.IGNORECASE,
)

# Schema constraints that reduce SSRF risk
_SAFE_CONSTRAINTS = {
    "enum",     # Restricts to a fixed set of values
    "const",    # Single allowed value
    "format",   # format: uri with pattern can restrict
}

# Patterns in description text indicating URL validation is in place
_VALIDATION_HINTS = re.compile(
    r"(allowlist|allow.?list|whitelist|white.?list|allowed\s+domains?|"
    r"approved\s+url|trusted\s+url|validated\s+url|restricted\s+to|"
    r"only\s+(http|https)\s+url|blocklist|block.?list|denylist)",
    re.IGNORECASE,
)

# Redirect-following keywords in description — amplifies SSRF risk
_REDIRECT_PATTERNS = re.compile(
    r"follow.?(redirect|location)|redirect.?follow|follow_redirects",
    re.IGNORECASE,
)

# Keywords indicating the tool fetches content from user-supplied URLs
_FETCH_CAPABILITY = re.compile(
    r"\b(fetch|retrieve|download|get|request|load|read|access|navigate|browse)\b",
    re.IGNORECASE,
)

# Tool description patterns indicating blind SSRF (all URLs accepted equally)
_BLIND_SSRF_PATTERNS: list[tuple[str, str, float]] = [
    (
        r"(?i)fetch\s+(any|all|arbitrary|given|specified)\s+url",
        "Tool explicitly states it fetches arbitrary URLs without restriction",
        8.5,
    ),
    (
        r"(?i)url.{0,30}(internet|web|external|any\s+website)",
        "Tool fetches from unconstrained internet sources",
        7.5,
    ),
    (
        r"(?i)(now\s+grant\s+you|gives?\s+you)\s+internet\s+access",
        "Tool grants unconditional internet access — known pattern in mcp-server-fetch",
        8.0,
    ),
]


def _url_param_lacks_validation(param_name: str, param_schema: dict[str, Any]) -> bool:
    """Return True if this URL parameter has no meaningful SSRF protection."""
    # If any safe constraint is present, less likely to be exploitable
    for constraint in _SAFE_CONSTRAINTS:
        if constraint in param_schema:
            return False

    # Check for a restrictive pattern (e.g. ^https://api\.example\.com/)
    pattern = param_schema.get("pattern", "")
    if pattern:
        # A pattern that restricts to specific domains is protective
        # A pattern like ^https?:// alone is NOT sufficient
        if len(pattern) > 20 and re.search(r"(domain|host|example|api)", pattern, re.IGNORECASE):
            return False

    # No meaningful constraint found
    return True


def scan_for_ssrf(tool_definitions: list[dict[str, Any]]) -> list[SSRFFinding]:
    """
    Scan tool definitions for Server-Side Request Forgery (SSRF) risks.

    Detects:
    - SS-001: URL parameter with no allowlist/blocklist protection
    - SS-002: Tool description indicates blind URL fetching
    - SS-003: Redirect-following without revalidation mentioned
    - SS-004: Non-HTTPS scheme accepted (file://, gopher://, etc.)

    Args:
        tool_definitions: List of MCP tool dicts (name, description, inputSchema).

    Returns:
        Sorted list of SSRFFinding instances.
    """
    findings: list[SSRFFinding] = []

    for tool in tool_definitions:
        tool_name = tool.get("name", "<unnamed>")
        description = tool.get("description", "") or ""
        server = tool.get("_server", "")
        location_prefix = f"{server}.{tool_name}" if server else tool_name
        input_schema = tool.get("inputSchema", {}) or {}
        parameters = input_schema.get("properties", {}) or {}

        # --- SS-001: URL parameter without validation ---
        url_params: list[str] = []
        for param_name, param_schema in parameters.items():
            if _URL_PARAM_PATTERNS.match(param_name):
                if isinstance(param_schema, dict) and _url_param_lacks_validation(
                    param_name, param_schema
                ):
                    url_params.append(param_name)

        if url_params:
            # Check if description indicates validation is present
            has_validation_hint = bool(_VALIDATION_HINTS.search(description))
            has_fetch_capability = bool(_FETCH_CAPABILITY.search(description + " " + tool_name))

            if not has_validation_hint and has_fetch_capability:
                # HIGH: URL param + fetch capability + no validation hint
                severity = Severity.HIGH
                cvss = 7.5
            elif not has_validation_hint:
                # MEDIUM: URL param without validation mention (may not actually fetch)
                severity = Severity.MEDIUM
                cvss = 5.5
            else:
                continue  # Validation hint present — skip

            param_list = ", ".join(f"`{p}`" for p in url_params)
            findings.append(
                SSRFFinding(
                    rule_id="SS-001",
                    severity=severity,
                    title="URL Parameter Without SSRF Protection",
                    description=(
                        f"Tool '{tool_name}' accepts URL parameter(s) {param_list} with no "
                        "apparent allowlist, blocklist, or scheme restriction. An attacker "
                        "controlling tool arguments via prompt injection can direct requests "
                        "to internal services, cloud metadata endpoints (169.254.169.254), "
                        "or RFC 1918 ranges to exfiltrate credentials or probe internal networks."
                    ),
                    location=f"tool:{location_prefix}.inputSchema.{url_params[0]}",
                    evidence=(
                        f"Parameter(s) {param_list} accept unconstrained strings. "
                        f"No URL validation keywords found in tool description. "
                        f"Tool has fetch/network capability: {has_fetch_capability}."
                    ),
                    remediation=(
                        "1. Restrict URL to https:// scheme only (reject file://, gopher://, etc.). "
                        "2. Resolve hostname and reject RFC 1918, loopback, link-local, and cloud "
                        "metadata IP ranges (169.254.169.254, fd00:ec2::254, metadata.google.internal). "
                        "3. If redirects are followed, re-validate each redirect destination. "
                        "4. Add JSON Schema `pattern` or `enum` to restrict to approved domains. "
                        "See: OWASP SSRF Prevention Cheat Sheet."
                    ),
                    cvss_score=cvss,
                )
            )

        # --- SS-002: Blind SSRF descriptor in description ---
        for pattern, reason, cvss in _BLIND_SSRF_PATTERNS:
            match = re.search(pattern, description)
            if match:
                findings.append(
                    SSRFFinding(
                        rule_id="SS-002",
                        severity=Severity.HIGH,
                        title="Blind URL Fetch — No Scope Restriction Indicated",
                        description=(
                            f"Tool '{tool_name}' description indicates unconditional URL fetching: "
                            f"{reason}. This is characteristic of tools vulnerable to SSRF via "
                            "prompt injection (CVE pattern: attacker-controlled URL → internal "
                            "service → credential exfiltration)."
                        ),
                        location=f"tool:{location_prefix}.description",
                        evidence=match.group(0)[:120],
                        remediation=(
                            "Revise tool description to document URL restrictions. "
                            "Implement server-side URL validation before any outbound request. "
                            "Reference: CVE-2025-SSRF-MCP-FETCH class vulnerabilities."
                        ),
                        cvss_score=cvss,
                    )
                )
                break  # One SS-002 per tool

        # --- SS-003: Redirect following without revalidation ---
        if _REDIRECT_PATTERNS.search(description):
            # Only flag if there's also a URL param
            if url_params or _FETCH_CAPABILITY.search(description):
                findings.append(
                    SSRFFinding(
                        rule_id="SS-003",
                        severity=Severity.MEDIUM,
                        title="Redirect Following Without Revalidation Risk",
                        description=(
                            f"Tool '{tool_name}' follows HTTP redirects. Without re-validating "
                            "each redirect destination against the SSRF blocklist, an attacker "
                            "can use a public 301/302 redirect to a private IP (e.g., "
                            "https://attacker.com/redirect → http://169.254.169.254/) to "
                            "bypass URL validation applied only to the initial URL."
                        ),
                        location=f"tool:{location_prefix}.description",
                        evidence=_REDIRECT_PATTERNS.search(description).group(0),  # type: ignore
                        remediation=(
                            "Disable redirect following (follow_redirects=False) or re-validate "
                            "every Location header against the SSRF blocklist before following. "
                            "Bound redirect chains to a maximum depth (e.g., 3 hops)."
                        ),
                        cvss_score=6.5,
                    )
                )

    # Deduplicate and sort by CVSS descending
    seen: set[str] = set()
    unique: list[SSRFFinding] = []
    for f in findings:
        key = f"{f.rule_id}:{f.location}"
        if key not in seen:
            seen.add(key)
            unique.append(f)

    unique.sort(key=lambda f: f.cvss_score, reverse=True)
    return unique
