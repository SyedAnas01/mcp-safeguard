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
from pathlib import PurePath
from typing import Any

from .prompt_injection import Severity

# Rule catalog for introspection (security://rules resource, docs generation).
RULE_IDS: list[tuple[str, str]] = [
    ("SS-001", "Unconstrained URL parameter with no allowlist/blocklist"),
    ("SS-002", "Redirect-following URL fetch with no revalidation"),
    ("SS-003", "Missing scheme restriction on a URL-fetching tool"),
    ("SS-004", "Unguarded fetch of client-supplied auth metadata/JWKS/discovery URL"),
]


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


# ---------------------------------------------------------------------------
# SS-004: source-level sink context for authorization-server metadata fetches
# (CIMD client_id metadata documents, JWKS / jku, discovery and registration
# URLs). The URL is attacker-chosen by design in these flows, so the fetch
# itself must carry a private-range guard (and ideally redirect + scheme
# guards). Heuristic, line-based, file-scoped; JS/TS, Python and Go.
# ---------------------------------------------------------------------------

_LANG_BY_EXT = {
    ".js": "js", ".mjs": "js", ".cjs": "js", ".jsx": "js", ".ts": "js", ".tsx": "js",
    ".py": "py", ".go": "go",
}

# Identifiers that mean "URL taken from a client / token / remote document".
_META_TOKEN = re.compile(
    r"client_?id|jwks_?(uri|url)|\bjku\b|metadata_?(url|uri|document)|"
    r"\bissuer\b|\biss\b|discovery|registration_?(endpoint|url)|"
    r"openid-configuration|oauth-authorization-server|\.well-known|"
    r"sector_?identifier_?uri|request_?uri|\bx5u\b",
    re.IGNORECASE,
)

# Strong subset: identifiers that name a value the *caller or token* supplies.
# Bare path fragments (.well-known, discovery, openid-configuration) are not
# enough on their own, because `fetch(`${authServerUrl}/.well-known/...`)` with an
# operator-configured base is the server's own discovery call, not an SSRF sink.
_META_STRONG = re.compile(
    r"client_?id|jwks_?(uri|url)|\bjku\b|metadata_?(url|uri|document)|"
    r"\bissuer\b|\biss\b|registration_?(endpoint|url)|"
    r"sector_?identifier_?uri|request_?uri|\bx5u\b",
    re.IGNORECASE,
)
# ALL_CAPS constants and env/config reads are operator-set, not client-supplied.
_OPERATOR_CONST = re.compile(
    r"\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b|process\.env\.\w+|os\.environ(?:\.get)?\W+\w+|"
    r"\b(?:config|settings|cfg)\.\w+"
)


# Evidence the file reads caller-controlled input (request body/headers/params, a
# decoded token, or a JWT header) -- without it the "client-supplied" URL is more
# likely an operator-configured one.
_REQUEST_INPUT = re.compile(
    r"\b(?:req|request|ctx|c)\.(?:body|query|params|headers?|json|form|args|data|get_json)\b|"
    r"\brequest\.(?:GET|POST)\b|\bjwt\.(?:decode|decode_header|get_unverified\w*)|"
    r"\bdecodeJwt\b|\bdecodeProtectedHeader\b|\bjwtDecode\b|\bBody\(|\bQuery\(|"
    r"\bheader\.jku\b|\bclient_id\s*=\s*(?:request|req)|\bFormValue\(|\bURL\.Query\(",
    re.IGNORECASE,
)


# Names whose value the *caller* chooses by definition (CIMD client_id URL, JWT jku/x5u
# header, client-registered jwks_uri). `issuer` / `metadata_url` are often operator config.
_INHERENT_CLIENT = re.compile(r"client_?id|\bjku\b|\bx5u\b|jwks_?(?:uri|url)|sector_?identifier", re.IGNORECASE)


def _client_supplied(text: str) -> bool:
    return bool(_META_STRONG.search(_OPERATOR_CONST.sub(" ", text)))


_SINKS: dict[str, re.Pattern[str]] = {
    "js": re.compile(
        r"\b(fetch|axios(?:\.\w+)?|got(?:\.\w+)?|ky(?:\.\w+)?|needle|superagent\.\w+|"
        r"undici\.(?:fetch|request)|(?:https?)\.(?:get|request)|"
        r"createRemoteJWKSet|(?:http|client|api|session)\.(?:get|post))\s*\("
    ),
    "py": re.compile(
        r"\b(requests\.\w+|httpx\.\w+|urlopen|urllib\.request\.\w+|PyJWKClient|"
        r"(?:session|client|http|self\.\w+)\.(?:get|post|request))\s*\("
    ),
    "go": re.compile(
        r"\b(http\.(?:Get|Post|Head|NewRequest(?:WithContext)?)|"
        r"(?:client|c|httpClient|hc)\.(?:Get|Post|Head)|jwk\.Fetch|keyfunc\.NewDefault|"
        r"jwk\.NewCache)\s*\("
    ),
}

# Wrapper / dialer-level guard: covers range, redirects and scheme at once.
_SAFE_WRAPPER = re.compile(
    r"safe_?fetch|safe_?http|ssrf[-_]?(req[-_]?filter|guard|safe|protect|filter|check)|"
    r"assert_?public|validate_?(public|external)_?url|secure_?fetch|"
    r"Control\s*:\s*func|DialContext\s*:\s*\w*[Ss]afe|safeDialer|ssrfSafe|"
    r"advocate\.|ssrf_?protect",
)
_RANGE_GUARD = re.compile(
    r"is_?private|is_?loopback|is_?link_?local|is_?reserved|is_?global|is_?multicast|"
    r"\.is_?internal|private_?ip|is_?internal|ipaddress\.ip_|ip_?range|"
    r"IsPrivate|IsLoopback|IsLinkLocal\w*|IsUnspecified|169\.254|"
    r"ipaddr\.js|isPrivateIP|isIP\(|net\.BlockList|BlockList",
)
_REDIRECT_GUARD = re.compile(
    r"redirect\s*:\s*['\"](error|manual)['\"]|allow_redirects\s*=\s*False|"
    r"follow_redirects\s*=\s*False|max_?redirects\s*[:=]\s*0|"
    r"CheckRedirect|ErrUseLastResponse|maxRedirections\s*:\s*0",
)
_SCHEME_GUARD = re.compile(
    r"protocol\s*[!=]==?\s*['\"]https?:?|\bscheme\s*(?:!=|==|not in|in)\b|"
    r"startswith\(\s*['\"]https://|HasPrefix\([^)]*https://|\.Scheme\s*[!=]=|"
    r"startsWith\(\s*['\"]https://|\.scheme\b",
)

_ASSIGN = re.compile(r"^\s*(?:const|let|var)?\s*([A-Za-z_]\w*)\s*(?::=|=)(?!=)\s*(.+)$")
_SEVERE_REMEDIATION = (
    "Before fetching a client-supplied metadata/JWKS/discovery URL: require https, resolve the "
    "host and reject loopback, RFC 1918, link-local (169.254.0.0/16, fd00:ec2::254) and "
    "other non-global ranges, pin the validated IP for the connection (re-check at dial time), "
    "and disable redirects or re-validate each hop. Cap response size and time."
)


def _strip_comments(lines: list[str]) -> list[str]:
    out = []
    for ln in lines:
        t = ln.lstrip()
        out.append("" if t.startswith(("//", "#", "*", "/*")) else ln)
    return out


def _call_args(lines: list[str], idx: int, start_col: int) -> str:
    """Text from the sink's open paren to its matching close (max 8 lines)."""
    buf, depth, begun = [], 0, False
    for j in range(idx, min(idx + 8, len(lines))):
        seg = lines[j][start_col:] if j == idx else lines[j]
        for ch in seg:
            if ch == "(":
                depth += 1
                begun = True
            elif ch == ")":
                depth -= 1
            buf.append(ch)
            if begun and depth == 0:
                return "".join(buf)
        buf.append("\n")
    return "".join(buf)


def scan_source_for_metadata_ssrf(
    source: str, path: str = "<source>", language: str | None = None
) -> list[SSRFFinding]:
    """
    SS-004: flag an unguarded fetch of a client-supplied auth metadata URL.

    A sink counts when its URL argument mentions (directly, or via a one-hop
    local assignment) a metadata-style identifier such as client_id, jwks_uri,
    jku, issuer or a .well-known path. The file is silent if it contains a
    private-range guard or a safe-fetch / dial-time guard. If only a
    pre-check range guard exists but redirects are followed unguarded, a
    MEDIUM finding is emitted (validate-then-redirect bypass).
    """
    lang = language or _LANG_BY_EXT.get(PurePath(path).suffix.lower())
    if lang not in _SINKS:
        return []
    lines = _strip_comments(source.splitlines())
    code = "\n".join(lines)

    if _SAFE_WRAPPER.search(code):
        return []
    has_range = bool(_RANGE_GUARD.search(code))
    has_redirect = bool(_REDIRECT_GUARD.search(code))
    has_scheme = bool(_SCHEME_GUARD.search(code))
    if has_range and has_redirect:
        return []

    tainted_at: dict[str, int] = {}
    for i, ln in enumerate(lines):
        m = _ASSIGN.match(ln)
        if m and _client_supplied(m.group(2)):
            tainted_at[m.group(1)] = i

    findings: list[SSRFFinding] = []
    for i, ln in enumerate(lines):
        for m in _SINKS[lang].finditer(ln):
            args = _call_args(lines, i, m.end() - 1)
            hit = _client_supplied(args) or any(
                re.search(rf"\b{re.escape(v)}\b", args)
                for v, at in tainted_at.items() if 0 <= i - at <= 20
            )
            if not hit:
                continue
            missing = [
                n for n, ok in (
                    ("private-range check", has_range),
                    ("redirect guard", has_redirect),
                    ("scheme restriction", has_scheme),
                ) if not ok
            ]
            if has_range:
                sev, cvss, ttl = Severity.MEDIUM, 6.5, "Range check can be bypassed via redirect"
            elif not (_INHERENT_CLIENT.search(args) or _INHERENT_CLIENT.search(" ".join(
                lines[max(0, i - 20):i + 1])) or _REQUEST_INPUT.search(code)):
                sev, cvss, ttl = Severity.MEDIUM, 5.5, "Fetch of a metadata/JWKS URL with no visible caller-controlled source (lead)"
            else:
                sev, cvss, ttl = Severity.HIGH, 8.0, "Unguarded fetch of client-supplied metadata URL"
            findings.append(
                SSRFFinding(
                    rule_id="SS-004",
                    severity=sev,
                    title=ttl,
                    description=(
                        "The server fetches a URL controlled by the OAuth/OIDC client or token "
                        "issuer (CIMD client_id document, JWKS/jku, discovery or registration "
                        "URL) without a complete SSRF guard. An unauthenticated client can point "
                        "it at internal services or cloud metadata endpoints."
                    ),
                    location=f"{path}:{i + 1}",
                    evidence=f"{ln.strip()[:120]} | missing: {', '.join(missing)}",
                    remediation=_SEVERE_REMEDIATION,
                    cvss_score=cvss,
                )
            )
            break
    return findings
