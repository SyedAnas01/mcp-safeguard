"""Analyze MCP tool definitions for permission scope, blast radius, and poisoning risks."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

from .prompt_injection import Severity


@dataclass
class ToolRiskProfile:
    """Risk assessment for a single MCP tool."""

    tool_name: str
    blast_radius_score: float  # 0–10
    permission_risk: float  # 0–10
    overall_risk: float  # 0–10
    risk_level: Severity
    risk_factors: list[str]
    recommendations: list[str]
    parameter_risks: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class ToolPoisoningFinding:
    """A tool poisoning or abuse-of-scope finding."""

    rule_id: str
    severity: Severity
    title: str
    description: str
    location: str
    evidence: str
    remediation: str
    cvss_score: float = 0.0


# High-risk capability keywords in tool descriptions
_HIGH_RISK_CAPABILITIES: list[tuple[str, float, str]] = [
    # (pattern, blast_radius_increment, reason)
    (r"\b(delete|remove|drop|destroy|wipe|purge|truncate)\b", 3.0, "Destructive operations"),
    (r"\b(exec|execute|run|spawn|fork|subprocess|shell)\b", 3.5, "Code/shell execution"),
    (r"\b(write|create|modify|update|upsert|insert)\b", 2.0, "Write operations"),
    (r"\b(admin|root|sudo|privilege|superuser)\b", 3.0, "Privileged operations"),
    (r"\b(send|transmit|post|publish|broadcast|email|sms)\b", 2.5, "Outbound communication"),
    (r"\b(read|list|get|fetch|query|search)\b", 0.5, "Read operations (lower risk)"),
    (r"\b(file|filesystem|disk|storage|s3|bucket)\b", 2.0, "File system access"),
    (r"\b(database|db|sql|query|transaction)\b", 2.0, "Database access"),
    (r"\b(network|http|request|api|webhook|curl|fetch)\b", 2.0, "Network access"),
    (r"\b(credential|secret|token|key|password|auth)\b", 3.5, "Credential handling"),
    (r"\b(user|account|identity|profile|session)\b", 2.0, "User data access"),
    (r"\b(payment|billing|charge|stripe|invoice)\b", 4.0, "Payment operations"),
    (r"\b(deploy|provision|scale|terminate|instance)\b", 3.0, "Infrastructure operations"),
    (r"\b(git|commit|push|merge|branch|repository)\b", 2.0, "SCM operations"),
]

# Parameter name patterns indicating high-risk inputs
_HIGH_RISK_PARAM_PATTERNS: list[tuple[str, str, float]] = [
    (r"(command|cmd|exec|eval|code)", "Command execution parameter", 3.5),
    (r"(path|filepath|filename|file)", "File path parameter (traversal risk)", 2.0),
    (r"(url|uri|endpoint|callback|webhook)", "URL parameter (SSRF risk)", 2.5),
    (r"(query|sql|filter|where)", "Query parameter (injection risk)", 2.5),
    (r"(token|key|secret|password|credential)", "Credential parameter", 3.5),
    (r"(template|format|pattern)", "Template parameter (injection risk)", 2.0),
    (r"(script|code|expression|formula)", "Code parameter", 3.5),
    (r"(selector|xpath|css|jq)", "Selector parameter (injection risk)", 2.0),
    (r"(header|cookie|session)", "HTTP context parameter", 2.0),
    (r"(user_id|account_id|org_id|tenant_id)", "Identity scoping parameter (IDOR risk)", 2.5),
]

# Tool poisoning patterns — tools that may masquerade as safe but have dangerous effects
_POISONING_PATTERNS: list[tuple[str, Severity, str, str, float]] = [
    (
        r"(?i)(search|find|look\s*up).{0,50}(also|additionally|simultaneously)",
        Severity.HIGH,
        "TP-001",
        "Hidden Side-Effect in Benign Tool",
        8.0,
    ),
    (
        r"(?i)(returns?|provides?|gives?).{0,100}(without|transparently|silently|secretly)",
        Severity.HIGH,
        "TP-002",
        "Covert Operation Descriptor",
        8.5,
    ),
    (
        r"(?i)do\s+not\s+(log|record|save|store|report)\s+this",
        Severity.CRITICAL,
        "TP-003",
        "Instruction to Suppress Logging",
        9.0,
    ),
    (
        r"(?i)(invisible|hidden|covert|stealth)\s+(action|operation|effect)",
        Severity.CRITICAL,
        "TP-004",
        "Explicitly Covert Tool Action",
        9.5,
    ),
    (
        r"(?i)(background|quietly|silently)\s+(upload|send|transmit|post)",
        Severity.CRITICAL,
        "TP-005",
        "Silent Data Exfiltration Descriptor",
        9.8,
    ),
    (
        r"(?i)appears?\s+to\s+(be|do).{0,50}but\s+(actually|also|really)",
        Severity.HIGH,
        "TP-006",
        "Deceptive Tool Description",
        8.8,
    ),
    (
        r"(?i)(always|automatically)\s+(call|invoke|execute).{0,50}tool",
        Severity.MEDIUM,
        "TP-007",
        "Forced Tool Chain Trigger",
        6.0,
    ),
    (
        r"(?i)(user\s+)?(never|won.t|cannot)\s+(see|know|notice|detect)",
        Severity.CRITICAL,
        "TP-008",
        "User Awareness Suppression",
        9.5,
    ),
    (
        r"(?i)<\s*(important|system|instructions?|secret|hidden|meta)\s*>",
        Severity.CRITICAL,
        "TP-009",
        "Hidden Instruction Tag in Tool Description",
        9.0,
    ),
    (
        r"(?i)do\s+not\s+(mention|tell|reveal|disclose|inform|report)",
        Severity.HIGH,
        "TP-010",
        "Instruction to Conceal Action from User",
        8.0,
    ),
    (
        r"(?i)read\s+.{0,80}(~/|/etc/|\.ssh|id_rsa|mcp\.json|\.env|config|secret|credential)"
        r".{0,120}(pass|send|provide|return|include|attach).{0,40}\b(as|to|via|in)\b",
        Severity.CRITICAL,
        "TP-011",
        "Read Sensitive File Then Pass As Argument",
        9.5,
    ),
]


def _compute_risk_level(score: float) -> Severity:
    """Map numeric score to severity level."""
    if score >= 8.0:
        return Severity.CRITICAL
    if score >= 6.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score >= 2.0:
        return Severity.LOW
    return Severity.INFO


def analyze_tool_risk(tool: dict[str, Any]) -> ToolRiskProfile:
    """
    Compute a blast radius and permission risk score for a single MCP tool.

    Args:
        tool: MCP tool definition dict with name, description, inputSchema.

    Returns:
        ToolRiskProfile with quantitative risk scores.
    """
    tool_name = tool.get("name", "<unnamed>")
    description = tool.get("description", "")
    if not isinstance(description, str):
        description = ""
    input_schema = tool.get("inputSchema", {})
    if not isinstance(input_schema, dict):
        # A tool fetched from a scan target over the network (scan_mcp_server)
        # doesn't go through validate_tool_json's type checks, so a malformed
        # or hostile target response can still reach here with a wrong-typed
        # inputSchema -- coerce rather than crash. See validate_tool_json's
        # matching check for the direct-input path.
        input_schema = {}
    parameters = input_schema.get("properties", {})

    blast_radius = 0.0
    permission_risk = 0.0
    risk_factors: list[str] = []
    recommendations: list[str] = []
    parameter_risks: list[dict[str, Any]] = []

    # Analyze description for capability keywords
    full_text = f"{description} {tool_name}".lower()
    for pattern, increment, reason in _HIGH_RISK_CAPABILITIES:
        if re.search(pattern, full_text, re.IGNORECASE):
            blast_radius += increment
            risk_factors.append(f"Capability: {reason}")

    # Check if tool has no description (obfuscation risk)
    if not description or len(description.strip()) < 10:
        blast_radius += 2.0
        risk_factors.append("Missing or trivial description (obfuscation risk)")
        recommendations.append(
            "Add a clear, complete description of what the tool does and its effects."
        )

    # Analyze parameters
    required_params = input_schema.get("required", [])
    for param_name, param_schema in parameters.items():
        param_risk = 0.0
        param_reasons: list[str] = []

        # Check for dangerous parameter names
        for pattern, reason, risk_val in _HIGH_RISK_PARAM_PATTERNS:
            if re.search(pattern, param_name, re.IGNORECASE):
                param_risk += risk_val
                param_reasons.append(reason)

        # Check parameter type risks
        param_type = param_schema.get("type", "")
        if param_type == "string" and param_name in required_params:
            param_risk += 0.5
        if not param_schema.get("description"):
            param_risk += 1.0
            param_reasons.append("No description (input intent unclear)")

        # Check for overly permissive schemas
        if (
            param_type == "string"
            and not param_schema.get("maxLength")
            and not param_schema.get("enum")
        ):
            param_risk += 0.5
            param_reasons.append("Unbounded string input")

        if param_risk > 0:
            parameter_risks.append(
                {
                    "parameter": param_name,
                    "risk_score": round(min(param_risk, 10.0), 1),
                    "reasons": param_reasons,
                }
            )
            permission_risk += param_risk * 0.3

    # Normalize scores to 0–10
    blast_radius = min(blast_radius, 10.0)
    permission_risk = min(permission_risk, 10.0)
    overall_risk = min((blast_radius * 0.6 + permission_risk * 0.4), 10.0)

    # Generate recommendations
    if blast_radius > 7:
        recommendations.append(
            "This tool has a high blast radius — ensure explicit user confirmation before destructive operations."
        )
    if blast_radius > 5:
        recommendations.append("Log all invocations of this tool with full parameter context.")
    if permission_risk > 6:
        recommendations.append(
            "Restrict the parameter set to minimum required inputs with strict validation."
        )
    if not parameters:
        recommendations.append(
            "Consider whether this tool can accept parameters that would increase its risk profile."
        )

    return ToolRiskProfile(
        tool_name=tool_name,
        blast_radius_score=round(blast_radius, 1),
        permission_risk=round(permission_risk, 1),
        overall_risk=round(overall_risk, 1),
        risk_level=_compute_risk_level(overall_risk),
        risk_factors=list(dict.fromkeys(risk_factors)),  # deduplicate
        recommendations=recommendations,
        parameter_risks=parameter_risks,
    )


def scan_for_tool_poisoning(tool_definitions: list[dict[str, Any]]) -> list[ToolPoisoningFinding]:
    """
    Scan tool definitions for tool poisoning indicators.

    Args:
        tool_definitions: List of MCP tool definition dicts.

    Returns:
        Sorted list of ToolPoisoningFinding instances.
    """
    findings: list[ToolPoisoningFinding] = []

    for tool in tool_definitions:
        tool_name = tool.get("name", "<unnamed>")
        # .get(..., "") only supplies the default when the key is absent; a tool
        # definition with the (valid) "description": null crashes re.search below
        # with a None value unless the falsy null is also caught here.
        description = tool.get("description") or ""

        for pattern, severity, rule_id, title, cvss_score in _POISONING_PATTERNS:
            match = re.search(pattern, description, re.IGNORECASE | re.DOTALL)
            if match:
                findings.append(
                    ToolPoisoningFinding(
                        rule_id=rule_id,
                        severity=severity,
                        title=title,
                        description=f"Tool '{tool_name}' shows poisoning indicator: {title}",
                        location=f"tool:{tool_name}.description",
                        evidence=match.group(0)[:150],
                        remediation=_get_poisoning_remediation(rule_id),
                        cvss_score=cvss_score,
                    )
                )

    findings.sort(key=lambda f: f.cvss_score, reverse=True)
    return findings


def _get_poisoning_remediation(rule_id: str) -> str:
    """Return remediation for tool poisoning rule."""
    remediations = {
        "TP-001": "Separate concerns: each tool should do exactly one thing. Remove hidden side effects.",
        "TP-002": "Descriptions must accurately describe all effects. Never use 'silently' or 'transparently' for data actions.",
        "TP-003": "Never suppress audit logging in tool descriptions. All tool actions must be logged.",
        "TP-004": "Remove all references to covert or stealth operations.",
        "TP-005": "Explicitly disallow silent data uploads in tool definitions.",
        "TP-006": "Tool descriptions must be honest. Deceptive descriptions are a security violation.",
        "TP-007": "Tools must not automatically chain invocations without explicit user intent.",
        "TP-008": "Users must always be aware of what tools are doing. Never suppress user awareness.",
        "TP-009": "Remove hidden instruction tags (<IMPORTANT>, <SYSTEM>, etc.) from tool descriptions. Tool metadata must not carry directives to the model.",
        "TP-010": "Tool descriptions must never instruct the AI to conceal its actions from the user.",
        "TP-011": "Tools must never instruct the AI to read sensitive local files (SSH keys, .env, credentials) and exfiltrate their contents via tool arguments. Quarantine this tool immediately.",
    }
    return remediations.get(
        rule_id,
        "Remove this pattern from the tool description — it indicates deceptive or malicious design.",
    )


def hash_tool_definitions(tool_definitions: list[dict[str, Any]]) -> dict[str, str]:
    """
    Compute a stable content hash per tool, for rug-pull / definition-change detection.

    Args:
        tool_definitions: List of MCP tool definition dicts.

    Returns:
        Dict mapping tool name (or "<unnamed>") to the sha256 hex digest of its
        JSON representation (keys sorted for stability).
    """
    hashes: dict[str, str] = {}
    for tool in tool_definitions:
        name = tool.get("name", "<unnamed>")
        digest = hashlib.sha256(json.dumps(tool, sort_keys=True).encode()).hexdigest()
        hashes[name] = digest
    return hashes
