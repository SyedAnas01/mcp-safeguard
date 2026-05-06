"""Detect prompt injection surfaces in MCP tool definitions."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Vulnerability severity levels aligned with CVSS."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class InjectionFinding:
    """A single prompt injection vulnerability finding."""

    rule_id: str
    severity: Severity
    title: str
    description: str
    location: str
    evidence: str
    remediation: str
    cvss_score: float = 0.0


# Patterns that indicate prompt injection or instruction hijacking attempts
_INJECTION_PATTERNS: list[tuple[str, Severity, str, str, float]] = [
    # (pattern, severity, rule_id, title, cvss_score)
    (
        r"ignore\s+(previous|prior|above|all)\s+(instructions?|prompts?|context)",
        Severity.CRITICAL,
        "PI-001",
        "Instruction Override Attempt",
        9.3,
    ),
    (
        r"(you\s+are\s+now|act\s+as|pretend\s+(to\s+be|you\s+are)|roleplay\s+as)",
        Severity.HIGH,
        "PI-002",
        "Identity Hijacking Pattern",
        8.1,
    ),
    (
        r"(system\s*:?\s*|<\s*system\s*>|\\nsystem\b)",
        Severity.HIGH,
        "PI-003",
        "Fake System Message Injection",
        7.8,
    ),
    (
        r"(disregard|forget|override)\s+(your|the|all)\s+(rules?|guidelines?|training|constraints?)",
        Severity.CRITICAL,
        "PI-004",
        "Constraint Bypass Attempt",
        9.1,
    ),
    (
        r"<\s*(hidden|invisible|secret)\s*>.*?<\s*/\s*(hidden|invisible|secret)\s*>",
        Severity.HIGH,
        "PI-005",
        "Hidden Instruction Tag",
        8.5,
    ),
    (
        r"(reveal|show|print|output|display)\s+(your\s+)?(system\s+prompt|instructions?|training\s+data)",
        Severity.HIGH,
        "PI-006",
        "System Prompt Exfiltration",
        7.5,
    ),
    (
        r"(do\s+not\s+|don.t\s+)(mention|tell|say|inform).*(user|human|person)",
        Severity.MEDIUM,
        "PI-007",
        "Deception Instruction",
        5.5,
    ),
    (
        r"(translate|encode|base64|hex|rot13).*(instruction|prompt|command)",
        Severity.MEDIUM,
        "PI-008",
        "Encoded Instruction Obfuscation",
        5.8,
    ),
    (
        r"when\s+(you\s+see|the\s+user\s+(says?|asks?|sends?))\s+[\"']",
        Severity.MEDIUM,
        "PI-009",
        "Conditional Trigger Instruction",
        5.2,
    ),
    (
        r"(execute|run|eval|call)\s+(this|the\s+following)?\s*(code|script|command|function)",
        Severity.HIGH,
        "PI-010",
        "Code Execution Prompt",
        8.0,
    ),
    (
        r"(exfiltrat|leak|send|transmit|steal).{0,20}(data|information|credentials?|tokens?|keys?)",
        Severity.CRITICAL,
        "PI-011",
        "Data Exfiltration Instruction",
        9.5,
    ),
    (
        r"\{\{[^}]+\}\}|\$\{[^}]+\}",
        Severity.MEDIUM,
        "PI-012",
        "Template Injection Pattern",
        5.0,
    ),
    (
        r"(--\s*|#\s*|//\s*|/\*\s*).{0,50}(ignore|override|bypass)",
        Severity.MEDIUM,
        "PI-013",
        "Comment-Hidden Instruction",
        4.8,
    ),
    (
        r"[​‌‍⁠﻿]",
        Severity.HIGH,
        "PI-014",
        "Zero-Width Character Steganography",
        7.2,
    ),
    (
        r"(now\s+)?(always|must|should|will)\s+(also\s+)?(call|invoke|execute|trigger)\s+\w+",
        Severity.MEDIUM,
        "PI-015",
        "Forced Tool Call Instruction",
        6.0,
    ),
]

# Schema field patterns that create injection vectors
_SCHEMA_RISK_PATTERNS: list[tuple[str, Severity, str, str]] = [
    (
        r'"default"\s*:\s*"[^"]{200,}"',
        Severity.MEDIUM,
        "PI-SCH-001",
        "Oversized Default Value (potential injection vector)",
    ),
    (
        r'"description"\s*:\s*"[^"]{500,}"',
        Severity.LOW,
        "PI-SCH-002",
        "Unusually Long Parameter Description",
    ),
    (
        r'"enum"\s*:\s*\[[^\]]{500,}\]',
        Severity.LOW,
        "PI-SCH-003",
        "Oversized Enum Definition",
    ),
    (
        r'"(x-|X-)[\w-]+"\s*:',
        Severity.INFO,
        "PI-SCH-004",
        "Non-standard Schema Extension",
    ),
]


def _extract_text_fields(obj: Any, path: str = "") -> list[tuple[str, str]]:
    """Recursively extract all string values with their JSON paths."""
    results: list[tuple[str, str]] = []
    if isinstance(obj, str):
        results.append((path, obj))
    elif isinstance(obj, dict):
        for k, v in obj.items():
            results.extend(_extract_text_fields(v, f"{path}.{k}" if path else k))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            results.extend(_extract_text_fields(item, f"{path}[{i}]"))
    return results


def _truncate(text: str, max_len: int = 120) -> str:
    """Truncate evidence string for display."""
    return text[:max_len] + "…" if len(text) > max_len else text


def scan_for_prompt_injection(
    tool_definitions: list[dict[str, Any]],
) -> list[InjectionFinding]:
    """
    Scan a list of MCP tool definition dicts for prompt injection indicators.

    Args:
        tool_definitions: List of MCP tool definition objects (name, description, inputSchema, …)

    Returns:
        List of InjectionFinding instances, sorted by CVSS score descending.
    """
    findings: list[InjectionFinding] = []

    for tool in tool_definitions:
        tool_name = tool.get("name", "<unnamed>")
        text_fields = _extract_text_fields(tool)

        for path, text in text_fields:
            if not text or len(text) < 5:
                continue

            for pattern, severity, rule_id, title, cvss_score in _INJECTION_PATTERNS:
                match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
                if match:
                    findings.append(
                        InjectionFinding(
                            rule_id=rule_id,
                            severity=severity,
                            title=title,
                            description=(
                                f"Possible prompt injection in tool '{tool_name}' "
                                f"at field '{path}'. The pattern '{pattern}' matched."
                            ),
                            location=f"tool:{tool_name} → {path}",
                            evidence=_truncate(match.group(0)),
                            remediation=_get_remediation(rule_id),
                            cvss_score=cvss_score,
                        )
                    )

        # Check raw JSON for schema-level risks
        raw_json = json.dumps(tool)
        for pattern, severity, rule_id, title in _SCHEMA_RISK_PATTERNS:
            match = re.search(pattern, raw_json)
            if match:
                findings.append(
                    InjectionFinding(
                        rule_id=rule_id,
                        severity=severity,
                        title=title,
                        description=(f"Schema-level risk in tool '{tool_name}': {title}"),
                        location=f"tool:{tool_name} → schema",
                        evidence=_truncate(match.group(0)),
                        remediation="Review and minimize schema field sizes; avoid embedding instructions in schema metadata.",
                        cvss_score=3.5,
                    )
                )

    findings.sort(key=lambda f: f.cvss_score, reverse=True)
    return findings


def scan_description_text(description: str, context: str = "unknown") -> list[InjectionFinding]:
    """
    Scan a single text string (e.g., a tool description) for injection patterns.

    Args:
        description: The text to scan.
        context: Human-readable context label for the finding location.

    Returns:
        List of InjectionFinding instances.
    """
    findings: list[InjectionFinding] = []
    for pattern, severity, rule_id, title, cvss_score in _INJECTION_PATTERNS:
        match = re.search(pattern, description, re.IGNORECASE | re.DOTALL)
        if match:
            findings.append(
                InjectionFinding(
                    rule_id=rule_id,
                    severity=severity,
                    title=title,
                    description=f"Prompt injection pattern found in {context}.",
                    location=context,
                    evidence=_truncate(match.group(0)),
                    remediation=_get_remediation(rule_id),
                    cvss_score=cvss_score,
                )
            )
    return findings


def _get_remediation(rule_id: str) -> str:
    """Return remediation advice for a given rule ID."""
    remediations = {
        "PI-001": "Remove instruction override phrases from tool descriptions. Tool descriptions should describe capability, not provide instructions to the AI.",
        "PI-002": "Eliminate identity-changing directives. Tool metadata must not attempt to redefine the AI's persona.",
        "PI-003": "Do not embed fake system message markers in tool descriptions or parameter defaults.",
        "PI-004": "Tool definitions must not instruct the AI to bypass safety constraints.",
        "PI-005": "Remove hidden content tags. All instructions in tool definitions must be visible.",
        "PI-006": "Do not include prompts that request the AI to reveal its system configuration.",
        "PI-007": "Tool descriptions must not instruct the AI to deceive users.",
        "PI-008": "Avoid encoding/obfuscation in tool metadata. All content should be plaintext.",
        "PI-009": "Remove conditional trigger instructions from tool descriptions.",
        "PI-010": "Tool descriptions should not contain prompts to execute arbitrary code.",
        "PI-011": "Immediately audit this tool — it appears designed to exfiltrate data.",
        "PI-012": "Validate and sanitize template expressions in tool parameters.",
        "PI-013": "Remove comment-hidden instructions. All tool content must be transparent.",
        "PI-014": "Strip zero-width characters from all tool text fields.",
        "PI-015": "Do not embed forced tool-call instructions in descriptions.",
        "PI-SCH-001": "Reduce default parameter values to minimal, safe strings.",
        "PI-SCH-002": "Keep parameter descriptions concise (under 200 characters).",
        "PI-SCH-003": "Minimize enum definitions; large enums may be used to smuggle instructions.",
        "PI-SCH-004": "Document the purpose of non-standard schema extensions.",
    }
    return remediations.get(
        rule_id, "Review and sanitize this field to remove potentially malicious content."
    )
