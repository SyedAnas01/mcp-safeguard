"""Scan MCP server configurations for credential leaks and over-scoped OAuth."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from .prompt_injection import Severity


@dataclass
class CredentialFinding:
    """A credential-related security finding."""

    rule_id: str
    severity: Severity
    title: str
    description: str
    location: str
    evidence: str
    remediation: str
    cvss_score: float = 0.0


# Credential leak patterns: (pattern, severity, rule_id, title, cvss_score)
_CREDENTIAL_PATTERNS: list[tuple[str, Severity, str, str, float]] = [
    # API Keys and tokens
    (
        r"(?i)(sk|pk|rk|ak)[-_]?(live|test|secret|prod|dev)?[-_]?[A-Za-z0-9]{20,}",
        Severity.CRITICAL,
        "CRED-001",
        "Hardcoded API Key",
        9.8,
    ),
    (
        r"(?i)(api[_\-]?key|apikey|api[_\-]?secret)\s*[=:]\s*[\"']?[A-Za-z0-9\-_]{16,}",
        Severity.CRITICAL,
        "CRED-002",
        "Hardcoded API Key Assignment",
        9.5,
    ),
    (
        r"(?i)(password|passwd|pwd)[\"']?\s*[=:]\s*[\"'][^\"']{4,}[\"']",
        Severity.CRITICAL,
        "CRED-003",
        "Hardcoded Password",
        9.8,
    ),
    (
        r"(?i)(secret[_\-]?key|secret)\s*[=:]\s*[\"'][^\"']{8,}[\"']",
        Severity.HIGH,
        "CRED-004",
        "Hardcoded Secret Key",
        8.5,
    ),
    # JWT and Bearer tokens
    (
        r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]*",
        Severity.HIGH,
        "CRED-005",
        "Exposed JWT Token",
        8.8,
    ),
    (
        r"(?i)bearer\s+[A-Za-z0-9\-_=]{20,}",
        Severity.HIGH,
        "CRED-006",
        "Exposed Bearer Token",
        8.5,
    ),
    # AWS credentials
    (
        r"AKIA[0-9A-Z]{16}",
        Severity.CRITICAL,
        "CRED-007",
        "AWS Access Key ID",
        9.9,
    ),
    (
        r"(?i)(aws[_\-]?secret|aws[_\-]?key)\s*[=:]\s*[\"']?[A-Za-z0-9/+=]{40}",
        Severity.CRITICAL,
        "CRED-008",
        "AWS Secret Access Key",
        9.9,
    ),
    # GitHub / GitLab tokens
    (
        r"gh[pousr]_[A-Za-z0-9]{36}",
        Severity.HIGH,
        "CRED-009",
        "GitHub Personal Access Token",
        8.5,
    ),
    (
        r"glpat-[A-Za-z0-9\-_]{20}",
        Severity.HIGH,
        "CRED-010",
        "GitLab Personal Access Token",
        8.5,
    ),
    # Database URLs
    (
        r"(?i)(postgres|mysql|mongodb|redis|sqlite)[+a-z]*://[^:]+:[^@]+@[^\s\"']+",
        Severity.CRITICAL,
        "CRED-011",
        "Database Connection String with Credentials",
        9.5,
    ),
    # Private keys
    (
        r"-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE KEY-----",
        Severity.CRITICAL,
        "CRED-012",
        "Private Key Material",
        10.0,
    ),
    # Generic tokens
    (
        r"(?i)(access[_\-]?token|auth[_\-]?token)\s*[=:]\s*[\"']?[A-Za-z0-9\-_]{20,}",
        Severity.HIGH,
        "CRED-013",
        "Hardcoded Access Token",
        8.0,
    ),
    # Slack tokens
    (
        r"xox[baprs]-[A-Za-z0-9\-]{10,}",
        Severity.HIGH,
        "CRED-014",
        "Slack API Token",
        8.5,
    ),
    # Stripe keys
    (
        r"(?i)(sk_live|sk_test|pk_live|pk_test)_[A-Za-z0-9]{24,}",
        Severity.CRITICAL,
        "CRED-015",
        "Stripe API Key",
        9.8,
    ),
    # OpenAI keys
    (
        r"sk-[A-Za-z0-9]{48}",
        Severity.CRITICAL,
        "CRED-016",
        "OpenAI API Key",
        9.5,
    ),
    # Anthropic keys
    (
        r"sk-ant-[A-Za-z0-9\-_]{40,}",
        Severity.CRITICAL,
        "CRED-017",
        "Anthropic API Key",
        9.5,
    ),
]

# OAuth scope risk rules: (scope_pattern, severity, rule_id, title, cvss_score)
_OAUTH_SCOPE_RISKS: list[tuple[str, Severity, str, str, float]] = [
    (
        r"^(admin|root|superuser|\*|all)$",
        Severity.CRITICAL,
        "OAUTH-001",
        "Wildcard or Admin OAuth Scope",
        9.0,
    ),
    (
        r"\bwrite\b",
        Severity.MEDIUM,
        "OAUTH-002",
        "Write-Scoped OAuth (check if read-only suffices)",
        4.5,
    ),
    (r"\bdelete\b", Severity.HIGH, "OAUTH-003", "Delete-Scoped OAuth Token", 7.5),
    (
        r"\boffline_access\b",
        Severity.MEDIUM,
        "OAUTH-004",
        "Offline Access Scope (persistent token risk)",
        5.0,
    ),
    (
        r"\bsudo\b|\bimpersonat",
        Severity.CRITICAL,
        "OAUTH-005",
        "Sudo/Impersonation OAuth Scope",
        9.5,
    ),
    (r"\buser:email\b|\bprofile\b", Severity.LOW, "OAUTH-006", "PII-Exposing OAuth Scope", 3.0),
    (r"\brepo\b(?!:read)", Severity.MEDIUM, "OAUTH-007", "Full Repository OAuth Scope", 5.5),
]

# Environment variable exposure patterns
_ENV_VAR_PATTERNS: list[tuple[str, Severity, str]] = [
    (r"\$\{?[A-Z_]{3,}[A-Z0-9_]*\}?", Severity.INFO, "Direct env var reference in tool definition"),
    (r"os\.environ\[", Severity.MEDIUM, "Python os.environ access in tool text"),
    (r"process\.env\.", Severity.MEDIUM, "Node.js process.env access in tool text"),
    (r"getenv\(", Severity.LOW, "getenv call in tool text"),
]


def _mask_credential(text: str) -> str:
    """Mask most of a credential for safe display in reports."""
    if len(text) <= 8:
        return "****"
    return text[:4] + "*" * (len(text) - 8) + text[-4:]


def _extract_all_strings(obj: Any, path: str = "") -> list[tuple[str, str]]:
    """Recursively extract all string values with paths."""
    results: list[tuple[str, str]] = []
    if isinstance(obj, str):
        results.append((path, obj))
    elif isinstance(obj, dict):
        for k, v in obj.items():
            results.extend(_extract_all_strings(v, f"{path}.{k}" if path else k))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            results.extend(_extract_all_strings(item, f"{path}[{i}]"))
    return results


def scan_for_credentials(config: dict[str, Any]) -> list[CredentialFinding]:
    """
    Scan an MCP server configuration for hardcoded credentials.

    Args:
        config: MCP server configuration dict (env, args, or full server config).

    Returns:
        Sorted list of CredentialFinding instances.
    """
    findings: list[CredentialFinding] = []
    raw_json = json.dumps(config)

    for pattern, severity, rule_id, title, cvss_score in _CREDENTIAL_PATTERNS:
        for match in re.finditer(pattern, raw_json):
            matched_text = match.group(0)
            masked = _mask_credential(matched_text)
            findings.append(
                CredentialFinding(
                    rule_id=rule_id,
                    severity=severity,
                    title=title,
                    description=f"Potential {title.lower()} found in configuration.",
                    location="config",
                    evidence=masked,
                    remediation=_get_cred_remediation(rule_id),
                    cvss_score=cvss_score,
                )
            )

    # Check env section specifically
    env_vars = config.get("env", {})

    # Sensitive env var name patterns (flag by name regardless of value)
    _SENSITIVE_ENV_NAMES: list[tuple[str, str, str, float]] = [
        (r"(?i)(stripe.*(key|secret|token)|stripe_secret)", "CRED-018", "Stripe Credential in Environment", 8.5),
        (r"(?i)(openai.*(key|secret|token)|openai_api_key)", "CRED-019", "OpenAI Credential in Environment", 8.5),
        (r"(?i)(anthropic.*(key|secret|token)|claude_api_key)", "CRED-020", "Anthropic Credential in Environment", 8.5),
        (r"(?i)(twilio.*(sid|token|secret)|twilio_auth)", "CRED-021", "Twilio Credential in Environment", 7.5),
        (r"(?i)(sendgrid.*(key|token)|sendgrid_api)", "CRED-022", "SendGrid Credential in Environment", 7.5),
        (r"(?i)(slack.*(token|secret|webhook)|slack_bot_token)", "CRED-023", "Slack Credential in Environment", 7.5),
        (r"(?i)(github.*(token|pat|key)|gh_token|github_token)", "CRED-024", "GitHub Credential in Environment", 8.0),
        (r"(?i)(aws.*(access.*key|secret.*key)|aws_access_key_id|aws_secret)", "CRED-025", "AWS Credential in Environment", 9.5),
    ]

    for key, value in env_vars.items():
        # Check by env var name (catches redacted/placeholder values too)
        for name_pattern, rule_id, title, cvss_score in _SENSITIVE_ENV_NAMES:
            if re.search(name_pattern, key, re.IGNORECASE):
                # Only flag if value looks like a real secret (not a reference like ${VAR} or empty)
                val_str = str(value) if value else ""
                is_reference = bool(re.match(r"^\$\{?[A-Z_]+\}?$", val_str))
                if val_str and not is_reference:
                    findings.append(
                        CredentialFinding(
                            rule_id=f"{rule_id}-NAME",
                            severity=Severity.HIGH,
                            title=f"{title} (by name)",
                            description=f"Env var '{key}' name indicates a hardcoded credential.",
                            location=f"env.{key}",
                            evidence=_mask_credential(val_str) if len(val_str) > 4 else "[set]",
                            remediation="Use a secrets manager (AWS Secrets Manager, HashiCorp Vault) instead of inline env vars.",
                            cvss_score=cvss_score,
                        )
                    )
                break  # one match per key is enough

        # Check by value pattern
        if isinstance(value, str) and len(value) > 5:
            for pattern, severity, rule_id, title, cvss_score in _CREDENTIAL_PATTERNS:
                if re.search(pattern, value, re.IGNORECASE):
                    findings.append(
                        CredentialFinding(
                            rule_id=f"{rule_id}-ENV",
                            severity=severity,
                            title=f"{title} in Environment Variable",
                            description=f"Env var '{key}' appears to contain a {title.lower()}.",
                            location=f"env.{key}",
                            evidence=_mask_credential(value),
                            remediation="Use a secrets manager (AWS Secrets Manager, HashiCorp Vault) instead of inline env vars.",
                            cvss_score=cvss_score,
                        )
                    )

    findings.sort(key=lambda f: f.cvss_score, reverse=True)
    # Deduplicate by rule_id + location
    seen: set[str] = set()
    unique: list[CredentialFinding] = []
    for f in findings:
        key = f"{f.rule_id}:{f.location}:{f.evidence[:20]}"
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def scan_oauth_scopes(scopes: list[str]) -> list[CredentialFinding]:
    """
    Analyze OAuth scope list for over-permissioning.

    Args:
        scopes: List of OAuth scope strings.

    Returns:
        List of CredentialFinding instances for risky scopes.
    """
    findings: list[CredentialFinding] = []
    for scope in scopes:
        for pattern, severity, rule_id, title, cvss_score in _OAUTH_SCOPE_RISKS:
            if re.search(pattern, scope, re.IGNORECASE):
                findings.append(
                    CredentialFinding(
                        rule_id=rule_id,
                        severity=severity,
                        title=title,
                        description=f"OAuth scope '{scope}' matches risk pattern: {title}",
                        location=f"oauth.scope:{scope}",
                        evidence=scope,
                        remediation=_get_oauth_remediation(rule_id),
                        cvss_score=cvss_score,
                    )
                )
    return findings


def _get_cred_remediation(rule_id: str) -> str:
    """Return remediation for credential rule."""
    base = rule_id.split("-ENV")[0]
    remediations = {
        "CRED-001": "Rotate this key immediately. Store via environment variables or a secrets manager.",
        "CRED-002": "Remove hardcoded key. Use os.environ or a vault integration.",
        "CRED-003": "Rotate the password. Never store passwords in configuration files.",
        "CRED-004": "Move this secret to a secrets manager and rotate it.",
        "CRED-005": "Rotate the JWT secret. Do not embed live tokens in configs.",
        "CRED-006": "Revoke and rotate this bearer token. Use short-lived tokens.",
        "CRED-007": "Rotate AWS credentials immediately. Use IAM roles instead of static keys.",
        "CRED-008": "Rotate AWS Secret Access Key. Use instance profiles or assume-role flows.",
        "CRED-009": "Revoke this GitHub PAT. Use GitHub Apps with minimal scopes.",
        "CRED-010": "Revoke this GitLab PAT. Use project-scoped tokens.",
        "CRED-011": "Remove credentials from connection string. Use environment variables or a secrets vault.",
        "CRED-012": "Remove private key from config. Store private keys in secure key storage.",
        "CRED-013": "Rotate this access token. Use short-lived tokens with refresh flows.",
        "CRED-014": "Rotate this Slack token. Use OAuth flows with minimal scopes.",
        "CRED-015": "Rotate Stripe keys immediately. Use restricted keys with minimum permissions.",
        "CRED-016": "Rotate this OpenAI API key. Use project-scoped keys with spending limits.",
        "CRED-017": "Rotate this Anthropic API key. Use workspace-scoped keys.",
    }
    return remediations.get(base, "Rotate the credential and move to a secrets manager.")


def _get_oauth_remediation(rule_id: str) -> str:
    """Return remediation for OAuth scope risk."""
    remediations = {
        "OAUTH-001": "Apply least-privilege: request only the specific scopes your tool requires.",
        "OAUTH-002": "Verify that write access is strictly necessary. Use read-only scopes where possible.",
        "OAUTH-003": "Delete scope should only be granted with explicit user confirmation flows.",
        "OAUTH-004": "Prefer short-lived tokens; justify offline_access use.",
        "OAUTH-005": "Never grant sudo/impersonation scopes to MCP tools.",
        "OAUTH-006": "Only collect PII when explicitly required and disclosed to users.",
        "OAUTH-007": "Use repo:read scope unless write access is explicitly required.",
    }
    return remediations.get(rule_id, "Apply least-privilege OAuth scoping.")
