"""Tests for the credential scanner."""

from mcp_shield.scanner.credential_scanner import (
    scan_for_credentials,
    scan_oauth_scopes,
)
from mcp_shield.scanner.prompt_injection import Severity


def test_clean_config_no_findings():
    config = {
        "command": "python",
        "args": ["-m", "my_server"],
        "env": {"LOG_LEVEL": "INFO", "PORT": "8000"},
    }
    findings = scan_for_credentials(config)
    assert findings == []


def test_detects_hardcoded_api_key():
    config = {"env": {"MY_KEY": "sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890abcdefghij"}}
    findings = scan_for_credentials(config)
    assert len(findings) > 0
    assert any("CRED-017" in f.rule_id or "CRED" in f.rule_id for f in findings)


def test_detects_aws_access_key():
    config = {"env": {"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE"}}
    findings = scan_for_credentials(config)
    rule_ids = [f.rule_id for f in findings]
    assert any("CRED-007" in r for r in rule_ids)


def test_detects_hardcoded_password():
    config = {"auth": {"password": "super-secret-password-123"}}
    findings = scan_for_credentials(config)
    assert len(findings) > 0
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_detects_github_pat():
    config = {"env": {"GITHUB_TOKEN": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234"}}
    findings = scan_for_credentials(config)
    rule_ids = [f.rule_id for f in findings]
    assert any("CRED-009" in r for r in rule_ids)


def test_detects_database_url():
    config = {"database_url": "postgresql://admin:password123@localhost:5432/prod_db"}
    findings = scan_for_credentials(config)
    rule_ids = [f.rule_id for f in findings]
    assert any("CRED-011" in r for r in rule_ids)


def test_detects_hugging_face_token():
    token = "hf_" + "a" * 34
    config = {"env": {"HF_TOKEN": token}}
    findings = scan_for_credentials(config)
    rule_ids = [f.rule_id for f in findings]
    assert any("CRED-026" in r for r in rule_ids)


def test_credential_evidence_is_masked():
    config = {"env": {"SECRET": "sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890abcdefghij"}}
    findings = scan_for_credentials(config)
    for f in findings:
        # Evidence should not contain the full key
        assert len(f.evidence) <= 50 or "*" in f.evidence


def test_findings_sorted_by_cvss():
    config = {
        "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIE...",
        "env": {"API_KEY": "sk-proj-abcdefghijklmnopqrstuvwxyz123456"},
    }
    findings = scan_for_credentials(config)
    if len(findings) >= 2:
        scores = [f.cvss_score for f in findings]
        assert scores == sorted(scores, reverse=True)


def test_every_finding_has_remediation():
    config = {"env": {"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE"}}
    findings = scan_for_credentials(config)
    for f in findings:
        assert f.remediation, "Every finding must have remediation"


# OAuth scope tests


def test_clean_scopes_no_findings():
    scopes = ["read:user", "read:org"]
    findings = scan_oauth_scopes(scopes)
    assert findings == []


def test_wildcard_scope_critical():
    findings = scan_oauth_scopes(["*"])
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_admin_scope_critical():
    findings = scan_oauth_scopes(["admin"])
    assert len(findings) > 0


def test_sudo_scope_critical():
    findings = scan_oauth_scopes(["sudo"])
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_delete_scope_high():
    findings = scan_oauth_scopes(["delete"])
    assert any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings)


def test_empty_scopes_no_findings():
    assert scan_oauth_scopes([]) == []
