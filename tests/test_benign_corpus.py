"""Benign-corpus regression tests: legitimate inputs must not trip scanners.

These guard against false positives introduced by overly broad regexes in
the prompt-injection and credential scanners.
"""

from mcp_safeguard.scanner.credential_scanner import scan_for_credentials
from mcp_safeguard.scanner.prompt_injection import scan_for_prompt_injection


def test_filesystem_word_triggers_no_prompt_injection_findings():
    tools = [
        {
            "name": "list_dir",
            "description": "List files on the filesystem in the given directory.",
        }
    ]
    findings = scan_for_prompt_injection(tools)
    assert findings == [], f"Expected no findings, got: {findings}"


def test_operating_system_phrase_triggers_no_prompt_injection_findings():
    tools = [
        {
            "name": "get_os_info",
            "description": "Return details about the current operating system version.",
        }
    ]
    findings = scan_for_prompt_injection(tools)
    assert findings == [], f"Expected no findings, got: {findings}"


def test_desktop_commander_server_arg_triggers_no_credential_findings():
    config = {"env": {"CLIENT_ID": "DesktopCommanderServer1234567890"}}
    findings = scan_for_credentials(config)
    assert findings == [], f"Expected no findings, got: {findings}"


def test_single_openai_key_produces_exactly_one_finding():
    config = {"env": {"OPENAI_API_KEY": "sk-" + "A" * 48}}
    findings = scan_for_credentials(config)
    assert len(findings) == 1, f"Expected exactly 1 finding, got: {findings}"
