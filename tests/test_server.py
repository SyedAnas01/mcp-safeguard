"""Tests for the MCP server tools and validators."""

import json

import pytest

from mcp_shield.scanner.prompt_injection import Severity
from mcp_shield.scanner.tool_analyzer import analyze_tool_risk
from mcp_shield.security.auth_middleware import (
    authenticate_request,
    generate_api_key,
    verify_api_key,
)
from mcp_shield.security.input_validator import (
    ValidationError,
    sanitize_scan_id,
    validate_config_json,
    validate_host,
    validate_port,
    validate_tool_json,
    validate_url,
)
from mcp_shield.security.rate_limiter import RateLimiter

# ---------------------------------------------------------------------------
# Input Validator
# ---------------------------------------------------------------------------


def test_validate_url_accepts_http_localhost():
    result = validate_url("http://localhost:8000")
    assert result == "http://localhost:8000"


def test_validate_url_rejects_metadata_endpoint():
    with pytest.raises(ValidationError, match="SSRF"):
        validate_url("http://169.254.169.254/latest/meta-data")


def test_validate_url_rejects_ftp():
    with pytest.raises(ValidationError, match="scheme"):
        validate_url("ftp://localhost/file")


def test_validate_url_rejects_too_long():
    with pytest.raises(ValidationError):
        validate_url("http://localhost/" + "a" * 2100)


def test_validate_host_accepts_localhost():
    assert validate_host("localhost") == "localhost"


def test_validate_host_rejects_metadata():
    with pytest.raises(ValidationError, match="SSRF"):
        validate_host("169.254.169.254")


def test_validate_host_rejects_invalid_format():
    with pytest.raises(ValidationError):
        validate_host("not a host!")


def test_validate_port_valid():
    assert validate_port(8000) == 8000
    assert validate_port("443") == 443


def test_validate_port_rejects_zero():
    with pytest.raises(ValidationError):
        validate_port(0)


def test_validate_port_rejects_overflow():
    with pytest.raises(ValidationError):
        validate_port(99999)


def test_validate_tool_json_single_tool():
    tool_json = json.dumps({"name": "my_tool", "description": "Does something"})
    result = validate_tool_json(tool_json)
    assert isinstance(result, list)
    assert result[0]["name"] == "my_tool"


def test_validate_tool_json_array():
    tools = [{"name": "t1"}, {"name": "t2"}]
    result = validate_tool_json(json.dumps(tools))
    assert len(result) == 2


def test_validate_tool_json_rejects_missing_name():
    with pytest.raises(ValidationError, match="name"):
        validate_tool_json(json.dumps([{"description": "no name"}]))


def test_validate_tool_json_rejects_oversized():
    with pytest.raises(ValidationError, match="length"):
        validate_tool_json("x" * 60_000, max_length=50_000)


def test_validate_config_json_valid():
    config = {"command": "python", "args": ["-m", "server"]}
    result = validate_config_json(json.dumps(config))
    assert result["command"] == "python"


def test_sanitize_scan_id_valid():
    valid_id = "550e8400-e29b-41d4-a716-446655440000"
    assert sanitize_scan_id(valid_id) == valid_id


def test_sanitize_scan_id_rejects_traversal():
    with pytest.raises(ValidationError):
        sanitize_scan_id("../../etc/passwd")


# ---------------------------------------------------------------------------
# Rate Limiter
# ---------------------------------------------------------------------------


def test_rate_limiter_allows_within_limit():
    rl = RateLimiter(requests_per_window=10, window_seconds=60)
    for _ in range(5):
        assert rl.is_allowed("client1") is True


def test_rate_limiter_blocks_excess():
    rl = RateLimiter(requests_per_window=3, window_seconds=60)
    for _ in range(3):
        rl.is_allowed("client2")
    assert rl.is_allowed("client2") is False


def test_rate_limiter_separate_clients():
    rl = RateLimiter(requests_per_window=2, window_seconds=60)
    rl.is_allowed("a")
    rl.is_allowed("a")
    # a is exhausted, b should still work
    assert rl.is_allowed("b") is True


def test_rate_limiter_reset():
    rl = RateLimiter(requests_per_window=1, window_seconds=60)
    rl.is_allowed("c")
    assert rl.is_allowed("c") is False
    rl.reset("c")
    assert rl.is_allowed("c") is True


# ---------------------------------------------------------------------------
# Auth Middleware
# ---------------------------------------------------------------------------


def test_verify_api_key_correct():
    key = "test-key-abc123"
    assert verify_api_key(key, key) is True


def test_verify_api_key_wrong():
    assert verify_api_key("wrong-key", "correct-key") is False


def test_verify_api_key_empty():
    assert verify_api_key("", "key") is False


def test_generate_api_key_has_prefix():
    key = generate_api_key("msh")
    assert key.startswith("msh_")
    assert len(key) > 20


def test_authenticate_no_config():
    ctx = authenticate_request(None, None, None)
    assert ctx.authenticated is True
    assert ctx.auth_method == "none"


def test_authenticate_valid_api_key():
    expected = "my-secret-key"
    ctx = authenticate_request(expected, None, expected)
    assert ctx.authenticated is True
    assert ctx.auth_method == "api_key"


def test_authenticate_wrong_key():
    ctx = authenticate_request("wrong", None, "correct")
    assert ctx.authenticated is False


def test_authenticate_bearer_token():
    key = "my-bearer-token"
    ctx = authenticate_request(None, f"Bearer {key}", key)
    assert ctx.authenticated is True
    assert ctx.auth_method == "bearer"


# ---------------------------------------------------------------------------
# Tool Analyzer
# ---------------------------------------------------------------------------


def test_safe_read_tool_has_low_blast_radius():
    tool = {
        "name": "list_files",
        "description": "List files in a directory.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "directory": {"type": "string", "description": "The directory to list."}
            },
        },
    }
    profile = analyze_tool_risk(tool)
    assert profile.blast_radius_score < 5.0


def test_delete_tool_has_high_blast_radius():
    tool = {
        "name": "delete_database",
        "description": "Delete all records from the database table permanently.",
        "inputSchema": {
            "type": "object",
            "properties": {"table": {"type": "string", "description": "Table to delete."}},
        },
    }
    profile = analyze_tool_risk(tool)
    assert profile.blast_radius_score >= 3.0


def test_payment_tool_high_risk():
    tool = {
        "name": "process_payment",
        "description": "Process a payment charge with Stripe billing.",
        "inputSchema": {"type": "object", "properties": {}},
    }
    profile = analyze_tool_risk(tool)
    assert profile.overall_risk >= 2.0


def test_tool_with_credential_param_has_permission_risk():
    tool = {
        "name": "set_config",
        "description": "Set configuration value.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "password": {"type": "string"},
            },
        },
    }
    profile = analyze_tool_risk(tool)
    assert profile.permission_risk > 0


def test_tool_risk_level_is_valid_severity():
    tool = {"name": "t", "description": "does something"}
    profile = analyze_tool_risk(tool)
    assert profile.risk_level in (
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    )
