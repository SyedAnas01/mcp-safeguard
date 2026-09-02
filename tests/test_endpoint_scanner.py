"""Tests for the endpoint scanner (non-network tests)."""

import pytest

from mcp_safeguard.scanner.endpoint_scanner import (
    _is_ssrf_safe,
    _port_open,
    _resolves_to_unsafe_ip,
)
from mcp_safeguard.scanner.prompt_injection import Severity


def test_localhost_is_ssrf_safe():
    assert _is_ssrf_safe("localhost") is True


def test_127_0_0_1_is_ssrf_safe():
    assert _is_ssrf_safe("127.0.0.1") is True


def test_ipv6_loopback_is_ssrf_safe():
    assert _is_ssrf_safe("::1") is True


def test_cloud_metadata_is_not_safe():
    assert _is_ssrf_safe("169.254.169.254") is False


def test_gcp_metadata_internal_suffix_is_not_safe():
    """metadata.google.internal ends with '.internal' but must still be blocked —
    the metadata blocklist must be checked before the .internal/.local allowance."""
    assert _is_ssrf_safe("metadata.google.internal") is False


def test_external_ip_not_safe_without_allowlist():
    assert _is_ssrf_safe("8.8.8.8") is False


def test_allowlisted_host_is_safe():
    assert _is_ssrf_safe("myserver.internal", allowlist=["myserver.internal"]) is True


def test_local_suffix_is_not_automatically_safe():
    """A ".local"/".internal"-suffixed hostname is NOT automatically safe -- it
    used to be (a bare suffix match bypassed the allowlist entirely), which is
    exactly the EP-SSRF-001 blind spot this fixed. Such hosts now need explicit
    allowlisting like any other host."""
    assert _is_ssrf_safe("mcp-server.local") is False
    assert _is_ssrf_safe("db.internal") is False
    # An explicit allowlist entry still works, as always.
    assert _is_ssrf_safe("mcp-server.local", allowlist=["mcp-server.local"]) is True


def test_resolves_to_unsafe_ip_rejects_link_local():
    """A hostname that resolves to a link-local/metadata IP must be rejected —
    guards against DNS rebinding where an allowlisted-looking name resolves
    to 169.254.169.254 at request time."""
    assert _resolves_to_unsafe_ip("169.254.169.254") is True


def test_resolves_to_unsafe_ip_allows_loopback():
    assert _resolves_to_unsafe_ip("127.0.0.1") is False


def test_resolves_to_unsafe_ip_rejects_full_rfc1918_range():
    """Previously only checked link-local (169.254.0.0/16) and metadata IPs --
    a literal RFC1918 address (10.x/172.16.x/192.168.x) resolved via a hostname
    was NOT caught. Now delegates to the shared, full-range check."""
    assert _resolves_to_unsafe_ip("10.0.0.5") is True
    assert _resolves_to_unsafe_ip("172.16.0.5") is True
    assert _resolves_to_unsafe_ip("192.168.1.1") is True


def test_closed_port_returns_false():
    assert _port_open("127.0.0.1", 19999, timeout=0.5) is False


@pytest.mark.asyncio
async def test_scan_endpoints_blocks_ssrf():
    """Scanning a non-allowlisted host returns a blocked finding."""
    from mcp_safeguard.scanner.endpoint_scanner import scan_endpoints

    findings = await scan_endpoints(
        host="8.8.8.8",
        port=80,
        ssrf_allowlist=["localhost", "127.0.0.1"],
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "EP-SSRF-001"
    assert findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_scan_endpoints_localhost_no_ssrf_block():
    """Localhost is always allowed for scanning."""
    from mcp_safeguard.scanner.endpoint_scanner import scan_endpoints

    # Should not return SSRF block (server is unlikely running, so likely 0 HTTP findings)
    findings = await scan_endpoints(host="localhost", port=19998, timeout=0.3)
    assert not any(f.rule_id == "EP-SSRF-001" for f in findings)
