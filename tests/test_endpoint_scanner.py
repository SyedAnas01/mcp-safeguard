"""Tests for the endpoint scanner (non-network tests)."""

import pytest

import mcp_shield.scanner.endpoint_scanner as endpoint_scanner
from mcp_shield.scanner.endpoint_scanner import (
    _is_ssrf_safe,
    _port_open,
    _resolves_to_unsafe_ip,
)
from mcp_shield.scanner.prompt_injection import Severity


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


def test_local_suffix_is_safe():
    assert _is_ssrf_safe("mcp-server.local") is True


def test_resolves_to_unsafe_ip_rejects_link_local():
    """A hostname that resolves to a link-local/metadata IP must be rejected —
    guards against DNS rebinding where an allowlisted-looking name resolves
    to 169.254.169.254 at request time."""
    assert _resolves_to_unsafe_ip("169.254.169.254") is True


def test_resolves_to_unsafe_ip_allows_loopback():
    assert _resolves_to_unsafe_ip("127.0.0.1") is False


def test_closed_port_returns_false():
    assert _port_open("127.0.0.1", 19999, timeout=0.5) is False


@pytest.mark.asyncio
async def test_scan_endpoints_blocks_ssrf():
    """Scanning a non-allowlisted host returns a blocked finding."""
    from mcp_shield.scanner.endpoint_scanner import scan_endpoints

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
    from mcp_shield.scanner.endpoint_scanner import scan_endpoints

    # Should not return SSRF block (server is unlikely running, so likely 0 HTTP findings)
    findings = await scan_endpoints(host="localhost", port=19998, timeout=0.3)
    assert not any(f.rule_id == "EP-SSRF-001" for f in findings)


class _FakeResponse:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload
        self.text = ""

    def json(self):
        return self._payload


class _FakeAsyncClient:
    def __init__(self, graphql_response, **kwargs):
        self._graphql_response = graphql_response

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    async def get(self, url):
        return _FakeResponse(404)

    async def post(self, url, json, headers):
        assert url.endswith("/graphql")
        assert "__schema" in json["query"]
        return self._graphql_response


@pytest.mark.asyncio
async def test_graphql_introspection_exposure_detected(monkeypatch):
    response = _FakeResponse(
        200,
        {"data": {"__schema": {"queryType": {"name": "Query"}}}},
    )
    monkeypatch.setattr(endpoint_scanner, "_port_open", lambda *args, **kwargs: False)
    monkeypatch.setattr(
        endpoint_scanner.httpx,
        "AsyncClient",
        lambda **kwargs: _FakeAsyncClient(response, **kwargs),
    )

    findings = await endpoint_scanner.scan_endpoints(host="localhost", port=8000)

    graphql_findings = [f for f in findings if f.rule_id == "EP-029"]
    assert len(graphql_findings) == 1
    assert graphql_findings[0].severity == Severity.MEDIUM
    assert graphql_findings[0].cvss_score == 5.3
    assert "Query" in graphql_findings[0].evidence


@pytest.mark.asyncio
async def test_graphql_endpoint_without_introspection_not_reported(monkeypatch):
    response = _FakeResponse(
        200,
        {"errors": [{"message": "GraphQL introspection is disabled"}]},
    )
    monkeypatch.setattr(endpoint_scanner, "_port_open", lambda *args, **kwargs: False)
    monkeypatch.setattr(
        endpoint_scanner.httpx,
        "AsyncClient",
        lambda **kwargs: _FakeAsyncClient(response, **kwargs),
    )

    findings = await endpoint_scanner.scan_endpoints(host="localhost", port=8000)

    assert not any(f.rule_id == "EP-029" for f in findings)
