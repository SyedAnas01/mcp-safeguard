"""Tests for the endpoint scanner (non-network tests)."""

import socket
import threading

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


class TestScanEndpointsDoesNotReopenDNSRebindingTOCTOU:
    """A separate agent fixing Taig Mac Carthy's DNS-rebinding report on
    scan_mcp_server (2026-09-06, see SECURITY_FIXES_TAIG_2026-09-06.md)
    flagged scan_endpoints() as having the exact same shape:
    _resolves_to_unsafe_ip(host) validated the hostname once, then
    _port_open()'s socket.create_connection((host, port)) and the httpx
    client below it both independently re-resolved `host` at connect time --
    an attacker's DNS server can answer the validation lookup safely and
    every connection lookup with a private/internal address. Confirmed for
    real (12/12 dangerous-port probes reached a private double, 0 reached the
    validated target) and fixed the same way as scan_mcp_server: resolve
    `host` once via resolve_pinned_ip() and connect every probe to that
    single pinned IP, never `host` again."""

    @pytest.mark.asyncio
    async def test_original_hostname_resolved_exactly_once(self, monkeypatch):
        """Mirrors TestResolvePinnedIp.test_resolves_host_exactly_once in
        test_input_validator.py, but through the real scan_endpoints() entry
        point -- this is the call site that used to re-resolve the hostname a
        second time, not resolve_pinned_ip() itself (which was already
        correct in isolation)."""
        from mcp_safeguard.scanner.endpoint_scanner import scan_endpoints

        fake_host = "rebind-scan-endpoints.attacker.test"
        calls_for_host = []
        orig_getaddrinfo = socket.getaddrinfo

        def fake_getaddrinfo(host, *args, **kwargs):
            host_str = host.decode() if isinstance(host, bytes) else host
            if host_str == fake_host:
                calls_for_host.append(host_str)
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]
            return orig_getaddrinfo(host, *args, **kwargs)

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

        await scan_endpoints(
            host=fake_host, port=59999, timeout=0.3, ssrf_allowlist=[fake_host]
        )

        assert calls_for_host == [fake_host]

    @pytest.mark.asyncio
    async def test_port_probe_never_reaches_a_rebound_target(self, monkeypatch):
        """End-to-end reproduction: an attacker's DNS answers the
        validation-time lookup with a safe address and every later lookup
        with a private double's address instead. Before the fix,
        _port_open()'s socket.create_connection() re-resolved the hostname
        and reached the private double directly. After the fix, every
        connection uses the single pinned IP from the first lookup, so the
        private double never receives anything."""
        from mcp_safeguard.scanner.endpoint_scanner import scan_endpoints

        fake_host = "rebind-scan-endpoints-2.attacker.test"
        orig_getaddrinfo = socket.getaddrinfo
        call_count = {"n": 0}

        # Private double a DNS-rebinding attacker controls -- the fix must
        # never let a real connection reach it.
        private_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        private_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        private_srv.bind(("127.0.0.1", 0))
        private_srv.listen(5)
        private_port = private_srv.getsockname()[1]
        accepted: list[tuple[str, int]] = []

        def accept_loop():
            while True:
                try:
                    conn, addr = private_srv.accept()
                except OSError:
                    return
                accepted.append(addr)
                try:
                    conn.close()
                except OSError:
                    pass

        t = threading.Thread(target=accept_loop, daemon=True)
        t.start()

        def fake_getaddrinfo(host, *args, **kwargs):
            host_str = host.decode() if isinstance(host, bytes) else host
            if host_str == fake_host:
                call_count["n"] += 1
                if call_count["n"] == 1:
                    # Validation-time lookup: a safe (loopback) address.
                    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]
                # Connection-time lookup(s): rebound to the private double.
                return [
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", private_port))
                ]
            return orig_getaddrinfo(host, *args, **kwargs)

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
        try:
            await scan_endpoints(
                host=fake_host, port=59999, timeout=0.3, ssrf_allowlist=[fake_host]
            )
        finally:
            private_srv.close()

        assert accepted == []
