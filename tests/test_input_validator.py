"""Regression tests for SSRF fixes found by Fable's adversarial review of
mcp-safeguard's own code (2026-09-02, v0.7.x hardening pass).

C1: IPv4-mapped IPv6 (::ffff:a.b.c.d) and 6to4 (2002::/16) addresses bypass
    the private/reserved/metadata IP check because they don't match any
    IPv6-specific private range on their own, even though a dual-stack
    socket resolves and connects them to the real underlying IPv4 address.

Control-flow bug in validate_host(): ValidationError subclasses ValueError,
    so raising it inside a `try` block that's followed by `except ValueError`
    gets silently swallowed -- the SSRF block never actually fired for any
    literal IP input to validate_host().
"""

import socket

import pytest

from mcp_safeguard.security.input_validator import (
    ValidationError,
    resolve_pinned_ip,
    resolves_to_unsafe_ip,
    validate_config_json,
    validate_host,
    validate_tool_json,
    validate_url,
)


class TestIPv4MappedIPv6Bypass:
    """Fable finding C1 (CRITICAL)."""

    def test_mapped_metadata_ip_blocked_by_validate_url(self):
        with pytest.raises(ValidationError, match="SSRF blocked"):
            validate_url("http://[::ffff:169.254.169.254]/latest/meta-data/")

    def test_mapped_private_ip_blocked_by_validate_url(self):
        with pytest.raises(ValidationError, match="SSRF blocked"):
            validate_url("http://[::ffff:10.0.0.5]/")

    def test_6to4_encoded_metadata_ip_blocked_by_validate_url(self):
        # 2002:a9fe:a9fe:: is the 6to4 encoding of 169.254.169.254
        with pytest.raises(ValidationError, match="SSRF blocked"):
            validate_url("http://[2002:a9fe:a9fe::]/")

    def test_mapped_loopback_still_allowed(self):
        # Loopback is an intentional, documented allowance for local
        # MCP server testing -- must not regress into a block.
        validate_url("http://[::ffff:127.0.0.1]/")  # no raise

    def test_mapped_metadata_ip_blocked_by_validate_host(self):
        with pytest.raises(ValidationError, match="SSRF blocked"):
            validate_host("::ffff:169.254.169.254")

    def test_public_ip_still_allowed(self):
        validate_url("http://8.8.8.8/")  # no raise
        assert validate_host("8.8.8.8") == "8.8.8.8"


class TestValidateHostControlFlowBug:
    """validate_host() previously never blocked literal private IPs because
    the raise was caught by the very except clause meant to handle
    hostnames (ValidationError is a ValueError subclass)."""

    def test_rfc1918_ip_blocked(self):
        with pytest.raises(ValidationError, match="private IP range"):
            validate_host("192.168.1.1")

    def test_metadata_ip_blocked(self):
        with pytest.raises(ValidationError, match="SSRF blocked"):
            validate_host("169.254.169.254")

    def test_link_local_ip_blocked(self):
        with pytest.raises(ValidationError, match="private IP range"):
            validate_host("169.254.1.1")

    def test_hostname_still_allowed(self):
        assert validate_host("example.com") == "example.com"

    def test_invalid_hostname_still_rejected(self):
        with pytest.raises(ValidationError, match="Invalid hostname"):
            validate_host("not a valid host!!")


class TestResolvesToUnsafeIpUsesSharedHelper:
    """resolves_to_unsafe_ip() (the DNS-rebinding guard) shares _is_unsafe_ip
    with validate_url/validate_host -- sanity-check it still behaves after
    the refactor away from the standalone _PRIVATE_NETWORKS list."""

    def test_localhost_resolves_safe(self):
        assert resolves_to_unsafe_ip("localhost") is False

    def test_unresolvable_host_is_not_flagged(self):
        assert resolves_to_unsafe_ip("this-host-does-not-exist.invalid") is False


class TestDeeplyNestedJsonDoesNotCrash:
    """Fable adversarial review, 2026-09-02 (M5): deeply nested JSON (e.g.
    thousands of levels of "[[[...]]]") fits comfortably under the
    char-length cap while still exhausting Python's call stack in the JSON
    decoder, raising an uncaught RecursionError instead of a clean
    ValidationError."""

    def test_validate_config_json_rejects_deep_nesting_cleanly(self):
        nested = '{"a":' * 10_000 + "1" + "}" * 10_000
        assert len(nested) < 100_000  # within the default max_length
        with pytest.raises(ValidationError, match="nesting depth"):
            validate_config_json(nested)

    def test_validate_tool_json_rejects_deep_nesting_cleanly(self):
        nested = "[" * 10_000 + "]" * 10_000
        with pytest.raises(ValidationError, match="nesting depth"):
            validate_tool_json(nested, max_length=len(nested) + 10)


class TestResolvePinnedIp:
    """Taig Mac Carthy, 2026-09-06 (DNS-rebinding SSRF in scan_mcp_server):
    resolves_to_unsafe_ip() validates a hostname by resolving it, but a
    caller that then connects using the hostname STRING triggers a second,
    independent DNS resolution -- an attacker's DNS server can answer that
    second query differently from the first. resolve_pinned_ip() closes this
    by resolving exactly once and handing back the single IP the caller must
    actually connect to."""

    def test_resolves_localhost_to_a_pinned_ip(self):
        pinned = resolve_pinned_ip("localhost")
        assert pinned in ("127.0.0.1", "::1")

    def test_public_ip_literal_pins_to_itself(self):
        assert resolve_pinned_ip("8.8.8.8") == "8.8.8.8"

    def test_rejects_host_resolving_to_private_ip(self, monkeypatch):
        def fake_getaddrinfo(host, port, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 0))]

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
        with pytest.raises(ValidationError, match="SSRF blocked"):
            resolve_pinned_ip("private.example")

    def test_rejects_if_any_of_multiple_resolved_addresses_is_unsafe(self, monkeypatch):
        """Same conservative rule as resolves_to_unsafe_ip(): one unsafe
        address among several rejects the whole hostname, not just that
        record -- an attacker's DNS response can list a public address
        alongside a private one and a client isn't guaranteed to pick the
        first."""

        def fake_getaddrinfo(host, port, *args, **kwargs):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.1", 0)),
            ]

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
        with pytest.raises(ValidationError, match="SSRF blocked"):
            resolve_pinned_ip("mixed.example")

    def test_raises_on_resolution_failure(self, monkeypatch):
        def fake_getaddrinfo(host, port, *args, **kwargs):
            raise OSError("Name or service not known")

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
        with pytest.raises(ValidationError, match="Could not resolve"):
            resolve_pinned_ip("this-host-does-not-exist.invalid")

    def test_resolves_host_exactly_once(self, monkeypatch):
        """The whole point of resolve_pinned_ip(): a single resolution, not
        one for validation and a second, independent one at connect time."""
        calls = []

        def fake_getaddrinfo(host, port, *args, **kwargs):
            calls.append(host)
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
        pinned = resolve_pinned_ip("rebind.attacker.test")

        assert pinned == "93.184.216.34"
        assert calls == ["rebind.attacker.test"]
