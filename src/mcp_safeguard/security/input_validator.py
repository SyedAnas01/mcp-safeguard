"""Input sanitization and SSRF prevention for MCP scan inputs."""

from __future__ import annotations

import ipaddress
import json
import re
import socket
from urllib.parse import urlparse


class ValidationError(ValueError):
    """Raised when an input fails validation."""


_CLOUD_METADATA_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.azure.com",
    "fd00:ec2::254",
}

_CLOUD_METADATA_IPS = {"169.254.169.254", "fd00:ec2::254"}


def _is_unsafe_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """
    True if `ip` is not safe to let this tool connect to as a scan target.

    Unwraps IPv4-mapped (::ffff:a.b.c.d) and 6to4 (2002::/16) IPv6 forms to
    their real underlying IPv4 address FIRST, then checks that address --
    an un-unwrapped ::ffff:169.254.169.254 is an ordinary IPv6Address that
    matches none of the IPv6 private/reserved ranges on its own (it isn't
    private, link-local, or in the literal metadata-IP set as a v6 string),
    but a dual-stack socket resolves and connects it to the real IPv4
    169.254.169.254 -- a real, verified SSRF bypass of every earlier version
    of this check, caught by this project's own adversarial review of its
    own code the same night these rules were built to catch this exact bug
    class in OTHER servers.

    Uses ipaddress's own is_private/is_link_local/is_reserved properties
    (covering the full RFC1918/RFC4193/RFC3927 ranges and more) instead of a
    hand-maintained network list, EXCEPT loopback, which is intentionally
    excluded here -- it's an explicit, documented allowance for scanning a
    local MCP server during development (validate_url/validate_host both
    permit it), not a gap.
    """
    if isinstance(ip, ipaddress.IPv6Address):
        mapped = ip.ipv4_mapped
        if mapped is not None:
            ip = mapped
        else:
            sixtofour = ip.sixtofour
            if sixtofour is not None:
                ip = sixtofour

    if str(ip) in _CLOUD_METADATA_IPS:
        return True
    if ip.is_loopback:
        return False
    return bool(
        ip.is_private or ip.is_link_local or ip.is_reserved
        or ip.is_multicast or ip.is_unspecified
    )


def resolves_to_unsafe_ip(host: str) -> bool:
    """
    DNS-rebinding guard: resolve `host` and reject if ANY resolved address is a
    private/reserved IP range (RFC1918/ULA/link-local) or a known cloud metadata
    IP. This is the canonical shared implementation -- both endpoint_scanner.py
    and server.py's scan-target intake use it, so a hostname-only allowlist
    check (which validate_url/validate_host alone cannot do, since they run
    before any network resolution) can't be bypassed by pointing an
    innocuous-looking hostname at an internal or metadata address via DNS.

    Args:
        host: Hostname or IP string to resolve and check.

    Returns:
        True if any resolved address is private/reserved/metadata, False
        otherwise (including on a resolution failure -- the caller's own
        connection attempt will fail too in that case).
    """
    try:
        addrinfo = socket.getaddrinfo(host, None)
    except OSError:
        return False

    for _family, _type, _proto, _canonname, sockaddr in addrinfo:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str.split("%")[0])  # strip IPv6 zone id
        except ValueError:
            continue
        if _is_unsafe_ip(ip):
            return True

    return False


def validate_url(url: str, allowed_schemes: list[str] | None = None) -> str:
    """
    Validate and sanitize a URL for use as a scan target.

    Raises ValidationError for SSRF-risky URLs.

    Args:
        url: URL string to validate.
        allowed_schemes: Allowed URL schemes (default: http, https).

    Returns:
        The validated URL.
    """
    if not url or not isinstance(url, str):
        raise ValidationError("URL must be a non-empty string.")

    if len(url) > 2048:
        raise ValidationError("URL exceeds maximum length of 2048 characters.")

    allowed_schemes = allowed_schemes or ["http", "https"]
    parsed = urlparse(url)

    if parsed.scheme not in allowed_schemes:
        raise ValidationError(
            f"URL scheme '{parsed.scheme}' is not allowed. Use one of: {allowed_schemes}."
        )

    host = parsed.hostname or ""
    if not host:
        raise ValidationError("URL must contain a valid hostname.")

    if host in _CLOUD_METADATA_HOSTS:
        raise ValidationError(f"SSRF blocked: '{host}' is a cloud metadata endpoint.")

    # Check if it's a literal IP that's unsafe to connect to (this only
    # catches a literal IP in the URL itself; a hostname that RESOLVES to an
    # unsafe address is caught separately by resolves_to_unsafe_ip() at scan
    # time, since DNS resolution can't happen here without making a network
    # call from inside a pure validator).
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # Not an IP address — hostname-based, allow (DNS resolution happens at scan time)
        pass
    else:
        if _is_unsafe_ip(ip):
            raise ValidationError(
                f"SSRF blocked: '{host}' resolves to a private/reserved/metadata address."
            )
        # Loopback (127.0.0.1/::1) intentionally passes _is_unsafe_ip() as
        # False -- allowed for scan targets (local MCP server testing).

    return url


def validate_host(host: str) -> str:
    """
    Validate a host string for use as a scan target.

    Args:
        host: Hostname or IP address.

    Returns:
        Validated host string.
    """
    if not host or not isinstance(host, str):
        raise ValidationError("Host must be a non-empty string.")

    host = host.strip().lower()

    if len(host) > 253:
        raise ValidationError("Host exceeds maximum length.")

    if host in _CLOUD_METADATA_HOSTS:
        raise ValidationError(f"SSRF blocked: '{host}' is a cloud metadata endpoint.")

    # Allow localhost and loopback
    if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        return host

    # Validate as IP or hostname. NOTE: the SSRF check below must NOT be
    # inside this try block -- ValidationError subclasses ValueError, so a
    # `raise ValidationError` here would be caught by `except ValueError`
    # and silently swallowed, falling through to the hostname-format regex
    # (which a dotted-decimal IP string like "192.168.1.1" passes fine) and
    # returning the host as if it were safe. Using try/except/else keeps the
    # SSRF raise outside the except's reach.
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # Hostname — validate format
        if not re.match(
            r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$", host
        ):
            raise ValidationError(f"Invalid hostname format: '{host}'") from None
    else:
        if _is_unsafe_ip(ip):
            raise ValidationError(f"SSRF blocked: '{host}' is in a private IP range.")

    return host


def validate_port(port: int | str) -> int:
    """
    Validate a port number.

    Args:
        port: Port number (int or str).

    Returns:
        Validated port as int.
    """
    try:
        port_int = int(port)
    except (TypeError, ValueError) as e:
        raise ValidationError(f"Port must be an integer, got: {port}") from e

    if not 1 <= port_int <= 65535:
        raise ValidationError(f"Port must be between 1 and 65535, got: {port_int}")

    return port_int


def validate_tool_json(tool_json: str, max_length: int = 50_000) -> list[dict]:
    """
    Validate and parse tool definition JSON.

    Args:
        tool_json: JSON string of tool definitions.
        max_length: Maximum allowed character length.

    Returns:
        Parsed list of tool definition dicts.
    """
    if not tool_json or not isinstance(tool_json, str):
        raise ValidationError("Tool JSON must be a non-empty string.")

    if len(tool_json) > max_length:
        raise ValidationError(f"Tool JSON exceeds maximum length of {max_length} characters.")

    try:
        parsed = json.loads(tool_json)
    except json.JSONDecodeError as e:
        raise ValidationError(f"Invalid JSON: {e}") from e
    except RecursionError:
        # Deeply nested JSON (e.g. thousands of levels of "[[[...]]]") is
        # well within the char-length cap above but exhausts Python's call
        # stack in the JSON decoder -- a real, uncaught crash found by this
        # project's own adversarial self-review (Fable, 2026-09-02), not a
        # hypothetical: ~10,000 levels of nesting fits in ~60KB, under the
        # default max_length here.
        raise ValidationError("Invalid JSON: exceeds maximum nesting depth.") from None

    if isinstance(parsed, dict):
        # Single tool definition
        parsed = [parsed]

    if not isinstance(parsed, list):
        raise ValidationError("Tool JSON must be a JSON array or a single tool object.")

    for i, item in enumerate(parsed):
        if not isinstance(item, dict):
            raise ValidationError(f"Tool at index {i} must be a JSON object.")
        if "name" not in item:
            raise ValidationError(f"Tool at index {i} is missing required 'name' field.")
        # Well-formed JSON with the right top-level shape but a wrong-typed
        # field (e.g. description as a number, inputSchema as a string) used
        # to pass this check and crash downstream in analyze_tool_risk()
        # with an uncaught AttributeError -- a real finding from this
        # project's own adversarial self-review (Fable, 2026-09-02).
        # Rejecting it here with a clear error is better than a stack trace.
        description = item.get("description")
        if description is not None and not isinstance(description, str):
            raise ValidationError(f"Tool at index {i}: 'description' must be a string.")
        input_schema = item.get("inputSchema")
        if input_schema is not None and not isinstance(input_schema, dict):
            raise ValidationError(f"Tool at index {i}: 'inputSchema' must be a JSON object.")

    return parsed


def validate_config_json(config_json: str, max_length: int = 100_000) -> dict:
    """
    Validate and parse server configuration JSON.

    Args:
        config_json: JSON string of server configuration.
        max_length: Maximum character length.

    Returns:
        Parsed configuration dict.
    """
    if not config_json or not isinstance(config_json, str):
        raise ValidationError("Config JSON must be a non-empty string.")

    if len(config_json) > max_length:
        raise ValidationError(f"Config JSON exceeds maximum length of {max_length}.")

    try:
        parsed = json.loads(config_json)
    except json.JSONDecodeError as e:
        raise ValidationError(f"Invalid JSON: {e}") from e
    except RecursionError:
        # See the matching comment in validate_tool_json -- deeply nested
        # JSON fits well under max_length while still exhausting the stack.
        raise ValidationError("Invalid JSON: exceeds maximum nesting depth.") from None

    if not isinstance(parsed, dict):
        raise ValidationError("Config JSON must be a JSON object.")

    return parsed


def sanitize_scan_id(scan_id: str) -> str:
    """
    Validate a scan ID to prevent path traversal.

    Args:
        scan_id: Scan ID string.

    Returns:
        Validated scan ID.
    """
    if not scan_id or not isinstance(scan_id, str):
        raise ValidationError("Scan ID must be a non-empty string.")
    if not re.match(r"^[a-f0-9\-]{36}$", scan_id):
        raise ValidationError("Invalid scan ID format. Must be a UUID.")
    return scan_id
