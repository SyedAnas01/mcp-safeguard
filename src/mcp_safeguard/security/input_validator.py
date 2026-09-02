"""Input sanitization and SSRF prevention for MCP scan inputs."""

from __future__ import annotations

import ipaddress
import json
import re
from urllib.parse import urlparse


class ValidationError(ValueError):
    """Raised when an input fails validation."""


_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local / metadata
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

_CLOUD_METADATA_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.azure.com",
    "fd00:ec2::254",
}


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

    # Check if it resolves to a private IP (basic check without DNS resolution)
    try:
        ip = ipaddress.ip_address(host)
        for network in _PRIVATE_NETWORKS:
            if ip in network:
                raise ValidationError(
                    f"SSRF blocked: '{host}' resolves to a private/reserved IP range."
                )
        if ip.is_loopback:
            # Localhost is allowed for scan targets (local MCP server testing)
            pass
    except ValueError:
        # Not an IP address — hostname-based, allow (DNS resolution happens at scan time)
        pass

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

    # Validate as IP or hostname
    try:
        ip = ipaddress.ip_address(host)
        for network in _PRIVATE_NETWORKS:
            if ip in network:
                raise ValidationError(f"SSRF blocked: '{host}' is in a private IP range.")
    except ValueError:
        # Hostname — validate format
        if not re.match(
            r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$", host
        ):
            raise ValidationError(f"Invalid hostname format: '{host}'") from None

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
