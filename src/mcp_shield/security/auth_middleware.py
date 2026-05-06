"""OAuth2/API key authentication middleware."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass


@dataclass
class AuthContext:
    """Represents an authenticated request context."""

    client_id: str
    authenticated: bool
    auth_method: str  # "api_key", "bearer", "none"
    scopes: list[str]


def verify_api_key(provided_key: str, expected_key: str) -> bool:
    """
    Constant-time API key comparison to prevent timing attacks.

    Args:
        provided_key: The key provided in the request.
        expected_key: The expected key from configuration.

    Returns:
        True if keys match.
    """
    if not provided_key or not expected_key:
        return False
    return hmac.compare_digest(
        hashlib.sha256(provided_key.encode()).digest(),
        hashlib.sha256(expected_key.encode()).digest(),
    )


def extract_bearer_token(authorization_header: str) -> str | None:
    """
    Extract bearer token from Authorization header value.

    Args:
        authorization_header: The raw Authorization header value.

    Returns:
        The token string, or None if not a Bearer header.
    """
    if not authorization_header:
        return None
    parts = authorization_header.strip().split(" ", 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return None


def generate_api_key(prefix: str = "msh") -> str:
    """
    Generate a cryptographically secure API key.

    Args:
        prefix: Short prefix for key type identification.

    Returns:
        A formatted API key string.
    """
    token = secrets.token_urlsafe(32)
    return f"{prefix}_{token}"


def authenticate_request(
    api_key_header: str | None,
    authorization_header: str | None,
    expected_api_key: str | None,
) -> AuthContext:
    """
    Authenticate an incoming request using API key or Bearer token.

    Args:
        api_key_header: Value of the X-API-Key header.
        authorization_header: Value of the Authorization header.
        expected_api_key: The configured API key to check against.

    Returns:
        AuthContext indicating whether the request is authenticated.
    """
    # No auth configured — open access (warn in production)
    if not expected_api_key:
        return AuthContext(
            client_id="anonymous",
            authenticated=True,
            auth_method="none",
            scopes=["*"],
        )

    # Check X-API-Key header
    if api_key_header and verify_api_key(api_key_header, expected_api_key):
        client_id = hashlib.sha256(api_key_header.encode()).hexdigest()[:16]
        return AuthContext(
            client_id=client_id,
            authenticated=True,
            auth_method="api_key",
            scopes=["scan:read", "scan:write", "report:read"],
        )

    # Check Authorization: Bearer header
    if authorization_header:
        token = extract_bearer_token(authorization_header)
        if token and verify_api_key(token, expected_api_key):
            client_id = hashlib.sha256(token.encode()).hexdigest()[:16]
            return AuthContext(
                client_id=client_id,
                authenticated=True,
                auth_method="bearer",
                scopes=["scan:read", "scan:write", "report:read"],
            )

    return AuthContext(
        client_id="unauthenticated",
        authenticated=False,
        auth_method="none",
        scopes=[],
    )
