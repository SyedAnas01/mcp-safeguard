"""SRC-046: OAuth proxy with no per-client consent check (confused deputy).

Anchor: MCP 2026-07-28 security-best-practices, "Confused Deputy Problem".
An MCP server that fronts a third-party authorization server with a STATIC
upstream client_id, while accepting dynamic client registration (DCR), must
obtain per-client user consent before forwarding to the upstream authorize
endpoint. Otherwise a malicious dynamically-registered client rides the
consent the user already gave to the static client.

Heuristic (regex over one file, LEAD not proof): file defines an /authorize
handler that redirects to an upstream authorize URL with a static client id,
exposes a /register (DCR) endpoint, and contains no consent/approved-client
bookkeeping anywhere.
"""

from __future__ import annotations

import re
from pathlib import Path

from .prompt_injection import Severity
from .source_scanner import SourceFinding, _iter_source, _line_of

RULE_IDS: list[tuple[str, str]] = [
    ("SRC-046", "OAuth proxy forwards to upstream authorize with static client_id + DCR and no per-client consent check"),
]
EXPERIMENTAL: frozenset[str] = frozenset()

_AUTHORIZE_ROUTE = re.compile(
    r"""(?:route|get|post|add_api_route|add_route|use|path|Route)\s*\(\s*f?["'`]/?(?:oauth/)?authorize\b"""
    r"""|def\s+(?:oauth_)?authorize\s*\(|(?:async\s+)?function\s+authorize\w*\s*\(""",
    re.IGNORECASE,
)
_REGISTER_ROUTE = re.compile(
    r"""["'`]/?(?:oauth/)?register["'`]|def\s+(?:handle_)?register_client\s*\(|registerClient\s*\(""",
    re.IGNORECASE,
)
_UPSTREAM_REDIRECT = re.compile(
    r"""(?:redirect|RedirectResponse|Location)\b[^\n]{0,200}?authorize[^\n]{0,300}?client_id"""
    r"""|authorize\?[^\n"']{0,200}client_id=|client_id\s*[:=]\s*(?:os\.environ|os\.getenv|process\.env|UPSTREAM_|[A-Z][A-Z_]*CLIENT_ID)""",
    re.IGNORECASE,
)
_STATIC_CLIENT_ID = re.compile(
    r"""(?:os\.environ(?:\.get)?\s*[\[(]\s*["']|os\.getenv\s*\(\s*["']|process\.env\.?\[?["']?)[A-Z_]*CLIENT_ID""",
)
_CONSENT = re.compile(
    r"""consent|approved[_ ]?clients?|approvedClients|has_approved|user_approv|"""
    r"""client_approval|consent_cookie|__Host-[\w-]*approved""",
    re.IGNORECASE,
)


def scan_text(rel: str, text: str) -> list[SourceFinding]:
    """Scan one (comment-stripped) source file."""
    if not _AUTHORIZE_ROUTE.search(text) or not _REGISTER_ROUTE.search(text):
        return []
    redirect = _UPSTREAM_REDIRECT.search(text)
    if not redirect or not _STATIC_CLIENT_ID.search(text):
        return []
    if _CONSENT.search(text):
        return []
    return [SourceFinding(
        "SRC-046", Severity.HIGH,
        "OAuth proxy: no per-client consent before forwarding to upstream authorize",
        "The file proxies authorization to a third-party server using a static "
        "upstream client_id and also accepts dynamic client registration, but no "
        "per-client consent record (cookie/store of approved client_ids) is "
        "checked. A malicious registered client can obtain an authorization code "
        "using the consent the user already gave the static client (confused deputy).",
        f"{rel}:{_line_of(text, redirect.start())}",
        text[redirect.start():redirect.start() + 120].strip(),
        "Before redirecting upstream, require explicit per-client consent bound to "
        "the requesting client_id (signed, __Host- cookie or server store), show "
        "the client name/redirect_uri, validate redirect_uri exactly, and use "
        "single-use state.",
        7.5,
    )]


def scan_tree(root: str | Path) -> list[SourceFinding]:
    root = Path(root)
    out: list[SourceFinding] = []
    for path, text, _raw in _iter_source(root):
        rel = str(path.relative_to(root)) if path.is_relative_to(root) else str(path)
        out.extend(scan_text(rel, text))
    return out
