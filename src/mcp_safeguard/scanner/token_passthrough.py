"""SRC-041: inbound bearer token forwarded upstream with no audience check.

Anchor: MCP 2026-07-28 security-best-practices, "Token Passthrough": servers
MUST NOT accept tokens not explicitly issued for them. Detects a variable
read from the inbound Authorization header and then placed in an outbound
request's Authorization header, in a file that never validates `aud`/audience
or introspects the token.

Heuristic (regex, LEAD not proof). Python and JS/TS.
"""

from __future__ import annotations

import re
from pathlib import Path

from .prompt_injection import Severity
from .source_scanner import SourceFinding, _iter_source, _line_of

RULE_IDS: list[tuple[str, str]] = [
    ("SRC-041", "Inbound bearer token reused on an outbound call with no audience validation"),
]
EXPERIMENTAL: frozenset[str] = frozenset()

# VAR = <something reading the Authorization header>
_INBOUND = re.compile(
    r"""^[ \t]*(?:const|let|var)?[ \t]*(\w+)[ \t]*(?::[^=\n]+)?=[ \t]*[^\n]*?"""
    r"""(?:headers?(?:\.get\(|\[|\.)|get_header\(|\.get\()\s*["']?authorization["']?""",
    re.IGNORECASE | re.MULTILINE,
)
_AUDIENCE = re.compile(
    r"""\baud\b|["']aud["']|audience|introspect|verify_aud|resource_indicator|validate_?token""",
    re.IGNORECASE,
)
_OUTBOUND = re.compile(
    r"""\b(?:requests|httpx|aiohttp|urllib3?)\b"""
    r"""|(?:session|client)\.\w*(?:get|post|put|patch|delete|request)\s*\("""
    r"""|\bfetch\s*\(|\baxios\b|\bgot\b|http\.NewRequest""",
    re.IGNORECASE,
)


def scan_text(rel: str, text: str) -> list[SourceFinding]:
    if _AUDIENCE.search(text) or not _OUTBOUND.search(text):
        return []
    for m in _INBOUND.finditer(text):
        var = m.group(1)
        use = re.search(
            r"""authorization["']?\s*[:=,]\s*[^\n]{0,60}?\b""" + re.escape(var) + r"""\b""",
            text[m.end():], re.IGNORECASE,
        )
        if not use:
            continue
        at = m.end() + use.start()
        return [SourceFinding(
            "SRC-041", Severity.HIGH,
            "Inbound bearer token passed through to an upstream call, no audience check",
            f"`{var}` is read from the inbound Authorization header and re-sent as the "
            "Authorization of an outbound request. No `aud`/audience validation or "
            "introspection exists in the file, so the server accepts tokens not issued "
            "to it and acts as a confused deputy for the downstream API (token passthrough).",
            f"{rel}:{_line_of(text, at)}",
            text[max(0, at - 20):at + 100].strip(),
            "Validate the token's audience/resource against this server before use, and "
            "obtain a separate downstream token (OAuth token exchange / on-behalf-of) "
            "instead of forwarding the client's token.",
            7.5,
        )]
    return []


def scan_tree(root: str | Path) -> list[SourceFinding]:
    root = Path(root)
    out: list[SourceFinding] = []
    for path, text, _raw in _iter_source(root):
        rel = str(path.relative_to(root)) if path.is_relative_to(root) else str(path)
        out.extend(scan_text(rel, text))
    return out
