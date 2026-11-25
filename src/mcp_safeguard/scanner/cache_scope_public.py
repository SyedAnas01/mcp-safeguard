"""SRC-045 (EXPERIMENTAL): cacheScope "public" with a freshness window on per-user data.

Anchor: MCP 2026-07-28 caching utility: `public` results may be served to any
user by shared caches; servers MUST NOT rely on cacheScope alone. Flags a file
that sets scope public (or Go SetCacheable with a non-zero TTL and no private
scope) with ttlMs>0 while also reading auth/user context. Expected hit rate
~0 today; class UNPROVEN (WS10 memo). Hardening lead, not a vuln claim.
"""

from __future__ import annotations

import re
from pathlib import Path

from .prompt_injection import Severity
from .source_scanner import SourceFinding, _iter_source, _line_of

RULE_IDS: list[tuple[str, str]] = [
    ("SRC-045", "[experimental] cacheScope public with ttl>0 in a file that reads per-user/auth context"),
]
EXPERIMENTAL: frozenset[str] = frozenset({"SRC-045"})

_PUBLIC = re.compile(r"""cache_?scope["']?\s*[:=]\s*["']public["']""", re.IGNORECASE)
_GO_CACHEABLE = re.compile(r"""SetCacheable\s*\(|Cacheable\s*\{""")
_TTL_POS = re.compile(r"""ttl_?ms["']?\s*[:=]\s*[1-9]\d*|TTLMs\s*:\s*[1-9]\d*""", re.IGNORECASE)
_PRIVATE = re.compile(r"""cache_?scope["']?\s*[:=]\s*["']private["']""", re.IGNORECASE)
_USER_CTX = re.compile(
    r"""\buser_?id\b|\bcurrent_?user\b|\bprincipal\b|auth_?info|\bauthContext\b|"""
    r"""headers?(?:\.get\(|\[|\.)\s*["']?authorization|\bctx\.(?:auth|user)|\btenant_?id\b""",
    re.IGNORECASE,
)


def scan_text(rel: str, text: str) -> list[SourceFinding]:
    ttl = _TTL_POS.search(text)
    if not ttl or not _USER_CTX.search(text):
        return []
    pub = _PUBLIC.search(text)
    go_default = _GO_CACHEABLE.search(text) and not _PRIVATE.search(text)
    hit = pub or go_default
    if not hit:
        return []
    return [SourceFinding(
        "SRC-045", Severity.LOW,
        "[experimental] Public cache scope with TTL in a file that reads per-user context",
        "A positive ttlMs is set with a public (or defaulted-public Go) cacheScope, and the "
        "file reads auth/user context. If any cached result depends on the caller, a shared "
        "cache may serve it to other users. Hardening lead only.",
        f"{rel}:{_line_of(text, hit.start())}",
        text[max(0, hit.start() - 20):hit.start() + 100].strip(),
        "Use cacheScope \"private\" (and ttl 0) for any per-user or token-filtered result; "
        "keep per-primitive access control regardless of cache hints.",
        3.0,
        confidence="low",
    )]


def scan_tree(root: str | Path) -> list[SourceFinding]:
    root = Path(root)
    out: list[SourceFinding] = []
    for path, text, _raw in _iter_source(root):
        rel = str(path.relative_to(root)) if path.is_relative_to(root) else str(path)
        out.extend(scan_text(rel, text))
    return out
