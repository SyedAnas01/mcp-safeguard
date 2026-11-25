"""SRC-044 (EXPERIMENTAL, hardening): MRTR requestState consumed without integrity protection.

Anchor: MCP 2026-07-28 MRTR pattern, server req. 4: servers MUST treat
`requestState` as attacker-controlled and, if it influences authorization,
resource access or business logic, MUST protect its integrity (HMAC/AEAD) and
reject state failing verification. Protection is opt-in in the TS and Go SDKs.

This is a HARDENING lead (client-held-state tampering, a known family with a
spec MUST), not a new vulnerability class and not a vuln claim (WS10 memo).
Flags a file that reads requestState (TS/JS/Go) with no verify/HMAC/AEAD/seal
marker anywhere in it. Python's SDK seals by default, so .py is not scanned.
"""

from __future__ import annotations

import re
from pathlib import Path

from .prompt_injection import Severity
from .source_scanner import SourceFinding, _iter_source, _line_of

RULE_IDS: list[tuple[str, str]] = [
    ("SRC-044", "[experimental] requestState read with no integrity verification (HMAC/AEAD/verify)"),
]
EXPERIMENTAL: frozenset[str] = frozenset({"SRC-044"})

_READ = re.compile(
    r"""\brequestState\s*(?:<[^>\n]*>)?\s*\(\s*\)"""      # ctx.mcpReq.requestState<string>()
    r"""|\.RequestState\b(?!\s*=[^=])"""                   # Go: req.Params.RequestState
    r"""|\bRequestState\s*==""",
)
_INTEGRITY = re.compile(
    r"""requestState\s*:\s*\{[^}]*verify|\bverify\w*\s*\(|hmac|aead|aes-?gcm|createHmac|"""
    r"""\bseal\w*|\bunseal\w*|\.Open\(|signRequestState|sign_state|crypto/hmac|ed25519""",
    re.IGNORECASE,
)


def scan_text(rel: str, text: str, suffix: str = ".ts") -> list[SourceFinding]:
    if suffix == ".py":
        return []
    m = _READ.search(text)
    if not m or _INTEGRITY.search(text):
        return []
    return [SourceFinding(
        "SRC-044", Severity.LOW,
        "[experimental] requestState consumed without integrity protection (hardening)",
        "The file reads the client-echoed MRTR `requestState` but has no HMAC/AEAD/verify "
        "step. The spec requires servers to treat it as attacker-controlled and protect "
        "its integrity when it influences authorization, lookups or amounts. Hardening "
        "lead only: impact depends on what the state feeds.",
        f"{rel}:{_line_of(text, m.start())}",
        text[max(0, m.start() - 30):m.start() + 90].strip(),
        "Configure the SDK's requestState verify/codec (HMAC or AEAD bound to principal, "
        "method+params digest and a short TTL) and reject state that fails verification; "
        "re-check authorization from the retry's own params, not from state.",
        3.0,
        confidence="low",
    )]


def scan_tree(root: str | Path) -> list[SourceFinding]:
    root = Path(root)
    out: list[SourceFinding] = []
    for path, text, _raw in _iter_source(root):
        rel = str(path.relative_to(root)) if path.is_relative_to(root) else str(path)
        out.extend(scan_text(rel, text, path.suffix))
    return out
