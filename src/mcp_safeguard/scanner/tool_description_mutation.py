"""SRC-043 (EXPERIMENTAL): tool description/schema rewritten on refresh with
no re-approval or change-pinning (rug-pull primitive).

A server (typically a gateway/registry) that re-fetches upstream tool
definitions and overwrites the stored description / input schema silently lets
an upstream flip a benign, approved tool into a poisoned one. Safe designs
hash/pin definitions and require re-approval on change.

Heuristic (regex): a description/schema overwrite inside a refresh/sync/update
style function, in a file with no hash/pin/approval markers.
Experimental: class validity is being assessed separately (WS10).
"""

from __future__ import annotations

import re
from pathlib import Path

from .prompt_injection import Severity
from .source_scanner import SourceFinding, _iter_source, _line_of

RULE_IDS: list[tuple[str, str]] = [
    ("SRC-043", "[experimental] Tool description/schema overwritten on refresh with no pinning or re-approval"),
]
EXPERIMENTAL: frozenset[str] = frozenset({"SRC-043"})

_REFRESH_FN = re.compile(
    r"""(?:def|function|func)\s+(\w*(?:refresh|sync|update_or_create|upsert|reload|update_tools?|fetch_tools?|discover)\w*)\s*\(""",
    re.IGNORECASE,
)
_MUTATION = re.compile(
    r"""\.(?:description|input_?schema|inputSchema)\s*=(?!=)"""
    r"""|\[\s*["'](?:description|input_?schema|inputSchema)["']\s*\]\s*=(?!=)"""
    r"""|UPDATE\s+\w*tools?\w*\s+SET[^;\n]{0,120}description""",
    re.IGNORECASE,
)
_PIN = re.compile(
    r"""hash|digest|sha\d*|checksum|fingerprint|\bpin(?:ned|s)?\b|re-?approv|needs_?approval|"""
    r"""approval|quarantine|pending_?review|changed_?requires|diff_?alert""",
    re.IGNORECASE,
)


def scan_text(rel: str, text: str) -> list[SourceFinding]:
    if _PIN.search(text):
        return []
    for fn in _REFRESH_FN.finditer(text):
        window = text[fn.end():fn.end() + 3000]
        m = _MUTATION.search(window)
        if m:
            at = fn.end() + m.start()
            return [SourceFinding(
                "SRC-043", Severity.MEDIUM,
                "[experimental] Tool definition overwritten on refresh without pinning (rug-pull primitive)",
                f"`{fn.group(1)}` overwrites a stored tool description/schema from refreshed "
                "upstream data and the file has no hashing, pinning or re-approval step. An "
                "upstream server can mutate an approved tool into a poisoned one after approval.",
                f"{rel}:{_line_of(text, at)}",
                text[at:at + 100].strip(),
                "Store a hash of each approved definition; on mismatch, quarantine the tool "
                "and require explicit re-approval (and surface a diff) before exposing it.",
                5.0,
                confidence="low",
            )]
    return []


def scan_tree(root: str | Path) -> list[SourceFinding]:
    root = Path(root)
    out: list[SourceFinding] = []
    for path, text, _raw in _iter_source(root):
        rel = str(path.relative_to(root)) if path.is_relative_to(root) else str(path)
        out.extend(scan_text(rel, text))
    return out
