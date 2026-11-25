"""v28: deterministic choice of the single reported location for an LLM finding.

A maintainer's fix lands on the statement that *builds* the value the sink
consumes (``const p = path.join(root, name)``), not on the ``sink(p)`` call,
unless the sink takes the raw input inline. A finding therefore reports the
construction line when one can be shown by def-use, else the adversary's line,
else the sink. Pure functions, no I/O beyond the file text passed in.
"""
from __future__ import annotations

import re
from collections.abc import Callable

_ASSIGN = re.compile(
    r"^\s*(?:(?:export\s+)?(?:const|let|var|final|val)\s+|[A-Za-z_][\w<>\[\], ]*\s+)?"
    r"(?P<lhs>[A-Za-z_$][\w$.]*)\s*(?::\s*[\w<>\[\]|, .]+)?\s*:?=(?!=)"
)
_COMMENT = re.compile(r"^\s*(?://|#|/\*|\*|--|<!--)")


def _line(text_of: Callable[[str], str | None], file: str, n: int) -> str | None:
    t = text_of(file)
    if t is None:
        return None
    ls = t.splitlines()
    return ls[n - 1] if 1 <= n <= len(ls) else None


def is_assignment_of(line: str | None, sink_line: str | None) -> bool:
    """True when ``line`` assigns an identifier that is used in ``sink_line``."""
    if not line or not sink_line or _COMMENT.match(line):
        return False
    m = _ASSIGN.match(line)
    if not m:
        return False
    ident = m.group("lhs").split(".")[-1]
    if len(ident) < 2:
        return False
    return re.search(r"(?<![\w$])" + re.escape(ident) + r"(?![\w$])", sink_line) is not None


def refile_line_fixed(finding: dict, line_fixed: int | None, line_fixed_file: str | None = None) -> tuple[str, int] | None:
    """Attach an adversary ``line_fixed`` integer to the file of the citation it matches.

    Falls back to the sink citation's file, then the finding's own file.
    """
    if not line_fixed:
        return None
    if line_fixed_file:
        return line_fixed_file, line_fixed
    cits = finding.get("citations") or []
    for c in cits:
        if c.get("line") == line_fixed:
            return c["file"], line_fixed
    for c in cits:
        if c.get("role") == "sink":
            return c["file"], line_fixed
    return finding["file"], line_fixed


def select_primary(
    finding: dict,
    line_fixed: int | None,
    text_of: Callable[[str], str | None],
    line_fixed_file: str | None = None,
) -> tuple[str, int]:
    """Return the (file, line) to report as the finding's location."""
    cits = finding.get("citations") or []
    sink = next((c for c in cits if c.get("role") == "sink"), None)
    refiled = refile_line_fixed(finding, line_fixed, line_fixed_file)
    if sink:
        sink_text = _line(text_of, sink["file"], sink["line"])
        for c in cits:
            if c.get("role") != "guard" or c["file"] != sink["file"]:
                continue
            if is_assignment_of(_line(text_of, c["file"], c["line"]), sink_text):
                return c["file"], c["line"]
    if refiled:
        return refiled
    if sink:
        return sink["file"], sink["line"]
    return finding["file"], finding["line"]
