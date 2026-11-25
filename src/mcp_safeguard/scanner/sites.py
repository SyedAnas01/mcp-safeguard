"""v28: deterministic sink-site enumeration for the LLM hunter (no model call).

Hunters stop after one or two instances of a class. This lists every candidate
site of a few sink shapes so the hunter must dispose of each (cite it or name
its guard). Output is a list of (kind, file, line, snippet).
"""
from __future__ import annotations

import re
from pathlib import Path

_PARAM = r"(?:id|name|key|category|run|session|preset|path|file|filename|dir|folder|slug|bundle|skill)\w*"
_SRC_EXT = {".py", ".js", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".rs", ".java", ".kt", ".rb", ".ex", ".exs", ".c", ".h"}
_SKIP = {"node_modules", ".git", "dist", "build", "vendor", "__pycache__", "target", "venv", ".venv"}

KINDS = {
    "path_join": re.compile(
        r"(?:path\.(?:join|resolve)\(|os\.path\.join\(|Path\([^)]*\)\s*/\s*|filepath\.Join\(|base\w*\s*/\s*)[^\n;]*\b" + _PARAM + r"\b",
        re.IGNORECASE,
    ),
    "doc_derived_fetch": re.compile(
        r"(?:fetch|axios\.\w+|httpx\.\w+|requests\.\w+|http\.Get|urlopen)\([^)\n]*\b\w*(?:endpoint|_uri|jwks|resource|discovery|metadata|issuer)\w*",
        re.IGNORECASE,
    ),
    "argv_builder": re.compile(
        r"(?:\bargs\.(?:push|extend|append)\(|\bcmd\.(?:extend|append)\(|\bargv\.(?:push|append)\(|\bcmd\s*\+=)[^\n]*\b" + _PARAM + r"\b",
        re.IGNORECASE,
    ),
    "dispatcher": re.compile(r"[\"'](?:tools/call|resources/read|prompts/get)[\"']|\bhandle_message\b"),
    "archive_extract": re.compile(r"\b(?:extractall|extract_all|tar\.extract|unzip|zipfile\.ZipFile|tarfile\.open|untar)\b"),
}


def enumerate_sites(root: str | Path, per_kind_cap: int = 25) -> list[tuple[str, str, int, str]]:
    root = Path(root)
    out: list[tuple[str, str, int, str]] = []
    counts = dict.fromkeys(KINDS, 0)
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.suffix not in _SRC_EXT or any(part in _SKIP for part in p.parts):
            continue
        rel = p.relative_to(root).as_posix()
        if re.search(r"(?:^|/)(?:tests?|__tests__|spec|fixtures?)/|\.test\.|\.spec\.|_test\.", rel):
            continue
        try:
            lines = p.read_text(errors="replace").splitlines()
        except OSError:
            continue
        for i, ln in enumerate(lines, 1):
            if len(ln) > 400:
                continue
            for k, rx in KINDS.items():
                if counts[k] < per_kind_cap and rx.search(ln):
                    counts[k] += 1
                    out.append((k, rel, i, ln.strip()[:140]))
    return out


def render(sites: list[tuple[str, str, int, str]]) -> str:
    return "\n".join(f"{k}\t{f}:{n}\t{s}" for k, f, n, s in sites)
