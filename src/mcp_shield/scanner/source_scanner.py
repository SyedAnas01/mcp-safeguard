"""Source-audit mode: scan an MCP server's SOURCE TREE for code-level security
footguns that a config/tool-definition scanner cannot see.

Unlike the other scanners (which read a config JSON of tool definitions), this one
walks a repository and flags patterns in the server's implementation. It is
heuristic (regex over source, not a full type-aware analysis), so findings are
LEADS to confirm by reading the cited file, not proofs. Every rule below was
derived from a real pattern found in an official big-company MCP server.

Rules:
  SRC-001  Auth header re-applied per-request in a Go transport with no CheckRedirect
           -> credential can survive a cross-host redirect (GitHub, Grafana).
  SRC-002  httpx client with follow_redirects=True AND a bearer/Authorization header
           -> Python equivalent of SRC-001 (AWS openapi-mcp).
  SRC-003  SQL "read-only" enforced by string/regex only, with no DB-level read-only
           transaction in the same connection path (AWS keyspaces).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .prompt_injection import Severity


@dataclass
class SourceFinding:
    rule_id: str
    severity: Severity
    title: str
    description: str
    location: str  # file:line
    evidence: str
    remediation: str
    cvss_score: float = 0.0


_GO_AUTH_SET = re.compile(
    r"""\.Header\.(Set|Add)\(\s*["']?[\w.]*[Aa]uthorization""",
)
_GO_ROUNDTRIP = re.compile(r"func\s*\([^)]*\)\s*RoundTrip\(")
_PY_HTTPX_CLIENT = re.compile(r"httpx\.(Async)?Client\(")
_PY_FOLLOW_REDIRECTS_TRUE = re.compile(r"follow_redirects\s*=\s*True")
_PY_AUTH_HEADER = re.compile(r"""["']?[Aa]uthorization["']?\s*[:=]\s*f?["']?Bearer|Bearer\s*\{""")
_SQL_STARTSWITH_SELECT = re.compile(r"""\.startswith\(\s*["']select""", re.IGNORECASE)
_SQL_DB_READONLY = re.compile(
    r"SET\s+TRANSACTION\s+READ\s+ONLY|BEGIN\s+(TRANSACTION\s+)?READ\s+ONLY|READ\s+ONLY\s+TRANSACTION",
    re.IGNORECASE,
)

# SRC-004: a server-held credential (token/secret/api key) is placed as the
# connection password / bearer while the destination host is an interpolated
# variable -> if that host is caller/model-controlled and unvalidated, the
# credential is exfiltrated to an attacker host (confused-deputy). Matches
# connection-string builders that interpolate the target host into one field
# and a bearer/access token into the password field: the C# pattern seen in
# the original finding, and the equivalent Python/JS f-string construction.
_CRED_TO_HOST = re.compile(
    r"(Host|Server|Data\s*Source|Endpoint)\s*=\s*[\{\$]\{?[^}\"'\n]+\}?"
    r".{0,200}?"
    r"(Password|Pwd)\s*=\s*[\{\$]\{?[^}\"'\n]*"
    r"(token|accesstoken|secret|apikey|api_key|credential|bearer)",
    re.IGNORECASE,
)

_SRC_EXTS = {".go", ".py", ".ts", ".js", ".cs"}
# Matched against whole PATH COMPONENTS (via Path.parts), not a substring of
# the stringified path. Substring matching on e.g. "/test" also matches any
# directory that merely starts with "test" (a real "testUtils/" package, or
# pytest's own tmp_path dirs, named "test_<function name>...") and, for a
# relative root path, a top-level "tests/" dir has no leading slash to match
# against at all -- both silently skip real source. Component matching is
# exact and immune to both.
_SKIP_DIRS = {"node_modules", "dist", "vendor", ".git", "__pycache__", "test", "tests"}


def _iter_source(root: Path):
    for p in root.rglob("*"):
        if p.suffix not in _SRC_EXTS or not p.is_file():
            continue
        if any(part in _SKIP_DIRS for part in p.relative_to(root).parts[:-1]):
            continue
        if p.stem.endswith("_test"):
            continue
        try:
            yield p, p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue


def _line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def scan_source_tree(root: str | Path) -> list[SourceFinding]:
    """Walk a source tree and return heuristic code-level security findings."""
    root = Path(root)
    findings: list[SourceFinding] = []

    for path, text in _iter_source(root):
        rel = str(path.relative_to(root)) if path.is_relative_to(root) else str(path)

        # SRC-001 (Go): a RoundTrip that sets Authorization, in a file whose
        # package sets no CheckRedirect -> auth may survive a cross-host redirect.
        if path.suffix == ".go" and _GO_ROUNDTRIP.search(text):
            m = _GO_AUTH_SET.search(text)
            if m and "CheckRedirect" not in text:
                findings.append(SourceFinding(
                    "SRC-001", Severity.MEDIUM,
                    "Auth header re-applied in transport without redirect guard",
                    "A custom http.RoundTripper sets the Authorization header on every "
                    "round-trip and no CheckRedirect drops it on host change. Go strips "
                    "auth on cross-host redirects only for headers set on the original "
                    "request; a transport that re-adds it defeats that, so a redirect can "
                    "forward the credential to a foreign host.",
                    f"{rel}:{_line_of(text, m.start())}",
                    text[max(0, m.start() - 40):m.start() + 60].strip(),
                    "Add a CheckRedirect to the wrapping http.Client that removes the "
                    "Authorization header when the redirect target host differs.",
                    6.5,
                ))

        # SRC-002 (Python): httpx client with follow_redirects=True and a bearer header.
        if path.suffix == ".py" and _PY_HTTPX_CLIENT.search(text):
            if _PY_FOLLOW_REDIRECTS_TRUE.search(text) and _PY_AUTH_HEADER.search(text):
                m = _PY_FOLLOW_REDIRECTS_TRUE.search(text)
                findings.append(SourceFinding(
                    "SRC-002", Severity.MEDIUM,
                    "httpx client follows redirects while carrying a bearer token",
                    "An httpx client is created with follow_redirects=True and an "
                    "Authorization/Bearer header. httpx keeps client headers across "
                    "redirects and does not strip auth on host change, so a redirect can "
                    "leak the token to a foreign host.",
                    f"{rel}:{_line_of(text, m.start())}",
                    text[max(0, m.start() - 40):m.start() + 40].strip(),
                    "Set follow_redirects=False, or add an event hook that strips the "
                    "Authorization header when the redirect host differs.",
                    6.5,
                ))

        # SRC-003 (SQL read-only by string check only, no DB-level read-only txn).
        if _SQL_STARTSWITH_SELECT.search(text) and not _SQL_DB_READONLY.search(text):
            m = _SQL_STARTSWITH_SELECT.search(text)
            findings.append(SourceFinding(
                "SRC-003", Severity.HIGH,
                "SQL read-only enforced by string prefix check only",
                "Read-only mode is gated on the query text starting with 'select' with "
                "no database-level read-only transaction (SET TRANSACTION READ ONLY / "
                "BEGIN READ ONLY) in this file. Prefix/keyword checks are defeated by "
                "leading comments, CTEs that write, and stacked statements.",
                f"{rel}:{_line_of(text, m.start())}",
                text[max(0, m.start() - 30):m.start() + 40].strip(),
                "Enforce read-only at the database layer (read-only transaction or a "
                "read-only role/login), not only by inspecting the query string.",
                7.5,
            ))

        # SRC-004: server-held credential sent to an interpolated (possibly
        # caller-controlled) destination host.
        for m in _CRED_TO_HOST.finditer(text):
            findings.append(SourceFinding(
                "SRC-004", Severity.HIGH,
                "Credential attached to a caller-influenced destination host",
                "A token/secret/API key is placed as the connection password (or "
                "bearer) while the destination host is an interpolated variable. If "
                "that host comes from a tool argument and is not validated against an "
                "allowlist, a caller (e.g. via prompt injection) can point it at an "
                "attacker host and receive the credential (confused-deputy). Confirm "
                "the host variable is pinned to a trusted allowlist before the "
                "credential is attached.",
                f"{rel}:{_line_of(text, m.start())}",
                text[m.start():m.start() + 90].strip(),
                "Never send a credential to a caller-influenced destination: resolve "
                "the host from trusted config/ARM or validate it against an allowlist, "
                "or withhold the credential when the host is not the trusted one.",
                7.5,
            ))

    return findings


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "."
    for f in scan_source_tree(target):
        print(f"[{f.severity.name if hasattr(f.severity, 'name') else f.severity}] "
              f"{f.rule_id} {f.title}\n    {f.location}\n    {f.remediation}\n")
