"""Deterministic deployment-profile stage (WS5 / plan item C1).

Checkpoint 4 lost 3 of 10 ground-truth findings at the adversary gate because
their exploitability hinged on a multi-tenant / shared-state deployment that the
bounded evidence window could not establish either way. This module computes
that fact from the repo itself (no LLM) so the adversary receives it as an
INPUT instead of guessing.

The profile is a set of cheap, auditable signals (regexes over source files,
bounded file count/size), each reported with the file that produced it. It never
claims more than the signals show: `unknown` is a legal answer.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .untrusted_text import wrap_untrusted

_SOURCE_SUFFIXES = frozenset({".py", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".go", ".java", ".kt", ".rs"})
_SKIP_DIRS = frozenset({
    "node_modules", ".git", ".venv", "venv", "dist", "build", "target", "vendor", "__pycache__", "docs",
})
_TEST_RE = re.compile(r"(^|/)(tests?|__tests__|spec|examples?|e2e)(/|$)|(\.test\.|\.spec\.|_test\.|test_)")
_MAX_FILES = 1500
_MAX_FILE_BYTES = 400_000

# signal name -> regex over source text
_SIGNALS: dict[str, re.Pattern[str]] = {
    "stdio": re.compile(
        r"StdioServerTransport|stdio_server\(|StdioServerParameters|StdioClientTransport|"
        r"\bstdio\.NewServer|StdioTransport|mcp\.StdioTransport|transport\s*=\s*[\"']stdio[\"']", re.I),
    "http": re.compile(
        r"StreamableHTTP|streamable[_-]?http|SSEServerTransport|SseServerTransport|sse_app\(|"
        r"http_app\(|http\.ListenAndServe|http\.Server\b|createServer\(|express\(\)|"
        r"uvicorn|starlette|FastAPI\(|HttpServlet|@RestController|WebFluxSse|WebMvcSse|"
        r"app\.listen\(|ServeMux", re.I),
    "session_state": re.compile(
        r"Mcp-Session-Id|sessionIdGenerator|session_id_generator|_sessions\b|sessions\s*[:=]\s*(new Map|\{\}|dict|map\[)|"
        r"SessionManager|session_manager|Map<[^>]*Session|\bsessions\.(get|set|put)|_requestToStreamMapping|"
        r"ConcurrentHashMap<", re.I),
    "stateless_mode": re.compile(r"stateless|sessionIdGenerator\s*:\s*undefined", re.I),
    "auth": re.compile(
        r"OAuth|bearer|Authorization[\"']?\]?\s*[:=(]|authMiddleware|requireAuth|require_auth|"
        r"TokenVerifier|token_verifier|verify_token|AuthProvider|auth_provider|JWT|jwks|"
        r"sessionToken|session_token|AUTH_TOKEN|api[_-]?key", re.I),
    "multi_tenant": re.compile(
        r"multi[-_ ]?tenan|\btenant[_-]?id\b|\bper[-_ ]user\b|multiple (users|clients|callers)|"
        r"shared (across|between) (users|clients|sessions)|concurrent (users|clients|sessions)|"
        r"remote (server|deployment|access)|hosted", re.I),
    "loopback_only": re.compile(
        r"127\.0\.0\.1|localhost|\[::1\]|loopback|DNS rebinding|allowedHosts|allowed_hosts", re.I),
    "library_marker": re.compile(r"^\s*(export\s+class|class\s+\w*(Transport|Server|Session|Manager)\b|type\s+\w*Transport)", re.M),
}


@dataclass
class DeploymentProfile:
    """What the repo's own code says about how it is deployed."""

    transport: str  # "stdio-only" | "http-capable" | "stdio+http" | "unknown"
    isolation: str  # "per-process-local" | "shared-state-capable" | "stateless" | "unknown"
    auth: str  # "present" | "absent" | "unknown"
    multi_tenant_exposure: str  # "no" | "conditional" | "likely" | "unknown"
    is_library: bool
    signals: dict[str, list[str]] = field(default_factory=dict)  # signal -> up to 3 example files
    n_sources: int = 0

    def render(self) -> str:
        """Prompt-ready summary. Pure derived facts + file names, no hunter text."""

        def ev(name: str) -> str:
            files = self.signals.get(name, [])
            # file names come from the scanned repo: untrusted
            return " (e.g. " + wrap_untrusted(", ".join(files)) + ")" if files else ""

        return (
            "## Deployment profile (computed deterministically from this repo's own source; "
            "not from the claim)\n"
            f"- Transport: {self.transport}{ev('http') if 'http' in self.transport else ev('stdio')}\n"
            f"- State model: {self.isolation}{ev('session_state')}\n"
            f"- Authentication code present: {self.auth}{ev('auth')}\n"
            f"- Repo role: {'library/SDK embedded by other applications' if self.is_library else 'application/server'}\n"
            f"- Multi-tenant exposure: {self.multi_tenant_exposure}\n"
            f"  (files scanned: {self.n_sources})"
        )


def _iter_source_files(root: Path):
    n = 0
    for p in sorted(root.rglob("*")):
        if n >= _MAX_FILES:
            return
        if p.suffix not in _SOURCE_SUFFIXES or not p.is_file():
            continue
        rel = p.relative_to(root).as_posix()
        if set(rel.split("/")[:-1]) & _SKIP_DIRS or _TEST_RE.search(rel):
            continue
        n += 1
        yield rel, p


_MANIFESTS = ("pyproject.toml", "package.json", "go.mod", "pom.xml", "build.gradle", "build.gradle.kts")
_LIB_RE = re.compile(r"\b(SDK|library|framework)\b", re.I)


def _declares_library(root: Path) -> bool:
    """The repo's own package metadata / README opening calls it an SDK or library."""
    head = ""
    for name in ("pyproject.toml", "package.json", "README.md"):
        p = root / name
        if p.is_file():
            try:
                head += p.read_text(errors="ignore")[:1500]
            except OSError:
                pass
    return bool(_LIB_RE.search(head)) or root.name.lower().endswith("-sdk") or "-sdk" in root.name.lower()


def compute_deployment_profile(repo_root: str | Path) -> DeploymentProfile:
    root = Path(repo_root)
    hits: dict[str, list[str]] = {k: [] for k in _SIGNALS}
    counts: dict[str, int] = dict.fromkeys(_SIGNALS, 0)
    scanned = 0
    for rel, p in _iter_source_files(root):
        try:
            if p.stat().st_size > _MAX_FILE_BYTES:
                continue
            text = p.read_text(errors="ignore")
        except OSError:
            continue
        scanned += 1
        client_side = "client" in rel.lower().split("/") or "/client" in rel.lower() or rel.lower().startswith("client")
        for name, rx in _SIGNALS.items():
            if name == "auth" and client_side:
                continue  # a client's own OAuth code says nothing about the server side's auth
            if rx.search(text):
                counts[name] += 1
                if len(hits[name]) < 3:
                    hits[name].append(rel)

    has_http = counts["http"] > 0
    has_stdio = counts["stdio"] > 0
    transport = (
        "stdio+http" if has_http and has_stdio else "http-capable" if has_http
        else "stdio-only" if has_stdio else "unknown"
    )
    # A repo with many class/Transport definitions and few app entrypoints is an SDK.
    is_library = _declares_library(root) or (
        counts["library_marker"] >= max(5, scanned // 6)
        and any((root / m).exists() for m in _MANIFESTS)
    )

    if counts["session_state"] and has_http:
        isolation = "shared-state-capable"
    elif counts["stateless_mode"] and has_http:
        isolation = "stateless"
    elif transport == "stdio-only":
        isolation = "per-process-local"
    else:
        isolation = "unknown"

    auth = "present" if counts["auth"] >= 3 else "absent" if scanned and counts["auth"] == 0 else "unknown"

    if transport == "stdio-only":
        mt = "no"
    elif has_http and isolation == "shared-state-capable":
        mt = "likely" if (counts["multi_tenant"] and not is_library) else "conditional"
    elif has_http:
        mt = "conditional"
    else:
        mt = "unknown"

    return DeploymentProfile(
        transport=transport, isolation=isolation, auth=auth, multi_tenant_exposure=mt,
        is_library=is_library, signals={k: v for k, v in hits.items() if v}, n_sources=scanned,
    )
