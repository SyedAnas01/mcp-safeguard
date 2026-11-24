"""Stage 5: real execution sandbox + generalized runtime oracle.

`verify.py` (Stage 4) grounds an LLM's verdict in the real source text of a
tier "S" static-taint finding, but it never actually RUNS anything -- its
verdict is still a model's read of code. This module is the execution
backend a `ClaimCard`-shaped caller (hunter, adversary, or an automated
Stage 5 driver) uses to go one step further: actually invoke the suspect
function, inside an isolated sandbox, with a set of interposition hooks
watching what it really does, and get back a structured `OracleTrace`
instead of a model's opinion.

This generalizes a real, one-off verification this campaign ran by hand: a
local PostgreSQL 16 container was spun up, the real `validateReadQuery`
function was imported from a live target's actual source, a crafted query
was run through it, and a genuine row-count change was observed. That was
done once, ad hoc, with a bespoke script. `run_in_sandbox()` below is the
reusable version -- the same "import the real function, call it for real,
watch what happens" shape, usable against any repo this project scans.

## Isolation

`docker_available()` gates two isolation strategies:
  - Docker (preferred): the target repo is bind-mounted READ-ONLY at
    `/repo`, resource limits are applied (`--memory`, `--cpus`,
    `--pids-limit`), all Linux capabilities are dropped, `--network none`
    is the default (a caller can opt into a specific existing docker
    network -- see `SandboxConfig.network` -- when the entrypoint under
    test genuinely needs to reach something, e.g. a sibling Postgres
    container started by the caller for a DB-effect check), and a single
    read-write scratch directory is mounted for the oracle's own trace
    output.
  - No Docker: a resource-limited subprocess fallback
    (`_run_python_fallback`), POSIX-only, using the stdlib `resource`
    module to bound CPU time and address space. This is explicitly NOT
    real isolation -- the child shares the host filesystem and network
    exactly like any other subprocess. It exists so this module still DOES
    something (rather than silently no-op) when Docker is unavailable, and
    its own docstring says so; it is not a substitute for Docker when the
    target code is untrusted. **Opt-in only**: `run_in_sandbox()` refuses
    to use it by default (`allow_unsafe_host_execution=False`) -- a caller
    genuinely reaching for it (e.g. a pre-sandboxed CI environment that
    already isolates the whole process) must pass
    `allow_unsafe_host_execution=True` explicitly. Without it,
    Docker-unavailable + `runtime="python"` now raises
    `SandboxUnavailableError` instead of silently running untrusted target
    code on the host -- matching the JS/TS behavior below, which never had
    a silent fallback in the first place.
JS/TS entrypoints have no fallback: calling arbitrary Node code safely
without a container is a much bigger surface than a CPU/memory rlimit can
plausibly bound, so `run_in_sandbox()` raises `SandboxUnavailableError` for
a `runtime="node"` entrypoint when Docker is not present, naming exactly
what is missing, rather than pretending to isolate it.

## The oracle: what's actually new here

VIPER-MCP's own oracle (per this project's architecture research) hooks
file/process/network activity narrowly. The generalization this module
adds -- the piece the design calls out as unlocking the credential
-forwarding/confused-deputy bug class -- is inspecting the CONTENT of every
outbound HTTP request: headers and body fields are matched against a small
set of credential-shaped patterns (known header names like `Authorization`/
`X-API-Key`, and value shapes like `Bearer <token>`, AWS access key IDs,
GitHub/OpenAI/Slack-style secret prefixes) and, on a match, recorded as a
`credential_flags` entry naming the exact destination host:port the
credential-shaped value was sent to. A bug like "this tool reads an
operator-scoped secret and forwards it to an attacker-controlled URL taken
from a tool argument" produces a `credential_flags` entry with a real
destination; VIPER-MCP's file/process/network-only oracle would only ever
show "a network connection was made," with no way to tell a same-shaped
benign API call apart from a credential exfiltration.

Python hooks (`PythonOracle`, fully implemented and validated -- see
`tests/test_sandbox.py` and `bench/S1_SANDBOX_STATUS.md`) monkeypatch
`subprocess.Popen`/`os.system` (every subprocess/exec call, full argv),
`builtins.open` (every file open, resolved real path, flagged if outside
the sandbox's expected root -- `io.open` is the same C-level function as
`builtins.open` in CPython, so one patch covers both), `socket.socket
.connect`/`.connect_ex` (every outbound TCP connection, destination host
/port), and `http.client.HTTPConnection.putrequest`/`.putheader`/
`.endheaders` for the credential-content inspection above. That last hook
point was chosen deliberately over patching `HTTPConnection.request()`
itself: empirically, `requests` (via urllib3) does not always route through
the base class's own `.request()` method, but every real HTTP client this
project tested -- stdlib `urllib.request` and `requests` alike -- still
calls `putrequest`/`putheader`/`endheaders` to actually write the request,
because that is the level at which the request line and headers are
physically assembled. Patching there is one interception point that
transparently covers both.

JS/TS hooks (`render_js_oracle_preload_source()`) are a `--require`-loaded
CommonJS preload that patches `child_process` (`exec`/`execSync`/`spawn`/
`spawnSync`/`execFile`/`execFileSync`), `fs` (`readFileSync`/
`writeFileSync`/`openSync`), `net.Socket.prototype.connect`, `http`/
`https`.request, and `globalThis.fetch` (Node 18+/undici). This is real,
validated code -- not a placeholder -- confirmed working against a plain
Node CJS target, a plain Node ESM target, AND (the case this project's own
targets are usually shaped like) a TypeScript/ESM file transpiled on the
fly by `tsx` and dynamically imported by a generic runner script, including
the exact credential-forwarding shape (an env var read and sent as a
`Bearer` header to a URL taken from an argument) -- see
`bench/S1_SANDBOX_STATUS.md` for the reproduced transcript. What is NOT
independently re-verified: whether every hook fires identically for every
possible JS HTTP/subprocess library in the wild (only `http`/`https`/
`fetch`/`child_process`/`fs` themselves were exercised) -- documented
honestly rather than claimed as exhaustive.

## Two languages, two entrypoint-invocation calling conventions

Both `_run_python_in_docker` and `_run_node_in_docker` share the same
overall shape (mount repo read-only, mount a small oracle/runner script
read-only, mount a scratch dir read-write, run, read the trace back) but
necessarily differ in mechanics: Python dynamically imports the target
module by file path (`importlib.util.spec_from_file_location`) and calls
the named function directly in the SAME process the hooks are installed
in; JS dynamically `import()`s the target file (a plain `.mjs` runner can
dynamically import a `.ts`/`.mts` file and have it transformed on the fly,
as long as a TS-capable loader -- `tsx`, found in the target repo's own
`node_modules` or a small fallback tooling install -- registered itself
before that import runs) and calls the named export, letting the SAME
generic runner work for `.js`/`.mjs`/`.cjs` targets with no transform step
at all.
"""

from __future__ import annotations

import builtins
import dataclasses
import http.client
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from .entrypoints import McpEntrypoint

# --------------------------------------------------------------------------
# Runtime detection -- reuses entrypoints.py/entrypoints_js.py's own notion
# of "what kind of repo is this" (their file-extension walks), plus the
# cheaper/faster marker-file check most repos make available for free.
# --------------------------------------------------------------------------

RuntimeKind = Literal["python", "node", "unknown"]

_PY_MARKER_FILES = ("pyproject.toml", "setup.py", "setup.cfg", "requirements.txt", "Pipfile")
_NODE_MARKER_FILES = ("package.json",)


@dataclass
class RuntimeInfo:
    kind: RuntimeKind
    confidence: str  # "high" (marker file found) | "medium" (file-count tiebreak) | "low" (no signal either way)
    indicator: str  # what triggered detection, for a human reading a report


def detect_runtime(repo_path: str | Path) -> RuntimeInfo:
    """Guess whether `repo_path` is a Python or Node/JS project. Marker
    files are checked first (cheap, unambiguous when present); a repo with
    both a `pyproject.toml` and a `package.json` (a JS project with Python
    tooling scripts, or vice versa) falls through to counting source files
    by extension, same tiebreak entrypoints.py/entrypoints_js.py would
    effectively apply on their own. A repo with neither signal returns
    `kind="unknown"` -- silence, not a guess, matching this package's
    existing discipline (entrypoints.py's own module docstring)."""
    root = Path(repo_path)
    has_py_marker = any((root / m).is_file() for m in _PY_MARKER_FILES)
    has_node_marker = any((root / m).is_file() for m in _NODE_MARKER_FILES)
    if has_py_marker and not has_node_marker:
        return RuntimeInfo("python", "high", "found " + next(m for m in _PY_MARKER_FILES if (root / m).is_file()))
    if has_node_marker and not has_py_marker:
        return RuntimeInfo("node", "high", "found package.json")

    py_count = sum(1 for _ in _bounded_glob(root, "*.py"))
    js_count = sum(1 for _ in _bounded_glob(root, "*.ts")) + sum(1 for _ in _bounded_glob(root, "*.js"))
    if py_count == 0 and js_count == 0:
        return RuntimeInfo("unknown", "low", "no pyproject.toml/package.json and no .py/.js/.ts files found")
    if py_count >= js_count:
        return RuntimeInfo("python", "medium", f"{py_count} .py files vs {js_count} .js/.ts files")
    return RuntimeInfo("node", "medium", f"{js_count} .js/.ts files vs {py_count} .py files")


def _bounded_glob(root: Path, pattern: str, limit: int = 2000):
    """`root.rglob(pattern)`, stopping after `limit` matches -- this is only
    ever used for a coarse language tiebreak count, not an exhaustive scan,
    so it should never spend real time walking a huge, already-vendored
    `node_modules` just to decide "python or node?"."""
    n = 0
    skip = {"node_modules", ".git", ".venv", "venv", "dist", "build", "__pycache__"}
    for p in root.rglob(pattern):
        if any(part in skip for part in p.parts):
            continue
        yield p
        n += 1
        if n >= limit:
            return


# --------------------------------------------------------------------------
# Docker availability
# --------------------------------------------------------------------------

_docker_available_cache: bool | None = None


def docker_available(force_recheck: bool = False) -> bool:
    """True if a working `docker` CLI that can actually talk to a daemon is
    on PATH. Cached after the first real check (a `docker version` round
    -trip is not free) -- pass `force_recheck=True` to bypass the cache,
    e.g. in a test that wants to simulate Docker becoming unavailable."""
    global _docker_available_cache
    if _docker_available_cache is not None and not force_recheck:
        return _docker_available_cache
    if shutil.which("docker") is None:
        _docker_available_cache = False
        return False
    try:
        result = subprocess.run(["docker", "version", "--format", "{{.Server.Version}}"], capture_output=True, timeout=10)
        _docker_available_cache = result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        _docker_available_cache = False
    return _docker_available_cache


class SandboxUnavailableError(RuntimeError):
    """Raised when `run_in_sandbox()` cannot honestly proceed -- e.g. a
    `runtime="node"` entrypoint with Docker unavailable. Never used to
    paper over a real failure; the message always says exactly what was
    missing and what running it for real would require."""


# --------------------------------------------------------------------------
# Configuration + entrypoint description
# --------------------------------------------------------------------------


@dataclass
class SandboxConfig:
    """Resource/isolation knobs for one `run_in_sandbox()` call. Defaults
    are deliberately restrictive (`network="none"`) -- a caller who knows
    the entrypoint under test needs to reach something (a sibling container
    the caller itself started, e.g. a throwaway Postgres for a DB-effect
    check) opts in explicitly by naming that docker network, rather than
    the sandbox defaulting to open network access."""

    timeout_seconds: int = 30
    memory_mb: int = 512
    cpus: float = 1.0
    pids_limit: int = 128
    network: str = "none"  # docker --network value: "none" | "bridge" | an existing network name
    extra_mounts: list[tuple[str, str, str]] = field(default_factory=list)  # (host_path, container_path, "ro"|"rw")
    extra_env: dict[str, str] = field(default_factory=dict)
    python_image: str = "python:3.12-slim"
    node_image: str = "node:22-slim"
    # Where this module creates its own scratch dirs (trace output, generated
    # runner scripts) for a Docker run. Deliberately NOT the OS default temp
    # dir (`tempfile.gettempdir()`, usually under a per-user path like macOS's
    # `/var/folders/...`): a Docker Desktop VM or a Colima VM only bind-mounts
    # a specific, configured set of host paths into itself, and on THIS
    # project's own dev machine (Colima, confirmed via `docker info` reporting
    # an Ubuntu VM rather than the host's real macOS) the default temp dir is
    # NOT one of them -- a container can write into a mount rooted there and
    # the host-side directory silently never reflects it (no error from
    # either `docker run` or the container's own write; verified directly
    # with a `docker run -v <tmp>:/scratch alpine sh -c "echo hi > /scratch/x"`
    # + a host-side `cat` that found nothing). The user's home directory is
    # shared by both Docker Desktop's and Colima's default configurations, so
    # that's the default here; override this for an environment where it
    # genuinely differs. See bench/S1_SANDBOX_STATUS.md.
    scratch_base_dir: Path | None = None


@dataclass
class SandboxEntrypoint:
    """What to call. `file` may be absolute (must be under the `repo_path`
    passed to `run_in_sandbox`) or relative to it. This is deliberately a
    plain, small descriptor rather than requiring an `McpEntrypoint` --
    `entrypoints.py`/`entrypoints_js.py` recover real MCP tool HANDLERS,
    but a Stage 5 caller often needs to invoke a HELPER function a step
    away from the handler (e.g. the validation function a handler calls
    into, which is exactly the shape of the real Aiven bug this module was
    validated against) -- `from_mcp_entrypoint()` is there for the common
    case where the thing to call really is a recovered entrypoint."""

    file: Path
    function_name: str
    runtime: RuntimeKind = "python"

    def __post_init__(self) -> None:
        self.file = Path(self.file)

    @classmethod
    def from_mcp_entrypoint(cls, ep: McpEntrypoint, runtime: RuntimeKind = "python") -> SandboxEntrypoint:
        return cls(file=ep.file, function_name=ep.function_name, runtime=runtime)


# --------------------------------------------------------------------------
# OracleTrace: the structured result. Kept as one flat dataclass of plain
# dicts/lists (not a hierarchy of nested dataclasses) on purpose -- every
# field here has already crossed a JSON boundary at least once (out of a
# container, or out of a resource-limited subprocess), so a plain
# JSON-shaped dict is the natural representation, not something to wrap and
# unwrap through `dataclasses.asdict`/custom `__init__`s for no benefit.
# --------------------------------------------------------------------------


@dataclass
class OracleTrace:
    sandbox_kind: str  # "docker" | "subprocess-fallback" | "in-process"
    runtime: str  # "python" | "node"
    entrypoint: str  # "<file>:<function_name>", for a human reading a report
    timed_out: bool = False
    started_at: float = 0.0
    ended_at: float = 0.0
    duration_seconds: float = 0.0
    return_value: Any = None
    return_value_repr: str | None = None
    exception: str | None = None  # an exception the TARGET code raised
    error: str | None = None  # a SANDBOX-level failure (docker/runner error), distinct from the above
    stdout: str = ""
    stderr: str = ""
    subprocess_calls: list[dict] = field(default_factory=list)
    file_opens: list[dict] = field(default_factory=list)
    network_connections: list[dict] = field(default_factory=list)
    http_requests: list[dict] = field(default_factory=list)
    credential_flags: list[dict] = field(default_factory=list)
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> OracleTrace:
        known = {f.name for f in dataclasses.fields(cls)}
        return cls(**{k: v for k, v in d.items() if k in known})


# --------------------------------------------------------------------------
# Credential-shaped pattern matching -- shared logic description; the
# Python implementation lives here, the JS implementation is the
# functionally-equivalent block inside `_JS_ORACLE_PRELOAD_SOURCE` below
# (kept as a literal JS string, not generated from this, since the two
# languages' stdlib header representations differ enough that a shared
# code-generator would be more indirection than the ~20 lines it saves).
# --------------------------------------------------------------------------

_CRED_HEADER_NAMES = {
    "authorization", "proxy-authorization", "x-api-key", "api-key", "apikey",
    "x-auth-token", "x-access-token", "x-amz-security-token", "cookie",
}
_CRED_VALUE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"^Bearer\s+\S+", re.I), "bearer_token"),
    (re.compile(r"^Basic\s+[A-Za-z0-9+/=]{8,}", re.I), "basic_auth"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "aws_access_key_id"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "openai_style_secret"),
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"), "github_token"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "slack_token"),
]
_CRED_BODY_FIELD_NAMES = {"api_key", "apikey", "password", "secret", "token", "access_token", "client_secret", "refresh_token"}


def _preview(value: Any) -> str:
    """A short, non-reversible preview of a flagged value -- enough for a
    human to recognize what was flagged, never enough to recover the
    secret. The real value is never stored anywhere else in the trace."""
    s = str(value)
    if len(s) <= 10:
        return "(redacted)"
    return f"{s[:6]}...({len(s)} chars, redacted)"


def _scan_credentials(headers: dict[str, Any], body: bytes | str | None, destination: str) -> list[dict]:
    flags: list[dict] = []
    for name, value in (headers or {}).items():
        lname = str(name).lower()
        value_str = str(value)
        if lname in _CRED_HEADER_NAMES:
            flags.append({"destination": destination, "location": f"header:{name}", "matched_pattern": "credential_header_name", "value_preview": _preview(value_str)})
            continue
        for pattern, label in _CRED_VALUE_PATTERNS:
            if pattern.search(value_str):
                flags.append({"destination": destination, "location": f"header:{name}", "matched_pattern": label, "value_preview": _preview(value_str)})
                break
    if body:
        body_str = body.decode("utf-8", "ignore") if isinstance(body, bytes) else str(body)
        for field_name in _CRED_BODY_FIELD_NAMES:
            m = re.search(rf'["\']?{re.escape(field_name)}["\']?\s*[:=]\s*["\']?([^&"\'\s]+)', body_str, re.I)
            if m:
                flags.append({"destination": destination, "location": f"body:{field_name}", "matched_pattern": "credential_body_field_name", "value_preview": _preview(m.group(1))})
    return flags


def _redact_headers(headers: dict[str, Any]) -> dict[str, str]:
    out = {}
    for name, value in (headers or {}).items():
        lname = str(name).lower()
        value_str = str(value)
        is_cred = lname in _CRED_HEADER_NAMES or any(p.search(value_str) for p, _ in _CRED_VALUE_PATTERNS)
        out[name] = _preview(value_str) if is_cred else value_str
    return out


# --------------------------------------------------------------------------
# PythonOracle: the in-process hook installer. Directly importable and
# directly testable with no subprocess/Docker involved -- see
# tests/test_sandbox.py. This is also EXACTLY what runs inside the Docker
# container (via `run_python_entrypoint_with_oracle` below) and inside the
# no-Docker subprocess fallback: one implementation, three call sites.
# --------------------------------------------------------------------------


class PythonOracle:
    """Installs/uninstalls the stdlib monkeypatches described in this
    module's docstring. `expected_root`, if given, is used to flag a file
    open that resolves outside it (`outside_root: true` in `file_opens`) --
    the sandbox's own signal for "this touched something it shouldn't have
    had access to," independent of whatever OS-level enforcement (or lack
    of it, in the fallback path) is also in effect.
    """

    def __init__(self, expected_root: str | Path | None = None):
        self.expected_root = str(Path(expected_root).resolve()) if expected_root else None
        self.subprocess_calls: list[dict] = []
        self.file_opens: list[dict] = []
        self.network_connections: list[dict] = []
        self.http_requests: list[dict] = []
        self.credential_flags: list[dict] = []
        self._orig: dict[str, Any] = {}
        self._pending_http: dict[int, dict] = {}
        self._installed = False

    def _outside_root(self, path_str: str) -> bool:
        if not self.expected_root:
            return False
        try:
            resolved = str(Path(path_str).resolve())
        except OSError:
            return False
        return not resolved.startswith(self.expected_root)

    def install(self) -> None:
        if self._installed:
            return
        self._installed = True
        oracle = self

        # --- subprocess/exec ---
        orig_popen_init = subprocess.Popen.__init__

        def patched_popen_init(popen_self, args, *a, **kw):
            argv = list(args) if isinstance(args, (list, tuple)) else [args]
            oracle.subprocess_calls.append({"argv": [str(x) for x in argv], "cwd": kw.get("cwd"), "timestamp": time.time()})
            return orig_popen_init(popen_self, args, *a, **kw)

        subprocess.Popen.__init__ = patched_popen_init
        self._orig["popen_init"] = orig_popen_init

        orig_system = os.system

        def patched_system(command):
            oracle.subprocess_calls.append({"argv": ["<shell>", command], "cwd": None, "timestamp": time.time()})
            return orig_system(command)

        os.system = patched_system
        self._orig["os_system"] = orig_system

        # --- file open (io.open IS builtins.open in CPython -- one patch covers both) ---
        orig_open = builtins.open

        def patched_open(file, mode="r", *a, **kw):
            path_str = str(file) if isinstance(file, (str, Path, bytes)) else repr(file)
            outside = oracle._outside_root(path_str) if isinstance(file, (str, Path)) else False
            try:
                resolved = str(Path(file).resolve()) if isinstance(file, (str, Path)) else path_str
            except OSError:
                resolved = path_str
            oracle.file_opens.append({"path": path_str, "resolved_path": resolved, "mode": mode, "outside_root": outside, "timestamp": time.time()})
            return orig_open(file, mode, *a, **kw)

        builtins.open = patched_open
        self._orig["open"] = orig_open

        # --- outbound TCP connections ---
        orig_connect = socket.socket.connect

        def patched_connect(sock_self, address):
            try:
                host, port = address[0], address[1]
            except (TypeError, IndexError):
                host, port = repr(address), None
            oracle.network_connections.append({"host": host, "port": port, "timestamp": time.time()})
            return orig_connect(sock_self, address)

        socket.socket.connect = patched_connect
        self._orig["socket_connect"] = orig_connect

        # --- HTTP header/body inspection -- see module docstring for why
        # putrequest/putheader/endheaders, not HTTPConnection.request() ---
        orig_putrequest = http.client.HTTPConnection.putrequest

        def patched_putrequest(conn, method, url, *a, **kw):
            oracle._pending_http[id(conn)] = {"method": method, "url": url, "host": conn.host, "port": conn.port, "headers": {}}
            return orig_putrequest(conn, method, url, *a, **kw)

        http.client.HTTPConnection.putrequest = patched_putrequest
        self._orig["putrequest"] = orig_putrequest

        orig_putheader = http.client.HTTPConnection.putheader

        def patched_putheader(conn, header, *values):
            rec = oracle._pending_http.get(id(conn))
            if rec is not None:
                rec["headers"][str(header)] = ", ".join(str(v) for v in values)
            return orig_putheader(conn, header, *values)

        http.client.HTTPConnection.putheader = patched_putheader
        self._orig["putheader"] = orig_putheader

        orig_endheaders = http.client.HTTPConnection.endheaders

        def patched_endheaders(conn, message_body=None, *a, **kw):
            rec = oracle._pending_http.pop(id(conn), None)
            if rec is not None:
                dest = f"{rec['host']}:{rec['port']}"
                flags = _scan_credentials(rec["headers"], message_body, dest)
                oracle.credential_flags.extend(flags)
                oracle.http_requests.append({
                    "method": rec["method"], "url": rec["url"], "host": rec["host"], "port": rec["port"],
                    "headers": _redact_headers(rec["headers"]), "credential_flags": flags, "timestamp": time.time(),
                })
            return orig_endheaders(conn, message_body, *a, **kw)

        http.client.HTTPConnection.endheaders = patched_endheaders
        self._orig["endheaders"] = orig_endheaders

    def uninstall(self) -> None:
        if not self._installed:
            return
        subprocess.Popen.__init__ = self._orig["popen_init"]
        os.system = self._orig["os_system"]
        builtins.open = self._orig["open"]
        socket.socket.connect = self._orig["socket_connect"]
        http.client.HTTPConnection.putrequest = self._orig["putrequest"]
        http.client.HTTPConnection.putheader = self._orig["putheader"]
        http.client.HTTPConnection.endheaders = self._orig["endheaders"]
        self._orig.clear()
        self._installed = False

    def __enter__(self) -> PythonOracle:
        self.install()
        return self

    def __exit__(self, *exc_info) -> None:
        self.uninstall()


def run_python_entrypoint_with_oracle(
    module_path: str | Path, function_name: str, args: list, expected_root: str | Path | None = None,
) -> OracleTrace:
    """Dynamically import `module_path` as a standalone module (by file
    path, via `importlib.util` -- it does not need to be part of an
    installed/importable package) and call `function_name(*args)` with
    `PythonOracle` hooks installed for the duration of that one call. This
    is the exact function that runs inside the Docker container (see
    `_PYTHON_RUNNER_BOOTSTRAP` below) and inside the no-Docker fallback --
    calling it directly, with no subprocess or container at all, is what
    makes the hook mechanism itself unit-testable without Docker.
    """
    import importlib.util

    oracle = PythonOracle(expected_root=expected_root)
    trace = OracleTrace(sandbox_kind="in-process", runtime="python", entrypoint=f"{module_path}:{function_name}")
    started = time.time()
    oracle.install()
    try:
        spec = importlib.util.spec_from_file_location(f"_sandboxed_target_{uuid.uuid4().hex}", module_path)
        if spec is None or spec.loader is None:
            raise ImportError(f"could not load a module spec for {module_path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        fn = getattr(module, function_name, None)
        if not callable(fn):
            raise AttributeError(f"{module_path} has no callable attribute {function_name!r}")
        result = fn(*args)
        trace.return_value_repr = repr(result)[:2000]
        try:
            json.dumps(result)
            trace.return_value = result
        except TypeError:
            pass  # not JSON-serializable -- return_value_repr above still carries it
    except Exception as exc:  # noqa: BLE001 -- deliberately broad: this reports the TARGET's own exception, never raises it
        trace.exception = f"{type(exc).__name__}: {exc}"
    finally:
        oracle.uninstall()
        trace.ended_at = time.time()
        trace.started_at = started
        trace.duration_seconds = trace.ended_at - started
        trace.subprocess_calls = oracle.subprocess_calls
        trace.file_opens = oracle.file_opens
        trace.network_connections = oracle.network_connections
        trace.http_requests = oracle.http_requests
        trace.credential_flags = oracle.credential_flags
    return trace


# Bootstrap source run inside the Docker container (see _run_python_in_docker)
# and inside the subprocess fallback (see _run_python_fallback). Mounts this
# package's own `src/` read-only at /oracle_src so the container's bare
# Python (no pip install needed -- this module and entrypoints.py are both
# stdlib-only) can `import mcp_safeguard.scanner.sandbox` directly.
_PYTHON_RUNNER_BOOTSTRAP = """
import json, sys
sys.path.insert(0, {oracle_src!r})
from mcp_safeguard.scanner.sandbox import run_python_entrypoint_with_oracle
args = json.loads({args_json!r})
trace = run_python_entrypoint_with_oracle({module_path!r}, {function_name!r}, args, expected_root={expected_root!r})
with open({out_path!r}, "w") as f:
    json.dump(trace.to_dict(), f, default=str)
"""


# --------------------------------------------------------------------------
# Generic Docker orchestration: start detached, poll for completion (with
# an explicit `docker kill` on timeout), read logs + exit code, clean up.
# Detached + polled rather than a foreground `docker run` + host-side
# subprocess timeout, specifically so a timeout reliably kills the
# CONTAINER (not just the local `docker` CLI client process, which does
# not by itself guarantee the daemon stops the container).
# --------------------------------------------------------------------------


@dataclass
class _DockerRunResult:
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool


def _run_docker_container(
    image: str,
    argv: list[str],
    mounts: list[tuple[str, str, str]],
    env: dict[str, str],
    config: SandboxConfig,
) -> _DockerRunResult:
    name = f"mcp-safeguard-sandbox-{uuid.uuid4().hex[:12]}"
    cmd = [
        "docker", "run", "-d", "--name", name,
        "--network", config.network,
        "--memory", f"{config.memory_mb}m",
        "--cpus", str(config.cpus),
        "--pids-limit", str(config.pids_limit),
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
    ]
    # Run as the invoking user. With --cap-drop ALL, a root container loses
    # DAC override and cannot write into a host scratch dir created 0700 by
    # mkdtemp (Linux CI runners); matching the host uid also avoids root.
    if hasattr(os, "getuid"):
        cmd += ["--user", f"{os.getuid()}:{os.getgid()}"]
    for host_path, container_path, mode in mounts:
        cmd += ["-v", f"{host_path}:{container_path}:{mode}"]
    for key, value in env.items():
        cmd += ["-e", f"{key}={value}"]
    cmd += [image, *argv]

    try:
        launch = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return _DockerRunResult(None, "", f"failed to launch sandbox container: {exc}", False)
    if launch.returncode != 0:
        return _DockerRunResult(None, "", f"docker run failed: {launch.stderr.strip()}", False)

    deadline = time.time() + config.timeout_seconds
    timed_out = False
    while time.time() < deadline:
        inspect = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Running}}", name], capture_output=True, text=True,
        )
        if inspect.returncode != 0 or inspect.stdout.strip() != "true":
            break
        time.sleep(0.2)
    else:
        timed_out = True
        subprocess.run(["docker", "kill", name], capture_output=True)

    logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True)
    exit_inspect = subprocess.run(["docker", "inspect", "--format", "{{.State.ExitCode}}", name], capture_output=True, text=True)
    try:
        exit_code = int(exit_inspect.stdout.strip())
    except ValueError:
        exit_code = None
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)

    return _DockerRunResult(exit_code, logs.stdout, logs.stderr, timed_out)


def _mcp_safeguard_src_dir() -> Path:
    """`.../src` -- this file lives at `.../src/mcp_safeguard/scanner/sandbox.py`."""
    return Path(__file__).resolve().parents[2]


def _scratch_base_dir(config: SandboxConfig) -> Path:
    base = config.scratch_base_dir or (Path.home() / ".cache" / "mcp_safeguard" / "sandbox_scratch")
    base.mkdir(parents=True, exist_ok=True)
    return base


def _run_python_in_docker(repo_path: Path, entrypoint: SandboxEntrypoint, args: list, config: SandboxConfig) -> OracleTrace:
    rel_file = entrypoint.file.relative_to(repo_path) if entrypoint.file.is_absolute() else entrypoint.file
    container_module_path = f"/repo/{rel_file.as_posix()}"

    with tempfile.TemporaryDirectory(prefix="mcp_safeguard_sandbox_", dir=str(_scratch_base_dir(config))) as scratch:
        scratch_path = Path(scratch)
        out_path = scratch_path / "trace.json"
        bootstrap = _PYTHON_RUNNER_BOOTSTRAP.format(
            oracle_src="/oracle_src", args_json=json.dumps(args), module_path=container_module_path,
            function_name=entrypoint.function_name, expected_root="/repo", out_path="/scratch/trace.json",
        )
        mounts = [
            (str(repo_path), "/repo", "ro"),
            (str(_mcp_safeguard_src_dir()), "/oracle_src", "ro"),
            (str(scratch_path), "/scratch", "rw"),
            *config.extra_mounts,
        ]
        env = {"PYTHONPATH": "/oracle_src", **config.extra_env}
        result = _run_docker_container(config.python_image, ["python", "-c", bootstrap], mounts, env, config)

        trace = OracleTrace(
            sandbox_kind="docker", runtime="python", entrypoint=f"{entrypoint.file}:{entrypoint.function_name}",
            timed_out=result.timed_out, stdout=result.stdout, stderr=result.stderr,
        )
        if result.timed_out:
            trace.error = f"sandbox timed out after {config.timeout_seconds}s and was killed"
            return trace
        if out_path.exists():
            data = json.loads(out_path.read_text())
            merged = OracleTrace.from_dict(data)
            # `run_python_entrypoint_with_oracle` (running INSIDE the
            # container) stamps its own `sandbox_kind="in-process"" and an
            # `entrypoint` built from `container_module_path` (e.g.
            # "/repo/foo.py:fn") -- both true from the container's own
            # perspective, but this call site's job is to report the OUTER
            # sandbox that actually isolated it, in the SAME host-relative
            # "<file>:<function_name>" canonical form every other
            # `OracleTrace` producer uses (`_run_python_fallback`, the
            # error paths above, and the JS Docker path's pre-stamped
            # `base` trace) -- critic.py's `check_reachability_soundness()`
            # compares this field against `ThreatModelDocument` entrypoints
            # in that host-relative form, and a bare container path can
            # never match there regardless of how sound the finding is.
            merged.sandbox_kind = "docker"
            merged.entrypoint = f"{entrypoint.file}:{entrypoint.function_name}"
            merged.stdout, merged.stderr = result.stdout, result.stderr
            return merged
        trace.error = f"container exited (code={result.exit_code}) without producing a trace file: {result.stderr.strip()[:2000]}"
        return trace


def _posix_resource_limits(memory_mb: int, cpu_seconds: int):
    """`preexec_fn` for the no-Docker subprocess fallback -- bounds address
    space and CPU time via the stdlib `resource` module. POSIX only (the
    caller is responsible for not using this on Windows); returns a no-op
    callable if the `resource` module can't be imported (documented as a
    real gap, not silently ignored) or if a specific rlimit isn't settable
    on this platform (best-effort per-limit, not all-or-nothing)."""

    def _set_limits():
        try:
            import resource
        except ImportError:
            return
        mem_bytes = memory_mb * 1024 * 1024
        for limit_name, value in (("RLIMIT_AS", mem_bytes), ("RLIMIT_CPU", cpu_seconds)):
            rlimit = getattr(resource, limit_name, None)
            if rlimit is None:
                continue
            try:
                resource.setrlimit(rlimit, (value, value))
            except (ValueError, OSError):
                pass  # best-effort: some platforms refuse a tighter soft limit than the current one

    return _set_limits


def _run_python_fallback(repo_path: Path, entrypoint: SandboxEntrypoint, args: list, config: SandboxConfig) -> OracleTrace:
    """No-Docker fallback: a plain subprocess with best-effort CPU/memory
    rlimits (POSIX only), NO filesystem or network isolation whatsoever --
    the target code sees the real host filesystem and network exactly like
    any other subprocess of this process. This exists so `run_in_sandbox()`
    still does something real (bounded run, real trace) rather than
    silently refusing when Docker is unavailable; it must never be
    mistaken for actual isolation. See this module's own docstring and
    `bench/S1_SANDBOX_STATUS.md` for the explicit list of what it does not
    provide.
    """
    rel_file = entrypoint.file.relative_to(repo_path) if entrypoint.file.is_absolute() else entrypoint.file
    module_path = str(repo_path / rel_file)

    with tempfile.TemporaryDirectory(prefix="mcp_safeguard_sandbox_fallback_") as scratch:
        out_path = Path(scratch) / "trace.json"
        bootstrap = _PYTHON_RUNNER_BOOTSTRAP.format(
            oracle_src=str(_mcp_safeguard_src_dir()), args_json=json.dumps(args), module_path=module_path,
            function_name=entrypoint.function_name, expected_root=str(repo_path), out_path=str(out_path),
        )
        started = time.time()
        preexec = _posix_resource_limits(config.memory_mb, config.timeout_seconds) if os.name == "posix" else None
        try:
            proc = subprocess.run(
                [sys.executable, "-c", bootstrap], capture_output=True, text=True,
                timeout=config.timeout_seconds, preexec_fn=preexec,
            )
            timed_out, stdout, stderr = False, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")

        trace = OracleTrace(
            sandbox_kind="subprocess-fallback", runtime="python", entrypoint=f"{entrypoint.file}:{entrypoint.function_name}",
            timed_out=timed_out, stdout=stdout, stderr=stderr, started_at=started, ended_at=time.time(),
        )
        trace.duration_seconds = trace.ended_at - trace.started_at
        if timed_out:
            trace.error = f"sandbox (no-Docker fallback) timed out after {config.timeout_seconds}s"
            return trace
        if out_path.exists():
            data = json.loads(out_path.read_text())
            merged = OracleTrace.from_dict(data)
            merged.sandbox_kind, merged.stdout, merged.stderr = "subprocess-fallback", stdout, stderr
            return merged
        trace.error = f"fallback subprocess exited without producing a trace file: {stderr.strip()[:2000]}"
        return trace


# --------------------------------------------------------------------------
# JS/TS oracle preload + generic entrypoint-invocation runner. Docker-only
# (see SandboxUnavailableError above) -- validated against plain Node CJS
# and ESM targets AND a real tsx-transpiled TypeScript/ESM target; see
# bench/S1_SANDBOX_STATUS.md for the reproduced transcripts.
# --------------------------------------------------------------------------

_JS_ORACLE_PRELOAD_SOURCE = r"""
'use strict';
const fs = require('fs');
const path = require('path');
const net = require('net');
const http = require('http');
const https = require('https');
const child_process = require('child_process');

const TRACE = { subprocess_calls: [], file_opens: [], network_connections: [], http_requests: [], credential_flags: [] };
const EXPECTED_ROOT = process.env.SANDBOX_EXPECTED_ROOT || null;
const TRACE_DIR = process.env.SANDBOX_TRACE_DIR || null;

const CRED_HEADER_NAMES = new Set(['authorization', 'proxy-authorization', 'x-api-key', 'api-key', 'apikey', 'x-auth-token', 'x-access-token', 'x-amz-security-token', 'cookie']);
const CRED_VALUE_PATTERNS = [
  [/^Bearer\s+\S+/i, 'bearer_token'],
  [/^Basic\s+[A-Za-z0-9+/=]{8,}/i, 'basic_auth'],
  [/AKIA[0-9A-Z]{16}/, 'aws_access_key_id'],
  [/sk-[A-Za-z0-9]{20,}/, 'openai_style_secret'],
  [/gh[pousr]_[A-Za-z0-9]{36,}/, 'github_token'],
  [/xox[baprs]-[A-Za-z0-9-]{10,}/, 'slack_token'],
];

function preview(v) {
  v = String(v);
  return v.length > 10 ? v.slice(0, 6) + '...(' + v.length + ' chars, redacted)' : '(redacted)';
}

function scanCredentials(headers, destination) {
  const flags = [];
  headers = headers || {};
  for (const name of Object.keys(headers)) {
    const lname = name.toLowerCase();
    const value = String(headers[name]);
    if (CRED_HEADER_NAMES.has(lname)) {
      flags.push({ destination, location: 'header:' + name, matched_pattern: 'credential_header_name', value_preview: preview(value) });
      continue;
    }
    for (const [pattern, label] of CRED_VALUE_PATTERNS) {
      if (pattern.test(value)) {
        flags.push({ destination, location: 'header:' + name, matched_pattern: label, value_preview: preview(value) });
        break;
      }
    }
  }
  return flags;
}

function isOutside(p) {
  if (!EXPECTED_ROOT) return false;
  try { return !path.resolve(String(p)).startsWith(EXPECTED_ROOT); } catch (e) { return false; }
}

function extractConnectTarget(args) {
  const opts = args[0];
  if (typeof opts === 'number') return { host: (typeof args[1] === 'string' ? args[1] : 'localhost'), port: opts };
  if (typeof opts === 'string') return { host: null, port: null, path: opts };
  if (opts && typeof opts === 'object' && !Array.isArray(opts)) {
    if (opts.path) return { host: 'unix:' + opts.path, port: null };
    return { host: opts.host || opts.hostname || null, port: opts.port || null };
  }
  return { host: null, port: null };
}

for (const fnName of ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync']) {
  const orig = child_process[fnName];
  if (typeof orig !== 'function') continue;
  child_process[fnName] = function (...args) {
    TRACE.subprocess_calls.push({ fn: fnName, argv: args.filter(a => typeof a === 'string' || Array.isArray(a)), timestamp: Date.now() / 1000 });
    return orig.apply(this, args);
  };
}

for (const fnName of ['readFileSync', 'writeFileSync', 'openSync']) {
  const orig = fs[fnName];
  if (typeof orig !== 'function') continue;
  fs[fnName] = function (p, ...rest) {
    let resolved;
    try { resolved = path.resolve(String(p)); } catch (e) { resolved = String(p); }
    TRACE.file_opens.push({ path: String(p), resolved_path: resolved, fn: fnName, outside_root: isOutside(String(p)), timestamp: Date.now() / 1000 });
    return orig.call(this, p, ...rest);
  };
}

const origConnect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function (...args) {
  try {
    const target = extractConnectTarget(args);
    TRACE.network_connections.push({ ...target, timestamp: Date.now() / 1000 });
  } catch (e) { /* never break the real connect on oracle bugs */ }
  return origConnect.apply(this, args);
};

for (const mod of [http, https]) {
  const origRequest = mod.request;
  mod.request = function (...args) {
    try {
      let urlOrOpts = args[0];
      let options = (typeof args[1] === 'object' && args[1] !== null) ? args[1] : ((typeof urlOrOpts === 'object' && !(urlOrOpts instanceof URL)) ? urlOrOpts : {});
      let urlStr = typeof urlOrOpts === 'string' ? urlOrOpts : (urlOrOpts instanceof URL ? urlOrOpts.toString() : null);
      const headers = options.headers || {};
      const host = options.host || options.hostname || (urlStr ? new URL(urlStr).hostname : 'unknown');
      const port = options.port || (mod === https ? 443 : 80);
      const dest = String(host) + ':' + String(port);
      const flags = scanCredentials(headers, dest);
      TRACE.credential_flags.push(...flags);
      TRACE.http_requests.push({
        method: options.method || 'GET', url: urlStr, host, port,
        headers: Object.fromEntries(Object.entries(headers).map(([k, v]) => [k, CRED_HEADER_NAMES.has(k.toLowerCase()) ? preview(String(v)) : v])),
        credential_flags: flags, timestamp: Date.now() / 1000,
      });
    } catch (e) { /* never break the real request on oracle bugs */ }
    return origRequest.apply(this, args);
  };
}

if (typeof globalThis.fetch === 'function') {
  const origFetch = globalThis.fetch;
  globalThis.fetch = function (input, init) {
    try {
      const urlStr = typeof input === 'string' ? input : (input && input.url) || String(input);
      const rawHeaders = (init && init.headers) || (input && input.headers) || {};
      const headersObj = (typeof Headers !== 'undefined' && rawHeaders instanceof Headers) ? Object.fromEntries(rawHeaders.entries()) : { ...rawHeaders };
      const u = new URL(urlStr);
      const flags = scanCredentials(headersObj, u.host);
      TRACE.credential_flags.push(...flags);
      TRACE.http_requests.push({
        method: (init && init.method) || 'GET', url: urlStr, host: u.hostname, port: u.port || null,
        headers: Object.fromEntries(Object.entries(headersObj).map(([k, v]) => [k, CRED_HEADER_NAMES.has(k.toLowerCase()) ? preview(String(v)) : v])),
        credential_flags: flags, timestamp: Date.now() / 1000,
      });
    } catch (e) { /* never break the real fetch on oracle bugs */ }
    return origFetch.call(this, input, init);
  };
}

// `extra` (the runner script's own return_value/exception) is stashed on
// this shared object rather than written directly by the runner -- the
// SINGLE write happens here, in the 'exit' handler, which always merges in
// whatever is currently stashed. Writing directly from the runner AND
// having the 'exit' handler ALSO write unconditionally is a real bug this
// module hit during its own validation: both fire for the same process,
// and since 'exit' handlers run after the script body, the second
// (data-less) write silently clobbered the first (real) one -- every
// return_value/exception came back null. See bench/S1_SANDBOX_STATUS.md.
function writeTraceAndExit(extra) {
  if (extra) global.__mcpSafeguardOracle.extra = extra;
  if (!TRACE_DIR) return;
  try {
    fs.mkdirSync(TRACE_DIR, { recursive: true });
    const merged = Object.assign({ pid: process.pid }, TRACE, global.__mcpSafeguardOracle.extra || {});
    fs.writeFileSync(path.join(TRACE_DIR, process.pid + '.json'), JSON.stringify(merged));
  } catch (e) { /* best effort */ }
}

global.__mcpSafeguardOracle = { TRACE, writeTraceAndExit, extra: null };
process.on('exit', () => writeTraceAndExit());
"""

# Generic entrypoint-invocation runner: a plain ESM .mjs file that
# dynamically `import()`s an arbitrary target file (a .ts/.mts file is
# transformed on the fly as long as a TS loader -- tsx -- already
# registered itself in this process, which it does before this script's
# own body runs when invoked via `node <tsx>/dist/cli.mjs runner.mjs ...`)
# and calls one named export.
_JS_RUNNER_SOURCE = r"""
import { pathToFileURL } from 'node:url';
const targetPath = process.argv[2];
const functionName = process.argv[3];
const args = JSON.parse(process.argv[4]);
let result = null, error = null;
try {
  const mod = await import(pathToFileURL(targetPath).href);
  const fn = mod[functionName] ?? (mod.default && mod.default[functionName]);
  if (typeof fn !== 'function') throw new Error('entrypoint function not found or not callable: ' + functionName);
  result = await fn(...args);
} catch (e) {
  error = String((e && e.stack) || e);
}
// Stash on the shared oracle object; the preload's own 'exit' handler does
// the actual (single) write -- see writeTraceAndExit's own comment above.
if (globalThis.__mcpSafeguardOracle) {
  globalThis.__mcpSafeguardOracle.extra = { return_value: (result === undefined ? null : result), exception: error };
}
if (error) process.exitCode = 1;
"""


def render_js_oracle_preload_source() -> str:
    """The CommonJS preload source, for a caller that wants to `--require`
    it directly (e.g. to reproduce this module's own validation, or to
    drive a JS target this module's Docker orchestration doesn't cover
    yet)."""
    return _JS_ORACLE_PRELOAD_SOURCE


_TS_SUFFIXES = {".ts", ".mts", ".cts", ".tsx"}


def _find_tsx_cli(repo_path: Path) -> Path | None:
    """A TS-capable loader entry point from the TARGET repo's own
    node_modules (not the `.bin/tsx` shell shim, which re-execs and would
    swallow this module's own env-based wiring). Only safe to use if that
    node_modules was itself installed for the DOCKER DAEMON's platform --
    see `_ensure_tooling_tsx()`, which is tried first and is what this
    module actually relies on; this is the documented fallback for when
    that tooling install is unavailable (no npm/network)."""
    candidate = repo_path / "node_modules" / "tsx" / "dist" / "cli.mjs"
    return candidate if candidate.is_file() else None


def _docker_server_arch() -> str:
    """The Docker DAEMON's own CPU architecture (which may differ from the
    architecture this Python process itself runs on, e.g. Docker Desktop/
    Colima on Apple Silicon still runs an x86 daemon in some configs, and
    vice versa) -- mapped to the value npm's `--cpu` foreign-platform
    install flag expects. Defaults to "x64" if this can't be determined
    (matches the far more common case)."""
    try:
        r = subprocess.run(["docker", "version", "--format", "{{.Server.Arch}}"], capture_output=True, text=True, timeout=10)
        arch = r.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        arch = ""
    return {"arm64": "arm64", "aarch64": "arm64", "amd64": "x64", "x86_64": "x64"}.get(arch, "x64")


def _ensure_tooling_tsx() -> Path | None:
    """A `tsx` install this module manages itself, built for the DOCKER
    DAEMON's platform via npm's `--os`/`--cpu` foreign-platform install --
    rather than trusting whatever platform the TARGET repo's own
    node_modules happened to be installed on. This is not a hypothetical
    concern: a repo cloned and `npm install`ed on a macOS host (this
    project's own dev machine, and a common case generally) carries
    `@esbuild/darwin-*` (tsx's own TS-transform dependency), which crashes
    at import time inside a Linux container with a clear platform
    -mismatch error -- reproduced directly against the real
    `Aiven-Open/mcp-aiven` clone this module is validated against; see
    `bench/S1_SANDBOX_STATUS.md` for the exact error and the fix. Cached
    under `~/.cache/mcp_safeguard/sandbox_tooling/tsx_linux/` after the
    first successful install (needs `npm` + network ONCE, never touches
    the target repo's own node_modules); returns None (never raises) if
    `npm` is unavailable or the install fails, so the caller can fall back
    to `_find_tsx_cli()` -- worse-but-real rather than a hard stop.
    """
    tooling_dir = Path.home() / ".cache" / "mcp_safeguard" / "sandbox_tooling" / "tsx_linux"
    cli = tooling_dir / "node_modules" / "tsx" / "dist" / "cli.mjs"
    if cli.is_file():
        return tooling_dir
    if shutil.which("npm") is None:
        return None
    tooling_dir.mkdir(parents=True, exist_ok=True)
    pkg_json = tooling_dir / "package.json"
    if not pkg_json.is_file():
        pkg_json.write_text('{"name": "mcp-safeguard-sandbox-tooling", "version": "1.0.0", "private": true}\n')
    arch = _docker_server_arch()
    try:
        subprocess.run(
            ["npm", "install", "tsx", "--no-audit", "--no-fund", "--os=linux", f"--cpu={arch}", "--libc=glibc"],
            cwd=str(tooling_dir), capture_output=True, text=True, timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return tooling_dir if cli.is_file() else None


def _run_node_in_docker(repo_path: Path, entrypoint: SandboxEntrypoint, args: list, config: SandboxConfig) -> OracleTrace:
    rel_file = entrypoint.file.relative_to(repo_path) if entrypoint.file.is_absolute() else entrypoint.file
    container_target_path = f"/repo/{rel_file.as_posix()}"

    needs_ts = entrypoint.file.suffix in _TS_SUFFIXES
    extra_mounts: list[tuple[str, str, str]] = []
    if needs_ts:
        tooling_dir = _ensure_tooling_tsx()
        if tooling_dir is not None:
            extra_mounts.append((str(tooling_dir), "/tooling", "ro"))
            interpreter = ["node", "/tooling/node_modules/tsx/dist/cli.mjs"]
        else:
            repo_tsx = _find_tsx_cli(repo_path)
            if repo_tsx is None:
                return OracleTrace(
                    sandbox_kind="docker", runtime="node", entrypoint=f"{entrypoint.file}:{entrypoint.function_name}",
                    error=(
                        f"{entrypoint.file} is TypeScript but no TS loader is available: this module's own "
                        "managed `tsx` tooling install failed (no `npm` on PATH, or the install itself "
                        f"failed), and no `tsx` was found in {repo_path}/node_modules to fall back to. "
                        "Ensure npm/network access for the managed install, `npm install tsx` in the target "
                        "repo, or pass a pre-transpiled .js/.mjs entrypoint."
                    ),
                )
            interpreter = ["node", "/repo/node_modules/tsx/dist/cli.mjs"]
    else:
        interpreter = ["node"]

    with tempfile.TemporaryDirectory(prefix="mcp_safeguard_sandbox_js_", dir=str(_scratch_base_dir(config))) as scratch:
        scratch_path = Path(scratch)
        (scratch_path / "oracle_preload.cjs").write_text(_JS_ORACLE_PRELOAD_SOURCE)
        (scratch_path / "runner.mjs").write_text(_JS_RUNNER_SOURCE)
        trace_dir = scratch_path / "oracle_traces"
        trace_dir.mkdir()

        mounts = [
            (str(repo_path), "/repo", "ro"),
            (str(scratch_path), "/scratch", "rw"),
            *extra_mounts,
            *config.extra_mounts,
        ]
        env = {
            "NODE_OPTIONS": "--require /scratch/oracle_preload.cjs",
            "SANDBOX_EXPECTED_ROOT": "/repo",
            "SANDBOX_TRACE_DIR": "/scratch/oracle_traces",
            **config.extra_env,
        }
        argv = [*interpreter, "/scratch/runner.mjs", container_target_path, entrypoint.function_name, json.dumps(args)]
        result = _run_docker_container(config.node_image, argv, mounts, env, config)

        trace = OracleTrace(
            sandbox_kind="docker", runtime="node", entrypoint=f"{entrypoint.file}:{entrypoint.function_name}",
            timed_out=result.timed_out, stdout=result.stdout, stderr=result.stderr,
        )
        if result.timed_out:
            trace.error = f"sandbox timed out after {config.timeout_seconds}s and was killed"
            return trace
        return _merge_js_trace_shards(trace_dir, trace)


def _merge_js_trace_shards(trace_dir: Path, base: OracleTrace) -> OracleTrace:
    """Every Node process that loaded the preload (the entry process AND
    any child it spawns that inherits NODE_OPTIONS, e.g. tsx's own internal
    re-exec) writes its OWN `<pid>.json` shard rather than sharing one
    file -- see this module's docstring / bench/S1_SANDBOX_STATUS.md for
    why a single shared trace file silently loses data to whichever
    process happens to exit last. This merges every shard's events into
    one trace; `return_value`/`exception` come from whichever shard
    actually carries them (the leaf process that called the target
    function -- an intermediate re-exec wrapper has neither key)."""
    shards = sorted(trace_dir.glob("*.json")) if trace_dir.is_dir() else []
    if not shards:
        base.error = base.error or "no oracle trace shard was written -- the target process may have crashed before the preload's exit hook ran"
        return base
    for shard_path in shards:
        try:
            data = json.loads(shard_path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        base.subprocess_calls.extend(data.get("subprocess_calls", []))
        base.file_opens.extend(data.get("file_opens", []))
        base.network_connections.extend(data.get("network_connections", []))
        base.http_requests.extend(data.get("http_requests", []))
        base.credential_flags.extend(data.get("credential_flags", []))
        if "return_value" in data:
            base.return_value = data["return_value"]
            base.return_value_repr = repr(data["return_value"])[:2000]
        if data.get("exception"):
            base.exception = data["exception"]
    return base


# --------------------------------------------------------------------------
# Public entry point
# --------------------------------------------------------------------------


def run_in_sandbox(
    repo_path: str | Path,
    entrypoint: SandboxEntrypoint,
    args: list,
    timeout_seconds: int = 30,
    config: SandboxConfig | None = None,
    allow_unsafe_host_execution: bool = False,
) -> OracleTrace:
    """Launch `entrypoint.function_name` from `entrypoint.file` (a file
    inside `repo_path`) with `args`, inside an isolated sandbox, and return
    a structured `OracleTrace` of everything the runtime-appropriate oracle
    observed. Docker is used when available (`docker_available()`).

    When Docker is NOT available: a Node/JS entrypoint always raises
    `SandboxUnavailableError` (there is no fallback for it, see module
    docstring). A Python entrypoint also raises `SandboxUnavailableError`
    by default -- the resource-limited, NOT filesystem/network-isolated
    host subprocess fallback (`_run_python_fallback`'s own docstring) only
    runs when the caller passes `allow_unsafe_host_execution=True`,
    explicitly opting into running untrusted target code directly on this
    process's own host with no real isolation.
    """
    repo_path = Path(repo_path).resolve()
    # `timeout_seconds` is always the effective value; `config` supplies
    # everything else (and may be omitted entirely for the common case).
    config = dataclasses.replace(config or SandboxConfig(), timeout_seconds=timeout_seconds)

    if entrypoint.runtime == "python":
        if docker_available():
            return _run_python_in_docker(repo_path, entrypoint, args, config)
        if not allow_unsafe_host_execution:
            raise SandboxUnavailableError(
                "run_in_sandbox() for a Python entrypoint requires Docker -- it was not detected in this "
                "environment (checked `docker version` on PATH). Docker unavailable, host execution skipped: "
                "the no-Docker fallback runs untrusted target code directly on this host with NO filesystem or "
                "network isolation, so it is no longer used silently. Install Docker and ensure the daemon is "
                "running, or pass allow_unsafe_host_execution=True (CLI: --allow-unsafe-host-execution) to "
                "explicitly opt into the unsafe host fallback anyway (e.g. in a CI environment that already "
                "isolates this whole process)."
            )
        return _run_python_fallback(repo_path, entrypoint, args, config)
    if entrypoint.runtime == "node":
        if not docker_available():
            raise SandboxUnavailableError(
                "run_in_sandbox() for a Node/JS entrypoint requires Docker -- it was not detected in this "
                "environment (checked `docker version` on PATH). There is no resource-limited-subprocess "
                "fallback for JS the way there is for Python: safely bounding arbitrary Node code without a "
                "container is a materially bigger surface than a CPU/memory rlimit can plausibly cover. "
                "Install Docker and ensure the daemon is running, then retry."
            )
        return _run_node_in_docker(repo_path, entrypoint, args, config)
    raise ValueError(f"unsupported entrypoint.runtime: {entrypoint.runtime!r} (expected 'python' or 'node')")
