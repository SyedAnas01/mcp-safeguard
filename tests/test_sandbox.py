"""Tests for the Stage 5 execution sandbox + oracle (scanner/sandbox.py).

Per the module's own docstring, the hook mechanisms are the novel piece and
must be verifiable without a container runtime present -- most tests below
call `PythonOracle`/`run_python_entrypoint_with_oracle` directly, in-process,
with no subprocess or Docker involved at all. A smaller set of tests drives
the real `docker`/`node` CLIs (skipped when either is unavailable) to prove
the full `run_in_sandbox()` path and the JS preload for real, not just in
theory.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import textwrap
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from mcp_safeguard.scanner.entrypoints import McpEntrypoint
from mcp_safeguard.scanner.sandbox import (
    OracleTrace,
    PythonOracle,
    SandboxEntrypoint,
    SandboxUnavailableError,
    _scan_credentials,
    detect_runtime,
    docker_available,
    render_js_oracle_preload_source,
    run_in_sandbox,
    run_python_entrypoint_with_oracle,
)

pytestmark_docker = pytest.mark.skipif(not docker_available(), reason="docker not available")
pytestmark_node = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")


@pytest.fixture
def docker_tmp_path():
    """Like `tmp_path`, but rooted under the user's home directory instead
    of the OS default temp dir. Needed specifically for the Docker-backed
    tests below: on a Colima-based Docker setup (this project's own dev
    environment -- `docker info` reports the VM, not the host, and
    `~/.colima/default/colima.yaml` confirms only `$HOME` is mounted into
    it by default), a bind mount rooted outside `$HOME` resolves to an
    empty directory INSIDE the container with no error from `docker run` or
    from the container's own reads/writes -- verified directly with a
    `docker run -v <tmp>:/x alpine sh -c "echo hi > /x/f"` whose write a
    host-side `cat` then couldn't find. `SandboxConfig.scratch_base_dir`
    defaults the same way for this module's OWN scratch dirs; this fixture
    gives the *target repo* passed to `run_in_sandbox` the same treatment,
    since a Docker-backed test's `repo_path` needs to be visible inside the
    container too. See bench/S1_SANDBOX_STATUS.md."""
    base = Path.home() / ".cache" / "mcp_safeguard" / "test_scratch"
    base.mkdir(parents=True, exist_ok=True)
    d = Path(tempfile.mkdtemp(dir=base))
    yield d
    shutil.rmtree(d, ignore_errors=True)


def _write(path, text):
    path.write_text(textwrap.dedent(text))


# --------------------------------------------------------------------------
# Runtime detection
# --------------------------------------------------------------------------


def test_detect_runtime_python_marker(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
    info = detect_runtime(tmp_path)
    assert info.kind == "python"
    assert info.confidence == "high"


def test_detect_runtime_node_marker(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    info = detect_runtime(tmp_path)
    assert info.kind == "node"
    assert info.confidence == "high"


def test_detect_runtime_file_count_tiebreak(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "b.py").write_text("x = 1\n")
    (tmp_path / "c.ts").write_text("const x = 1;\n")
    info = detect_runtime(tmp_path)
    assert info.kind == "python"
    assert info.confidence == "medium"


def test_detect_runtime_unknown_when_no_signal(tmp_path):
    info = detect_runtime(tmp_path)
    assert info.kind == "unknown"


# --------------------------------------------------------------------------
# OracleTrace round-trip
# --------------------------------------------------------------------------


def test_oracle_trace_to_dict_from_dict_roundtrip():
    trace = OracleTrace(sandbox_kind="in-process", runtime="python", entrypoint="f.py:g", credential_flags=[{"a": 1}])
    d = trace.to_dict()
    restored = OracleTrace.from_dict(d)
    assert restored == trace


def test_oracle_trace_from_dict_ignores_unknown_keys():
    restored = OracleTrace.from_dict({"sandbox_kind": "docker", "runtime": "node", "entrypoint": "x", "pid": 123, "argv": []})
    assert restored.sandbox_kind == "docker"
    assert not hasattr(restored, "pid")


# --------------------------------------------------------------------------
# SandboxEntrypoint
# --------------------------------------------------------------------------


def test_sandbox_entrypoint_from_mcp_entrypoint(tmp_path):
    ep = McpEntrypoint(file=tmp_path / "server.py", function_name="get_weather", line=3, parameter_names=["city"], sdk_shape="fastmcp_decorator", confidence="high")
    se = SandboxEntrypoint.from_mcp_entrypoint(ep)
    assert se.file == tmp_path / "server.py"
    assert se.function_name == "get_weather"
    assert se.runtime == "python"


# --------------------------------------------------------------------------
# Credential-pattern matching (the specific novel piece)
# --------------------------------------------------------------------------


def test_scan_credentials_flags_authorization_header():
    flags = _scan_credentials({"Authorization": "Bearer abc123supersecrettoken"}, None, "evil.example.com:443")
    assert len(flags) == 1
    assert flags[0]["destination"] == "evil.example.com:443"
    assert flags[0]["matched_pattern"] == "credential_header_name"
    assert "abc123supersecrettoken" not in flags[0]["value_preview"]


def test_scan_credentials_flags_aws_key_in_arbitrary_header():
    flags = _scan_credentials({"X-Debug": "AKIAIOSFODNN7EXAMPLE"}, None, "host:80")
    assert any(f["matched_pattern"] == "aws_access_key_id" for f in flags)


def test_scan_credentials_ignores_benign_headers():
    flags = _scan_credentials({"Content-Type": "application/json", "Accept": "*/*"}, None, "host:80")
    assert flags == []


def test_scan_credentials_flags_body_field():
    flags = _scan_credentials({}, b'{"api_key": "sk-abcdefghijklmnopqrstuvwxyz"}', "host:80")
    assert any(f["location"] == "body:api_key" for f in flags)


# --------------------------------------------------------------------------
# PythonOracle: hook mechanisms in isolation, fully in-process (no
# subprocess, no Docker) -- these are the tests that must pass with no
# container runtime present at all.
# --------------------------------------------------------------------------


def test_python_oracle_captures_subprocess_call():
    oracle = PythonOracle()
    with oracle:
        subprocess.run(["echo", "hi"], capture_output=True)
    assert any(call["argv"] == ["echo", "hi"] for call in oracle.subprocess_calls)


def test_python_oracle_captures_os_system():
    oracle = PythonOracle()
    with oracle:
        __import__("os").system("true")
    assert any("true" in str(call["argv"]) for call in oracle.subprocess_calls)


def test_python_oracle_captures_file_open_inside_and_outside_root(tmp_path):
    inside = tmp_path / "inside.txt"
    inside.write_text("ok")
    outside_root = tmp_path / "sandboxed"
    outside_root.mkdir()

    oracle = PythonOracle(expected_root=outside_root)
    with oracle:
        with open(inside) as f:
            f.read()
    matches = [e for e in oracle.file_opens if e["path"] == str(inside)]
    assert matches
    assert matches[0]["outside_root"] is True


def test_python_oracle_file_open_inside_expected_root_not_flagged(tmp_path):
    target = tmp_path / "inside.txt"
    target.write_text("ok")
    oracle = PythonOracle(expected_root=tmp_path)
    with oracle:
        with open(target) as f:
            f.read()
    matches = [e for e in oracle.file_opens if e["path"] == str(target)]
    assert matches
    assert matches[0]["outside_root"] is False


def test_python_oracle_captures_socket_connect():
    server = HTTPServer(("127.0.0.1", 0), _EchoHandler)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        oracle = PythonOracle()
        with oracle:
            import http.client

            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/")
            conn.getresponse().read()
            conn.close()
        assert any(c["host"] == "127.0.0.1" and c["port"] == port for c in oracle.network_connections)
    finally:
        server.shutdown()


class _EchoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.last_headers = dict(self.headers)
        self.rfile.read(length)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def _run_local_server():
    server = HTTPServer(("127.0.0.1", 0), _EchoHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, t


def test_python_oracle_flags_credential_forwarding_via_requests():
    requests = pytest.importorskip("requests")
    server, _ = _run_local_server()
    port = server.server_port
    try:
        oracle = PythonOracle()
        with oracle:
            requests.post(
                f"http://127.0.0.1:{port}/ingest",
                headers={"Authorization": "Bearer super-secret-token-abc123xyz789"},
                json={"note": "hi"},
                timeout=5,
            )
        assert oracle.credential_flags, oracle.http_requests
        flag = oracle.credential_flags[0]
        assert flag["destination"] == f"127.0.0.1:{port}"
        assert flag["location"] == "header:Authorization"
        assert "super-secret" not in flag["value_preview"]
        assert oracle.http_requests[0]["headers"]["Authorization"] != "Bearer super-secret-token-abc123xyz789"
    finally:
        server.shutdown()


def test_python_oracle_flags_credential_forwarding_via_urllib():
    import urllib.request

    server, _ = _run_local_server()
    port = server.server_port
    try:
        oracle = PythonOracle()
        with oracle:
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/ingest",
                headers={"Authorization": "Bearer another-secret-token-value-999"},
                method="GET",
            )
            urllib.request.urlopen(req, timeout=5).read()
        assert oracle.credential_flags
        assert oracle.credential_flags[0]["destination"] == f"127.0.0.1:{port}"
    finally:
        server.shutdown()


def test_python_oracle_no_false_positive_on_benign_request():
    server, _ = _run_local_server()
    port = server.server_port
    try:
        oracle = PythonOracle()
        with oracle:
            import http.client

            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/", headers={"Accept": "application/json"})
            conn.getresponse().read()
            conn.close()
        assert oracle.credential_flags == []
    finally:
        server.shutdown()


def test_python_oracle_uninstall_restores_originals():
    import builtins
    import http.client
    import socket
    import subprocess as sp

    orig_open, orig_popen, orig_connect = builtins.open, sp.Popen.__init__, socket.socket.connect
    orig_putrequest = http.client.HTTPConnection.putrequest
    oracle = PythonOracle()
    oracle.install()
    oracle.uninstall()
    assert builtins.open is orig_open
    assert sp.Popen.__init__ is orig_popen
    assert socket.socket.connect is orig_connect
    assert http.client.HTTPConnection.putrequest is orig_putrequest


# --------------------------------------------------------------------------
# run_python_entrypoint_with_oracle: the full in-process bootstrap (dynamic
# import by file path + call + hooks), still no subprocess/Docker.
# --------------------------------------------------------------------------


def test_run_python_entrypoint_with_oracle_captures_everything(tmp_path):
    _write(
        tmp_path / "target.py",
        """
        import subprocess

        def do_things(name):
            subprocess.run(["echo", name], capture_output=True)
            with open(__file__) as f:
                f.read()
            return {"greeted": name}
        """,
    )
    trace = run_python_entrypoint_with_oracle(tmp_path / "target.py", "do_things", ["world"], expected_root=tmp_path)
    assert trace.exception is None
    assert trace.return_value == {"greeted": "world"}
    assert any(c["argv"] == ["echo", "world"] for c in trace.subprocess_calls)
    assert any(str(tmp_path / "target.py") == e["path"] for e in trace.file_opens)
    assert all(not e["outside_root"] for e in trace.file_opens)


def test_run_python_entrypoint_with_oracle_records_target_exception(tmp_path):
    _write(tmp_path / "target.py", "def boom():\n    raise ValueError('nope')\n")
    trace = run_python_entrypoint_with_oracle(tmp_path / "target.py", "boom", [])
    assert trace.exception is not None
    assert "ValueError" in trace.exception
    assert "nope" in trace.exception


def test_run_python_entrypoint_with_oracle_missing_function(tmp_path):
    _write(tmp_path / "target.py", "def other():\n    return 1\n")
    trace = run_python_entrypoint_with_oracle(tmp_path / "target.py", "missing_fn", [])
    assert trace.exception is not None
    assert "missing_fn" in trace.exception


def test_run_python_entrypoint_with_oracle_credential_forwarding_synthetic(tmp_path, monkeypatch):
    """The exact scenario the task calls out: a function reads an env var
    named `credential` and sends it to a URL taken from an argument."""
    server, _ = _run_local_server()
    port = server.server_port
    try:
        _write(
            tmp_path / "target.py",
            """
            import os
            import requests

            def forward_credential(url):
                token = os.environ["credential"]
                resp = requests.post(url, headers={"Authorization": f"Bearer {token}"}, json={"note": "hi"}, timeout=5)
                return resp.status_code
            """,
        )
        monkeypatch.setenv("credential", "super-secret-token-abc123xyz789")
        trace = run_python_entrypoint_with_oracle(
            tmp_path / "target.py", "forward_credential", [f"http://127.0.0.1:{port}/ingest"], expected_root=tmp_path,
        )
        assert trace.exception is None
        assert trace.return_value == 200
        assert trace.credential_flags, trace
        flag = trace.credential_flags[0]
        assert flag["destination"] == f"127.0.0.1:{port}"
        assert "super-secret" not in json.dumps(trace.to_dict())
    finally:
        server.shutdown()


# --------------------------------------------------------------------------
# run_in_sandbox(): dispatch + fallback behavior. The no-Docker fallback is
# exercised for real (forcing docker_available() to report False), so this
# passes with no container runtime present.
# --------------------------------------------------------------------------


def test_run_in_sandbox_python_without_docker_refuses_by_default(tmp_path, monkeypatch):
    """Bug 2 regression (see bench/SELF_ATTACK_FIX_STATUS.md): the no-Docker
    Python fallback must never run silently -- it is a real, documented
    host-execution risk (no filesystem/network isolation whatsoever), so
    the default behavior is to refuse, matching the existing Node/JS
    behavior, not to silently execute untrusted target code on the host."""
    import mcp_safeguard.scanner.sandbox as sandbox_mod

    monkeypatch.setattr(sandbox_mod, "docker_available", lambda force_recheck=False: False)
    _write(tmp_path / "target.py", "def add(a, b):\n    return a + b\n")
    entrypoint = SandboxEntrypoint(file=tmp_path / "target.py", function_name="add", runtime="python")
    with pytest.raises(SandboxUnavailableError, match="allow_unsafe_host_execution"):
        run_in_sandbox(tmp_path, entrypoint, [2, 3], timeout_seconds=10)


def test_run_in_sandbox_python_fallback_when_docker_unavailable_and_explicitly_allowed(tmp_path, monkeypatch):
    """The existing (unsafe but now opt-in) fallback behavior must still
    work for a caller that explicitly wants it, e.g. a pre-sandboxed CI
    environment."""
    import mcp_safeguard.scanner.sandbox as sandbox_mod

    monkeypatch.setattr(sandbox_mod, "docker_available", lambda force_recheck=False: False)
    _write(tmp_path / "target.py", "def add(a, b):\n    return a + b\n")
    entrypoint = SandboxEntrypoint(file=tmp_path / "target.py", function_name="add", runtime="python")
    trace = run_in_sandbox(tmp_path, entrypoint, [2, 3], timeout_seconds=10, allow_unsafe_host_execution=True)
    assert trace.sandbox_kind == "subprocess-fallback"
    assert trace.return_value == 5
    assert trace.error is None


def test_run_in_sandbox_node_without_docker_raises(tmp_path, monkeypatch):
    import mcp_safeguard.scanner.sandbox as sandbox_mod

    monkeypatch.setattr(sandbox_mod, "docker_available", lambda force_recheck=False: False)
    entrypoint = SandboxEntrypoint(file=tmp_path / "target.js", function_name="f", runtime="node")
    with pytest.raises(SandboxUnavailableError, match="Docker"):
        run_in_sandbox(tmp_path, entrypoint, [])


# --------------------------------------------------------------------------
# Docker-backed end-to-end (skipped if Docker unavailable).
# --------------------------------------------------------------------------


@pytestmark_docker
def test_run_in_sandbox_python_docker_end_to_end(docker_tmp_path):
    _write(
        docker_tmp_path / "target.py",
        """
        import subprocess

        def handler(name):
            subprocess.run(["echo", name], capture_output=True)
            return {"greeted": name}
        """,
    )
    entrypoint = SandboxEntrypoint(file=docker_tmp_path / "target.py", function_name="handler", runtime="python")
    trace = run_in_sandbox(docker_tmp_path, entrypoint, ["world"], timeout_seconds=30)
    assert trace.error is None, trace.stderr
    assert trace.sandbox_kind == "docker"
    assert trace.return_value == {"greeted": "world"}
    assert any(c["argv"] == ["echo", "world"] for c in trace.subprocess_calls)


@pytestmark_docker
def test_run_in_sandbox_python_docker_network_none_blocks_egress(docker_tmp_path):
    _write(
        docker_tmp_path / "target.py",
        """
        import socket

        def try_connect():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            try:
                s.connect(("1.1.1.1", 80))
                return "connected"
            except OSError as e:
                return f"blocked: {type(e).__name__}"
        """,
    )
    entrypoint = SandboxEntrypoint(file=docker_tmp_path / "target.py", function_name="try_connect", runtime="python")
    trace = run_in_sandbox(docker_tmp_path, entrypoint, [], timeout_seconds=20)
    assert trace.error is None, trace.stderr
    assert trace.return_value.startswith("blocked"), trace.return_value


@pytestmark_docker
def test_run_in_sandbox_python_docker_timeout(docker_tmp_path):
    _write(docker_tmp_path / "target.py", "import time\n\ndef sleep_forever():\n    time.sleep(60)\n")
    entrypoint = SandboxEntrypoint(file=docker_tmp_path / "target.py", function_name="sleep_forever", runtime="python")
    trace = run_in_sandbox(docker_tmp_path, entrypoint, [], timeout_seconds=3)
    assert trace.timed_out is True


# --------------------------------------------------------------------------
# JS oracle preload: hook mechanisms in isolation, driven directly via
# `node --require` (no Docker needed) -- skipped only if node isn't
# installed at all.
# --------------------------------------------------------------------------


@pytestmark_node
def test_js_oracle_preload_captures_subprocess_fs_and_credential_forwarding(tmp_path):
    server, _ = _run_local_server()
    port = server.server_port
    try:
        preload_path = tmp_path / "preload.cjs"
        preload_path.write_text(render_js_oracle_preload_source())

        target_path = tmp_path / "target.mjs"
        target_path.write_text(
            textwrap.dedent(
                f"""
                import {{ execSync }} from 'node:child_process';
                execSync('echo hi_from_node');
                const token = process.env.credential;
                const resp = await fetch('http://127.0.0.1:{port}/ingest', {{
                  method: 'POST',
                  headers: {{ 'Authorization': `Bearer ${{token}}` }},
                  body: JSON.stringify({{note: 'hi'}}),
                }});
                await resp.text();
                """
            )
        )
        trace_dir = tmp_path / "trace_shards"
        env = {
            "SANDBOX_EXPECTED_ROOT": str(tmp_path),
            "SANDBOX_TRACE_DIR": str(trace_dir),
            "NODE_OPTIONS": f"--require {preload_path}",
            "credential": "super-secret-token-abc123xyz789",
            "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
        }
        result = subprocess.run(["node", str(target_path)], env=env, capture_output=True, text=True, timeout=15)
        assert result.returncode == 0, result.stderr

        shards = list(trace_dir.glob("*.json"))
        assert shards
        data = json.loads(shards[0].read_text())
        assert any("echo hi_from_node" in str(c) for c in data["subprocess_calls"])
        assert data["credential_flags"], data
        assert data["credential_flags"][0]["destination"] == f"127.0.0.1:{port}"
        assert "super-secret" not in json.dumps(data)
    finally:
        server.shutdown()


@pytestmark_node
def test_js_oracle_preload_no_false_positive_on_benign_fetch(tmp_path):
    server, _ = _run_local_server()
    port = server.server_port
    try:
        preload_path = tmp_path / "preload.cjs"
        preload_path.write_text(render_js_oracle_preload_source())
        target_path = tmp_path / "target.mjs"
        target_path.write_text(f"await fetch('http://127.0.0.1:{port}/', {{headers: {{'Accept': 'application/json'}}}});\n")
        trace_dir = tmp_path / "trace_shards"
        env = {
            "SANDBOX_TRACE_DIR": str(trace_dir),
            "NODE_OPTIONS": f"--require {preload_path}",
            "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
        }
        result = subprocess.run(["node", str(target_path)], env=env, capture_output=True, text=True, timeout=15)
        assert result.returncode == 0, result.stderr
        data = json.loads(next(trace_dir.glob("*.json")).read_text())
        assert data["credential_flags"] == []
    finally:
        server.shutdown()
