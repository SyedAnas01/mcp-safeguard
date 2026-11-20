"""Tests for the `mcp-safeguard hunt` CLI subcommand (cli.py's `_run_hunt`).

Same style as test_cli.py: call `_run_hunt` directly (not `main()`/sys.argv)
and assert on `capsys`-captured stdout/stderr plus the real ledger file
under `tmp_path`. The one real-Docker end-to-end case is gated the same way
test_sandbox.py/test_pipeline.py gate theirs.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import textwrap
from pathlib import Path

import pytest

from mcp_safeguard.cli import _run_hunt
from mcp_safeguard.scanner.ledger import read_entries
from mcp_safeguard.scanner.sandbox import docker_available

pytestmark_docker = pytest.mark.skipif(not docker_available(), reason="docker not available")


@pytest.fixture
def docker_tmp_path():
    """See test_sandbox.py/test_pipeline.py's own copy of this fixture for
    why a Docker-backed test needs a repo path under `$HOME` on this
    project's Colima-based dev setup."""
    base = Path.home() / ".cache" / "mcp_safeguard" / "test_scratch"
    base.mkdir(parents=True, exist_ok=True)
    d = Path(tempfile.mkdtemp(dir=base))
    yield d
    shutil.rmtree(d, ignore_errors=True)


def _write(path: Path, text: str) -> None:
    path.write_text(textwrap.dedent(text))


def test_hunt_rejects_nonexistent_directory(tmp_path, capsys):
    code = _run_hunt(str(tmp_path / "does_not_exist"), str(tmp_path / "ledger.jsonl"))
    assert code == 1
    assert "not a directory" in capsys.readouterr().err.lower()


def test_hunt_json_output_on_a_repo_with_no_tier_s_findings(tmp_path, capsys):
    """No taint findings at all (a plain, uninteresting repo) -> hunt still
    succeeds cleanly, reports zero findings, writes nothing to the ledger."""
    _write(tmp_path / "server.py", """
        def add(a: int, b: int) -> int:
            return a + b
    """)
    ledger_path = tmp_path / "ledger.jsonl"

    code = _run_hunt(str(tmp_path), str(ledger_path), "json")
    assert code == 0
    data = json.loads(capsys.readouterr().out)
    assert data["findings_scanned"] == 0
    assert data["counts"] == {"confirmed": 0, "refuted": 0, "unconfirmed": 0}
    assert data["outcomes"] == []
    assert not ledger_path.exists()


def test_hunt_json_output_includes_a_real_cost_report(tmp_path, capsys):
    """Cost-instrumentation milestone: `--format json` surfaces the real,
    aggregated cost/time report (scanner/cost.py's `CostTracker.to_dict()`)
    -- the taint-scan stage has a real wall-clock cost even on a repo with
    no findings and no ANTHROPIC_API_KEY."""
    _write(tmp_path / "server.py", """
        def add(a: int, b: int) -> int:
            return a + b
    """)
    ledger_path = tmp_path / "ledger.jsonl"

    code = _run_hunt(str(tmp_path), str(ledger_path), "json")
    assert code == 0
    data = json.loads(capsys.readouterr().out)
    assert data["cost"] is not None
    assert data["cost"]["by_stage"]["taint_scan"]["calls"] == 1
    assert data["cost"]["by_stage"]["taint_scan"]["wall_seconds"] > 0
    assert data["cost"]["totals"]["calls"] == 1


def test_hunt_text_output_includes_a_real_cost_report(tmp_path, capsys):
    _write(tmp_path / "server.py", """
        def add(a: int, b: int) -> int:
            return a + b
    """)
    ledger_path = tmp_path / "ledger.jsonl"

    code = _run_hunt(str(tmp_path), str(ledger_path), "text")
    assert code == 0
    out = capsys.readouterr().out
    assert "cost:" in out
    assert "taint_scan" in out


def test_hunt_text_output_reports_a_non_sandbox_testable_finding(tmp_path, capsys, monkeypatch):
    """A real TAINT-IDOR finding (absence-based, never sandboxed) drives the
    text-format report and the real ledger write path, with no Docker/API
    dependency."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    _write(tmp_path / "server.py", """
        class _Store:
            def get_memory(self, memory_id):
                return {"1": "alice's secret note", "2": "bob's secret note"}[memory_id]


        class _FakeMCP:
            def tool(self, *a, **kw):
                def deco(fn):
                    return fn
                return deco


        mcp = _FakeMCP()
        store = _Store()


        @mcp.tool()
        def get_memory(memory_id: str):
            return store.get_memory(memory_id)
    """)
    ledger_path = tmp_path / "ledger.jsonl"

    code = _run_hunt(str(tmp_path), str(ledger_path), "text", include_low_confidence=True)
    assert code == 0
    out = capsys.readouterr().out
    assert "TAINT-IDOR" in out
    assert "UNCONFIRMED" in out
    assert "confirmed=0" in out

    entries = read_entries(str(ledger_path))
    assert len(entries) == 1
    assert entries[0].claim_card.impossibility_argument is not None


def _write_shell_true_tool(repo: Path) -> None:
    _write(repo / "local_tools.py", """
        import subprocess


        class _FakeMCP:
            def tool(self, *a, **kw):
                def deco(fn):
                    return fn
                return deco


        mcp = _FakeMCP()


        @mcp.tool()
        def LOCAL_RunShellScript(script: str):
            process = subprocess.run(
                script,
                shell=True,
                capture_output=True,
            )
            return process.returncode
    """)


def test_hunt_without_docker_refuses_host_execution_by_default(tmp_path, capsys, monkeypatch):
    """Bug 2 regression (see bench/SELF_ATTACK_FIX_STATUS.md), exercised via
    the real CLI entry point: with Docker unavailable and no explicit
    opt-in, a sandbox-testable finding must be recorded "unconfirmed" with
    an honest refusal note -- never silently executed on the host."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    import mcp_safeguard.scanner.sandbox as sandbox_mod

    monkeypatch.setattr(sandbox_mod, "docker_available", lambda force_recheck=False: False)
    _write_shell_true_tool(tmp_path)
    ledger_path = tmp_path / "ledger.jsonl"

    code = _run_hunt(str(tmp_path), str(ledger_path), "json")
    assert code == 0
    data = json.loads(capsys.readouterr().out)
    assert data["counts"]["confirmed"] == 0
    assert data["outcomes"][0]["verdict"] == "unconfirmed"
    assert "allow_unsafe_host_execution" in data["outcomes"][0]["note"]

    entries = read_entries(str(ledger_path))
    assert len(entries) == 1
    assert entries[0].verdict == "unconfirmed"
    assert entries[0].claim_card.oracle_trace is None


def test_hunt_without_docker_allows_host_execution_with_explicit_flag(tmp_path, capsys, monkeypatch):
    """The existing (unsafe but now opt-in) fallback must still work end to
    end via the CLI when the caller explicitly passes the new flag."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    import mcp_safeguard.scanner.sandbox as sandbox_mod

    monkeypatch.setattr(sandbox_mod, "docker_available", lambda force_recheck=False: False)
    _write_shell_true_tool(tmp_path)
    ledger_path = tmp_path / "ledger.jsonl"

    code = _run_hunt(str(tmp_path), str(ledger_path), "json", allow_unsafe_host_execution=True)
    assert code == 0
    data = json.loads(capsys.readouterr().out)
    assert data["counts"]["confirmed"] == 1
    assert data["outcomes"][0]["verdict"] == "confirmed"

    entries = read_entries(str(ledger_path))
    assert len(entries) == 1
    assert entries[0].verdict == "confirmed"
    assert entries[0].claim_card.oracle_trace.sandbox_kind == "subprocess-fallback"


@pytestmark_docker
def test_hunt_end_to_end_via_cli_confirms_real_command_injection(monkeypatch, docker_tmp_path, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    repo = docker_tmp_path
    _write(repo / "local_tools.py", """
        import subprocess


        class _FakeMCP:
            def tool(self, *a, **kw):
                def deco(fn):
                    return fn
                return deco


        mcp = _FakeMCP()


        @mcp.tool()
        def LOCAL_RunShellScript(script: str):
            process = subprocess.run(
                script,
                shell=True,
                capture_output=True,
            )
            return process.returncode
    """)
    ledger_path = repo / "test_ledger.jsonl"

    code = _run_hunt(str(repo), str(ledger_path), "json", sandbox_timeout=30)
    assert code == 0
    data = json.loads(capsys.readouterr().out)
    assert data["findings_scanned"] == 1
    assert data["counts"]["confirmed"] == 1
    assert data["outcomes"][0]["verdict"] == "confirmed"

    entries = read_entries(str(ledger_path))
    assert len(entries) == 1
    assert entries[0].verdict == "confirmed"
    assert entries[0].claim_card.oracle_trace.sandbox_kind == "docker"
