"""Tests for the S8 polling-based diff-triggered re-scan (scanner/rescan.py).

Real local git repos under `tmp_path` (no network, no `origin` remote --
`_remote_head` fails closed and `_process_one` falls back to comparing
`_resolve_commit(root)`, i.e. plain local HEAD, exactly the "offline" path
documented in the module). `hunt_fn` is a cheap fake throughout, the same
discipline `test_cli_hunt.py`/`fleet_scan.py`'s own tests already use for the
real, expensive, network/Docker-dependent pipeline.

Run directly -- do NOT run the full test suite (this repo's Docker-backed
pipeline/sandbox tests are slow and out of scope for this change):
    .venv/bin/python -m pytest tests/test_rescan.py -q
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from mcp_safeguard.scanner.rescan import (
    DEFAULT_STATE_PATH,
    load_state,
    rescan,
    save_state,
)
from mcp_safeguard.scanner.threat_model import ThreatModelDocument, _cache_path, _resolve_commit


def _git(args: list[str], cwd: Path) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


def _init_repo(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    _git(["init", "--quiet"], root)
    _git(["config", "user.email", "test@example.com"], root)
    _git(["config", "user.name", "Test"], root)


def _commit_all(root: Path, message: str) -> str:
    _git(["add", "-A"], root)
    _git(["commit", "--quiet", "-m", message], root)
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, check=True).stdout.strip()


def _write_tmd_cache(root: Path, commit: str, handler_files: list[Path]) -> None:
    tmd = ThreatModelDocument(
        repo_path=str(root),
        repo_name=root.name,
        commit=commit,
        generated_at="2026-01-01T00:00:00+00:00",
        entrypoints=[
            {
                "file": str(f),
                "function_name": "handle",
                "line": 1,
                "parameter_names": [],
                "sdk_shape": "fastmcp_tool",
                "confidence": "high",
                "declared_authority": None,
                "credential_access": [],
            }
            for f in handler_files
        ],
        claims=[],
    )
    # Build via from_dict-compatible plain dicts so we don't need the real
    # EntrypointProfile import here -- to_dict()/from_dict() round-trip the
    # same shape either way.
    cache_path = _cache_path(root, root.name, commit, None)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(tmd.to_dict()), encoding="utf-8")


@dataclass
class _FakeHuntResult:
    commit: str
    findings_scanned: int = 0
    _counts: dict[str, int] = field(default_factory=lambda: {"confirmed": 0, "refuted": 0, "unconfirmed": 0})

    def counts(self) -> dict[str, int]:
        return self._counts


def _make_fake_hunt_fn(calls: list[Path]):
    def _fake_hunt(root: Path, *, ledger_path):
        calls.append(Path(root))
        return _FakeHuntResult(commit=_resolve_commit(Path(root)))

    return _fake_hunt


def _targets_file(tmp_path: Path, targets: list[Path]) -> Path:
    p = tmp_path / "targets.txt"
    p.write_text("\n".join(str(t) for t in targets) + "\n")
    return p


def test_bootstrap_no_state_no_cache_runs_full_hunt(tmp_path):
    repo = tmp_path / "repo_a"
    _init_repo(repo)
    (repo / "server.py").write_text("def handle():\n    pass\n")
    _commit_all(repo, "init")

    calls: list[Path] = []
    outcomes = rescan(
        _targets_file(tmp_path, [repo]),
        state_path=tmp_path / "state.json",
        ledger_path=tmp_path / "ledger.jsonl",
        hunt_fn=_make_fake_hunt_fn(calls),
    )
    assert len(outcomes) == 1
    assert outcomes[0].action == "baseline_full_hunt"
    assert len(calls) == 1

    state = load_state(tmp_path / "state.json")
    assert str(repo) in state
    assert state[str(repo)]["last_scanned_commit"] == outcomes[0].new_commit


def test_no_change_when_head_unchanged(tmp_path):
    repo = tmp_path / "repo_b"
    _init_repo(repo)
    (repo / "server.py").write_text("def handle():\n    pass\n")
    commit = _commit_all(repo, "init")

    state_path = tmp_path / "state.json"
    save_state({str(repo): {"last_scanned_commit": commit}}, state_path)

    calls: list[Path] = []
    outcomes = rescan(
        _targets_file(tmp_path, [repo]),
        state_path=state_path,
        ledger_path=tmp_path / "ledger.jsonl",
        hunt_fn=_make_fake_hunt_fn(calls),
    )
    assert outcomes[0].action == "no_change"
    assert len(calls) == 0


def test_rehunt_targeted_when_changed_file_touches_cached_handler(tmp_path):
    repo = tmp_path / "repo_c"
    _init_repo(repo)
    handler_file = repo / "server.py"
    handler_file.write_text("def handle():\n    pass\n")
    old_commit = _commit_all(repo, "init")
    _write_tmd_cache(repo, old_commit, [handler_file.resolve()])

    state_path = tmp_path / "state.json"
    save_state({str(repo): {"last_scanned_commit": old_commit}}, state_path)

    # Real change to the exact file the cache says is a handler.
    handler_file.write_text("def handle():\n    return 1\n")
    _commit_all(repo, "change handler")

    calls: list[Path] = []
    outcomes = rescan(
        _targets_file(tmp_path, [repo]),
        state_path=state_path,
        ledger_path=tmp_path / "ledger.jsonl",
        hunt_fn=_make_fake_hunt_fn(calls),
    )
    outcome = outcomes[0]
    assert outcome.action == "rehunt_targeted"
    assert outcome.touched_handlers == ["server.py"]
    assert len(calls) == 1


def test_skips_rehunt_when_only_non_handler_files_change(tmp_path):
    repo = tmp_path / "repo_d"
    _init_repo(repo)
    handler_file = repo / "server.py"
    handler_file.write_text("def handle():\n    pass\n")
    (repo / "README.md").write_text("docs\n")
    old_commit = _commit_all(repo, "init")
    _write_tmd_cache(repo, old_commit, [handler_file.resolve()])

    state_path = tmp_path / "state.json"
    save_state({str(repo): {"last_scanned_commit": old_commit}}, state_path)

    # Only touch README.md -- server.py (the known handler) is untouched.
    (repo / "README.md").write_text("docs updated\n")
    new_commit = _commit_all(repo, "docs only")

    calls: list[Path] = []
    outcomes = rescan(
        _targets_file(tmp_path, [repo]),
        state_path=state_path,
        ledger_path=tmp_path / "ledger.jsonl",
        hunt_fn=_make_fake_hunt_fn(calls),
    )
    outcome = outcomes[0]
    assert outcome.action == "skipped_no_handler_touch"
    assert outcome.changed_files == ["README.md"]
    assert len(calls) == 0

    state = load_state(state_path)
    assert state[str(repo)]["last_scanned_commit"] == new_commit


def test_falls_back_to_full_rehunt_when_no_cached_entrypoint_data(tmp_path):
    repo = tmp_path / "repo_e"
    _init_repo(repo)
    (repo / "server.py").write_text("def handle():\n    pass\n")
    old_commit = _commit_all(repo, "init")
    # Deliberately no _write_tmd_cache() call -- this target was never
    # actually hunt()-ed, only cloned/committed.

    state_path = tmp_path / "state.json"
    save_state({str(repo): {"last_scanned_commit": old_commit}}, state_path)

    (repo / "server.py").write_text("def handle():\n    return 2\n")
    _commit_all(repo, "change")

    calls: list[Path] = []
    outcomes = rescan(
        _targets_file(tmp_path, [repo]),
        state_path=state_path,
        ledger_path=tmp_path / "ledger.jsonl",
        hunt_fn=_make_fake_hunt_fn(calls),
    )
    outcome = outcomes[0]
    assert outcome.action == "rehunt_full_fallback_no_cache"
    assert len(calls) == 1


def test_one_target_failure_does_not_abort_the_batch(tmp_path):
    good = tmp_path / "repo_f"
    _init_repo(good)
    (good / "server.py").write_text("def handle():\n    pass\n")
    _commit_all(good, "init")

    bad_target = "not-a-real-path-and-not-a-git-url"

    calls: list[Path] = []
    outcomes = rescan(
        _targets_file(tmp_path, [Path(bad_target), good]),
        state_path=tmp_path / "state.json",
        ledger_path=tmp_path / "ledger.jsonl",
        hunt_fn=_make_fake_hunt_fn(calls),
    )
    assert outcomes[0].action == "failed"
    assert outcomes[1].action == "baseline_full_hunt"


def test_default_state_path_is_bench_rescan_state_json():
    assert str(DEFAULT_STATE_PATH) == "bench/rescan_state.json"
