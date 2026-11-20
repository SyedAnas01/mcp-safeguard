"""Tests for the cost-instrumentation milestone (scanner/cost.py) and its
wiring into `verify.py`/`hunter.py`/`adversary.py`/`critic.py`/`pipeline.py`.

Real gap this closes: no `ANTHROPIC_API_KEY` has ever existed in this
environment, so `AnthropicVerifier`/`AnthropicHunter`/`AnthropicAdversary`/
`AnthropicCriticVerifier` have never made a real call here -- every one of
their own module docstrings says so. `CostTracker` itself is tested directly
(deterministic, no LLM/network involved at all). Its wiring into the
`AnthropicX` classes is proven by construction only (never a fake/mocked
`.messages.create()` response -- this project's own `AnthropicX` classes are
documented, repeatedly, as "never invoked with a mocked response", and this
test file keeps that discipline). The real end-to-end proof -- that
`CostTracker` correctly aggregates REAL token counts end to end -- uses the
`ManualRecordX` playback backends with real, externally-supplied `"usage"`
dicts, exactly the seam `record_usage_dict` exists for.

The numbers in `_REAL_USAGE_*` below are not invented. They are real
`response.usage`-shaped token counts (model `claude-sonnet-5`) copied
verbatim from this project's own live Claude Code session transcript for
the night this milestone was built (2026-09-07) -- genuine numbers a real
Anthropic API call actually billed, read from
`~/.claude/projects/-Users-mr-syedanas-o1a/<session-id>.jsonl`. They are not
from a live `AnthropicVerifier`/`AnthropicHunter`/`AnthropicAdversary`/
`AnthropicCriticVerifier` call specifically (no `ANTHROPIC_API_KEY` has ever
existed for THIS package to make one of those calls with -- exactly the gap
this milestone closes) -- they are real usage numbers from a real call this
project's own tooling made that same night, plugged in here through the
`ManualRecordX` "externally-supplied usage" seam precisely because it is the
seam that exists for this: a caller with real, already-billed numbers
proving the tracker aggregates them correctly, ready for the day a real key
plugs into the `AnthropicX` classes directly.
"""

from __future__ import annotations

import shutil
import textwrap
import types

import pytest

from mcp_safeguard.scanner.adversary import AnthropicAdversary, ManualRecordAdversary
from mcp_safeguard.scanner.claim_card import ClaimCard
from mcp_safeguard.scanner.cost import CostEntry, CostTracker
from mcp_safeguard.scanner.critic import AnthropicCriticVerifier
from mcp_safeguard.scanner.hunter import (
    AnthropicHunter,
    ManualRecordHunter,
    TaintShapedHunter,
    run_hunter_fleet,
)
from mcp_safeguard.scanner.pipeline import hunt, hunt_fleet
from mcp_safeguard.scanner.taint_scanner import run_static_taint_scan
from mcp_safeguard.scanner.verify import AnthropicVerifier, ManualRecordVerifier, build_prompt

pytestmark_semgrep = pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")

# Real, verbatim `response.usage`-shaped token counts from tonight's own
# live session transcript (2026-09-07, model claude-sonnet-5) -- see module
# docstring. Four DISTINCT real tuples so an aggregation test can prove it
# is really summing per-entry, not just echoing one shared value back.
_REAL_MODEL = "claude-sonnet-5"
_REAL_USAGE_A = {"input_tokens": 2, "output_tokens": 4226, "cache_creation_input_tokens": 41761, "cache_read_input_tokens": 42506}
_REAL_USAGE_B = {"input_tokens": 2, "output_tokens": 3298, "cache_creation_input_tokens": 4299, "cache_read_input_tokens": 84267}
_REAL_USAGE_C = {"input_tokens": 2, "output_tokens": 2491, "cache_creation_input_tokens": 1796, "cache_read_input_tokens": 92874}
_REAL_USAGE_D = {"input_tokens": 2, "output_tokens": 610, "cache_creation_input_tokens": 43, "cache_read_input_tokens": 107865}
# A 5th, distinct tuple added by the v10 consolidation merge (see
# bench/FINAL_COMPLETE_V10_STATUS.md) for the sixth-angle-work milestone's
# own new `scope-selector-override` angle, which did not exist when this
# file's original 4-angle A-D tuples were captured from a real transcript --
# unlike those four, this one is a plausible, hand-shaped stand-in (same
# `response.usage` field shape, a distinct value on every field for the same
# "prove real per-entry summation" reason A-D were made distinct), not
# lifted from a real transcript, stated honestly rather than implied
# otherwise.
_REAL_USAGE_E = {"input_tokens": 2, "output_tokens": 1875, "cache_creation_input_tokens": 6320, "cache_read_input_tokens": 51204}
# A 6th, distinct tuple added by the transport-angle milestone for the new
# `transport-and-exposure` angle (hunter.py), which did not exist when the
# A-D tuples were captured -- same "plausible, hand-shaped stand-in, stated
# honestly" precedent as _REAL_USAGE_E above, not lifted from a real
# transcript.
_REAL_USAGE_F = {"input_tokens": 2, "output_tokens": 987, "cache_creation_input_tokens": 12045, "cache_read_input_tokens": 33018}


def _write(path, text):
    path.write_text(textwrap.dedent(text))


def _write_shell_true_tool(repo) -> None:
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
            process = subprocess.run(script, shell=True, capture_output=True)
            return process.returncode
    """)


# --------------------------------------------------------------------------
# CostTracker: direct, deterministic tests -- no LLM/network involved
# --------------------------------------------------------------------------


def test_record_defaults_missing_fields_to_zero_not_none():
    tracker = CostTracker()
    entry = tracker.record("verify", "finding-1")
    assert entry == CostEntry(stage="verify", label="finding-1", model="", input_tokens=0, output_tokens=0,
                               cache_creation_input_tokens=0, cache_read_input_tokens=0, wall_seconds=0.0)
    assert entry.total_tokens == 0


def test_record_from_response_pulls_real_shaped_usage_fields():
    """Simulates exactly what a real `anthropic` SDK response object looks
    like (`response.usage.input_tokens` etc, plain attributes) without
    faking an actual `AnthropicX.verify()`/`.critique()`/etc call -- this
    tests CostTracker's own parsing of a usage object, using the real
    tonight's-session numbers."""
    tracker = CostTracker()
    usage = types.SimpleNamespace(**_REAL_USAGE_A)
    response = types.SimpleNamespace(usage=usage)
    entry = tracker.record_from_response("verify", "server.py:10", _REAL_MODEL, response, wall_seconds=1.5)
    assert entry.input_tokens == _REAL_USAGE_A["input_tokens"]
    assert entry.output_tokens == _REAL_USAGE_A["output_tokens"]
    assert entry.cache_creation_input_tokens == _REAL_USAGE_A["cache_creation_input_tokens"]
    assert entry.cache_read_input_tokens == _REAL_USAGE_A["cache_read_input_tokens"]
    assert entry.model == _REAL_MODEL
    assert entry.wall_seconds == 1.5


def test_record_from_response_treats_missing_usage_fields_as_zero_not_a_crash():
    """An older SDK/account with no prompt-caching support might not
    populate cache_*_input_tokens at all -- must default to 0, never raise."""
    tracker = CostTracker()
    usage = types.SimpleNamespace(input_tokens=5, output_tokens=7)  # no cache_* attrs at all
    response = types.SimpleNamespace(usage=usage)
    entry = tracker.record_from_response("verify", "x", "model", response, wall_seconds=0.1)
    assert entry.input_tokens == 5
    assert entry.output_tokens == 7
    assert entry.cache_creation_input_tokens == 0
    assert entry.cache_read_input_tokens == 0


def test_record_from_response_handles_missing_usage_entirely():
    tracker = CostTracker()
    response = types.SimpleNamespace()  # no .usage attribute at all
    entry = tracker.record_from_response("verify", "x", "model", response, wall_seconds=0.1)
    assert entry.total_tokens == 0


def test_record_usage_dict_is_a_true_noop_when_usage_is_none():
    tracker = CostTracker()
    result = tracker.record_usage_dict("verify", "x", "model", usage=None)
    assert result is None
    assert tracker.totals()["calls"] == 0


def test_record_usage_dict_records_real_supplied_numbers():
    tracker = CostTracker()
    entry = tracker.record_usage_dict("adversary", "server.py:42 -- sink", "manual-recorded[cold-agent-dispatch]", usage=_REAL_USAGE_B)
    assert entry is not None
    assert entry.input_tokens == _REAL_USAGE_B["input_tokens"]
    assert entry.output_tokens == _REAL_USAGE_B["output_tokens"]
    assert entry.cache_creation_input_tokens == _REAL_USAGE_B["cache_creation_input_tokens"]
    assert entry.cache_read_input_tokens == _REAL_USAGE_B["cache_read_input_tokens"]


def test_totals_aggregates_across_multiple_real_entries():
    tracker = CostTracker()
    tracker.record_usage_dict("verify", "a", "m", _REAL_USAGE_A)
    tracker.record_usage_dict("adversary", "b", "m", _REAL_USAGE_B)
    totals = tracker.totals()
    assert totals["calls"] == 2
    assert totals["output_tokens"] == _REAL_USAGE_A["output_tokens"] + _REAL_USAGE_B["output_tokens"]
    assert totals["cache_read_input_tokens"] == _REAL_USAGE_A["cache_read_input_tokens"] + _REAL_USAGE_B["cache_read_input_tokens"]


def test_by_stage_groups_entries_by_their_own_stage():
    tracker = CostTracker()
    tracker.record_usage_dict("verify", "a", "m", _REAL_USAGE_A)
    tracker.record_usage_dict("verify", "b", "m", _REAL_USAGE_B)
    tracker.record_usage_dict("adversary", "c", "m", _REAL_USAGE_C)
    by_stage = tracker.by_stage()
    assert set(by_stage) == {"verify", "adversary"}
    assert by_stage["verify"]["calls"] == 2
    assert by_stage["verify"]["output_tokens"] == _REAL_USAGE_A["output_tokens"] + _REAL_USAGE_B["output_tokens"]
    assert by_stage["adversary"]["calls"] == 1
    assert by_stage["adversary"]["output_tokens"] == _REAL_USAGE_C["output_tokens"]


def test_to_dict_shape_carries_totals_by_stage_and_raw_entries():
    tracker = CostTracker()
    tracker.record_usage_dict("critic", "server.py:1", "claude-opus-5", _REAL_USAGE_D)
    data = tracker.to_dict()
    assert data["totals"]["calls"] == 1
    assert data["by_stage"]["critic"]["output_tokens"] == _REAL_USAGE_D["output_tokens"]
    assert len(data["entries"]) == 1
    assert data["entries"][0]["label"] == "server.py:1"
    assert data["entries"][0]["cache_read_input_tokens"] == _REAL_USAGE_D["cache_read_input_tokens"]


def test_report_says_no_calls_when_empty():
    assert "no instrumented API calls" in CostTracker().report()


def test_report_includes_real_totals_and_per_stage_breakdown():
    tracker = CostTracker()
    tracker.record_usage_dict("verify", "a", "m", _REAL_USAGE_A)
    tracker.record("taint_scan", "repo", wall_seconds=0.25)
    report = tracker.report()
    assert str(_REAL_USAGE_A["output_tokens"]) in report
    assert "taint_scan" in report
    assert "verify" in report


def test_entries_snapshot_is_a_copy_not_the_live_list():
    tracker = CostTracker()
    tracker.record("verify", "a")
    snapshot = tracker.entries
    tracker.record("verify", "b")
    assert len(snapshot) == 1  # the earlier snapshot must not see the later record


# --------------------------------------------------------------------------
# AnthropicX construction: `cost_tracker` is stored, never used to make (or
# fake) a real call here -- see module docstring on why this file never
# mocks `.messages.create()`.
# --------------------------------------------------------------------------


def test_anthropic_verifier_stores_the_cost_tracker_it_is_given():
    tracker = CostTracker()
    verifier = AnthropicVerifier(api_key="fake-test-key-not-a-real-credential", cost_tracker=tracker)
    assert verifier._cost_tracker is tracker


def test_anthropic_hunter_stores_the_cost_tracker_it_is_given():
    tracker = CostTracker()
    hunter = AnthropicHunter(api_key="fake-test-key-not-a-real-credential", cost_tracker=tracker)
    assert hunter._cost_tracker is tracker


def test_anthropic_adversary_stores_the_cost_tracker_it_is_given():
    tracker = CostTracker()
    adversary = AnthropicAdversary(api_key="fake-test-key-not-a-real-credential", cost_tracker=tracker)
    assert adversary._cost_tracker is tracker


def test_anthropic_critic_verifier_stores_the_cost_tracker_it_is_given():
    tracker = CostTracker()
    critic = AnthropicCriticVerifier(api_key="fake-test-key-not-a-real-credential", cost_tracker=tracker)
    assert critic._cost_tracker is tracker


# --------------------------------------------------------------------------
# ManualRecordX + real supplied usage: the actual "prove it works" proof.
# --------------------------------------------------------------------------


@pytestmark_semgrep
def test_manual_record_verifier_is_a_true_noop_without_supplied_usage(tmp_path):
    _write(tmp_path / "server.py", """
        import subprocess

        @mcp.tool()
        def run_it(cmd: str) -> str:
            process = subprocess.run(cmd, shell=True, capture_output=True)
            return process.stdout
    """)
    findings = run_static_taint_scan(tmp_path)
    finding = next(f for f in findings if f.rule_id == "TAINT-CMDI")
    prompt = build_prompt(finding, tmp_path)
    line = next(s["line"] for s in finding.taint_path if s["kind"] == "sink")
    recorded = {prompt.finding_key: [{
        "q1_reachable": {"answer": "yes", "cited_lines": [line], "reasoning": "reaches sink"},
        "q2_neutralized": {"answer": "no", "cited_lines": [line], "reasoning": "no sanitizer"},
        "q3_example_input": {"input": "; id", "cited_lines": [line], "reasoning": "shell sink"},
        "q4_non_issue_condition": {"condition": "shell=False", "cited_lines": [line]},
        # deliberately NO "usage" key -- must be a true no-op
    }]}
    tracker = CostTracker()
    verifier = ManualRecordVerifier(recorded=recorded, cost_tracker=tracker)
    result = verifier.verify(finding, tmp_path)
    assert result.verdict == "confirmed"  # the real playback behavior is unaffected
    assert tracker.totals()["calls"] == 0


@pytestmark_semgrep
def test_manual_record_verifier_records_real_supplied_usage_numbers(tmp_path):
    _write(tmp_path / "server.py", """
        import subprocess

        @mcp.tool()
        def run_it(cmd: str) -> str:
            process = subprocess.run(cmd, shell=True, capture_output=True)
            return process.stdout
    """)
    findings = run_static_taint_scan(tmp_path)
    finding = next(f for f in findings if f.rule_id == "TAINT-CMDI")
    prompt = build_prompt(finding, tmp_path)
    line = next(s["line"] for s in finding.taint_path if s["kind"] == "sink")
    recorded = {prompt.finding_key: [{
        "q1_reachable": {"answer": "yes", "cited_lines": [line], "reasoning": "reaches sink"},
        "q2_neutralized": {"answer": "no", "cited_lines": [line], "reasoning": "no sanitizer"},
        "q3_example_input": {"input": "; id", "cited_lines": [line], "reasoning": "shell sink"},
        "q4_non_issue_condition": {"condition": "shell=False", "cited_lines": [line]},
        "usage": _REAL_USAGE_A,
    }]}
    tracker = CostTracker()
    verifier = ManualRecordVerifier(recorded=recorded, cost_tracker=tracker)
    result = verifier.verify(finding, tmp_path)
    assert result.verdict == "confirmed"  # cost recording must never change the real verdict
    totals = tracker.totals()
    assert totals["calls"] == 1
    assert totals["output_tokens"] == _REAL_USAGE_A["output_tokens"]
    assert totals["cache_read_input_tokens"] == _REAL_USAGE_A["cache_read_input_tokens"]
    assert tracker.by_stage()["verify"]["calls"] == 1


def test_manual_record_hunter_records_real_supplied_usage_numbers(tmp_path):
    _write(tmp_path / "server.py", "def f(x):\n    return x\n")
    key = f"credential-and-secrets@{tmp_path.resolve()}"
    recorded = {key: [{"candidates": [], "no_finding_reasoning": "nothing found", "usage": _REAL_USAGE_B}]}
    tracker = CostTracker()
    hunter = ManualRecordHunter(recorded, cost_tracker=tracker)
    cards = hunter.hunt("credential-and-secrets", tmp_path)
    assert cards == []
    totals = tracker.totals()
    assert totals["calls"] == 1
    assert totals["output_tokens"] == _REAL_USAGE_B["output_tokens"]
    assert tracker.by_stage()["hunter:credential-and-secrets"]["cache_creation_input_tokens"] == _REAL_USAGE_B["cache_creation_input_tokens"]


def test_manual_record_hunter_is_a_true_noop_without_supplied_usage(tmp_path):
    _write(tmp_path / "server.py", "def f(x):\n    return x\n")
    key = f"credential-and-secrets@{tmp_path.resolve()}"
    recorded = {key: [{"candidates": [], "no_finding_reasoning": "nothing found"}]}
    tracker = CostTracker()
    hunter = ManualRecordHunter(recorded, cost_tracker=tracker)
    hunter.hunt("credential-and-secrets", tmp_path)
    assert tracker.totals()["calls"] == 0


def _placeholder_card(target_sink: str) -> ClaimCard:
    return ClaimCard(
        target_sink=target_sink,
        tainted_source="placeholder",
        caller_authority_assumed="placeholder",
        precondition="placeholder",
        violated_claim="placeholder",
        impossibility_argument="test fixture -- no execution oracle",
    )


def test_manual_record_adversary_records_real_supplied_usage_numbers():
    card = _placeholder_card("server.py:42 -- credential forwarded to caller-controlled host")
    recorded = {card.target_sink: [{"verdict": "refuted", "reasoning": "neutralized", "model": "cold-agent", "usage": _REAL_USAGE_C}]}
    tracker = CostTracker()
    adversary = ManualRecordAdversary(recorded, cost_tracker=tracker)
    result = adversary.adjudicate(card)
    assert result.verdict == "refuted"
    totals = tracker.totals()
    assert totals["calls"] == 1
    assert totals["output_tokens"] == _REAL_USAGE_C["output_tokens"]
    assert tracker.by_stage()["adversary"]["cache_read_input_tokens"] == _REAL_USAGE_C["cache_read_input_tokens"]


def test_manual_record_adversary_is_a_true_noop_without_supplied_usage():
    card = _placeholder_card("server.py:1 -- placeholder")
    recorded = {card.target_sink: [{"verdict": "unconfirmed", "reasoning": "n/a", "model": "cold-agent"}]}
    tracker = CostTracker()
    adversary = ManualRecordAdversary(recorded, cost_tracker=tracker)
    adversary.adjudicate(card)
    assert tracker.totals()["calls"] == 0


# --------------------------------------------------------------------------
# Integration: one shared CostTracker across a real taint-scan wall-time
# measurement (TaintShapedHunter) and real supplied usage for all 5
# LLM-backed hunter-fleet angles (ManualRecordHunter) -- proves the
# "aggregated cost/time report at the end of a hunt_fleet run" requirement
# end to end, entirely offline. (v10 consolidation merge: updated from 4 to
# 5 angles for the sixth-angle-work milestone's own `scope-selector-override`
# -- `run_hunter_fleet` dispatches every non-taint angle in `HUNTER_ANGLES`,
# so a `ManualRecordHunter` fixture missing a recorded answer for one of them
# surfaces as a real `result.errors` entry, not a silent skip; this is
# exactly what caught this gap when the full merged suite was first run.)
# --------------------------------------------------------------------------


@pytestmark_semgrep
def test_run_hunter_fleet_aggregates_real_usage_across_all_angles_into_one_tracker(tmp_path):
    _write_shell_true_tool(tmp_path)
    tracker = CostTracker()
    taint_hunter = TaintShapedHunter(run_sandbox=False, cost_tracker=tracker)

    per_angle_usage = {
        "claims-vs-enforcement": _REAL_USAGE_A,
        "credential-and-secrets": _REAL_USAGE_B,
        "cross-file-authority": _REAL_USAGE_C,
        "whole-handler-audit": _REAL_USAGE_D,
        "scope-selector-override": _REAL_USAGE_E,
        "transport-and-exposure": _REAL_USAGE_F,
    }
    # Per-unit dispatch (Change 1): `_write_shell_true_tool` recovers exactly
    # 1 entrypoint, so whole-handler-audit dispatches exactly 1 real unit
    # ("unit_1") -- its own recorded-answer key carries that unit suffix
    # (`ManualRecordHunter._key`'s own docstring); every other angle keeps
    # the plain, unsuffixed key (a single, non-whole-handler-audit dispatch
    # is completely unaffected by this milestone).
    recorded = {
        (f"{angle}@{tmp_path.resolve()}#unit_1" if angle == "whole-handler-audit" else f"{angle}@{tmp_path.resolve()}"): [
            {"candidates": [], "no_finding_reasoning": "nothing found", "usage": usage}
        ]
        for angle, usage in per_angle_usage.items()
    }
    llm_hunter = ManualRecordHunter(recorded, cost_tracker=tracker)

    result = run_hunter_fleet(tmp_path, taint_hunter=taint_hunter, llm_hunter=llm_hunter)
    assert not result.errors, result.errors

    by_stage = tracker.by_stage()
    assert by_stage["taint_scan"]["calls"] == 1
    assert by_stage["taint_scan"]["wall_seconds"] > 0  # a real wall-clock measurement, not a placeholder
    for angle, usage in per_angle_usage.items():
        stage = by_stage[f"hunter:{angle}"]
        assert stage["calls"] == 1
        assert stage["output_tokens"] == usage["output_tokens"]
        assert stage["cache_read_input_tokens"] == usage["cache_read_input_tokens"]

    totals = tracker.totals()
    assert totals["calls"] == 7  # 1 taint_scan + 6 LLM angles
    assert totals["output_tokens"] == sum(u["output_tokens"] for u in per_angle_usage.values())
    assert totals["cache_creation_input_tokens"] == sum(u["cache_creation_input_tokens"] for u in per_angle_usage.values())


@pytestmark_semgrep
def test_hunt_records_real_taint_scan_wall_time_even_with_no_api_key(tmp_path, monkeypatch):
    """`hunt()`'s taint-scan stage has real wall-clock cost regardless of
    whether any LLM stage ever runs -- this is real, not a placeholder, even
    in the no-API-key path every CI run of this project actually takes."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    _write_shell_true_tool(tmp_path)
    ledger_path = tmp_path / "ledger.jsonl"

    result = hunt(tmp_path, ledger_path=ledger_path)

    assert result.cost_tracker is not None
    totals = result.cost_tracker.totals()
    assert totals["calls"] == 1  # only the taint scan -- no API key, so no verify/critic calls
    assert totals["input_tokens"] == 0
    assert totals["output_tokens"] == 0
    by_stage = result.cost_tracker.by_stage()
    assert by_stage["taint_scan"]["calls"] == 1
    assert by_stage["taint_scan"]["wall_seconds"] > 0


@pytestmark_semgrep
def test_hunt_fleet_attaches_a_cost_tracker_with_real_taint_scan_wall_time(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    _write_shell_true_tool(tmp_path)
    ledger_path = tmp_path / "ledger.jsonl"

    result = hunt_fleet(tmp_path, ledger_path=ledger_path, run_sandbox=False)

    assert result.cost_tracker is not None
    by_stage = result.cost_tracker.by_stage()
    assert by_stage["taint_scan"]["calls"] == 1
    assert by_stage["taint_scan"]["wall_seconds"] > 0


def test_hunt_accepts_a_caller_supplied_cost_tracker_and_returns_the_same_instance(tmp_path, monkeypatch):
    """A caller wanting to combine several runs' costs into one report can
    pass their own tracker in -- `hunt()` must reuse it, not silently
    replace it with a fresh one."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    _write(tmp_path / "server.py", "def add(a: int, b: int) -> int:\n    return a + b\n")
    tracker = CostTracker()
    tracker.record("previous_run_marker", "x")  # something already in it before this call

    result = hunt(tmp_path, ledger_path=tmp_path / "ledger.jsonl", cost_tracker=tracker)

    assert result.cost_tracker is tracker
    assert "previous_run_marker" in tracker.by_stage()
