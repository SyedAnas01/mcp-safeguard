"""Tests for the S8 hunt pipeline (scanner/pipeline.py) -- the glue that
wires the taint engine, ClaimCard, threat_model.py's S2 context, the Stage 5
sandbox, Stage 4 LLM verification, and the S7 ledger into one real
`hunt()` call.

Split the same way `test_sandbox.py` splits: most tests exercise the pure
logic (PoC argument synthesis, trace interpretation, ClaimCard construction,
entrypoint resolution against real parsed source) with no Docker/API
dependency at all. A smaller set (`pytestmark_docker`) drives a REAL Docker
sandbox end to end against a small on-disk fixture repo, proving the full
`hunt()` path for real -- not just in theory. No test in this file makes a
real Anthropic API call; Stage 4 is exercised by monkeypatching
`pipeline.AnthropicVerifier`, never by hitting the real API.
"""

from __future__ import annotations

import shutil
import tempfile
import textwrap
from pathlib import Path

import pytest

from mcp_safeguard.scanner.claim_card import ClaimCard
from mcp_safeguard.scanner.ledger import read_entries
from mcp_safeguard.scanner.pipeline import (
    _build_poc_args,
    _final_verdict,
    _interpret_trace,
    _js_export_name,
    _process_finding,
    _synth_value,
    build_claim_card,
    hunt,
    resolve_sandbox_entrypoint,
)
from mcp_safeguard.scanner.sandbox import OracleTrace, docker_available
from mcp_safeguard.scanner.source_scanner import Severity, SourceFinding
from mcp_safeguard.scanner.taint_scanner import run_static_taint_scan
from mcp_safeguard.scanner.threat_model import build_threat_model

pytestmark_docker = pytest.mark.skipif(not docker_available(), reason="docker not available")


@pytest.fixture
def docker_tmp_path():
    """Like `tmp_path`, but rooted under the user's home directory --
    required for the Docker-backed tests below on a Colima-based Docker
    setup (this project's own dev environment), where a bind mount rooted
    outside `$HOME` silently resolves to an empty directory inside the
    container. See sandbox.py's own module docstring / bench/S1_SANDBOX_STATUS.md,
    and PIPELINE_WIRING_STATUS.md for this exact failure reproduced while
    wiring this module (a synthetic fixture under `/tmp` produced a real
    `FileNotFoundError` inside the container before it was moved under
    `$HOME`)."""
    base = Path.home() / ".cache" / "mcp_safeguard" / "test_scratch"
    base.mkdir(parents=True, exist_ok=True)
    d = Path(tempfile.mkdtemp(dir=base))
    yield d
    shutil.rmtree(d, ignore_errors=True)


def _write(path: Path, text: str) -> None:
    path.write_text(textwrap.dedent(text))


def _finding(**overrides) -> SourceFinding:
    base = {
        "rule_id": "TAINT-CMDI",
        "severity": Severity.CRITICAL,
        "title": "MCP tool parameter reaches a command-injection sink",
        "description": "test finding",
        "location": "server.py:10",
        "evidence": "subprocess.run(cmd, shell=True)",
        "remediation": "use argv form",
        "tier": "S",
        "taint_path": [
            {"kind": "source", "line": 5, "code": "cmd", "note": "handler param", "file": "server.py"},
            {"kind": "sink", "line": 10, "code": "subprocess.run(cmd, shell=True)", "note": "", "file": "server.py"},
        ],
        "confidence": "high",
    }
    base.update(overrides)
    return SourceFinding(**base)


# --------------------------------------------------------------------------
# PoC argument synthesis -- no sandbox/docker needed.
# --------------------------------------------------------------------------


def test_synth_value_credential_shaped_name_gets_fake_credential():
    assert "fakecred" in _synth_value("apiKey", "TAINT-CREDFWD")


def test_synth_value_url_shaped_name_gets_malicious_payload():
    assert _synth_value("origin", "TAINT-SSRF").startswith("http://169.254.169.254/")


def test_synth_value_unrelated_name_gets_benign_placeholder():
    assert _synth_value("query", "TAINT-CMDI") == "mcpsafeguard-poc-benign-b91c"


def test_build_poc_args_single_scalar_param_gets_the_malicious_payload():
    args = _build_poc_args(["script"], None, "TAINT-CMDI")
    assert args == ["; echo MCPSAFEGUARDPOCMARKER7F3A #"]


def test_build_poc_args_single_object_shaped_param_builds_a_dict():
    """Mirrors the real Aiven-Open/mcp-aiven `askDocs(opts)` shape: a single
    parameter whose body reads `opts.origin`/`opts.apiKey`/`opts.query`."""
    args = _build_poc_args(["opts"], ["origin", "apiKey", "query"], "TAINT-SSRF")
    assert len(args) == 1
    assert isinstance(args[0], dict)
    assert args[0]["origin"].startswith("http://169.254.169.254/")
    assert "fakecred" in args[0]["apiKey"]
    assert args[0]["query"] == "mcpsafeguard-poc-benign-b91c"


def test_build_poc_args_multi_param_puts_payload_in_the_matching_name():
    args = _build_poc_args(["apiKey", "url", "note"], None, "TAINT-CREDFWD")
    assert "fakecred" in args[0]
    assert args[1].startswith("http://169.254.169.254/")
    assert args[2] == "mcpsafeguard-poc-benign-b91c"


def test_build_poc_args_multi_param_with_no_shape_match_forces_first_param():
    """No name here looks credential/url/path-shaped -- the payload must
    still land SOMEWHERE real, not silently vanish."""
    args = _build_poc_args(["a", "b"], None, "TAINT-CMDI")
    assert args[0] == "; echo MCPSAFEGUARDPOCMARKER7F3A #"
    assert args[1] == "mcpsafeguard-poc-benign-b91c"


def test_build_poc_args_no_params_returns_empty_list():
    assert _build_poc_args([], None, "TAINT-CMDI") == []


def test_marker_and_placeholder_share_no_substring():
    """The real bug this module hit while wiring: a benign/placeholder value
    that happened to contain the same marker text made `_interpret_trace`
    falsely 'confirm' a finding from an unrelated, non-malicious argument.
    Guard it directly so it can't silently come back."""
    from mcp_safeguard.scanner.pipeline import (
        _BENIGN_PLACEHOLDER,
        _FAKE_CREDENTIAL_VALUE,
        _MARKER_TOKEN,
    )

    assert _MARKER_TOKEN not in _BENIGN_PLACEHOLDER
    assert _MARKER_TOKEN not in _FAKE_CREDENTIAL_VALUE


# --------------------------------------------------------------------------
# Trace interpretation -- given a synthetic OracleTrace directly, no
# sandbox/docker needed.
# --------------------------------------------------------------------------


def test_interpret_trace_cmdi_confirmed_when_marker_in_argv():
    trace = OracleTrace(sandbox_kind="docker", runtime="python", entrypoint="x:y",
                         subprocess_calls=[{"argv": ["; echo MCPSAFEGUARDPOCMARKER7F3A #"]}])
    confirmed, note = _interpret_trace("TAINT-CMDI", trace)
    assert confirmed is True
    assert "execution-confirmed" in note


def test_interpret_trace_cmdi_not_confirmed_when_no_subprocess_call():
    trace = OracleTrace(sandbox_kind="docker", runtime="python", entrypoint="x:y")
    confirmed, note = _interpret_trace("TAINT-CMDI", trace)
    assert confirmed is False


def test_interpret_trace_pathtrav_confirmed_via_outside_root_flag():
    trace = OracleTrace(sandbox_kind="docker", runtime="python", entrypoint="x:y",
                         file_opens=[{"path": "/etc/passwd", "resolved_path": "/etc/passwd", "outside_root": True}])
    confirmed, _ = _interpret_trace("TAINT-PATHTRAV", trace)
    assert confirmed is True


def test_interpret_trace_ssrf_confirmed_via_marker_host():
    trace = OracleTrace(sandbox_kind="docker", runtime="node", entrypoint="x:y",
                         network_connections=[{"host": "169.254.169.254", "port": 80}])
    confirmed, _ = _interpret_trace("TAINT-SSRF", trace)
    assert confirmed is True


def test_interpret_trace_credfwd_confirmed_via_credential_flags_alone():
    """CREDFWD's own point: a credential-shaped header reaching an outbound
    request is itself the confirming signal, even without the marker host
    (e.g. if the header carries a REAL destination taken from the PoC arg)."""
    trace = OracleTrace(sandbox_kind="docker", runtime="node", entrypoint="x:y",
                         credential_flags=[{"destination": "evil.example:443", "location": "header:X-API-KEY"}])
    confirmed, note = _interpret_trace("TAINT-CREDFWD", trace)
    assert confirmed is True
    assert "credential" in note


def test_interpret_trace_ssrf_alone_not_confirmed_by_credential_flags():
    """SSRF (unlike CREDFWD) needs the outbound request to actually reach
    the PoC host -- a stray credential flag alone is not SSRF evidence."""
    trace = OracleTrace(sandbox_kind="docker", runtime="node", entrypoint="x:y",
                         credential_flags=[{"destination": "evil.example:443"}])
    confirmed, _ = _interpret_trace("TAINT-SSRF", trace)
    assert confirmed is False


def test_interpret_trace_sandbox_error_is_inconclusive_not_confirmed():
    trace = OracleTrace(sandbox_kind="docker", runtime="python", entrypoint="x:y", error="container crashed")
    confirmed, note = _interpret_trace("TAINT-CMDI", trace)
    assert confirmed is False
    assert "inconclusive" in note


# --------------------------------------------------------------------------
# Sandbox-fix milestone: `trace.exception` (a TARGET-level runtime failure,
# e.g. a missing dependency's ModuleNotFoundError) is a real, distinct third
# outcome -- never worded like, or conflated with, a genuine "ran, no
# signal" sandbox negative. This is what the real bug on 44 recorded traces
# was: 39 of them carried `trace.exception` set (a target-level import
# failure) and got the byte-identical negative note as a genuine clean
# negative, because `_interpret_trace` never looked at `trace.exception` at
# all.
# --------------------------------------------------------------------------


def test_interpret_trace_cmdi_target_exception_is_inconclusive_not_negative():
    trace = OracleTrace(
        sandbox_kind="docker", runtime="python", entrypoint="x:y",
        exception="ModuleNotFoundError: No module named 'fastmcp'",
    )
    confirmed, note = _interpret_trace("TAINT-CMDI", trace)
    assert confirmed is False
    assert "inconclusive" in note
    assert "target raised before reaching the sink" in note
    assert "ModuleNotFoundError" in note
    # must NOT be the genuine "ran, no signal" negative wording
    assert "no subprocess call carried the injected PoC marker" not in note


def test_interpret_trace_pathtrav_target_exception_is_inconclusive_not_negative():
    from mcp_safeguard.scanner.pipeline import _NOTE_PATHTRAV_NO_TRIGGER

    trace = OracleTrace(
        sandbox_kind="docker", runtime="python", entrypoint="x:y",
        exception="ModuleNotFoundError: No module named 'httpx'",
    )
    confirmed, note = _interpret_trace("TAINT-PATHTRAV", trace)
    assert confirmed is False
    assert "inconclusive" in note
    assert _NOTE_PATHTRAV_NO_TRIGGER not in note


def test_interpret_trace_ssrf_credfwd_target_exception_is_inconclusive_not_negative():
    from mcp_safeguard.scanner.pipeline import _NOTE_SSRF_CREDFWD_NO_TRIGGER

    trace = OracleTrace(
        sandbox_kind="docker", runtime="node", entrypoint="x:y",
        exception="ERR_MODULE_NOT_FOUND: @llmindset/hf-mcp",
    )
    confirmed, note = _interpret_trace("TAINT-SSRF", trace)
    assert confirmed is False
    assert "inconclusive" in note
    assert _NOTE_SSRF_CREDFWD_NO_TRIGGER not in note


def test_interpret_trace_hit_wins_over_target_exception():
    """If the sink was ALREADY reached before the target raised, that's a
    real confirmation -- `trace.exception` must never downgrade a genuine
    hit to "inconclusive"."""
    trace = OracleTrace(
        sandbox_kind="docker", runtime="python", entrypoint="x:y",
        subprocess_calls=[{"argv": ["; echo MCPSAFEGUARDPOCMARKER7F3A #"]}],
        exception="RuntimeError: something raised after the sink call",
    )
    confirmed, note = _interpret_trace("TAINT-CMDI", trace)
    assert confirmed is True
    assert "execution-confirmed" in note


def test_is_sandbox_negative_pathtrav_ssrf_credfwd_false_for_inconclusive_target_exception():
    """The whole point of the new category: it must NOT be routed to the
    repo-reading adversary as "sandbox tried and failed"."""
    from mcp_safeguard.scanner.hunter import HuntCardOutcome
    from mcp_safeguard.scanner.pipeline import (
        _NOTE_INCONCLUSIVE_TARGET_EXCEPTION,
        _is_sandbox_negative_pathtrav_ssrf_credfwd,
    )

    note = f"{_NOTE_INCONCLUSIVE_TARGET_EXCEPTION}: ModuleNotFoundError: No module named 'fastmcp'"
    outcome = HuntCardOutcome(card=_taint_card_with_trace(), verdict="unconfirmed", note=note)
    assert _is_sandbox_negative_pathtrav_ssrf_credfwd(outcome) is False


def test_final_verdict_execution_confirmed_wins_regardless_of_llm():
    assert _final_verdict(True, None) == "confirmed"


def test_final_verdict_falls_back_to_llm_result():
    class _FakeAgreement:
        verdict = "refuted"
    assert _final_verdict(False, _FakeAgreement()) == "refuted"


def test_final_verdict_unconfirmed_when_neither_ran():
    assert _final_verdict(False, None) == "unconfirmed"


# --------------------------------------------------------------------------
# JS/TS export resolution -- real tree-sitter parsing, no Docker needed.
# Directly validates the logic that produced the real Aiven-Open/mcp-aiven
# proof-run result (askDocs is NOT exported -> None).
# --------------------------------------------------------------------------


def test_js_export_name_exported_function_declaration(tmp_path):
    from mcp_safeguard.scanner import entrypoints_js as ejs

    _write(tmp_path / "m.ts", """
        export function askDocs(opts) {
          return fetch(opts.origin);
        }
    """)
    root_node, src = ejs.parse_file(tmp_path / "m.ts")
    fn_node = ejs.find_enclosing_function(root_node, 3)
    assert _js_export_name(fn_node, src, ejs) == "askDocs"


def test_js_export_name_non_exported_function_declaration_is_none(tmp_path):
    """The real Aiven-Open/mcp-aiven shape: `async function askDocs(opts) {...}`
    with no `export` keyword -- not directly callable via Stage 5's
    dynamic import()."""
    from mcp_safeguard.scanner import entrypoints_js as ejs

    _write(tmp_path / "m.ts", """
        async function askDocs(opts) {
          return fetch(opts.origin);
        }
    """)
    root_node, src = ejs.parse_file(tmp_path / "m.ts")
    fn_node = ejs.find_enclosing_function(root_node, 3)
    assert _js_export_name(fn_node, src, ejs) is None


def test_js_export_name_exported_const_arrow(tmp_path):
    from mcp_safeguard.scanner import entrypoints_js as ejs

    _write(tmp_path / "m.ts", """
        export const askDocs = async (opts) => {
          return fetch(opts.origin);
        };
    """)
    root_node, src = ejs.parse_file(tmp_path / "m.ts")
    fn_node = ejs.find_enclosing_function(root_node, 3)
    assert _js_export_name(fn_node, src, ejs) == "askDocs"


def test_js_export_name_class_method_is_none(tmp_path):
    from mcp_safeguard.scanner import entrypoints_js as ejs

    _write(tmp_path / "m.ts", """
        export class Client {
          async askDocs(opts) {
            return fetch(opts.origin);
          }
        }
    """)
    root_node, src = ejs.parse_file(tmp_path / "m.ts")
    fn_node = ejs.find_enclosing_function(root_node, 4)
    assert _js_export_name(fn_node, src, ejs) is None


# --------------------------------------------------------------------------
# resolve_sandbox_entrypoint -- real AST/tree-sitter parsing, no Docker.
# --------------------------------------------------------------------------


def test_resolve_sandbox_entrypoint_python_module_level_function(tmp_path):
    _write(tmp_path / "server.py", """
        import subprocess

        def run_it(script):
            subprocess.run(script, shell=True)
    """)
    finding = _finding(location="server.py:5")
    resolution = resolve_sandbox_entrypoint(finding, tmp_path)
    assert resolution.error is None
    assert resolution.entrypoint.function_name == "run_it"
    assert resolution.entrypoint.runtime == "python"
    assert resolution.args == ["; echo MCPSAFEGUARDPOCMARKER7F3A #"]


def test_resolve_sandbox_entrypoint_python_class_method_is_unresolvable(tmp_path):
    _write(tmp_path / "server.py", """
        import subprocess

        class Handler:
            def run_it(self, script):
                subprocess.run(script, shell=True)
    """)
    finding = _finding(location="server.py:6")
    resolution = resolve_sandbox_entrypoint(finding, tmp_path)
    assert resolution.entrypoint is None
    assert "not a module-top-level function" in resolution.error


def test_resolve_sandbox_entrypoint_unrecognized_suffix(tmp_path):
    (tmp_path / "server.rb").write_text("puts 'hi'\n")
    finding = _finding(location="server.rb:1")
    resolution = resolve_sandbox_entrypoint(finding, tmp_path)
    assert resolution.entrypoint is None
    assert "unrecognized source file type" in resolution.error


def test_resolve_sandbox_entrypoint_missing_file(tmp_path):
    finding = _finding(location="does_not_exist.py:1")
    resolution = resolve_sandbox_entrypoint(finding, tmp_path)
    assert resolution.entrypoint is None
    assert "no longer exists" in resolution.error


# --------------------------------------------------------------------------
# build_claim_card
# --------------------------------------------------------------------------


def test_build_claim_card_with_oracle_trace_is_valid():
    trace = OracleTrace(sandbox_kind="docker", runtime="python", entrypoint="server.py:run_it")
    card = build_claim_card(_finding(), None, oracle_trace=trace)
    assert isinstance(card, ClaimCard)
    assert card.oracle_trace is trace
    assert card.impossibility_argument is None
    assert "server.py:10" in card.target_sink


def test_build_claim_card_with_impossibility_argument_is_valid():
    card = build_claim_card(_finding(), None, impossibility_argument="could not resolve a callable entrypoint")
    assert isinstance(card, ClaimCard)
    assert card.oracle_trace is None
    assert card.impossibility_argument == "could not resolve a callable entrypoint"


def test_build_claim_card_evidence_path_reuses_taint_path_steps():
    card = build_claim_card(_finding(), None, impossibility_argument="x")
    assert len(card.evidence_path) == 2
    assert card.evidence_path[0].kind == "source"
    assert card.evidence_path[1].kind == "sink"


def test_build_claim_card_enriches_authority_from_threat_model(tmp_path):
    _write(tmp_path / "server.py", """
        # requires an authenticated caller -- read-only mode
        def run_it(script):
            import subprocess
            subprocess.run(script, shell=True)
    """)
    tmd = build_threat_model(tmp_path, use_cache=False)
    finding = _finding(
        location="server.py:5",
        taint_path=[
            {"kind": "source", "line": 3, "code": "run_it(script)", "note": "handler param", "file": "server.py"},
            {"kind": "sink", "line": 5, "code": "subprocess.run(script, shell=True)", "note": "", "file": "server.py"},
        ],
    )
    card = build_claim_card(finding, tmd, impossibility_argument="x")
    # Whether or not S2 actually recovered `run_it` as a real MCP
    # entrypoint here (it needs a recognized registration decorator, which
    # this minimal fixture doesn't have), caller_authority_assumed must
    # never be empty and must never silently claim a match that wasn't made.
    assert card.caller_authority_assumed


# --------------------------------------------------------------------------
# _process_finding: TAINT-IDOR and non-sandbox-testable classes are skipped
# by design -- no sandbox/docker call is even attempted.
# --------------------------------------------------------------------------


def test_process_finding_idor_skips_sandbox_and_gets_impossibility_argument():
    finding = _finding(rule_id="TAINT-IDOR", confidence="low")
    outcome = _process_finding(finding, Path("."), None, 30, run_llm_verification=False)
    assert outcome.verdict == "unconfirmed"
    assert outcome.claim_card.oracle_trace is None
    assert "absence-based" in outcome.claim_card.impossibility_argument
    assert "sandbox stage skipped by design" in outcome.note


def test_process_finding_non_sandbox_testable_class_is_skipped():
    finding = _finding(rule_id="SRC-013", tier="L")
    outcome = _process_finding(finding, Path("."), None, 30, run_llm_verification=False)
    assert outcome.verdict == "unconfirmed"
    assert "not a sandbox-testable class" in outcome.note


def test_process_finding_records_llm_skip_note_when_no_api_key(monkeypatch, tmp_path):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    _write(tmp_path / "server.rb", "puts 'hi'\n")  # unrecognized suffix -> sandbox not attempted either
    finding = _finding(location="server.rb:1")
    outcome = _process_finding(finding, tmp_path, None, 30, run_llm_verification=True)
    assert "no ANTHROPIC_API_KEY set" in outcome.note
    assert outcome.verdict == "unconfirmed"


def test_process_finding_records_llm_result_when_verifier_is_mocked(monkeypatch, tmp_path):
    """Proves Stage 4's wiring for real without ever calling the real
    Anthropic API: `pipeline.AnthropicVerifier` (the name pipeline.py
    imports and calls) is replaced with a fake that returns a canned
    agreement result."""
    import mcp_safeguard.scanner.pipeline as pipeline_mod
    from mcp_safeguard.scanner.verify import AgreementResult, VerificationResult

    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key-for-test")

    class _FakeVerifier:
        def __init__(self, *args, **kwargs):
            pass

        def verify(self, finding, root):
            return VerificationResult("confirmed", "fake reasoning", {}, [5, 10], "fake-model", True)

    monkeypatch.setattr(pipeline_mod, "AnthropicVerifier", _FakeVerifier)
    monkeypatch.setattr(
        pipeline_mod, "verify_with_agreement",
        lambda verifier, finding, root, runs=2: AgreementResult(
            verdict="confirmed",
            run_a=VerificationResult("confirmed", "a", {}, [5, 10], "fake-model", True),
            run_b=VerificationResult("confirmed", "b", {}, [5, 10], "fake-model", True),
            agreed=True,
        ),
    )

    _write(tmp_path / "server.rb", "puts 'hi'\n")  # sandbox stage not attempted -> isolates Stage 4
    finding = _finding(location="server.rb:1")
    outcome = _process_finding(finding, tmp_path, None, 30, run_llm_verification=True)
    assert outcome.verdict == "confirmed"
    assert "Stage 4 LLM verification: confirmed" in outcome.note


# --------------------------------------------------------------------------
# hunt(): end-to-end against a real (but tiny, synthetic) target repo,
# writing to an isolated ledger path -- Docker-gated (real sandbox
# execution), no LLM call (ANTHROPIC_API_KEY unset).
# --------------------------------------------------------------------------


@pytestmark_docker
def test_hunt_end_to_end_confirms_a_real_command_injection(monkeypatch, docker_tmp_path):
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

    result = hunt(repo, ledger_path=ledger_path, sandbox_timeout_seconds=30)

    assert result.findings_scanned == 1
    outcome = result.outcomes[0]
    assert outcome.finding.rule_id == "TAINT-CMDI"
    assert outcome.verdict == "confirmed"
    assert outcome.claim_card.oracle_trace is not None
    assert outcome.claim_card.oracle_trace.sandbox_kind == "docker"
    assert any("MCPSAFEGUARDPOCMARKER7F3A" in " ".join(c["argv"]) for c in outcome.claim_card.oracle_trace.subprocess_calls)

    entries = read_entries(str(ledger_path))
    assert len(entries) == 1
    assert entries[0].verdict == "confirmed"
    assert entries[0].commit == result.commit


@pytestmark_docker
def test_hunt_idor_finding_never_reaches_the_sandbox(monkeypatch, docker_tmp_path):
    """A repo whose only tier-S finding is TAINT-IDOR must produce a real
    ledger entry with an impossibility_argument and no oracle_trace --
    Stage 5 must never even be attempted for it. Uses the real taint
    engine's own IDOR rule against a real target shape rather than a
    hand-built SourceFinding, so this is a genuine (not mocked) check of
    `hunt()`'s own dispatch."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    repo = docker_tmp_path
    _write(repo / "server.py", """
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
    findings = run_static_taint_scan(repo, include_low_confidence=True)
    if not any(f.rule_id == "TAINT-IDOR" for f in findings):
        pytest.skip("this fixture did not trigger the real TAINT-IDOR rule in this semgrep/tree-sitter version")

    ledger_path = repo / "test_ledger.jsonl"
    result = hunt(repo, ledger_path=ledger_path, include_low_confidence=True, sandbox_timeout_seconds=30)

    idor_outcomes = [o for o in result.outcomes if o.finding.rule_id == "TAINT-IDOR"]
    assert idor_outcomes
    for o in idor_outcomes:
        assert o.claim_card.oracle_trace is None
        assert "absence-based" in o.claim_card.impossibility_argument


# --------------------------------------------------------------------------
# hunt_fleet's adversary gate (this milestone): every non-"taint-shaped"
# ClaimCard hunter.py produces is always "unconfirmed" (no execution
# evidence -- see hunter.HuntCardOutcome's own docstring) and, before this
# milestone, went straight to the ledger with no adversarial check at all.
# `hunt_fleet` itself has no way to inject a custom llm_hunter (unlike
# `run_hunter_fleet`, which test_hunter.py's own `_StubHunter` tests exercise
# directly) -- these tests monkeypatch `hunter.run_hunter_fleet` itself
# (pipeline.py's own local `from .hunter import ... run_hunter_fleet` import
# happens fresh inside the function body on every call, so patching the
# hunter module's own attribute takes effect), same "monkeypatch the
# collaborator, not the seam" discipline this file already uses for Stage 4
# (`monkeypatch.setattr(pipeline_mod, "AnthropicVerifier", ...)`). No live
# LLM/Anthropic call anywhere in this section.
# --------------------------------------------------------------------------


def _stub_fleet_result(repo_path, angle, card, verdict, note):
    from mcp_safeguard.scanner.hunter import FleetHuntResult, HuntCardOutcome

    return FleetHuntResult(
        repo_path=str(repo_path),
        per_angle={"taint-shaped": [], angle: [card]},
        card_verdicts={"taint-shaped": [], angle: [HuntCardOutcome(card=card, verdict=verdict, note=note)]},
    )


def _patch_run_hunter_fleet(monkeypatch, stub_result):
    from mcp_safeguard.scanner import hunter as hunter_mod

    def _stub(root, *, taint_hunter, llm_hunter, enrich_with_exemplars, exemplar_ledger_path):
        return stub_result

    monkeypatch.setattr(hunter_mod, "run_hunter_fleet", _stub)


def _hunter_angle_card(**overrides) -> ClaimCard:
    kwargs = {
        "target_sink": "server.py:1 -- hunter-fleet candidate",
        "tainted_source": "placeholder",
        "caller_authority_assumed": "placeholder",
        "precondition": "placeholder",
        "violated_claim": "placeholder",
        "impossibility_argument": "hunter-fleet angle candidate, no execution oracle",
    }
    kwargs.update(overrides)
    return ClaimCard(**kwargs)


def test_hunt_fleet_skips_adversary_check_with_no_backend_and_no_api_key(tmp_path, monkeypatch):
    from mcp_safeguard.scanner.ledger import read_entries
    from mcp_safeguard.scanner.pipeline import hunt_fleet

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    card = _hunter_angle_card()
    stub_result = _stub_fleet_result(tmp_path, "credential-and-secrets", card, "unconfirmed", "hunter note")
    _patch_run_hunter_fleet(monkeypatch, stub_result)

    ledger_path = tmp_path / "findings.jsonl"
    result = hunt_fleet(tmp_path, ledger_path=ledger_path, run_sandbox=False)

    outcome = result.card_verdicts["credential-and-secrets"][0]
    assert outcome.verdict == "unconfirmed"
    assert "adversary check skipped, no backend configured" in outcome.note

    entries = read_entries(ledger_path)
    assert len(entries) == 1
    assert entries[0].verdict == "unconfirmed"
    assert "adversary check skipped, no backend configured" in entries[0].notes


def test_hunt_fleet_promotes_unconfirmed_card_when_adversary_confirms(tmp_path, monkeypatch):
    """The core wiring this milestone adds: a non-taint-shaped 'unconfirmed'
    outcome IS routed through the adversary gate, and BOTH the ledger entry
    AND the returned FleetHuntResult (not just the ledger file) reflect the
    real post-adversary-gate verdict -- proving the mutation-by-reference
    fix (HuntCardOutcome is a shared, mutable dataclass) actually works, not
    just the ledger write."""
    from mcp_safeguard.scanner.adversary import AdversaryResult
    from mcp_safeguard.scanner.ledger import read_entries
    from mcp_safeguard.scanner.pipeline import hunt_fleet

    # claims-vs-enforcement: the one LLM angle that stays on this lightweight
    # `adversary_backend`/`adversary_second_backend` gate under the
    # candidate-widened-adversary milestone (see pipeline.py's own
    # `_REPO_READING_ADVERSARY_ANGLES` comment) -- the other four angles now
    # use the repo-reading pair instead, covered by their own tests below.
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    card = _hunter_angle_card(target_sink="server.py:42 -- credential forwarded to caller-controlled host")
    stub_result = _stub_fleet_result(tmp_path, "claims-vs-enforcement", card, "unconfirmed", "hunter note")
    _patch_run_hunter_fleet(monkeypatch, stub_result)

    class _ConfirmingBackend:
        def adjudicate(self, claim_card):
            return AdversaryResult(verdict="confirmed", reasoning="held up under review", model="stub-adversary")

    ledger_path = tmp_path / "findings.jsonl"
    result = hunt_fleet(
        tmp_path, ledger_path=ledger_path, run_sandbox=False, adversary_backend=_ConfirmingBackend(),
    )

    outcome = result.card_verdicts["claims-vs-enforcement"][0]
    assert outcome.verdict == "adversary-reviewed"
    assert "single-adversary review" in outcome.note

    entries = read_entries(ledger_path)
    assert len(entries) == 1
    assert entries[0].verdict == "adversary-reviewed"


def test_hunt_fleet_downgrades_unconfirmed_card_when_adversary_refutes(tmp_path, monkeypatch):
    from mcp_safeguard.scanner.adversary import AdversaryResult
    from mcp_safeguard.scanner.ledger import read_entries
    from mcp_safeguard.scanner.pipeline import hunt_fleet

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    card = _hunter_angle_card()
    stub_result = _stub_fleet_result(tmp_path, "claims-vs-enforcement", card, "unconfirmed", "hunter note")
    _patch_run_hunter_fleet(monkeypatch, stub_result)

    class _RefutingBackend:
        def adjudicate(self, claim_card):
            return AdversaryResult(verdict="refuted", reasoning="the cited line neutralizes it", model="stub-adversary")

    ledger_path = tmp_path / "findings.jsonl"
    result = hunt_fleet(
        tmp_path, ledger_path=ledger_path, run_sandbox=False, adversary_backend=_RefutingBackend(),
    )

    outcome = result.card_verdicts["claims-vs-enforcement"][0]
    assert outcome.verdict == "refuted"
    entries = read_entries(ledger_path)
    assert entries[0].verdict == "refuted"


def test_hunt_fleet_never_routes_taint_shaped_outcomes_through_adversary_gate(tmp_path, monkeypatch):
    """taint-shaped findings already went through Stage 5 execution + the S6
    critic -- a materially different, execution-based check. Even a
    confirmed taint-shaped outcome must never be re-routed through the
    adversary gate, and an adversary backend that would refute everything
    must never be given the chance to touch it."""
    from mcp_safeguard.scanner.hunter import FleetHuntResult, HuntCardOutcome
    from mcp_safeguard.scanner.ledger import read_entries
    from mcp_safeguard.scanner.pipeline import hunt_fleet

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    taint_card = _hunter_angle_card(
        target_sink="server.py:9 -- real command injection", impossibility_argument=None,
        oracle_trace={"sandbox_kind": "docker", "runtime": "python", "entrypoint": "run"},
    )
    stub_result = FleetHuntResult(
        repo_path=str(tmp_path),
        per_angle={"taint-shaped": [taint_card]},
        card_verdicts={"taint-shaped": [HuntCardOutcome(card=taint_card, verdict="confirmed", note="execution-confirmed")]},
    )
    _patch_run_hunter_fleet(monkeypatch, stub_result)

    class _AlwaysRefutes:
        def adjudicate(self, claim_card):
            raise AssertionError("the adversary gate must never be called for a taint-shaped outcome")

    ledger_path = tmp_path / "findings.jsonl"
    result = hunt_fleet(tmp_path, ledger_path=ledger_path, run_sandbox=False, adversary_backend=_AlwaysRefutes())

    assert result.card_verdicts["taint-shaped"][0].verdict == "confirmed"
    entries = read_entries(ledger_path)
    assert entries[0].verdict == "confirmed"
    assert "adversary" not in entries[0].notes.lower()


def test_hunt_fleet_two_adversary_backends_disagree_stays_unconfirmed(tmp_path, monkeypatch):
    from mcp_safeguard.scanner.adversary import AdversaryResult
    from mcp_safeguard.scanner.ledger import read_entries
    from mcp_safeguard.scanner.pipeline import hunt_fleet

    # claims-vs-enforcement: stays on the lightweight pair (see the previous
    # test's own comment for why this angle specifically).
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    card = _hunter_angle_card()
    stub_result = _stub_fleet_result(tmp_path, "claims-vs-enforcement", card, "unconfirmed", "hunter note")
    _patch_run_hunter_fleet(monkeypatch, stub_result)

    class _Backend:
        def __init__(self, verdict):
            self._verdict = verdict

        def adjudicate(self, claim_card):
            return AdversaryResult(verdict=self._verdict, reasoning="stub", model="stub-adversary")

    ledger_path = tmp_path / "findings.jsonl"
    result = hunt_fleet(
        tmp_path, ledger_path=ledger_path, run_sandbox=False,
        adversary_backend=_Backend("confirmed"), adversary_second_backend=_Backend("refuted"),
    )

    outcome = result.card_verdicts["claims-vs-enforcement"][0]
    assert outcome.verdict == "unconfirmed"
    assert "two-adversary agreement" in outcome.note
    entries = read_entries(ledger_path)
    assert entries[0].verdict == "unconfirmed"


# --------------------------------------------------------------------------
# Adversary-severity milestone: hunt_fleet copies the adversary gate's real
# severity/CWE judgment onto the SAME ClaimCard object the ledger write and
# the returned FleetHuntResult both read -- the real gap this milestone
# fixes (an "adversary-reviewed" card previously carried no severity/CWE at
# all). No live LLM call -- same monkeypatched-collaborator discipline as
# the adversary-gate tests above.
# --------------------------------------------------------------------------


def test_hunt_fleet_populates_card_severity_and_cwe_when_adversary_confirms(tmp_path, monkeypatch):
    from mcp_safeguard.scanner.adversary import AdversaryResult
    from mcp_safeguard.scanner.ledger import read_entries
    from mcp_safeguard.scanner.pipeline import hunt_fleet
    from mcp_safeguard.scanner.prompt_injection import Severity

    # claims-vs-enforcement: stays on the lightweight `adversary_backend`
    # gate (see this file's own comment on the previous claims-vs-enforcement
    # tests for why).
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    card = _hunter_angle_card(target_sink="server.py:50 -- credential forwarded to caller-controlled host")
    stub_result = _stub_fleet_result(tmp_path, "claims-vs-enforcement", card, "unconfirmed", "hunter note")
    _patch_run_hunter_fleet(monkeypatch, stub_result)

    class _ConfirmingBackendWithSeverity:
        def adjudicate(self, claim_card):
            return AdversaryResult(
                verdict="confirmed", reasoning="held up under review", model="stub-adversary",
                severity=Severity.CRITICAL, cwe="CWE-441",
            )

    ledger_path = tmp_path / "findings.jsonl"
    result = hunt_fleet(
        tmp_path, ledger_path=ledger_path, run_sandbox=False,
        adversary_backend=_ConfirmingBackendWithSeverity(),
    )

    outcome = result.card_verdicts["claims-vs-enforcement"][0]
    assert outcome.verdict == "adversary-reviewed"
    # single-adversary path: capped one notch down from the adversary's own
    # CRITICAL opinion, same discipline run_adversary_check's own tests pin.
    assert outcome.card.severity == Severity.HIGH
    assert outcome.card.cwe == "CWE-441"

    entries = read_entries(ledger_path)
    assert entries[0].verdict == "adversary-reviewed"
    assert entries[0].claim_card.severity == Severity.HIGH
    assert entries[0].claim_card.cwe == "CWE-441"


def test_hunt_fleet_does_not_populate_card_severity_when_adversary_refutes(tmp_path, monkeypatch):
    from mcp_safeguard.scanner.adversary import AdversaryResult
    from mcp_safeguard.scanner.pipeline import hunt_fleet
    from mcp_safeguard.scanner.prompt_injection import Severity

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    card = _hunter_angle_card()
    stub_result = _stub_fleet_result(tmp_path, "claims-vs-enforcement", card, "unconfirmed", "hunter note")
    _patch_run_hunter_fleet(monkeypatch, stub_result)

    class _RefutingBackendWithSeverity:
        def adjudicate(self, claim_card):
            return AdversaryResult(
                verdict="refuted", reasoning="the cited line neutralizes it", model="stub-adversary",
                severity=Severity.CRITICAL, cwe="CWE-89",
            )

    ledger_path = tmp_path / "findings.jsonl"
    result = hunt_fleet(
        tmp_path, ledger_path=ledger_path, run_sandbox=False,
        adversary_backend=_RefutingBackendWithSeverity(),
    )

    outcome = result.card_verdicts["claims-vs-enforcement"][0]
    assert outcome.verdict == "refuted"
    # a refuted claim's severity is moot -- must never be populated, even
    # though the (refuting) adversary happened to report one.
    assert outcome.card.severity is None
    assert outcome.card.cwe is None


# --------------------------------------------------------------------------
# Repo-reading adversary path (adversary-repo-read milestone): a taint-shaped
# outcome whose Stage-5 sandbox genuinely RAN but did not trigger (PATHTRAV/
# SSRF/CREDFWD specifically) gets ONE more, repo-reading look before staying
# "unconfirmed" -- distinct from the lightweight ClaimCard-only gate above,
# which stays the 5 LLM angles' own default, unchanged. No live LLM/Anthropic
# call anywhere in this section -- same monkeypatched-collaborator discipline.
# --------------------------------------------------------------------------


def _taint_card_with_trace(**overrides) -> ClaimCard:
    from mcp_safeguard.scanner.sandbox import OracleTrace

    kwargs = {
        "target_sink": "server.py:9 -- SSRF sink",
        "tainted_source": "placeholder",
        "caller_authority_assumed": "placeholder",
        "precondition": "placeholder",
        "violated_claim": "placeholder",
        "oracle_trace": OracleTrace(sandbox_kind="docker", runtime="python", entrypoint="server.py:handler"),
    }
    kwargs.update(overrides)
    return ClaimCard(**kwargs)


def test_is_sandbox_negative_pathtrav_ssrf_credfwd_true_for_ssrf_no_trigger_note():
    from mcp_safeguard.scanner.hunter import HuntCardOutcome
    from mcp_safeguard.scanner.pipeline import (
        _NOTE_SSRF_CREDFWD_NO_TRIGGER,
        _is_sandbox_negative_pathtrav_ssrf_credfwd,
    )

    outcome = HuntCardOutcome(card=_taint_card_with_trace(), verdict="unconfirmed", note=_NOTE_SSRF_CREDFWD_NO_TRIGGER)
    assert _is_sandbox_negative_pathtrav_ssrf_credfwd(outcome) is True


def test_is_sandbox_negative_pathtrav_ssrf_credfwd_true_for_pathtrav_no_trigger_note():
    from mcp_safeguard.scanner.hunter import HuntCardOutcome
    from mcp_safeguard.scanner.pipeline import (
        _NOTE_PATHTRAV_NO_TRIGGER,
        _is_sandbox_negative_pathtrav_ssrf_credfwd,
    )

    outcome = HuntCardOutcome(card=_taint_card_with_trace(), verdict="unconfirmed", note=_NOTE_PATHTRAV_NO_TRIGGER)
    assert _is_sandbox_negative_pathtrav_ssrf_credfwd(outcome) is True


def test_is_sandbox_negative_pathtrav_ssrf_credfwd_false_for_cmdi_no_trigger_note():
    """CMDI is deliberately excluded from this routing -- a different, not
    -shared note string, per the task's own explicit CREDFWD/SSRF/PATHTRAV
    scope."""
    from mcp_safeguard.scanner.hunter import HuntCardOutcome
    from mcp_safeguard.scanner.pipeline import _is_sandbox_negative_pathtrav_ssrf_credfwd

    outcome = HuntCardOutcome(
        card=_taint_card_with_trace(), verdict="unconfirmed",
        note="sandbox ran; no subprocess call carried the injected PoC marker",
    )
    assert _is_sandbox_negative_pathtrav_ssrf_credfwd(outcome) is False


def test_is_sandbox_negative_pathtrav_ssrf_credfwd_false_for_sandbox_error():
    from mcp_safeguard.scanner.hunter import HuntCardOutcome
    from mcp_safeguard.scanner.pipeline import (
        _NOTE_SSRF_CREDFWD_NO_TRIGGER,
        _is_sandbox_negative_pathtrav_ssrf_credfwd,
    )
    from mcp_safeguard.scanner.sandbox import OracleTrace

    trace = OracleTrace(sandbox_kind="docker", runtime="python", entrypoint="server.py:handler", error="docker daemon unreachable")
    outcome = HuntCardOutcome(
        card=_taint_card_with_trace(oracle_trace=trace), verdict="unconfirmed", note=_NOTE_SSRF_CREDFWD_NO_TRIGGER,
    )
    assert _is_sandbox_negative_pathtrav_ssrf_credfwd(outcome) is False


def test_is_sandbox_negative_pathtrav_ssrf_credfwd_false_for_idor_absence_class():
    """TAINT-IDOR never gets a real OracleTrace at all (Stage 5 is skipped
    by design) -- the isinstance(trace, OracleTrace) check alone already
    excludes it, no separate rule_id check needed."""
    from mcp_safeguard.scanner.hunter import HuntCardOutcome
    from mcp_safeguard.scanner.pipeline import _is_sandbox_negative_pathtrav_ssrf_credfwd

    idor_card = ClaimCard(
        target_sink="x", tainted_source="y", caller_authority_assumed="z", precondition="p", violated_claim="v",
        impossibility_argument="TAINT-IDOR is an absence-based finding class",
    )
    outcome = HuntCardOutcome(card=idor_card, verdict="unconfirmed", note="TAINT-IDOR: sandbox stage skipped by design (absence-based)")
    assert _is_sandbox_negative_pathtrav_ssrf_credfwd(outcome) is False


def test_is_sandbox_negative_pathtrav_ssrf_credfwd_false_when_confirmed():
    from mcp_safeguard.scanner.hunter import HuntCardOutcome
    from mcp_safeguard.scanner.pipeline import (
        _NOTE_SSRF_CREDFWD_NO_TRIGGER,
        _is_sandbox_negative_pathtrav_ssrf_credfwd,
    )

    outcome = HuntCardOutcome(card=_taint_card_with_trace(), verdict="confirmed", note=_NOTE_SSRF_CREDFWD_NO_TRIGGER)
    assert _is_sandbox_negative_pathtrav_ssrf_credfwd(outcome) is False


def test_hunt_fleet_routes_sandbox_negative_taint_card_to_repo_reading_adversary(tmp_path, monkeypatch):
    from mcp_safeguard.scanner.adversary import AdversaryResult
    from mcp_safeguard.scanner.hunter import FleetHuntResult, HuntCardOutcome
    from mcp_safeguard.scanner.ledger import read_entries
    from mcp_safeguard.scanner.pipeline import _NOTE_SSRF_CREDFWD_NO_TRIGGER, hunt_fleet

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    taint_card = _taint_card_with_trace()
    stub_result = FleetHuntResult(
        repo_path=str(tmp_path),
        per_angle={"taint-shaped": [taint_card]},
        card_verdicts={
            "taint-shaped": [HuntCardOutcome(card=taint_card, verdict="unconfirmed", note=_NOTE_SSRF_CREDFWD_NO_TRIGGER)],
        },
    )
    _patch_run_hunter_fleet(monkeypatch, stub_result)

    class _ConfirmingRepoBackend:
        def adjudicate(self, claim_card):
            return AdversaryResult(verdict="confirmed", reasoning="the full file confirms it", model="stub-repo-adversary")

    ledger_path = tmp_path / "findings.jsonl"
    result = hunt_fleet(
        tmp_path, ledger_path=ledger_path, run_sandbox=False,
        repo_reading_adversary_backend=_ConfirmingRepoBackend(),
    )

    outcome = result.card_verdicts["taint-shaped"][0]
    # Fable's own risk (b): confirmed via this path lands at
    # "adversary-reviewed", NEVER plain "confirmed".
    assert outcome.verdict == "adversary-reviewed"
    # the original sandbox-negative fact stays visible in the final note.
    assert _NOTE_SSRF_CREDFWD_NO_TRIGGER in outcome.note
    assert "the full file confirms it" in outcome.note

    entries = read_entries(ledger_path)
    assert entries[0].verdict == "adversary-reviewed"


def test_hunt_fleet_repo_reading_adversary_skipped_honestly_with_no_backend(tmp_path, monkeypatch):
    from mcp_safeguard.scanner.hunter import FleetHuntResult, HuntCardOutcome
    from mcp_safeguard.scanner.ledger import read_entries
    from mcp_safeguard.scanner.pipeline import _NOTE_PATHTRAV_NO_TRIGGER, hunt_fleet

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    taint_card = _taint_card_with_trace()
    stub_result = FleetHuntResult(
        repo_path=str(tmp_path),
        per_angle={"taint-shaped": [taint_card]},
        card_verdicts={
            "taint-shaped": [HuntCardOutcome(card=taint_card, verdict="unconfirmed", note=_NOTE_PATHTRAV_NO_TRIGGER)],
        },
    )
    _patch_run_hunter_fleet(monkeypatch, stub_result)

    ledger_path = tmp_path / "findings.jsonl"
    result = hunt_fleet(tmp_path, ledger_path=ledger_path, run_sandbox=False)

    outcome = result.card_verdicts["taint-shaped"][0]
    assert outcome.verdict == "unconfirmed"
    assert "repo-reading adversary check skipped, no backend configured" in outcome.note
    entries = read_entries(ledger_path)
    assert "repo-reading adversary check skipped, no backend configured" in entries[0].notes


def test_hunt_fleet_repo_reading_adversary_respects_per_target_cap(tmp_path, monkeypatch):
    from mcp_safeguard.scanner.adversary import AdversaryResult
    from mcp_safeguard.scanner.hunter import FleetHuntResult, HuntCardOutcome
    from mcp_safeguard.scanner.pipeline import (
        _NOTE_SSRF_CREDFWD_NO_TRIGGER,
        _REPO_READING_ADVERSARY_PER_TARGET_CAP,
        hunt_fleet,
    )

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    n = _REPO_READING_ADVERSARY_PER_TARGET_CAP + 2
    cards = [_taint_card_with_trace(target_sink=f"server.py:{i} -- SSRF sink") for i in range(n)]
    outcomes = [HuntCardOutcome(card=c, verdict="unconfirmed", note=_NOTE_SSRF_CREDFWD_NO_TRIGGER) for c in cards]
    stub_result = FleetHuntResult(
        repo_path=str(tmp_path), per_angle={"taint-shaped": cards}, card_verdicts={"taint-shaped": outcomes},
    )
    _patch_run_hunter_fleet(monkeypatch, stub_result)

    calls = []

    class _CountingBackend:
        def adjudicate(self, claim_card):
            calls.append(claim_card)
            return AdversaryResult(verdict="confirmed", reasoning="confirmed", model="stub-repo-adversary")

    ledger_path = tmp_path / "findings.jsonl"
    result = hunt_fleet(
        tmp_path, ledger_path=ledger_path, run_sandbox=False, repo_reading_adversary_backend=_CountingBackend(),
    )

    assert len(calls) == _REPO_READING_ADVERSARY_PER_TARGET_CAP
    routed = [o for o in result.card_verdicts["taint-shaped"] if o.verdict == "adversary-reviewed"]
    skipped = [o for o in result.card_verdicts["taint-shaped"] if "per-target cap" in o.note]
    assert len(routed) == _REPO_READING_ADVERSARY_PER_TARGET_CAP
    assert len(skipped) == 2
    for o in skipped:
        assert o.verdict == "unconfirmed"


def test_hunt_fleet_lightweight_adversary_gate_unaffected_for_llm_angles(tmp_path, monkeypatch):
    """Explicit non-regression check: routing a sandbox-negative taint-shaped
    outcome to the repo-reading path must not change the existing
    lightweight ClaimCard-only gate's own behavior for `claims-vs-
    enforcement` -- the one LLM angle still on it under the
    candidate-widened-adversary milestone -- in the SAME hunt_fleet() call.
    (The other four LLM angles now share the repo-reading path with the
    taint-shaped case, on purpose -- see
    `test_hunt_fleet_all_four_widened_angles_route_to_repo_reading_pair`
    below for that coverage instead of here.)"""
    from mcp_safeguard.scanner.adversary import AdversaryResult
    from mcp_safeguard.scanner.hunter import FleetHuntResult, HuntCardOutcome
    from mcp_safeguard.scanner.ledger import read_entries
    from mcp_safeguard.scanner.pipeline import _NOTE_SSRF_CREDFWD_NO_TRIGGER, hunt_fleet

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    taint_card = _taint_card_with_trace()
    llm_card = _hunter_angle_card()
    stub_result = FleetHuntResult(
        repo_path=str(tmp_path),
        per_angle={"taint-shaped": [taint_card], "claims-vs-enforcement": [llm_card]},
        card_verdicts={
            "taint-shaped": [HuntCardOutcome(card=taint_card, verdict="unconfirmed", note=_NOTE_SSRF_CREDFWD_NO_TRIGGER)],
            "claims-vs-enforcement": [HuntCardOutcome(card=llm_card, verdict="unconfirmed", note="hunter note")],
        },
    )
    _patch_run_hunter_fleet(monkeypatch, stub_result)

    class _RefutingBackend:
        def adjudicate(self, claim_card):
            return AdversaryResult(verdict="refuted", reasoning="refuted", model="stub-adversary")

    class _ConfirmingRepoBackend:
        def adjudicate(self, claim_card):
            return AdversaryResult(verdict="confirmed", reasoning="confirmed via full file", model="stub-repo-adversary")

    ledger_path = tmp_path / "findings.jsonl"
    result = hunt_fleet(
        tmp_path, ledger_path=ledger_path, run_sandbox=False,
        adversary_backend=_RefutingBackend(), repo_reading_adversary_backend=_ConfirmingRepoBackend(),
    )

    assert result.card_verdicts["claims-vs-enforcement"][0].verdict == "refuted"
    assert result.card_verdicts["taint-shaped"][0].verdict == "adversary-reviewed"
    entries = {e.claim_card.target_sink: e for e in read_entries(ledger_path)}
    assert entries[llm_card.target_sink].verdict == "refuted"
    assert entries[taint_card.target_sink].verdict == "adversary-reviewed"


# --------------------------------------------------------------------------
# Role-diverse-adversary milestone (see
# bench/ROLE_DIVERSE_ADVERSARY_STATUS.md; transport-angle milestone added
# the 5th member): the five angles named in
# `pipeline._REPO_READING_ADVERSARY_ANGLES` (credential-and-secrets,
# cross-file-authority, whole-handler-audit, scope-selector-override,
# transport-and-exposure) are
# routed through Adversary A (`repo_reading_adversary_backend`, the
# repo-reading refuter, unchanged) paired with Adversary B
# (`role_diverse_adversary_backend`, a DIFFERENT role -- no repo access,
# external-assumption check -- not a second repo-reading copy), REPLACING
# the lightweight `adversary_backend`/`adversary_second_backend` gate for
# them entirely -- `claims-vs-enforcement` stays on the lightweight gate
# (covered above). No live LLM/Anthropic call anywhere in this section --
# same monkeypatched-collaborator discipline as every other section in this
# file (these stub backends test the WIRING, not either real prompt).
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "angle",
    ["credential-and-secrets", "cross-file-authority", "whole-handler-audit", "scope-selector-override", "transport-and-exposure"],
)
def test_hunt_fleet_widened_angles_route_to_role_diverse_pair_not_lightweight_gate(tmp_path, monkeypatch, angle):
    """The core wiring this milestone adds (five named angles as of the
    transport-angle milestone): each is
    routed through the Adversary-A/Adversary-B pair, and NEVER given to the
    lightweight `adversary_backend`/`adversary_second_backend` at all --
    proven by making the lightweight backend raise if it is ever called."""
    from mcp_safeguard.scanner.adversary import AdversaryResult
    from mcp_safeguard.scanner.ledger import read_entries
    from mcp_safeguard.scanner.pipeline import hunt_fleet

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    card = _hunter_angle_card(target_sink=f"server.py:1 -- {angle} candidate")
    stub_result = _stub_fleet_result(tmp_path, angle, card, "unconfirmed", "hunter note")
    _patch_run_hunter_fleet(monkeypatch, stub_result)

    class _NeverCallMe:
        def adjudicate(self, claim_card):
            raise AssertionError(f"the lightweight adversary must never be called for angle={angle!r}")

    class _ConfirmingRepoBackend:
        def adjudicate(self, claim_card):
            return AdversaryResult(verdict="confirmed", reasoning="held up under a full-repo read", model="stub-repo-adversary-a")

    class _ConfirmingRoleDiverseBackend:
        def adjudicate(self, claim_card):
            return AdversaryResult(verdict="confirmed", reasoning="agrees, independently", model="stub-role-diverse-adversary-b")

    ledger_path = tmp_path / "findings.jsonl"
    result = hunt_fleet(
        tmp_path, ledger_path=ledger_path, run_sandbox=False,
        adversary_backend=_NeverCallMe(), adversary_second_backend=_NeverCallMe(),
        repo_reading_adversary_backend=_ConfirmingRepoBackend(),
        role_diverse_adversary_backend=_ConfirmingRoleDiverseBackend(),
    )

    outcome = result.card_verdicts[angle][0]
    assert outcome.verdict == "adversary-reviewed"
    assert "two-adversary agreement" in outcome.note

    entries = read_entries(ledger_path)
    assert entries[0].verdict == "adversary-reviewed"


@pytest.mark.parametrize(
    "angle",
    ["credential-and-secrets", "cross-file-authority", "whole-handler-audit", "scope-selector-override", "transport-and-exposure"],
)
def test_hunt_fleet_widened_angle_role_diverse_pair_disagreement_collapses_to_unconfirmed(tmp_path, monkeypatch, angle):
    """Same 'disagreement is the real signal' discipline requires_agreement()
    already enforces for the lightweight gate -- now exercised through
    Adversary A (repo-reading) and Adversary B (role-diverse) instead."""
    from mcp_safeguard.scanner.adversary import AdversaryResult
    from mcp_safeguard.scanner.ledger import read_entries
    from mcp_safeguard.scanner.pipeline import hunt_fleet

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    card = _hunter_angle_card(target_sink=f"server.py:2 -- {angle} disagreement candidate")
    stub_result = _stub_fleet_result(tmp_path, angle, card, "unconfirmed", "hunter note")
    _patch_run_hunter_fleet(monkeypatch, stub_result)

    class _Backend:
        def __init__(self, verdict):
            self._verdict = verdict

        def adjudicate(self, claim_card):
            return AdversaryResult(verdict=self._verdict, reasoning="stub", model="stub-adversary")

    ledger_path = tmp_path / "findings.jsonl"
    result = hunt_fleet(
        tmp_path, ledger_path=ledger_path, run_sandbox=False,
        repo_reading_adversary_backend=_Backend("confirmed"),
        role_diverse_adversary_backend=_Backend("refuted"),
    )

    outcome = result.card_verdicts[angle][0]
    assert outcome.verdict == "unconfirmed"
    entries = read_entries(ledger_path)
    assert entries[0].verdict == "unconfirmed"


def test_hunt_fleet_widened_angle_skipped_honestly_with_no_repo_reading_backend(tmp_path, monkeypatch):
    """No injected repo-reading backend and no ANTHROPIC_API_KEY -> the same
    honest, non-fabricated skip note run_adversary_check itself produces for
    backend=None -- not a fabricated verdict, and NOT the lightweight gate's
    own skip path either (that gate is never consulted for this angle)."""
    from mcp_safeguard.scanner.ledger import read_entries
    from mcp_safeguard.scanner.pipeline import hunt_fleet

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    card = _hunter_angle_card()
    stub_result = _stub_fleet_result(tmp_path, "cross-file-authority", card, "unconfirmed", "hunter note")
    _patch_run_hunter_fleet(monkeypatch, stub_result)

    ledger_path = tmp_path / "findings.jsonl"
    result = hunt_fleet(tmp_path, ledger_path=ledger_path, run_sandbox=False)

    outcome = result.card_verdicts["cross-file-authority"][0]
    assert outcome.verdict == "unconfirmed"
    assert "adversary check skipped, no backend configured" in outcome.note
    entries = read_entries(ledger_path)
    assert entries[0].verdict == "unconfirmed"


def test_hunt_fleet_shares_one_lazily_built_repo_reading_pair_across_taint_and_llm_angle_candidates(tmp_path, monkeypatch):
    """A caller-injected Adversary-A/Adversary-B pair is reused for BOTH the
    taint-shaped sandbox-negative case (Adversary A alone) and a
    widened-LLM-angle case (both) in the SAME hunt_fleet() call -- proving
    the two real uses of this path share one pair rather than each
    independently constructing (or requiring) its own."""
    from mcp_safeguard.scanner.adversary import AdversaryResult
    from mcp_safeguard.scanner.hunter import FleetHuntResult, HuntCardOutcome
    from mcp_safeguard.scanner.ledger import read_entries
    from mcp_safeguard.scanner.pipeline import _NOTE_SSRF_CREDFWD_NO_TRIGGER, hunt_fleet

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    taint_card = _taint_card_with_trace()
    llm_card = _hunter_angle_card(target_sink="server.py:3 -- credential-and-secrets candidate")
    stub_result = FleetHuntResult(
        repo_path=str(tmp_path),
        per_angle={"taint-shaped": [taint_card], "credential-and-secrets": [llm_card]},
        card_verdicts={
            "taint-shaped": [HuntCardOutcome(card=taint_card, verdict="unconfirmed", note=_NOTE_SSRF_CREDFWD_NO_TRIGGER)],
            "credential-and-secrets": [HuntCardOutcome(card=llm_card, verdict="unconfirmed", note="hunter note")],
        },
    )
    _patch_run_hunter_fleet(monkeypatch, stub_result)

    calls_a: list[str] = []
    calls_b: list[str] = []

    class _BackendA:
        def adjudicate(self, claim_card):
            calls_a.append(claim_card.target_sink)
            return AdversaryResult(verdict="confirmed", reasoning="a", model="stub-repo-adversary-a")

    class _BackendB:
        def adjudicate(self, claim_card):
            calls_b.append(claim_card.target_sink)
            return AdversaryResult(verdict="confirmed", reasoning="b", model="stub-role-diverse-adversary-b")

    ledger_path = tmp_path / "findings.jsonl"
    hunt_fleet(
        tmp_path, ledger_path=ledger_path, run_sandbox=False,
        repo_reading_adversary_backend=_BackendA(), role_diverse_adversary_backend=_BackendB(),
    )

    # the taint-shaped case only ever calls the FIRST backend (single, not
    # paired -- unchanged adversary-repo-read behavior); the widened LLM-angle
    # case calls BOTH (the real pair). Both cases used the SAME two injected
    # instances -- no separate construction, no separate injection needed.
    assert taint_card.target_sink in calls_a
    assert taint_card.target_sink not in calls_b
    assert llm_card.target_sink in calls_a
    assert llm_card.target_sink in calls_b

    entries = {e.claim_card.target_sink: e for e in read_entries(ledger_path)}
    assert entries[taint_card.target_sink].verdict == "adversary-reviewed"
    assert entries[llm_card.target_sink].verdict == "adversary-reviewed"


def test_hunt_fleet_default_pair_is_repo_reading_plus_role_diverse_not_two_repo_readers(tmp_path, monkeypatch):
    """The real fix this milestone makes, proven at the default-construction
    level (no caller-injected backends): when ANTHROPIC_API_KEY is set,
    `_ensure_repo_reading_backends` builds ONE `RepoReadingAdversary`
    (Adversary A) and ONE `ExternalAssumptionAdversary` (Adversary B) --
    NEVER a second `RepoReadingAdversary` at a different model tier, which
    is the sibling candidate-widened-adversary-work clone's own design that
    bench/ROLE_DIVERSE_ADVERSARY_STATUS.md found does not work."""
    import mcp_safeguard.scanner.pipeline as pipeline_mod
    from mcp_safeguard.scanner.adversary import AdversaryResult
    from mcp_safeguard.scanner.ledger import read_entries
    from mcp_safeguard.scanner.pipeline import hunt_fleet

    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key-for-test")

    repo_reading_constructions = []
    role_diverse_constructions = []

    class _FakeRepoReadingAdversary:
        def __init__(self, **kwargs):
            repo_reading_constructions.append(kwargs)

        def adjudicate(self, claim_card):
            return AdversaryResult(verdict="confirmed", reasoning="a", model="fake-repo-reading")

    class _FakeExternalAssumptionAdversary:
        def __init__(self, **kwargs):
            role_diverse_constructions.append(kwargs)

        def adjudicate(self, claim_card):
            return AdversaryResult(verdict="confirmed", reasoning="b", model="fake-external-assumption")

    monkeypatch.setattr(pipeline_mod, "RepoReadingAdversary", _FakeRepoReadingAdversary)
    monkeypatch.setattr(pipeline_mod, "ExternalAssumptionAdversary", _FakeExternalAssumptionAdversary)

    card = _hunter_angle_card(target_sink="server.py:9 -- credential-and-secrets default-pair candidate")
    stub_result = _stub_fleet_result(tmp_path, "credential-and-secrets", card, "unconfirmed", "hunter note")
    _patch_run_hunter_fleet(monkeypatch, stub_result)

    ledger_path = tmp_path / "findings.jsonl"
    result = hunt_fleet(tmp_path, ledger_path=ledger_path, run_sandbox=False)

    assert len(repo_reading_constructions) == 1
    assert len(role_diverse_constructions) == 1
    # Shared-evidence-residue milestone: Adversary B now takes THIS run's own
    # repo_root too (like Adversary A) so it computes the same shared
    # evidence block A does -- no longer the no-repo-access role.
    assert "repo_root" in role_diverse_constructions[0]
    assert role_diverse_constructions[0]["repo_root"] == repo_reading_constructions[0]["repo_root"]

    outcome = result.card_verdicts["credential-and-secrets"][0]
    assert outcome.verdict == "adversary-reviewed"
    entries = read_entries(ledger_path)
    assert entries[0].verdict == "adversary-reviewed"
