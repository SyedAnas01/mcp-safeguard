"""Was a documented-not-fixed false-negative risk in critic.py's
`check_reachability_soundness()`: exact name/file matching against S2's
recovered entrypoints alone has no call-graph knowledge, so it cannot
recognize a genuine multi-hop finding (a real MCP tool handler calling a
helper function that holds the actual sink -- the exact shape the CREDFWD
class was built to catch from the real hf-mcp-server `invokeSpace`/
`callGradioToolWithHeaders` case) as reachable.

First fixed with a bounded, SINGLE-hop reverse-call check
(`_one_hop_reachable()`, as it was then named): does any real S2-recovered
entrypoint's own ON-DISK source directly call the function Stage 5 invoked?
That closed the deepseek-pp/`authedFetch` false positive but could not
resolve a genuine TWO-OR-MORE-hop finding -- the real hf-mcp-server bug's
true, deeper shape (see below).

Now generalized to a bounded, configurable MULTI-hop reverse-call check
(`_bounded_reverse_reachable()`, depth hard-capped 1-3, default 2): the
first two tests below (`test_genuine_multihop_finding_is_now_recognized_
sound`, `test_one_hop_check_does_not_manufacture_false_soundness`) are the
ORIGINAL single-hop regression tests, kept byte-identical in intent --
still passing proves the generalization did not regress the one-hop case
it replaces. The tests after them
(`test_genuine_two_hop_finding_is_recognized_sound_at_default_depth`,
`test_two_hop_check_does_not_follow_a_same_named_function_in_an_unrelated_
file`) are the new multi-hop validation: a genuine, deeper reachable chain
now correctly recognized as sound, and an adversarial same-named-function
-in-an-unrelated-file case that must still correctly stay unsound even with
the deeper search budget to explore it. See `bench/MULTIHOP_CRITIC_ATTEMPT_
STATUS.md` for the full validation, including the two real, ledger-backed
regression cases (deepseek-pp, Aiven) this file's synthetic fixtures don't
cover.
"""

from mcp_safeguard.scanner.claim_card import ClaimCard
from mcp_safeguard.scanner.critic import (
    CriticVerificationResult,
    build_critic_prompt,
    check_reachability_soundness,
    critique_finding,
    run_deterministic_critic,
)
from mcp_safeguard.scanner.prompt_injection import Severity
from mcp_safeguard.scanner.sandbox import OracleTrace
from mcp_safeguard.scanner.source_scanner import SourceFinding
from mcp_safeguard.scanner.taint_scanner import Step
from mcp_safeguard.scanner.threat_model import EntrypointProfile, ThreatModelDocument
from mcp_safeguard.scanner.untrusted_text import UNTRUSTED_BEGIN, UNTRUSTED_END

_GRADIO_CALLER_TS = """\
export async function invoke_space(space_id, headers) {
  return call_gradio_tool_with_headers(space_id, headers);
}

async function call_gradio_tool_with_headers(mcpUrl, hfToken) {
  const authHeaders = { Authorization: 'Bearer ' + hfToken };
  return fetch(mcpUrl, { headers: authHeaders });
}

async function unrelated_helper(x) {
  return fetch(x, {});
}
"""


def _write_gradio_caller(tmp_path):
    caller_dir = tmp_path / "space" / "utils"
    caller_dir.mkdir(parents=True)
    ts_file = caller_dir / "gradio-caller.ts"
    ts_file.write_text(_GRADIO_CALLER_TS)
    return ts_file


def _tmd_with_invoke_space(ts_file) -> ThreatModelDocument:
    return ThreatModelDocument(
        repo_path=str(ts_file.parents[2]),
        repo_name="hf-mcp-server",
        commit="abc123",
        generated_at="2026-01-01T00:00:00Z",
        entrypoints=[
            EntrypointProfile(
                file=str(ts_file),
                function_name="invoke_space",
                line=1,
                parameter_names=["space_id", "headers"],
                sdk_shape="fastmcp-tool",
                confidence="high",
            )
        ],
        claims=[],
    )


def test_genuine_multihop_finding_is_now_recognized_sound(tmp_path):
    """A real MCP entrypoint (`invoke_space`) calls a helper
    (`call_gradio_tool_with_headers`) that holds the real sink -- Stage 5
    resolves and invokes the HELPER directly (it is the sink-enclosing
    function), so `OracleTrace.entrypoint` names the helper, not the
    handler. The finding is genuinely reachable (a real external MCP caller
    of `invoke_space` can reach the sink): with a real `root` supplied,
    `check_reachability_soundness()` now re-parses `invoke_space()`'s own
    real source, finds the direct call to `call_gradio_tool_with_headers()`
    inside it, and correctly reports this as sound."""
    ts_file = _write_gradio_caller(tmp_path)
    tmd = _tmd_with_invoke_space(ts_file)
    claim_card = ClaimCard(
        target_sink=f"{ts_file}:6 -- call_gradio_tool_with_headers() forwards caller headers",
        tainted_source="headers argument, ultimately from invoke_space()'s own caller-controlled input",
        caller_authority_assumed="any MCP caller of invoke_space()",
        precondition="invoke_space() calls call_gradio_tool_with_headers() with caller-controlled headers",
        violated_claim=f"{ts_file}:6: forwards headers to an attacker-influenceable URL",
        oracle_trace=OracleTrace(
            sandbox_kind="docker",
            runtime="node",
            entrypoint=f"{ts_file}:call_gradio_tool_with_headers",
        ),
    )

    result = check_reachability_soundness(claim_card, claim_card.oracle_trace, tmd, root=tmp_path)

    assert result.sound is True
    assert result.checked_against_tmd is True
    assert "invoke_space" in result.reason


def test_one_hop_check_does_not_manufacture_false_soundness(tmp_path):
    """The one-hop fix must not overreach: a function in the SAME file that
    NO real recovered entrypoint calls (`unrelated_helper`, the
    deepseek-pp/`authedFetch`-shaped case -- a synthetic harness invoking an
    internal helper with no real caller) must still be flagged unsound, even
    though `root` is now supplied and the one-hop check runs for real."""
    ts_file = _write_gradio_caller(tmp_path)
    tmd = _tmd_with_invoke_space(ts_file)
    claim_card = ClaimCard(
        target_sink=f"{ts_file}:11 -- unrelated_helper() forwards its argument",
        tainted_source="x argument, synthesized directly by Stage 5 -- no real caller",
        caller_authority_assumed="none -- unrelated_helper() is never called by any recovered entrypoint",
        precondition="Stage 5 called unrelated_helper() directly as a synthetic PoC",
        violated_claim=f"{ts_file}:11: forwards its argument to an attacker-influenceable URL",
        oracle_trace=OracleTrace(
            sandbox_kind="docker",
            runtime="node",
            entrypoint=f"{ts_file}:unrelated_helper",
        ),
    )

    result = check_reachability_soundness(claim_card, claim_card.oracle_trace, tmd, root=tmp_path)

    assert result.sound is False
    assert result.checked_against_tmd is True


# --------------------------------------------------------------------------
# Multi-hop validation (depth 2-3): a genuine 2-hop reachable case, and an
# adversarial "looks reachable via a coincidentally-resolved same-named
# function in an unrelated file" case that must NOT be validated.
# --------------------------------------------------------------------------

_DYNAMIC_SPACE_TOOL_JS = """\
import { invoke_space } from './commands/invoke.js';

export async function dynamic_space(params) {
  return invoke_space(params.space_id, params.headers);
}
"""

_INVOKE_JS = """\
import { call_gradio_tool_with_headers } from '../utils/gradio-caller.js';

export async function invoke_space(space_id, headers) {
  return call_gradio_tool_with_headers(space_id, headers);
}
"""

_GRADIO_CALLER_JS = """\
export async function call_gradio_tool_with_headers(mcpUrl, hfToken) {
  const authHeaders = { Authorization: 'Bearer ' + hfToken };
  return fetch(mcpUrl, { headers: authHeaders });
}
"""


def _write_two_hop_hf_shape(tmp_path):
    """Mirrors the real, disclosed hf-mcp-server shape one level removed
    from the one-hop fixture above: the real, S2-recovered entrypoint
    (`dynamic_space`) does NOT call the real sink (`call_gradio_tool_with_
    headers`) directly -- it calls `invoke_space` (a different file, a real
    resolvable import), which is the one that calls the real sink (yet a
    THIRD file, also a real resolvable import). A one-hop-only check cannot
    see this; the bounded multi-hop check must recurse through
    `invoke_space` to find it."""
    space_dir = tmp_path / "space"
    (space_dir / "commands").mkdir(parents=True)
    (space_dir / "utils").mkdir(parents=True)
    dynamic_space_file = space_dir / "dynamic-space-tool.js"
    invoke_file = space_dir / "commands" / "invoke.js"
    gradio_caller_file = space_dir / "utils" / "gradio-caller.js"
    dynamic_space_file.write_text(_DYNAMIC_SPACE_TOOL_JS)
    invoke_file.write_text(_INVOKE_JS)
    gradio_caller_file.write_text(_GRADIO_CALLER_JS)
    return dynamic_space_file, invoke_file, gradio_caller_file


def test_genuine_two_hop_finding_is_recognized_sound_at_default_depth(tmp_path):
    """The real hf-mcp-server shape, one level deeper than the one-hop
    fixture: `dynamic_space()` (the real S2-recovered entrypoint) calls
    `invoke_space()` (a different file), which calls
    `call_gradio_tool_with_headers()` (the real sink, a THIRD file). Stage 5
    invoked the sink directly, two real, resolvable calls away from the
    real entrypoint. At the new default depth (2), `check_reachability_
    soundness()` must now recognize this as sound -- this is exactly the
    genuine multi-hop gap the original single-hop check (still exercised by
    the two tests above) could not close."""
    dynamic_space_file, invoke_file, gradio_caller_file = _write_two_hop_hf_shape(tmp_path)
    tmd = ThreatModelDocument(
        repo_path=str(tmp_path),
        repo_name="hf-mcp-server",
        commit="abc123",
        generated_at="2026-01-01T00:00:00Z",
        entrypoints=[
            EntrypointProfile(
                file=str(dynamic_space_file),
                function_name="dynamic_space",
                line=3,
                parameter_names=["params"],
                sdk_shape="fastmcp-tool",
                confidence="high",
            )
        ],
        claims=[],
    )
    claim_card = ClaimCard(
        target_sink=f"{gradio_caller_file}:1 -- call_gradio_tool_with_headers() forwards caller headers",
        tainted_source="headers argument, ultimately from dynamic_space()'s own caller-controlled input",
        caller_authority_assumed="any MCP caller of dynamic_space()",
        precondition="dynamic_space() -> invoke_space() -> call_gradio_tool_with_headers() with caller-controlled headers",
        violated_claim=f"{gradio_caller_file}:1: forwards headers to an attacker-influenceable URL",
        oracle_trace=OracleTrace(
            sandbox_kind="docker",
            runtime="node",
            entrypoint=f"{gradio_caller_file}:call_gradio_tool_with_headers",
        ),
    )

    # At the OLD depth (1, the original one-hop-only behavior): must still
    # NOT be found -- proves this genuine 2-hop finding really was outside
    # the original check's reach, not a fixture that happens to pass either way.
    one_hop_result = check_reachability_soundness(
        claim_card, claim_card.oracle_trace, tmd, root=tmp_path, max_reverse_call_depth=1
    )
    assert one_hop_result.sound is False

    # At the NEW default depth (2): now correctly recognized as sound.
    result = check_reachability_soundness(claim_card, claim_card.oracle_trace, tmd, root=tmp_path)
    assert result.sound is True
    assert result.checked_against_tmd is True
    assert "dynamic_space" in result.reason
    assert "invoke_space" in result.reason


_ADV_HANDLER_JS = """\
import { sink_fn } from './unrelated-helper.js';

export async function handler(x) {
  return process_request(x);
}

async function process_request(x) {
  return sink_fn(x);
}
"""

_ADV_UNRELATED_HELPER_JS = """\
export async function sink_fn(x) {
  return format_message(x);
}

function format_message(x) {
  return `harmless: ${x}`;
}
"""

_ADV_REAL_SINK_JS = """\
export async function sink_fn(mcpUrl, hfToken) {
  return fetch(mcpUrl, { headers: { Authorization: 'Bearer ' + hfToken } });
}
"""


def test_two_hop_check_does_not_follow_a_same_named_function_in_an_unrelated_file(tmp_path):
    """The adversarial case the task explicitly calls for: a call chain
    that IS real and DOES resolve through a genuine import -- just not to
    the function Stage 5 actually executed. `handler()` calls
    `process_request()` (same file), which calls `sink_fn()` -- a name that
    genuinely, resolvably imports to `unrelated-helper.js`'s OWN, unrelated
    `sink_fn()` (not a bare guess: a real `import` statement really points
    there). A completely different file, `real-sink.js`, happens to ALSO
    define a function literally named `sink_fn` -- the one Stage 5 actually
    invoked. Depth 3 gives the search enough budget to actually recurse
    INTO `unrelated-helper.js`'s `sink_fn()` body (proving this isn't just
    passing because the search ran out of depth before reaching the
    coincidental match) -- and it must still correctly conclude UNSOUND,
    because the real, resolved call target's FILE never matches
    `real-sink.js`, no matter how deep the search goes."""
    adv_dir = tmp_path / "adv"
    adv_dir.mkdir()
    handler_file = adv_dir / "handler.js"
    unrelated_file = adv_dir / "unrelated-helper.js"
    real_sink_file = adv_dir / "real-sink.js"
    handler_file.write_text(_ADV_HANDLER_JS)
    unrelated_file.write_text(_ADV_UNRELATED_HELPER_JS)
    real_sink_file.write_text(_ADV_REAL_SINK_JS)

    tmd = ThreatModelDocument(
        repo_path=str(tmp_path),
        repo_name="adversarial-fixture",
        commit="abc123",
        generated_at="2026-01-01T00:00:00Z",
        entrypoints=[
            EntrypointProfile(
                file=str(handler_file),
                function_name="handler",
                line=3,
                parameter_names=["x"],
                sdk_shape="fastmcp-tool",
                confidence="high",
            )
        ],
        claims=[],
    )
    claim_card = ClaimCard(
        target_sink=f"{real_sink_file}:1 -- sink_fn() forwards caller headers",
        tainted_source="mcpUrl/hfToken arguments, synthesized directly by Stage 5",
        caller_authority_assumed="none -- real-sink.js's sink_fn() is never really called by handler()",
        precondition="Stage 5 called real-sink.js's sink_fn() directly as a synthetic PoC",
        violated_claim=f"{real_sink_file}:1: forwards hfToken to an attacker-influenceable URL",
        oracle_trace=OracleTrace(
            sandbox_kind="docker",
            runtime="node",
            entrypoint=f"{real_sink_file}:sink_fn",
        ),
    )

    result = check_reachability_soundness(
        claim_card, claim_card.oracle_trace, tmd, root=tmp_path, max_reverse_call_depth=3
    )

    assert result.sound is False
    assert result.checked_against_tmd is True


# --------------------------------------------------------------------------
# Prompt-injection fix: untrusted ClaimCard fields and evidence-path source
# lines must be delimited in the critic's own prompt too. See
# untrusted_text.py and bench/PROMPT_INJECTION_FIX_STATUS.md.
# --------------------------------------------------------------------------


def _finding(severity: Severity = Severity.CRITICAL) -> SourceFinding:
    return SourceFinding(
        rule_id="TAINT-CREDFWD",
        severity=severity,
        title="Credential forwarded to attacker-controlled host",
        description="test fixture",
        location="server.py:10",
        evidence="API_TOKEN forwarded",
        remediation="n/a",
        cvss_score=9.1,
    )


def test_build_critic_prompt_wraps_claim_fields_and_evidence_path():
    finding = _finding()
    card = ClaimCard(
        target_sink="MARKER_SINK_c00",
        tainted_source="MARKER_SOURCE_c01",
        caller_authority_assumed="MARKER_AUTHORITY_c02",
        precondition="MARKER_PRECOND_c03",
        violated_claim="MARKER_CLAIM_c04",
        evidence_path=[Step(kind="sink", line=1, code="MARKER_CODE_c05", file="x.py")],
        impossibility_argument="test fixture, not a real Stage-5 execution",
    )
    deterministic = run_deterministic_critic(finding, card, None, "unconfirmed", False, None)
    prompt = build_critic_prompt(finding, card, deterministic)

    for marker in (
        "MARKER_SINK_c00", "MARKER_SOURCE_c01", "MARKER_AUTHORITY_c02",
        "MARKER_PRECOND_c03", "MARKER_CLAIM_c04", "MARKER_CODE_c05",
    ):
        idx = prompt.index(marker)
        begin_idx = prompt.rindex(UNTRUSTED_BEGIN, 0, idx)
        end_idx = prompt.index(UNTRUSTED_END, idx)
        assert begin_idx < idx < end_idx, f"{marker!r} is not enclosed by its own delimiter pair"


# --------------------------------------------------------------------------
# Severity-ceiling fix: the cross-tier LLM critic pass may LOWER or MATCH
# the deterministic pass's own recalibrated severity, never RAISE above it.
# See critique_finding's own docstring for why this is the fix, not the
# design's intent, and bench/PROMPT_INJECTION_FIX_STATUS.md for the wider
# writeup.
# --------------------------------------------------------------------------


def _unreachable_card() -> ClaimCard:
    """No `oracle_trace` at all and no `NO_ENTRYPOINT_MATCH_MARKER` in
    `caller_authority_assumed` -- `check_reachability_soundness()` returns
    `sound=True` (the tautology check this module targets simply doesn't
    apply when there's no real Stage-5 OracleTrace), but `recalibrate_
    severity()`'s OTHER condition (real execution evidence) is still False
    (no oracle_trace at all) -- so the deterministic pass downgrades one
    notch (CRITICAL -> HIGH) regardless of the sound reachability. This is
    the real ceiling every test below checks the LLM pass against."""
    return ClaimCard(
        target_sink="server.py:10 -- API_TOKEN forwarded",
        tainted_source="caller-controlled header",
        caller_authority_assumed="none",
        precondition="always",
        violated_claim="server.py:10: forwards credential to attacker host",
        impossibility_argument="test fixture, not a real Stage-5 execution",
    )


class _StubCriticVerifier:
    """A `CriticVerifier`-shaped stub that always returns a fixed,
    caller-chosen severity/verdict -- lets a test simulate an LLM critic
    that tries to RAISE severity, independent of any real API call."""

    def __init__(self, recommended_severity: Severity, recommended_verdict: str = "confirmed"):
        self._severity = recommended_severity
        self._verdict = recommended_verdict

    def critique(self, finding, claim_card, deterministic, root):
        return CriticVerificationResult(
            recommended_severity=self._severity,
            recommended_verdict=self._verdict,
            tautology_risk=False,
            reasoning="stub critic reasoning for test",
            model="stub-model",
        )


def test_deterministic_pass_downgrades_critical_to_high_with_no_execution_evidence():
    """Sanity-checks the fixture this whole section relies on: the
    deterministic ceiling the LLM pass must be capped against really is
    HIGH, not CRITICAL, for `_unreachable_card()`."""
    deterministic = run_deterministic_critic(_finding(Severity.CRITICAL), _unreachable_card(), None, "unconfirmed", False, None)
    assert deterministic.severity.recalibrated_severity == Severity.HIGH
    assert deterministic.severity.downgraded is True


def test_llm_critic_cannot_raise_severity_above_the_deterministic_ceiling():
    result = critique_finding(
        _finding(Severity.CRITICAL), _unreachable_card(), None, "unconfirmed", False, None,
        critic_verifier=_StubCriticVerifier(Severity.CRITICAL),
    )
    # the deterministic ceiling is HIGH (see the sanity check above); the
    # stub LLM critic tried to push severity back up to CRITICAL -- must be
    # capped at HIGH, never allowed through.
    assert result.final_severity == Severity.HIGH
    assert "capped" in result.note


def test_llm_critic_can_still_lower_severity_below_the_ceiling():
    """The cap is one-directional: the LLM pass may still lower severity
    further than the deterministic ceiling -- only RAISING above it is
    blocked, preserving "recalibrates severity downward by default" for
    this path too."""
    result = critique_finding(
        _finding(Severity.CRITICAL), _unreachable_card(), None, "unconfirmed", False, None,
        critic_verifier=_StubCriticVerifier(Severity.LOW),
    )
    assert result.final_severity == Severity.LOW
    assert "capped" not in result.note


def test_llm_critic_exactly_at_the_ceiling_is_not_flagged_as_capped():
    result = critique_finding(
        _finding(Severity.CRITICAL), _unreachable_card(), None, "unconfirmed", False, None,
        critic_verifier=_StubCriticVerifier(Severity.HIGH),
    )
    assert result.final_severity == Severity.HIGH
    assert "capped" not in result.note


# --------------------------------------------------------------------------
# critic-stage6-injection-fix milestone: finding.location AND the
# deterministic pass's own reachability/severity reason strings must be
# delimited too -- both are real, repo-derived (recovered by S2 threat-model
# extraction, embedding real function names/file paths from the scanned
# target) and were reaching this prompt unwrapped. See
# bench/CRITIC_STAGE6_INJECTION_FIX_STATUS.md and
# bench/critic_stage6_injection_fix_proof/critic_stage6_unwrapped_repro.py
# for the full real (taint-scanner-derived, not hand-typed) repro this test
# mirrors in miniature, and this file's own git history/`git stash` sanity
# check confirming this test fails against the pre-fix build_critic_prompt.
# --------------------------------------------------------------------------


def test_build_critic_prompt_wraps_location_and_reason_fields(tmp_path):
    """`finding.location`, `deterministic.reachability.reason`, and
    `deterministic.severity.reason` must all land inside their own
    `wrap_untrusted()` span. The first was tracked in
    `_KNOWN_UNFIXED_FINDINGS` (guard-heuristic-improvement milestone); the
    second was a previously unconfirmed "reason fields" lead, confirmed real
    here: both reason strings embed real repo-derived function names/file
    paths, e.g. `check_reachability_soundness()`'s own
    `", ".join(f"{e.function_name}@{e.file}" for e in tmd.entrypoints)` in
    its "not among the N real MCP entrypoint(s)" branch, exercised for real
    below via a genuinely mismatched OracleTrace/ThreatModelDocument pair
    (not a hand-typed reason string)."""
    finding = _finding()
    finding.location = "MARKER_LOCATION_c06.py:10"

    other_file = tmp_path / "other.py"
    other_file.write_text("def unrelated():\n    pass\n")
    tmd = ThreatModelDocument(
        repo_path=str(tmp_path),
        repo_name="critic-stage6-fix-test",
        commit="abc123",
        generated_at="2026-01-01T00:00:00Z",
        entrypoints=[
            EntrypointProfile(
                file=str(tmp_path / "MARKER_LOCATION_c06.py"),
                function_name="MARKER_ENTRYPOINT_c07",
                line=1,
                parameter_names=["x"],
                sdk_shape="fastmcp-tool",
                confidence="high",
            )
        ],
        claims=[],
    )
    card = ClaimCard(
        target_sink="MARKER_SINK_c00",
        tainted_source="MARKER_SOURCE_c01",
        caller_authority_assumed="MARKER_AUTHORITY_c02",
        precondition="MARKER_PRECOND_c03",
        violated_claim="MARKER_CLAIM_c04",
        oracle_trace=OracleTrace(sandbox_kind="docker", runtime="python", entrypoint=f"{other_file}:unrelated"),
    )
    deterministic = run_deterministic_critic(finding, card, card.oracle_trace, "confirmed", True, tmd, root=tmp_path)
    # Sanity check on the fixture itself: `unrelated()` really is NOT among
    # the TMD's recovered entrypoints, so check_reachability_soundness()
    # really does take the "not among the N real entrypoints" branch that
    # embeds MARKER_ENTRYPOINT_c07 into `.reason` -- not passing by luck.
    assert deterministic.reachability.sound is False
    assert "MARKER_ENTRYPOINT_c07" in deterministic.reachability.reason
    assert "MARKER_ENTRYPOINT_c07" in deterministic.severity.reason

    prompt = build_critic_prompt(finding, card, deterministic)

    for marker in ("MARKER_LOCATION_c06", "MARKER_ENTRYPOINT_c07"):
        idx = prompt.index(marker)
        begin_idx = prompt.rindex(UNTRUSTED_BEGIN, 0, idx)
        end_idx = prompt.index(UNTRUSTED_END, idx)
        assert begin_idx < idx < end_idx, f"{marker!r} is not enclosed by its own delimiter pair"

    # MARKER_ENTRYPOINT_c07 must appear, delimited, in BOTH the reachability
    # reasoning line and the severity reasoning line --
    # recalibrate_severity() embeds reachability.reason verbatim in its own
    # "missing" list, so this is a real, not incidental, second occurrence.
    severity_line_start = prompt.index("- severity reasoning:")
    severity_tail = prompt[severity_line_start:]
    assert "MARKER_ENTRYPOINT_c07" in severity_tail
    idx = severity_tail.index("MARKER_ENTRYPOINT_c07")
    begin_idx = severity_tail.rindex(UNTRUSTED_BEGIN, 0, idx)
    end_idx = severity_tail.index(UNTRUSTED_END, idx)
    assert begin_idx < idx < end_idx, "MARKER_ENTRYPOINT_c07 in the severity reasoning line is not enclosed by its own delimiter pair"
