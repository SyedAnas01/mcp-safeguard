"""S4/S6 (fleet design): the adversary input/output contract.

From `mcp-safeguard-agent-fleet-design-2026-09-05`: "context-asymmetric,
cold-start, cross-model-family Adversary agents try to refute each [claim],
seeing ONLY the claim and the code, never the hunter's reasoning trace
(this independence design is critical -- same-model agents agree with each
other ~60% of the time WHEN BOTH ARE WRONG, so cross-family disagreement is
the real signal, not consensus)".

Two things live here, both fully unit-testable with no live LLM call:

1. `build_adversary_prompt(claim_card)` -- turns a `ClaimCard` into the
   adversary's prompt text. The context-asymmetry rule is enforced AT THE
   TYPE LEVEL, not by convention: the function's only parameter is a
   `ClaimCard` object, not a free-text string, so there is no code path by
   which a hunter's own narrative/reasoning text could be concatenated in
   -- the prompt body only ever reads four of the card's fields
   (`target_sink`, `tainted_source`, `precondition`, `violated_claim`) plus
   the raw source lines already captured in `evidence_path`. It never reads
   `caller_authority_assumed`, `oracle_trace`, or `impossibility_argument`
   -- the last two are exactly where a hunter's own written reasoning
   would live, so they are deliberately excluded, not merely unused.

   Adversary-fullcontext milestone: `evidence_path`'s `Step`s can now also
   carry a `context` field (taint_scanner.py) -- a real, bounded block of
   surrounding source (typically the cited line's own enclosing function/
   method body; for a doc-file citation, its enclosing Markdown header
   section -- doc-context-fix milestone, see bench/DOC_CONTEXT_FIX_STATUS.md),
   re-read from disk by `hunter._evidence_path_from_citations`
   at candidate-parse time, the one place that already has both a real repo
   root and the real cited lines (this function's own signature stays a
   single `ClaimCard` parameter -- see the structural test in
   test_adversary.py -- so it has no repo root of its own to fetch more
   context with). This function renders every distinct `context` block it
   finds, deduped, in its own clearly separate section below the raw cited
   lines. It is still ONLY real source code, re-read from the same repo the
   hunter saw -- never the hunter's own reasoning, and a citation with
   nothing more to honestly show (module-level code, an unsupported
   language, or a doc-file line before its first heading) simply
   contributes nothing extra, exactly as before this milestone. Merged onto
   the prompt-injection fix
   (`untrusted_text.py`): this section is scanned-target source text like
   every other field in this prompt, so it is wrapped in the same
   `wrap_untrusted()` delimiter pair as `target_sink`/`source_lines`/etc,
   not left unmarked.
2. `requires_agreement(verdict_a, verdict_b)` -- the two-independent
   -adversary-agreement contract: only a shared `confirmed`/`refuted`
   verdict survives; any disagreement (including one side saying
   `unconfirmed`) collapses to `unconfirmed` with both raw verdicts
   attached for a human to review. Deliberately the same shape as
   `verify.py`'s own `verify_with_agreement`/`AgreementResult` (two-RUN
   agreement for one verifier), but this is two-AGENT agreement across
   independent adversaries -- a different axis of the same discipline: no
   single non-deterministic or biased judgment is ever trusted alone.
"""

from __future__ import annotations

import ast
import functools
import json
import os
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .claim_card import ClaimCard
from .cost import CostTracker
from .critic import (
    _cap_severity_at_ceiling,
    _js_call_hop_target,
    _js_callee_name,
    _one_notch_down,
    _py_call_hop_target,
    _py_callee_name,
    check_reachability_soundness,
)
from .cross_file import find_python_function
from .deployment_profile import DeploymentProfile, compute_deployment_profile
from .lexical import strip_comments_and_docstrings
from .prompt_injection import Severity
from .sandbox import OracleTrace
from .taint_scanner import _find_enclosing_function
from .threat_model import ThreatModelDocument, build_threat_model
from .untrusted_text import UNTRUSTED_CONTENT_WARNING, wrap_untrusted
from .verify import Verdict, build_anthropic_client

_VALID_VERDICTS = frozenset(("confirmed", "refuted", "unconfirmed"))

# WS5 (plan C2): the repo-reading path may also answer `confirmed-conditional`
# -- the mechanism is real in the code, but exploitability rests on a named
# deployment assumption the repo cannot establish either way (e.g. "one
# transport instance shared across unrelated callers"). `_VALID_VERDICTS`
# above is deliberately unchanged (the bare-prompt path has no such option);
# this wider set is what the repo-reading/residue backends and
# `requires_agreement` accept. It maps to the existing `adversary-reviewed`
# ledger tier (ledger.py is not changed by this milestone) and is surfaced
# through `AdversaryCheckResult.conditional`/`.assumption`.
CONDITIONAL_VERDICT = "confirmed-conditional"
_VALID_VERDICTS_V2 = _VALID_VERDICTS | {CONDITIONAL_VERDICT}
_CONFIRMING = frozenset(("confirmed", CONDITIONAL_VERDICT))


def build_adversary_prompt(claim_card: ClaimCard) -> str:
    """Build the adversary's prompt from a `ClaimCard` -- and ONLY a
    `ClaimCard`. Raises `TypeError` for anything else (including a plain
    string or dict), which is the point: there is no way to call this with
    free-text hunter narrative instead of a structured card, by
    construction of the signature, not by a runtime content filter.
    """
    if not isinstance(claim_card, ClaimCard):
        raise TypeError(
            f"build_adversary_prompt requires a ClaimCard object, got {type(claim_card).__name__!r} -- "
            "this is deliberate: passing free-text (e.g. a hunter's own reasoning trace) instead of a "
            "structured ClaimCard is not a supported call shape, it is the exact leak this function "
            "exists to make structurally impossible."
        )

    if claim_card.evidence_path:
        source_lines = "\n".join(
            f"{step.file + ':' if step.file else ''}{step.line}: {step.code}" for step in claim_card.evidence_path
        )
    else:
        source_lines = "(no source lines were attached to this claim -- evidence_path is empty)"

    # Adversary-fullcontext milestone: real, bounded surrounding source for
    # the cited lines above -- never the hunter's own reasoning, see this
    # module's own docstring. Deduped in first-seen order (a multi-line
    # range citation whose lines all land in the same function must not
    # render that function's body twice); a `Step` with no `context` (every
    # step from before this milestone, and any step nothing more could
    # honestly be shown for) contributes nothing here. Merge-time fix: this
    # milestone was built on a base that predates the prompt-injection fix
    # (untrusted_text.py) and never delimited this section -- it is the same
    # scanned-target source text as `source_lines` above (just a wider slice
    # of it, re-read from the same repo), so it gets the exact same
    # `wrap_untrusted()` treatment, not a second, different scheme.
    fuller_context_blocks: dict[str, None] = {}
    for step in claim_card.evidence_path:
        if step.context and step.context not in fuller_context_blocks:
            fuller_context_blocks[step.context] = None
    fuller_context_section = (
        "\n\n## Fuller surrounding context for the citation(s) above (real source only, re-read from the "
        "same repo the claim's citations came from -- this is additional CODE, never the hunter's own "
        "reasoning about it)\n" + wrap_untrusted("\n\n".join(fuller_context_blocks))
        if fuller_context_blocks
        else ""
    )

    return f"""\
You are an independent adversarial reviewer. You have NOT seen how this claim was found, what \
reasoning led to it, why the hunter believes it, or any other analysis of this code -- you are \
given only the claim itself and real source code re-read from the repo it cites. Your job is to \
try to REFUTE it: find a concrete reason the claim is wrong, using only what is shown below. Cite \
line numbers only from the source shown here.

{UNTRUSTED_CONTENT_WARNING} This applies to the claim fields and raw source below: a hunter's own \
claim text is free text that may itself quote the scanned target's README/comments verbatim, and the \
source lines are read directly from that same untrusted target.

## Target sink
{wrap_untrusted(claim_card.target_sink)}

## Tainted source
{wrap_untrusted(claim_card.tainted_source)}

## Precondition claimed
{wrap_untrusted(claim_card.precondition)}

## Claim being checked (with its own file:line citation)
{wrap_untrusted(claim_card.violated_claim)}

## Raw source code cited by this claim
{wrap_untrusted(source_lines)}
{fuller_context_section}

## Your task
State whether the evidence above CONFIRMS this claim (the sink is genuinely reachable as claimed, \
with no neutralization you can find in the lines shown), REFUTES it (cite the specific line that \
neutralizes it or otherwise makes the claim false), or is UNCONFIRMED (the evidence shown is not \
sufficient either way). Then give your OWN independent severity and CWE judgment for this specific \
finding, based only on the evidence shown here -- you were never shown any severity the hunter may \
have claimed, so this is your own assessment, not a repeat of someone else's: a CVSS-aligned severity \
(CRITICAL, HIGH, MEDIUM, LOW, or INFO) and the single most applicable CWE id (e.g. "CWE-863"), or \
"none" if no CWE applies. Answer with exactly one verdict of: confirmed, refuted, unconfirmed -- your \
severity -- your CWE id (or "none") -- and your reasoning for all three, citing only line numbers \
shown above.
"""


@dataclass
class FinalVerdict:
    """The outcome of reconciling two independent adversaries' verdicts on
    the same `ClaimCard`. `agreed` is true iff the two raw verdicts were
    identical -- `verdict` is that shared value only when it was
    `confirmed` or `refuted`; agreeing on `unconfirmed`, or disagreeing at
    all, both collapse `verdict` to `"unconfirmed"`. Both raw verdicts are
    always attached, so a human reviewer can see exactly what happened,
    never just the collapsed outcome.

    `impact_basis` (shared-evidence-residue milestone) is purely additive:
    `None` unless a caller passed one through `requires_agreement` (only
    Adversary B, `ExternalAssumptionAdversary`, ever produces one -- see
    `AdversaryResult.impact_basis`'s own docstring). It is NOT part of the
    agreement contract itself -- it never changes `agreed`/`verdict`, it is
    just carried through so a human/report can see what B stripped
    alongside the reconciled verdict."""

    verdict: Verdict
    verdict_a: Verdict
    verdict_b: Verdict
    agreed: bool
    impact_basis: str | None = None


def requires_agreement(verdict_a: Verdict, verdict_b: Verdict, impact_basis_b: str | None = None) -> FinalVerdict:
    """The two-independent-adversary-agreement contract: a `confirmed` or
    `refuted` verdict is only trusted when BOTH independent adversaries
    reached it. Any disagreement -- including one adversary saying
    `unconfirmed` while the other says `confirmed`/`refuted` -- returns
    `unconfirmed` with both raw verdicts attached, exactly the same
    "disagreement is the real signal, don't average it away" discipline
    the fleet design names for cross-model-family adversaries.

    `impact_basis_b` (shared-evidence-residue milestone, optional, default
    `None`) is Adversary B's own `AdversaryResult.impact_basis` -- passed
    through unchanged onto the returned `FinalVerdict.impact_basis`. It
    plays NO role in computing `agreed`/`verdict` -- the agreement contract
    itself is completely unchanged by this milestone, exactly as Fable
    specified ("no changes to `_VALID_VERDICTS`, tier mapping, or ledger" --
    this is the same guarantee applied to `requires_agreement` itself)."""
    for v in (verdict_a, verdict_b):
        if v not in _VALID_VERDICTS_V2:
            raise ValueError(f"not a recognized verdict: {v!r} -- expected one of {sorted(_VALID_VERDICTS_V2)}")

    agreed = verdict_a == verdict_b
    if verdict_a in _CONFIRMING and verdict_b in _CONFIRMING:
        # confirmed + confirmed-conditional: both think the mechanism is real;
        # the weaker (conditional) reading governs. Not a disagreement.
        agreed = True
        final: Verdict = CONDITIONAL_VERDICT if CONDITIONAL_VERDICT in (verdict_a, verdict_b) else "confirmed"  # type: ignore[assignment]
    else:
        final = verdict_a if (agreed and verdict_a in ("confirmed", "refuted")) else "unconfirmed"
    return FinalVerdict(
        verdict=final, verdict_a=verdict_a, verdict_b=verdict_b, agreed=agreed, impact_basis=impact_basis_b
    )


# --------------------------------------------------------------------------
# The adversary GATE (this milestone): the two functions above have existed
# since the fleet-scaffold milestone, but nothing ever called them -- every
# hunter-fleet ClaimCard with no execution evidence (the LLM angles in
# hunter.py: claims-vs-enforcement, credential-and-secrets, cross-file-
# authority, and -- added later -- whole-handler-audit, scope-selector-override,
# transport-and-exposure) went straight to the ledger as "unconfirmed" with no
# adversarial check at all (`grep -rn adversary pipeline.py hunter.py
# cli.py` returned zero hits before this milestone). What follows is a
# pluggable Verifier-shaped backend for actually RUNNING the adversary
# check, mirroring `verify.py`'s own `Verifier`/`AnthropicVerifier`/
# `ManualRecordVerifier` shape exactly -- same reasoning as that module's
# own docstring: a portable CLI tool cannot invoke Claude Code's own `Agent`
# tool, so a live-agent-backed adversary run comes in through the same
# injectable-callable seam a real `AnthropicAdversary` would use.
# --------------------------------------------------------------------------


@dataclass
class AdversaryResult:
    """One adversary backend's own answer for one `ClaimCard`: the raw
    `confirmed`/`refuted`/`unconfirmed` verdict, its own independent
    `severity`/`cwe` judgment (adversary-severity milestone --
    `build_adversary_prompt`'s "Your task" section asks for these alongside
    the verdict, not just confirmed/refuted), its reasoning text, and which
    model/backend produced it. Two of these (from two independent backends,
    or the same backend called twice -- see `run_adversary_check`) are what
    `requires_agreement()` above reconciles into a `FinalVerdict`, and what
    `run_adversary_check` reconciles the `severity`/`cwe` judgments of the
    same way (see its own docstring).

    `severity`/`cwe` default to `Severity.INFO`/`None` so that every
    pre-existing backend/stub built before this milestone (this module's own
    tests, `pipeline.py`'s test doubles) that constructs an `AdversaryResult`
    without them keeps working unchanged -- a real backend always sets both
    from the model's actual structured response.

    `impact_basis` (shared-evidence-residue milestone) defaults to `None`
    for the exact same reason -- only `ExternalAssumptionAdversary`
    (Adversary B) ever sets it (its own `_RESIDUE_TEST_TOOL_SCHEMA` is the
    only tool schema that asks for it); every other backend's
    `AdversaryResult` construction is unaffected. `"in-repo"` means B
    stripped nothing load-bearing; `"external:<system>: <step>"` means B
    stripped a real, load-bearing external-system assumption -- see this
    module's own shared-evidence-residue section comment."""

    verdict: Verdict
    reasoning: str
    model: str
    severity: Severity = Severity.INFO
    cwe: str | None = None
    impact_basis: str | None = None
    # WS5: the named deployment assumption behind a `confirmed-conditional`
    # verdict; `None` for every other verdict.
    assumption: str | None = None


class AdversaryBackend(Protocol):
    def adjudicate(self, claim_card: ClaimCard) -> AdversaryResult: ...


_ADVERSARY_TOOL_SCHEMA = {
    "name": "submit_adversary_verdict",
    "description": (
        "Submit this independent adversarial review's verdict, plus your own severity/CWE judgment, "
        "for the claim shown."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "verdict": {"type": "string", "enum": sorted(_VALID_VERDICTS)},
            "severity": {
                "type": "string",
                "enum": sorted(s.value for s in Severity),
                "description": (
                    "Your own CVSS-aligned severity judgment for this specific finding, based only on "
                    "the evidence shown here -- not a repeat of any severity claimed elsewhere, you were "
                    "never shown one."
                ),
            },
            "cwe": {
                "type": "string",
                "description": "The single most applicable CWE id (e.g. 'CWE-863'), or 'none' if none applies.",
            },
            "reasoning": {"type": "string"},
        },
        "required": ["verdict", "severity", "cwe", "reasoning"],
    },
}


_ADVERSARY_TOOL_SCHEMA_V2 = {
    "name": "submit_adversary_verdict",
    "description": _ADVERSARY_TOOL_SCHEMA["description"],
    "input_schema": {
        "type": "object",
        "properties": {
            **_ADVERSARY_TOOL_SCHEMA["input_schema"]["properties"],
            "verdict": {"type": "string", "enum": sorted(_VALID_VERDICTS_V2)},
            "assumption": {
                "type": "string",
                "description": (
                    "Only for verdict 'confirmed-conditional': the single concrete deployment condition "
                    "under which the finding is exploitable. Empty otherwise."
                ),
            },
        },
        "required": ["verdict", "severity", "cwe", "reasoning"],
    },
}


def _result_from_tool_input(data: dict[str, Any], model: str, *, impact_basis: Any = None) -> AdversaryResult:
    """Repo-reading/residue backends' shared parse (accepts `confirmed-conditional`).
    A conditional verdict without a stated assumption is downgraded to
    `unconfirmed`: an unnamed precondition is not a verdict."""
    verdict = data.get("verdict")
    if verdict not in _VALID_VERDICTS_V2:
        verdict = "unconfirmed"
    assumption = str(data.get("assumption") or "").strip() or None
    if verdict == CONDITIONAL_VERDICT and assumption is None:
        verdict = "unconfirmed"
    return AdversaryResult(
        verdict=verdict,
        reasoning=str(data.get("reasoning", "")),
        model=model,
        severity=_parse_adversary_severity(data.get("severity")),
        cwe=_parse_adversary_cwe(data.get("cwe")),
        impact_basis=_parse_impact_basis(impact_basis) if impact_basis is not None else None,
        assumption=assumption if verdict == CONDITIONAL_VERDICT else None,
    )


def _parse_adversary_severity(raw: Any) -> Severity:
    """Coerce a raw severity value (from a forced tool call's JSON, or a
    hand/agent-authored recorded-answer dict) into a real `Severity` --
    falls back to the safe floor `Severity.INFO` for anything missing or not
    one of the five recognized values, same 'never guess upward' discipline
    `AnthropicAdversary`/`ManualRecordAdversary` already apply to `verdict`
    below."""
    try:
        return Severity(raw)
    except (ValueError, TypeError):
        return Severity.INFO


def _parse_adversary_cwe(raw: Any) -> str | None:
    """`None` for a missing/blank CWE or the literal `"none"` (case
    -insensitive) the prompt explicitly allows as an answer -- never an
    empty string standing in for 'no CWE applies'."""
    text = str(raw).strip() if raw is not None else ""
    if not text or text.lower() == "none":
        return None
    return text


class AnthropicAdversary:
    """Real LLM backend for the adversary check, mirroring `AnthropicVerifier`
    (`verify.py`) and `AnthropicCriticVerifier` (`critic.py`) exactly:
    temperature 0, a forced tool call for structured JSON (never free-text
    parsing), requires a real `ANTHROPIC_API_KEY`, and is never invoked with
    a mocked response.

    Default model is a genuinely DIFFERENT tier than `hunter.py`'s own
    `AnthropicHunter` default (`claude-sonnet-4-5-20250929`) when this class
    is used as the SECOND of two adversaries -- same "cross-family in
    practice means cross-model-TIER within Claude" precedent
    `AnthropicCriticVerifier` already established (its own docstring), not a
    new convention invented here. Callers wanting genuine two-adversary
    independence should construct two instances with different `model=`
    values (see `pipeline.hunt_fleet`'s own default wiring) rather than
    relying on this class's own default alone.
    """

    def __init__(self, model: str = "claude-sonnet-4-5-20250929", api_key: str | None = None, *, cost_tracker: CostTracker | None = None):
        self._model = model
        self._client = build_anthropic_client("AnthropicAdversary", api_key)
        self._cost_tracker = cost_tracker

    def adjudicate(self, claim_card: ClaimCard) -> AdversaryResult:
        prompt = build_adversary_prompt(claim_card)
        start = time.monotonic()
        response = self._client.messages.create(
            model=self._model,
            max_tokens=1500,
            temperature=0,
            tools=[_ADVERSARY_TOOL_SCHEMA],
            tool_choice={"type": "tool", "name": "submit_adversary_verdict"},
            messages=[{"role": "user", "content": prompt}],
        )
        if self._cost_tracker is not None:
            self._cost_tracker.record_from_response(
                "adversary", claim_card.target_sink, self._model, response, time.monotonic() - start
            )
        tool_use = next((b for b in response.content if getattr(b, "type", None) == "tool_use"), None)
        if tool_use is None:
            return AdversaryResult(
                verdict="unconfirmed",
                reasoning="model did not return the required submit_adversary_verdict tool call",
                model=self._model,
            )
        verdict = tool_use.input.get("verdict")
        if verdict not in _VALID_VERDICTS:
            verdict = "unconfirmed"
        return AdversaryResult(
            verdict=verdict,
            reasoning=str(tool_use.input.get("reasoning", "")),
            model=self._model,
            severity=_parse_adversary_severity(tool_use.input.get("severity")),
            cwe=_parse_adversary_cwe(tool_use.input.get("cwe")),
        )


class ManualRecordAdversary:
    """Playback backend for recorded/offline adversary runs (no LLM API key
    available) -- same pattern as `ManualRecordVerifier`/`ManualRecordHunter`.
    Each recorded answer was produced by a real cold `Agent`-tool dispatch (or
    a human) reading the ACTUAL prompt `build_adversary_prompt()` generated
    for that exact `ClaimCard` -- context-asymmetric, seeing only the claim
    itself, never the hunter's own reasoning trace -- not mocked or guessed.
    Raises `KeyError` for any card it has no recorded answer for; it never
    fabricates one. See `bench/ADVERSARY_GATE_STATUS.md` for how the recorded
    answers in this project were actually produced.

    Keyed by `claim_card.target_sink` (a `ClaimCard` has no separate stable
    id field) -- unique enough across the real recorded proof cases this
    class was built for; a caller with two cards sharing an identical
    `target_sink` string would need to record answers for both under that
    one shared key (same limitation `ManualRecordHunter` accepts for its own
    `f"{angle}@{repo_path}"` key)."""

    def __init__(self, recorded: dict[str, list[dict[str, Any]]], *, cost_tracker: CostTracker | None = None):
        self._recorded = recorded
        self._calls: dict[str, int] = {}
        self._cost_tracker = cost_tracker

    @staticmethod
    def _key(claim_card: ClaimCard) -> str:
        return claim_card.target_sink

    def adjudicate(self, claim_card: ClaimCard) -> AdversaryResult:
        key = self._key(claim_card)
        runs = self._recorded.get(key)
        if not runs:
            raise KeyError(
                f"no manually-recorded adversary answer for target_sink={key!r} -- ManualRecordAdversary only "
                f"replays answers actually produced during a real cold-agent run, it does not fabricate one "
                f"for an unrecorded card"
            )
        idx = self._calls.get(key, 0)
        data = runs[idx % len(runs)]
        self._calls[key] = idx + 1
        if self._cost_tracker is not None:
            # True no-op unless `data` carries a "usage" dict of real,
            # externally-supplied token counts -- see
            # CostTracker.record_usage_dict's own docstring.
            self._cost_tracker.record_usage_dict(
                "adversary", key, str(data.get("model", "manual-recorded[cold-agent-dispatch]")), data.get("usage")
            )
        verdict = data.get("verdict")
        if verdict not in _VALID_VERDICTS:
            verdict = "unconfirmed"
        return AdversaryResult(
            verdict=verdict,
            reasoning=str(data.get("reasoning", "")),
            model=str(data.get("model", "manual-recorded[cold-agent-dispatch]")),
            severity=_parse_adversary_severity(data.get("severity")),
            cwe=_parse_adversary_cwe(data.get("cwe")),
        )


# `requires_agreement`'s own "confirmed"/"refuted" values mean "the adversary
# tried to refute this and could/couldn't" -- NOT "execution confirmed it"
# (that meaning is already owned by `pipeline._final_verdict`'s Stage-5
# oracle-trace path). A hunter-angle finding has no execution evidence and
# can never earn plain "confirmed" (see `ClaimCard`'s own emit invariant --
# these cards carry an `impossibility_argument`, never an `oracle_trace`).
# This map is the one place that distinction is enforced: an adversary
# agreeing the claim holds up promotes it to the distinct `"adversary-
# reviewed"` ledger tier (this project's own vocabulary for the fleet
# design's "V -- survived cross-family adversarial re-derivation" tier; see
# `bench/ADVERSARY_GATE_STATUS.md` for why the design doc's bare "V" letter
# was not reused verbatim -- `cli.py`'s pre-existing `--verify` tier display
# already uses "V" for a different mechanism, Stage-4 single-model 2-run
# agreement), never plain `"confirmed"`.
_ADVERSARY_VERDICT_TO_LEDGER_TIER: dict[Verdict, Verdict] = {
    "confirmed": "adversary-reviewed",
    CONDITIONAL_VERDICT: "adversary-reviewed",
    "refuted": "refuted",
    "unconfirmed": "unconfirmed",
}


@dataclass
class AdversaryCheckResult:
    """What `run_adversary_check` decided for one `ClaimCard`: the ledger
    tier to record (`verdict`), a human-readable `note` explaining how it
    was reached, whether a check actually ran at all (`checked` is `False`
    only for the graceful no-backend-configured skip), and the raw
    adversary answer(s) behind that tier for a human reviewer to audit.

    `severity`/`cwe` (adversary-severity milestone) are the FINAL,
    already-capped severity/CWE judgment for this claim -- populated ONLY
    when `verdict == "adversary-reviewed"` (a refuted/unconfirmed claim's
    severity is moot, same "severity only matters for an accepted finding"
    reasoning `critic.py`'s own S6 gate already uses); `None` for every other
    outcome, including the no-backend-configured skip and a raising backend.
    `pipeline.hunt_fleet` copies these onto `ClaimCard.severity`/`.cwe` when
    set. See this function's own docstring for exactly how they are derived
    and capped -- same "can only lower or match, never invent an unjustified
    High/Critical" discipline `critic.py`'s `_cap_severity_at_ceiling`
    already established for the S6 critic pass.

    `impact_basis` (shared-evidence-residue milestone) is Adversary B's own
    `AdversaryResult.impact_basis` for this claim, carried through
    `requires_agreement()` -- UNLIKE `severity`/`cwe`, it is set whenever the
    two-backend path actually ran, regardless of the final tier, because the
    whole point of the residue test is inspectable even on an `unconfirmed`
    outcome (e.g. confirming a case landed `unconfirmed` because B found an
    EMPTY residue, not for some unrelated reason). `None` for the
    single-backend path (only `ExternalAssumptionAdversary` ever produces
    one) and the no-backend-configured skip."""

    verdict: Verdict
    note: str
    checked: bool
    verdict_a: Verdict | None = None
    verdict_b: Verdict | None = None
    agreed: bool | None = None
    severity: Severity | None = None
    cwe: str | None = None
    impact_basis: str | None = None
    # WS5: True when the survival is conditional on `assumption` (the
    # `adversary-reviewed` tier alone does not say so). Reports must show it.
    conditional: bool = False
    assumption: str | None = None


def run_adversary_check(
    claim_card: ClaimCard,
    backend: AdversaryBackend | None,
    second_backend: AdversaryBackend | None = None,
) -> AdversaryCheckResult:
    """Run `claim_card` through the adversary gate before it is written to
    the ledger. Same graceful-degrade discipline used everywhere else in
    this pipeline (Stage 4 LLM verification, the S6 cross-tier critic pass):

    - `backend=None` (no `ANTHROPIC_API_KEY` and no backend injected) -- the
      check is honestly recorded as SKIPPED, never silently treated as a
      pass or a fail. `checked=False`, verdict stays `"unconfirmed"`.
    - `backend` given, `second_backend=None` -- a SINGLE adversary's own
      opinion (one `adjudicate()` call). This is a real independent
      adversarial review, but not yet the fleet design's full two-
      -independent-adversary-agreement contract -- the returned `note` says
      so explicitly, and `agreed` stays `None` (there was nothing to agree
      or disagree with).
    - both `backend` and `second_backend` given -- the real two-adversary-
      agreement contract: each backend is asked independently (2 separate
      `adjudicate()` calls), and their raw verdicts are reconciled through
      `requires_agreement()` -- the exact function this milestone finally
      wires up. Only a shared `confirmed` (promoted to `"adversary-
      reviewed"`) or shared `refuted` survives; any disagreement collapses
      to `"unconfirmed"`, both raw verdicts kept in the result.

    A raw `confirmed` verdict from an adversary (single- or two-backend
    path) is ALWAYS mapped to `"adversary-reviewed"`, never to plain
    `"confirmed"` -- see `_ADVERSARY_VERDICT_TO_LEDGER_TIER`'s own comment.
    A backend call raising (e.g. a real Anthropic API failure) is caught and
    recorded as an honest, inconclusive `"unconfirmed"` note -- same "one
    bad call must never abort the run" discipline as `hunter._dispatch_angle`
    and `pipeline._process_finding`'s own Stage-4 try/except.

    Severity/CWE (adversary-severity milestone) are only ever computed when
    the outcome actually reaches `"adversary-reviewed"` -- same cap-never
    -raise discipline `critic.py`'s own `recalibrate_severity()`/
    `_cap_severity_at_ceiling()` already established for the S6 critic pass,
    applied here to the ADVERSARY's own severity opinion instead of the
    critic's:

    - single-backend path -- one adversary's severity opinion is not
      independently corroborated (there is no second opinion to check it
      against), so it is capped one notch down the CVSS-aligned ladder
      (`critic._one_notch_down`) before ever reaching the ledger -- the same
      "no corroboration, no full trust" default-downgrade rule
      `recalibrate_severity()` applies when its own condition (b) fails.
    - two-backend agreement path -- BOTH independent adversaries' severities
      are read, and the final severity is capped at whichever of the two is
      LESS severe (`critic._cap_severity_at_ceiling(a, b)`, symmetric in its
      two arguments) -- so a single adversary can never alone push the
      recorded severity higher than the other adversary was independently
      willing to say, same "disagreement is the real signal, don't average
      it upward" discipline `requires_agreement()` already applies to the
      verdict itself. CWE only survives this path when both adversaries
      named the same one (case/whitespace-insensitive); a disagreement
      records no CWE rather than arbitrarily picking one.
    - shared-evidence-residue milestone: when Adversary B's own
      `impact_basis` (see `AdversaryResult`'s own docstring) starts with
      `"external:"` -- a real, load-bearing external-system assumption was
      stripped from the claim -- the already-capped two-backend severity
      above is capped ONE MORE notch down (`critic._one_notch_down`, the
      same function the single-backend path already uses, not new logic):
      a claim whose safety still rests partly on an external system's own
      behavior is never recorded at the same severity as one fully settled
      by this repo's own code."""
    if backend is None:
        return AdversaryCheckResult(
            verdict="unconfirmed",
            note="adversary check skipped, no backend configured",
            checked=False,
        )

    try:
        result_a = backend.adjudicate(claim_card)
    except Exception as exc:  # noqa: BLE001 -- one bad adversary call must never abort the hunt
        return AdversaryCheckResult(
            verdict="unconfirmed",
            note=f"adversary check attempted but failed: {type(exc).__name__}: {exc}",
            checked=True,
        )

    if second_backend is None:
        mapped = _ADVERSARY_VERDICT_TO_LEDGER_TIER[result_a.verdict]
        severity: Severity | None = None
        cwe: str | None = None
        severity_note = ""
        if mapped == "adversary-reviewed":
            severity = _one_notch_down(result_a.severity)
            if result_a.verdict == CONDITIONAL_VERDICT:
                severity = _one_notch_down(severity)  # conditional: one further notch, never full trust
            cwe = result_a.cwe
            severity_note = (
                f" | severity/CWE: adversary assessed {result_a.severity.value}"
                f"/{result_a.cwe or 'none'}, capped one notch down to {severity.value} -- a single "
                "adversary's own severity opinion is not independently corroborated, same "
                "no-second-check default-downgrade discipline as critic.recalibrate_severity's own rule"
            )
        return AdversaryCheckResult(
            verdict=mapped,
            note=(
                f"single-adversary review (model={result_a.model}): {result_a.verdict} -- {result_a.reasoning}"
                + severity_note
            ),
            checked=True,
            verdict_a=result_a.verdict,
            severity=severity,
            cwe=cwe,
            conditional=result_a.verdict == CONDITIONAL_VERDICT,
            assumption=result_a.assumption if result_a.verdict == CONDITIONAL_VERDICT else None,
        )

    try:
        result_b = second_backend.adjudicate(claim_card)
    except Exception as exc:  # noqa: BLE001 -- one bad adversary call must never abort the hunt
        return AdversaryCheckResult(
            verdict="unconfirmed",
            note=(
                f"two-adversary check: first adversary (model={result_a.model}) answered {result_a.verdict}, "
                f"second adversary call failed: {type(exc).__name__}: {exc}"
            ),
            checked=True,
            verdict_a=result_a.verdict,
        )

    final = requires_agreement(result_a.verdict, result_b.verdict, impact_basis_b=result_b.impact_basis)
    mapped = _ADVERSARY_VERDICT_TO_LEDGER_TIER[final.verdict]
    severity: Severity | None = None
    cwe: str | None = None
    severity_note = ""
    if mapped == "adversary-reviewed":
        severity = _cap_severity_at_ceiling(result_a.severity, result_b.severity)
        cwe_a_norm = (result_a.cwe or "").strip().upper()
        cwe_b_norm = (result_b.cwe or "").strip().upper()
        if cwe_a_norm and cwe_a_norm == cwe_b_norm:
            cwe = result_a.cwe
        severity_note = (
            f" | severity/CWE: a={result_a.severity.value}/{result_a.cwe or 'none'} "
            f"b={result_b.severity.value}/{result_b.cwe or 'none'} -> agreed severity capped at the LESS "
            f"severe of the two, {severity.value} (never the more severe reading -- same cap-never-raise "
            "discipline as critic.py's own _cap_severity_at_ceiling)"
            + (f", CWE {cwe} (both agreed)" if cwe else ", CWE not recorded -- the two adversaries disagreed")
        )
        # Shared-evidence-residue milestone: a real, load-bearing external
        # assumption in the residue-test answer caps severity one MORE notch
        # down -- reusing `_one_notch_down` (already imported, already used
        # by the single-backend path above), not new severity logic.
        if final.verdict == CONDITIONAL_VERDICT:
            severity = _one_notch_down(severity)
            severity_note += (
                " | verdict is confirmed-conditional: severity capped one further notch down because "
                "exploitability rests on a named deployment assumption"
            )
        if final.impact_basis is not None and final.impact_basis.startswith("external:"):
            pre_external_cap = severity
            severity = _one_notch_down(severity)
            severity_note += (
                f" | impact_basis={final.impact_basis!r} names a real, load-bearing external-system "
                f"assumption -- severity capped one more notch down from {pre_external_cap.value} to "
                f"{severity.value} (reusing critic._one_notch_down, the same function the single-backend "
                "path above already uses)"
            )
    return AdversaryCheckResult(
        verdict=mapped,
        note=(
            f"two-adversary agreement: a(model={result_a.model})={result_a.verdict!r} "
            f"b(model={result_b.model})={result_b.verdict!r} agreed={final.agreed} -- "
            f"a-reasoning: {result_a.reasoning} | b-reasoning: {result_b.reasoning}"
            f" | impact_basis (B): {result_b.impact_basis or 'not provided'}"
            + severity_note
        ),
        checked=True,
        verdict_a=result_a.verdict,
        verdict_b=result_b.verdict,
        agreed=final.agreed,
        severity=severity,
        cwe=cwe,
        impact_basis=final.impact_basis,
        conditional=final.verdict == CONDITIONAL_VERDICT,
        assumption=(
            " | ".join(dict.fromkeys(a for a in (result_a.assumption, result_b.assumption) if a)) or None
            if final.verdict == CONDITIONAL_VERDICT
            else None
        ),
    )


# --------------------------------------------------------------------------
# Repo-reading adversary path (adversary-repo-read milestone).
#
# Two real, independently-reproduced failures of the bare-ClaimCard adversary
# above motivated this:
#
#   1. palantir-mcp `src/utils/tokenCache.ts` false positive: the file is 91
#      lines; `saveConfig()`'s real `fs.mkdirSync(..., mode: 0o700)`/
#      `fs.writeFileSync(..., mode: 0o600)` fix sits at lines 63-70 -- past
#      hunter.py's own `_MAX_EXCERPT_LINES = 60` evidence-window cutoff. A
#      cold adversary shown only the 60-line excerpt confirmed a claim a
#      full read of the same file refutes. Reproduced identically twice
#      (bench/v10rerun_groupB_scratch/GROUPB_RERUN_RESULTS.md and its v9
#      predecessor).
#   2. auth0-mcp-server near-miss: whole-handler-audit correctly proposes the
#      real known bug (resource-servers.ts's missing `maskSensitiveFields()`
#      call), but the bare-ClaimCard adversary returned "unconfirmed"
#      because the evidence shown doesn't settle whether Auth0's own API
#      actually echoes `signing_secret` back -- a question a fuller repo
#      read (Auth0's own API client/type definitions elsewhere in the same
#      repo) could plausibly settle (bench/v10rerun_groupA_scratch/
#      GROUPA_RERUN_RESULTS.md).
#
# Fable's own recommendation (quoted): "Make the adversary a repo-reading
# agent that taint-shaped cards also pass through. Concretely: give it the
# repo root and the card, keep it forbidden from the hunter's reasoning, but
# require it to read the whole cited file(s) plus one hop before answering,
# and route sandbox-negative CREDFWD/SSRF/PATHTRAV taint cards into it under
# a per-target cap."
#
# Design decisions and why:
#
# - `build_repo_reading_adversary_prompt(claim_card, repo_root)` is a
#   SEPARATE, additive function -- `build_adversary_prompt` above is
#   UNCHANGED (still the single-`ClaimCard`-parameter function its own
#   structural test locks down, still what every one of the 6 LLM hunter
#   angles uses by default; see pipeline.py's own `hunt_fleet` docstring for
#   why that default is unchanged). This new function REUSES
#   `build_adversary_prompt(claim_card)` as its own base (the four allowed
#   claim fields, the raw cited lines, the fuller-enclosing-function context
#   -- all already delimited) and appends a new, additional section, rather
#   than duplicating any of that prompt-building logic.
# - Context-asymmetry is enforced the same way `build_adversary_prompt`
#   enforces it: `caller_authority_assumed` and `impossibility_argument` --
#   the two fields where a hunter's own written reasoning genuinely lives --
#   are never read anywhere in this section, exactly like the base function.
#   `claim_card.oracle_trace` IS read here (by `check_reachability_soundness`
#   below), but that is a deliberate, different thing: an `OracleTrace` is
#   Stage 5's own structured, machine-generated execution telemetry (which
#   subprocess ran, which file opened, which host was contacted) -- real
#   evidence a sandbox produced, never a hunter's narrative ABOUT that
#   evidence. Routing (pipeline.py's `hunt_fleet`) only ever sends a card
#   down this path when it already carries a real `OracleTrace` (a sandbox
#   -negative taint-shaped candidate), so reading that trace's own structured
#   fields is reading the same category of evidence `build_adversary_prompt`
#   already reads from `evidence_path` -- not a new leak.
# - The function's OWN signature (`claim_card: ClaimCard, repo_root: str |
#   Path`, exactly two parameters) is the structural guarantee, mirroring
#   `build_adversary_prompt`'s own enforced-at-the-signature-level design --
#   see this new test in test_adversary.py's own structural-test section for
#   this path.
# - Real content read from the repo (full files, one-hop-out files) goes
#   through the EXACT same two defenses every other LLM-facing evidence path
#   in this project already uses, with NO exceptions (Fable's own risk (c)):
#   `lexical.strip_comments_and_docstrings()` before it is ever placed in a
#   string, and `untrusted_text.wrap_untrusted()` at the point it enters the
#   prompt.
# - "One call-graph hop out" is built from TWO real, reused pieces of
#   critic.py's own call-graph machinery, not a new implementation of either:
#     * forward ("what does the cited code call") -- `_py_call_hop_target`/
#       `_js_call_hop_target`, the exact real, resolved (same-file-def-or-
#       import-resolved-only, never a same-named-function-in-an-unrelated-
#       file guess) edge resolvers `check_reachability_soundness`'s own
#       bounded reverse-call search is built from at every one of its hops.
#     * reverse ("is the cited code called by a real entrypoint") --
#       `check_reachability_soundness` itself, called directly at
#       `max_reverse_call_depth=1` (literally "one hop"). This is the exact
#       function Fable named.
# - Bounded on the same "never unbounded" discipline as every other
#   evidence-gathering path in this project (hunter.py's
#   `_WHOLE_FILE_MAX_CHARS`/`_WHOLE_FILE_TOTAL_BUDGET_CHARS`, critic.py's
#   `_MAX_REVERSE_CALL_VISITS`): `_REPO_READ_MAX_FILE_CHARS` per file,
#   `_REPO_READ_TOTAL_BUDGET_CHARS` per claim card's whole packet,
#   `_REPO_READ_MAX_ONE_HOP_FILES` distinct one-hop-out files. See
#   bench/ADVERSARY_REPO_READ_STATUS.md for the real numbers these were
#   picked from.
# --------------------------------------------------------------------------

# A real file this project has actually seen (palantir-mcp's whole repo) is
# well under this; generous enough for a genuinely large single source file
# while still being a real, enforced bound, not "read everything."
_REPO_READ_MAX_FILE_CHARS = 60_000
# Total budget for ONE claim card's whole repo-read packet (cited files +
# one-hop-out files combined) -- keeps a card with many distinct citations
# from producing an unbounded prompt, same "bounded effort, not bounded to
# zero" discipline as hunter.py's own whole-handler-audit budget.
_REPO_READ_TOTAL_BUDGET_CHARS = 200_000
# How many DISTINCT one-hop-out files (beyond the cited files themselves)
# this path reads in full -- a real, enforced cap on the forward-hop side of
# "one call-graph hop out."
_REPO_READ_MAX_ONE_HOP_FILES = 5
# "One hop out," literally -- passed to check_reachability_soundness's own
# max_reverse_call_depth (hard-clamped 1-3 by that function; 1 is the
# smallest legal value and matches this milestone's own "one hop" spec
# exactly, not an arbitrary pick within the allowed range).
_REPO_READ_MAX_REVERSE_CALL_DEPTH = 1

# Doc-suffix cap (candidate-widened-adversary milestone). Fable's own review
# of routing claims-vs-enforcement through this path: "`_repo_read_cited_files`
# reads every cited file in full, and `strip_comments_and_docstrings` returns
# `.md` unchanged. A claims-vs-enforcement card would put an entire README,
# unstripped, inside the adversary prompt with `wrap_untrusted` as the sole
# defense... Either exclude it or add a doc-suffix cap." claims-vs-enforcement
# itself is NOT wired to this path by this milestone (see pipeline.py's own
# `_LIGHTWEIGHT_ADVERSARY_ANGLES` comment) -- but the other four routed
# angles (`credential-and-secrets`, `cross-file-authority`,
# `whole-handler-audit`, `scope-selector-override`) can and do cite
# README/SECURITY.md prose lines too (e.g. a `credential-and-secrets` claim
# contrasting a doc's stated guarantee against the code), so this cap is
# real, not speculative, for the angles actually being wired here -- and
# having it in place now is what makes claims-vs-enforcement safely
# includable later without a separate, second fix.
#
# Suffixes treated as prose, not source: Markdown, plain text, and
# reStructuredText/AsciiDoc (the other common long-form-docs formats a repo
# actually ships -- README/CHANGELOG/SECURITY/CONTRIBUTING files). Matched
# case-insensitively the same way `lexical.strip_comments_and_docstrings`
# itself matches suffixes.
_DOC_FILE_SUFFIXES = frozenset({".md", ".markdown", ".txt", ".rst", ".adoc"})
# Bound picked to match hunter.py's own `_MAX_EXCERPT_LINES = 60` exactly --
# not a new, separate number to justify: it is the same bounded-excerpt size
# every non-repo-reading evidence path in this project already shows for a
# doc citation (see hunter.py's own credential-and-secrets/claims-vs-
# enforcement excerpt windows), so a doc file capped here is shown exactly as
# much as the lightweight path would have shown it, even though this
# function's whole reason to exist is reading everything else in full.
_DOC_FILE_MAX_EXCERPT_LINES = 60


def _cap_doc_file_text(text: str, suffix: str) -> str:
    """Bound a prose file's full text to `_DOC_FILE_MAX_EXCERPT_LINES` lines
    when `suffix` is a recognized doc suffix (`_DOC_FILE_SUFFIXES`) --
    applied AFTER `strip_comments_and_docstrings` (a no-op for these
    suffixes, see that function's own docstring) and BEFORE the
    `_REPO_READ_MAX_FILE_CHARS` char-count truncation, so a huge README is
    never placed into the prompt in full just because this path's whole
    purpose is "full file reads." A non-doc suffix (any real source file)
    is returned completely unchanged -- this cap targets prose specifically,
    never code, per Fable's own review (quoted above)."""
    if suffix.lower() not in _DOC_FILE_SUFFIXES:
        return text
    lines = text.split("\n")
    if len(lines) <= _DOC_FILE_MAX_EXCERPT_LINES:
        return text
    kept = lines[:_DOC_FILE_MAX_EXCERPT_LINES]
    omitted = len(lines) - _DOC_FILE_MAX_EXCERPT_LINES
    return "\n".join(kept) + (
        f"\n... [truncated: this is a prose/doc file ({suffix!r}) -- capped to the first "
        f"{_DOC_FILE_MAX_EXCERPT_LINES} lines ({omitted} more lines omitted) even though this path "
        "otherwise reads cited files in full, see this module's own doc-suffix-cap comment]"
    )


def _repo_read_cited_files(claim_card: ClaimCard) -> list[str]:
    """Distinct root-relative file paths cited anywhere in this claim's own
    `evidence_path`, in first-seen order -- the files this path reads in
    FULL (never truncated at hunter.py's own 60-line excerpt cap)."""
    seen: dict[str, None] = {}
    for step in claim_card.evidence_path:
        if step.file and step.file not in seen:
            seen[step.file] = None
    return list(seen)


def _read_whole_file_for_adversary(root: Path, rel: str) -> str | None:
    """Full text of `root/rel`, lexically stripped (Fable's own risk (c) --
    every piece of new repo content this path reads MUST go through the same
    comment/docstring stripping every other LLM-facing evidence path in this
    project already applies, no exceptions), doc-suffix-capped (a `.md`/
    `.txt`/other prose file is bounded to `_DOC_FILE_MAX_EXCERPT_LINES` even
    on this "read the whole file" path -- see `_cap_doc_file_text`'s own
    docstring for why), then bounded to `_REPO_READ_MAX_FILE_CHARS`. Never
    raises -- an unreadable file returns `None`, the same honest contract
    `hunter._read_file_text` already uses."""
    try:
        text = (root / rel).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    suffix = Path(rel).suffix
    text = strip_comments_and_docstrings(text, suffix)
    text = _cap_doc_file_text(text, suffix)
    if len(text) > _REPO_READ_MAX_FILE_CHARS:
        text = text[:_REPO_READ_MAX_FILE_CHARS] + (
            f"\n... [truncated: this single file exceeded the {_REPO_READ_MAX_FILE_CHARS}-char "
            "per-file cap for the repo-reading adversary path]"
        )
    return text


def _calls_from_py_function(fn_node: ast.FunctionDef | ast.AsyncFunctionDef, current_file: Path, tree: ast.Module, root: Path) -> list[tuple[Path, str]]:
    """Every real, resolved `(file, function_name)` target `fn_node`'s own
    body calls into -- the shared Python walk both the origin hop and every
    deeper hop in `_one_hop_forward_call_targets` reuse, rather than two
    near-identical copies of the same `ast.walk`+resolve loop."""
    out: list[tuple[Path, str]] = []
    for node in ast.walk(fn_node):
        if not isinstance(node, ast.Call):
            continue
        name = _py_callee_name(node.func)
        if name is None:
            continue
        target = _py_call_hop_target(current_file, tree, node, name, root)
        if target is not None:
            out.append(target)
    return out


def _calls_from_js_function(fn_node: Any, current_file: Path, root_node: Any, src: bytes, root: Path) -> list[tuple[Path, str]]:
    """JS/TS sibling of `_calls_from_py_function` -- same shared-walk reason."""
    from . import entrypoints_js as ejs

    out: list[tuple[Path, str]] = []
    for node in ejs.walk(fn_node):
        if node.type != "call_expression":
            continue
        callee = node.child_by_field_name("function")
        if callee is None:
            continue
        name = _js_callee_name(callee, src)
        if name is None:
            continue
        target = _js_call_hop_target(current_file, root_node, src, callee, name, root)
        if target is not None:
            out.append(target)
    return out


def _one_hop_forward_call_targets(root: Path, rel: str, line_no: int, *, max_depth: int = 1) -> list[tuple[str, str]]:
    """Real, resolved `(root-relative file, function_name)` pairs the
    enclosing function around `rel:line_no` directly calls into -- ONE hop
    by default, reusing critic.py's own real call-edge resolvers
    (`_py_call_hop_target`/`_js_call_hop_target`, the same
    same-file-def-or-import-resolved-only discipline
    `check_reachability_soundness`'s own bounded reverse-call search applies
    at every hop) rather than reimplementing call resolution here. Never
    raises; an unparseable file, an unsupported language, or a line with no
    enclosing function yields no hops -- an honest empty list, not a guess.

    demand-driven-tools milestone: this is the SAME real walk
    `_one_hop_forward_targets` (below) always did -- extended to also keep
    the resolved function NAME each hop already carries (`_py_call_hop_
    target`/`_js_call_hop_target` both return `(file, function_name)`; the
    old code discarded the name half, keeping only `target[0]`). Added
    because `hunter.py`'s own `callees()` demand-driven tool needs the real
    callee NAME, not just the file it lives in, to show the model something
    useful -- per the task's own explicit instruction to extend/expose this
    resolver rather than reimplement it. `_one_hop_forward_targets` is now a
    thin, file-only wrapper over this function (see below) -- one real walk,
    not two, and its own pre-existing return type/behavior is completely
    unchanged.

    `max_depth` (keyword-only, default 1 -- every pre-existing caller is
    completely unaffected): when > 1, additionally re-walks each hop's own
    resolved target function for ITS calls, one more explicit level at a
    time, up to `max_depth` hops total from `(rel, line_no)` -- reusing the
    exact same two-trusted-shapes resolver this function already applies at
    depth 1 (critic.py's own `depth_remaining`-bounded reverse-call walker,
    `_python_reaches`/`_js_walk_fn_for_reach`, already proved this identical
    resolver-reuse-across-depths pattern safe for a different purpose: "is
    X reachable from Y within N hops"). Added for the serverless-serverless
    sealed-holdout gap (`project-finder.js`, two real cross-file hops from
    the nearest recovered entrypoint -- `tools-definition.js` -> `list-
    projects.js` -> `project-finder.js` -- confirmed MISSED across
    checkpoints 1-4 specifically because this function's evidence-gathering
    callers only ever saw one hop). A (file, function_name) pair already
    visited at a shallower depth is never re-walked (cycle protection for
    mutual/self-recursive helpers) -- still no general call graph, just one
    more bounded, explicit hop than before."""
    suffix = Path(rel).suffix
    abs_path = root / rel
    targets: list[tuple[Path, str]] = []

    if suffix == ".py":
        try:
            text = abs_path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(text)
        except (OSError, SyntaxError):
            return []
        fn = _find_enclosing_function(tree, line_no)
        if fn is None:
            return []
        targets = _calls_from_py_function(fn, abs_path, tree, root)
    elif suffix in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
        try:
            from . import entrypoints_js as ejs
        except ImportError:
            return []
        parsed = ejs.parse_file(abs_path)
        if parsed is None:
            return []
        root_node, src = parsed
        fn = ejs.find_enclosing_function(root_node, line_no)
        if fn is None:
            return []
        targets = _calls_from_js_function(fn, abs_path, root_node, src, root)

    out: list[tuple[str, str]] = []
    visited: set[tuple[str, str]] = set()
    for t_file, t_name in targets:
        try:
            rel_t = str(Path(t_file).resolve().relative_to(root))
        except ValueError:
            continue
        pair = (rel_t, t_name)
        if pair not in visited:
            visited.add(pair)
            out.append(pair)

    frontier = list(out)
    depth = 1
    while depth < max_depth and frontier:
        next_frontier: list[tuple[str, str]] = []
        for f_rel, f_name in frontier:
            f_abs = root / f_rel
            f_suffix = Path(f_rel).suffix
            hop_targets: list[tuple[Path, str]] = []
            if f_suffix == ".py":
                found = find_python_function(f_abs, f_name)
                if found is None:
                    continue
                fn_node, fn_tree, _lines = found
                hop_targets = _calls_from_py_function(fn_node, f_abs, fn_tree, root)
            elif f_suffix in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
                try:
                    from . import entrypoints_js as ejs
                except ImportError:
                    continue
                parsed = ejs.parse_file(f_abs)
                if parsed is None:
                    continue
                f_root_node, f_src = parsed
                fn_node = ejs.find_function_by_name(f_root_node, f_name, f_src)
                if fn_node is None:
                    continue
                hop_targets = _calls_from_js_function(fn_node, f_abs, f_root_node, f_src, root)
            for t_file, t_name in hop_targets:
                try:
                    rel_t = str(Path(t_file).resolve().relative_to(root))
                except ValueError:
                    continue
                pair = (rel_t, t_name)
                if pair in visited:
                    continue
                visited.add(pair)
                out.append(pair)
                next_frontier.append(pair)
        frontier = next_frontier
        depth += 1

    return out


def _one_hop_forward_targets(root: Path, rel: str, line_no: int) -> list[str]:
    """Real, resolved root-relative file paths the enclosing function around
    `rel:line_no` directly calls into -- ONE hop. Thin, file-only wrapper
    over `_one_hop_forward_call_targets` above (demand-driven-tools
    milestone) -- same real walk, same behavior/return type as before that
    milestone existed, just deduped on file instead of (file, function)."""
    out: list[str] = []
    for rel_t, _name in _one_hop_forward_call_targets(root, rel, line_no):
        if rel_t not in out:
            out.append(rel_t)
    return out


def _reverse_hop_reachability_note(claim_card: ClaimCard, root: Path, tmd: ThreatModelDocument | None) -> str:
    """The "called by" half of "one call-graph hop out": is this claim's own
    Stage-5 sink reachable from a genuine external MCP entrypoint within ONE
    real, resolved call? Calls `check_reachability_soundness` DIRECTLY --
    the exact function Fable named -- rather than a second, reimplemented
    bounded reverse-call search.

    Guarded on `isinstance(claim_card.oracle_trace, OracleTrace)` BEFORE
    calling it, deliberately: `check_reachability_soundness`'s own
    "not a real OracleTrace" branch reads `claim_card.caller_authority_
    assumed` (to check for pipeline.py's own no-entrypoint-match marker) --
    a real, if narrow, leak of one of the two fields a hunter's own written
    reasoning genuinely lives in (an LLM-hunter-angle card's
    `caller_authority_assumed` is free text the hunter itself wrote; see
    `hunter.py`'s own `_HUNT_TOOL_SCHEMA`). That branch is legitimate inside
    `critic.py`'s own S6 pass (which already has full, un-asymmetric card
    access by design), but this adversary path must not inherit it. Once
    there IS a real `OracleTrace`, `check_reachability_soundness` never
    reads `caller_authority_assumed` again (confirmed directly against its
    own source) -- so this guard, not a modification to critic.py itself,
    is what keeps this call context-asymmetric. Without a real
    `OracleTrace` (this path is only ever routed to real-OracleTrace cards
    in practice -- see `pipeline.hunt_fleet` -- but `build_repo_reading_
    adversary_prompt` is independently callable/testable, so this must hold
    on its own), an honest, hunter-reasoning-free "not applicable" message
    is returned instead, never a fabricated hop."""
    if not isinstance(claim_card.oracle_trace, OracleTrace):
        return (
            "not applicable -- this claim carries no real Stage-5 OracleTrace, so there is no execution "
            "entrypoint to check one-hop reachability from."
        )
    soundness = check_reachability_soundness(
        claim_card, claim_card.oracle_trace, tmd, root=root, max_reverse_call_depth=_REPO_READ_MAX_REVERSE_CALL_DEPTH,
    )
    return soundness.reason


@functools.lru_cache(maxsize=32)
def _cached_deployment_profile(repo_root: str) -> DeploymentProfile:
    """One repo walk per root per process; the profile is deterministic."""
    return compute_deployment_profile(repo_root)


_CONDITIONAL_VERDICT_SECTION = """

## Conditional verdicts (overrides the three-verdict list above)
The deployment profile above is computed from the repo, not from the claim. Use it. If the code mechanism \
is real and you cannot refute it, but whether it is exploitable depends ONLY on a deployment fact the \
repo cannot settle (for example: "one transport/proxy instance is shared by mutually untrusting callers", \
"the embedding application exposes this over HTTP without its own auth"), answer \
`confirmed-conditional` and put that single fact in `assumption`. Rules: (a) the assumption must be a \
concrete, checkable deployment condition, not a restatement of the bug; (b) if the profile shows the \
condition cannot hold (e.g. stdio-only, per-process-local) answer `refuted`, not conditional; (c) if \
the mechanism itself is unproven, answer `unconfirmed`; (d) if nothing but the assumption is left and the \
assumption is implausible for the documented use of this code, answer `refuted`. `confirmed` still means \
exploitable under the deployment shown.
"""


def build_shared_repo_evidence_block(claim_card: ClaimCard, repo_root: str | Path) -> str:
    """The repo-reading evidence block, factored out of
    `build_repo_reading_adversary_prompt` (shared-evidence-residue milestone;
    see `bench/SHARED_EVIDENCE_RESIDUE_STATUS.md`) so it is computed by ONE
    piece of code, not two independent implementations that could drift: the
    full, untruncated content of every file this claim's own evidence cites,
    plus every file one real call-graph hop away from the cited code
    (forward: what it calls; reverse: whether a real recovered MCP
    entrypoint reaches it -- see this section's own module comment), exactly
    as `build_repo_reading_adversary_prompt` (Adversary A's prompt builder)
    always built it.

    `build_external_assumption_adversary_prompt` (Adversary B's prompt
    builder, below) now calls this SAME function with the SAME `repo_root`
    instead of giving Adversary B zero repo access -- this is the fix for
    the pure evidence-asymmetry misses `bench/ROLE_DIVERSE_ADVERSARY_STATUS.md`
    Section 4 (Mechanism 2) diagnosed: cases where Adversary B's own bare
    -citation prompt lacked a fact Adversary A's full-file read could see.
    Called with the same `(claim_card, repo_root)` within one
    `run_adversary_check()` pair, this deterministic, pure-local-disk
    function returns byte-identical text both times (`build_threat_model`
    itself is cache-keyed on repo identity+commit, so the second call is a
    cache read, not a re-scan) -- which is exactly what real Anthropic
    prompt caching needs: `RepoReadingAdversary.adjudicate` and
    `ExternalAssumptionAdversary.adjudicate` (below) both place a
    `cache_control` breakpoint at the end of this exact block, so the two
    calls sharing one claim card can reuse the server-side cache for it
    instead of paying full price for the same tokens twice.

    Best-effort threat-model build for the reverse-hop check
    (`build_threat_model`, cached by that function itself keyed on repo
    identity+commit): a failure here never prevents the rest of this block
    from being built, same "auxiliary enrichment must never be fatal"
    discipline this project applies everywhere else."""
    root = Path(repo_root)

    try:
        tmd: ThreatModelDocument | None = build_threat_model(root)
    except Exception:  # noqa: BLE001 -- best-effort context for the reverse-hop check, never fatal here
        tmd = None

    cited_files = _repo_read_cited_files(claim_card)
    budget_used = 0
    seen_files: set[str] = set()
    sections: list[str] = []

    for rel in cited_files:
        text = _read_whole_file_for_adversary(root, rel)
        if text is None:
            continue
        seen_files.add(rel)
        block = f"### Full file cited by this claim: {rel}\n{text}"
        if budget_used + len(block) > _REPO_READ_TOTAL_BUDGET_CHARS:
            sections.append(
                f"### Full file cited by this claim: {rel}\n"
                "(omitted -- this claim's own repo-read budget was already spent showing an earlier file)"
            )
            continue
        budget_used += len(block)
        sections.append(block)

    hop_files: dict[str, None] = {}
    for step in claim_card.evidence_path:
        if not step.file:
            continue
        for rel_target in _one_hop_forward_targets(root, step.file, step.line):
            if rel_target not in seen_files and rel_target not in hop_files:
                hop_files[rel_target] = None

    for rel in list(hop_files)[:_REPO_READ_MAX_ONE_HOP_FILES]:
        text = _read_whole_file_for_adversary(root, rel)
        if text is None:
            continue
        block = (
            f"### One-hop-out file (a function directly called from the cited code resolves here): {rel}\n{text}"
        )
        if budget_used + len(block) > _REPO_READ_TOTAL_BUDGET_CHARS:
            sections.append(
                f"### One-hop-out file: {rel}\n"
                "(omitted -- this claim's own repo-read budget was already spent)"
            )
            continue
        budget_used += len(block)
        seen_files.add(rel)
        sections.append(block)

    if not sections:
        sections.append(
            "(no cited file could be read in full -- either this claim's evidence_path is empty, or every "
            "cited file was unreadable from disk at the time of this check)"
        )

    reverse_note = _reverse_hop_reachability_note(claim_card, root, tmd)

    return (
        "\n\n## Full repository read (repo-reading adversary path)\n"
        "Unlike the bounded excerpt above, you are ALSO given the FULL, untruncated content of every file "
        "this claim's own evidence cites, plus every file one real, resolved call-graph hop away from the "
        "cited code. This exists because a bounded excerpt has been shown, in a real confirmed case, to cut "
        "off before a real fix a few lines past its own cutoff -- read the WHOLE file(s) below in full "
        "before answering, not just the excerpt above; if something past the excerpt above changes your "
        "answer, say so explicitly and cite the exact line.\n\n"
        + "\n\n".join(wrap_untrusted(s) for s in sections)
        + "\n\n## One-hop-out reachability (reusing critic.py's own check_reachability_soundness directly)\n"
        + wrap_untrusted(reverse_note)
        + "\n\n"
        + _cached_deployment_profile(str(root)).render()
        + _CONDITIONAL_VERDICT_SECTION
    )


def build_repo_reading_adversary_prompt(claim_card: ClaimCard, repo_root: str | Path) -> str:
    """Fable's own recommended repo-reading adversary prompt: everything
    `build_adversary_prompt(claim_card)` already builds (reused verbatim,
    not duplicated), PLUS `build_shared_repo_evidence_block` above. Exactly
    two parameters, exactly like `build_adversary_prompt`'s own single-
    `ClaimCard` signature is enforced by ITS structural test -- see the new
    structural test for this function in test_adversary.py. Raises
    `TypeError` for a non-`ClaimCard` first argument, same discipline.

    Still never reads `caller_authority_assumed`/`impossibility_argument`
    anywhere (the two fields a hunter's own written reasoning would live
    in) -- see this section's own module comment for why `oracle_trace`
    (real Stage-5 execution telemetry, not hunter narrative) is not held to
    that same exclusion."""
    if not isinstance(claim_card, ClaimCard):
        raise TypeError(
            f"build_repo_reading_adversary_prompt requires a ClaimCard object, got "
            f"{type(claim_card).__name__!r} -- same deliberate, structural context-asymmetry guarantee as "
            "build_adversary_prompt: there is no call shape by which free-text hunter narrative could be "
            "passed here instead of a structured card."
        )
    return build_adversary_prompt(claim_card) + build_shared_repo_evidence_block(claim_card, repo_root)


class RepoReadingAdversary:
    """Real LLM backend for the repo-reading adversary path (this
    milestone). Same real-API-call, temperature-0, forced-tool-call
    discipline as `AnthropicAdversary` -- the only structural difference is
    the prompt it sends (`build_repo_reading_adversary_prompt`, bound to a
    real `repo_root` at CONSTRUCTION time, not at `adjudicate()` call time),
    which keeps `adjudicate(self, claim_card)` satisfying the exact same
    single-`ClaimCard`-argument `AdversaryBackend` protocol
    `run_adversary_check`/`hunt_fleet` already use for every other adversary
    backend -- no protocol change needed, no special-casing in the fleet
    -wiring loop beyond which BACKEND is selected for which candidate. One
    instance is constructed per scanned repo (see `pipeline.hunt_fleet`),
    exactly like `AnthropicHunter`/`TaintShapedHunter` already are.

    Deliberately single-adversary, not a two-adversary agreement pair like
    `hunt_fleet`'s own default `adversary_backend`/`adversary_second_backend`
    pair for the 6 LLM angles: this path is materially more expensive per
    call (full files, not a 60-line excerpt) and is already gated behind a
    real per-target cap (see `pipeline.py`'s own `hunt_fleet` docstring) --
    doubling it to a two-adversary pair would double that already-capped
    cost again for a class of candidate this project has, so far, seen in
    small numbers per real target (see bench/ADVERSARY_REPO_READ_STATUS.md).
    A `"confirmed"` verdict from this backend is still mapped by
    `run_adversary_check`'s own `_ADVERSARY_VERDICT_TO_LEDGER_TIER` to
    `"adversary-reviewed"`, never plain `"confirmed"` -- same single
    -adversary, one-notch-down severity discipline as `AnthropicAdversary`'s
    own single-backend path, unchanged here."""

    def __init__(
        self,
        repo_root: str | Path,
        model: str = "claude-sonnet-4-5-20250929",
        api_key: str | None = None,
        *,
        cost_tracker: CostTracker | None = None,
    ):
        self._repo_root = Path(repo_root)
        self._model = model
        self._client = build_anthropic_client("RepoReadingAdversary", api_key)
        self._cost_tracker = cost_tracker

    def adjudicate(self, claim_card: ClaimCard) -> AdversaryResult:
        # Shared-evidence-residue milestone: this ENTIRE prompt is the shared
        # evidence block `ExternalAssumptionAdversary.adjudicate` (below) also
        # sends as ITS own cached prefix -- so the whole thing is sent as one
        # `cache_control`-marked content block, not a plain string, so a
        # same-run (A, B) pair can hit the server-side prompt cache instead of
        # each paying full price for identical tokens (see
        # `build_shared_repo_evidence_block`'s own docstring).
        prompt = build_repo_reading_adversary_prompt(claim_card, self._repo_root)
        start = time.monotonic()
        response = self._client.messages.create(
            model=self._model,
            max_tokens=2000,
            temperature=0,
            tools=[_ADVERSARY_TOOL_SCHEMA_V2],
            tool_choice={"type": "tool", "name": "submit_adversary_verdict"},
            messages=[{"role": "user", "content": [
                {"type": "text", "text": prompt, "cache_control": {"type": "ephemeral"}},
            ]}],
        )
        if self._cost_tracker is not None:
            self._cost_tracker.record_from_response(
                "repo-reading-adversary", claim_card.target_sink, self._model, response, time.monotonic() - start
            )
        tool_use = next((b for b in response.content if getattr(b, "type", None) == "tool_use"), None)
        if tool_use is None:
            return AdversaryResult(
                verdict="unconfirmed",
                reasoning="model did not return the required submit_adversary_verdict tool call",
                model=self._model,
            )
        return _result_from_tool_input(tool_use.input, self._model)


# --------------------------------------------------------------------------
# Role-diverse second adversary (role-diverse-adversary milestone; see
# bench/ROLE_DIVERSE_ADVERSARY_STATUS.md). Supersedes the sibling
# candidate-widened-adversary-work clone's own design, which paired the
# repo-reading adversary above with a SECOND, identical `RepoReadingAdversary`
# instance -- same prompt, same temperature-0, only a different model tier.
# Calibrated on the same 14 ground-truth cases used here
# (bench/repo_read_calibration/REPO_READ_CALIBRATION_STATUS.md, reused
# read-only from the sibling FINAL-complete-v11 clone), that pairing caught
# 0 of the errors it was meant to catch. Its one specific, reproduced
# failure (case 11): awslabs/mcp's IAM `NotPrincipal` case went from
# correctly `refuted` to wrongly `confirmed` by BOTH adversaries
# independently, because the true safety argument depends on AWS's own
# external IAM policy-evaluation semantics -- not on anything the repo's own
# code shows -- and a code-only full-file reader, however careful, cannot
# see that. Two same-family, same-prompt, temperature-0 instances asked the
# identical question just reached the identical wrong answer twice: a
# replay, not independent review.
#
# Fable's diagnosis and fix (quoted): "make the second member of the pair a
# different role, not a second copy. Adversary A stays the repo-reading
# refuter. Adversary B gets the lightweight (~5k char) prompt and one job:
# list the external assumptions the claimed impact depends on and say
# whether each is settled by the code shown; return 'unconfirmed' if any is
# not. requires_agreement already collapses any disagreement to unconfirmed,
# so B's 'unconfirmed' does the right thing with no changes to
# _VALID_VERDICTS, tier mapping, or ledger."
#
# Why role diversity, not model diversity, fixes THIS failure class: the
# awslabs/mcp case was not a reasoning-quality miss either adversary could
# have caught by trying harder, or by being a different model -- it is an
# evidence-availability miss. No amount of additional repo content, and no
# different model reading that same repo content, changes the fact that
# whether AWS's IAM API actually honors `NotPrincipal` with `Effect:Allow`
# the way the claim assumed is not decidable from the code at all. Two
# independent copies of the same repo-reading role converge on the same
# blind spot because the blind spot is in what evidence the ROLE is even
# looking at, not in which model or temperature is doing the looking.
# Changing the second reviewer's ROLE -- ask it to name the claim's own
# external dependencies and refuse to rubber-stamp an unsettled one, instead
# of asking it to re-derive the same in-repo reachability argument a second
# time -- gives `requires_agreement()` a second opinion that can actually
# disagree for a NEW reason, not just resample the same one.
#
# Design (superseded in two places by the shared-evidence-residue milestone
# immediately below -- kept here, not edited, because the reasoning above
# this point (WHY role diversity beats a second repo-reading copy) is still
# exactly correct; only the two specific choices below changed):
# - `build_external_assumption_adversary_prompt(claim_card)` REUSES
#   `build_adversary_prompt(claim_card)` verbatim as its own base -- the
#   same additive pattern `build_repo_reading_adversary_prompt` above
#   already established (reuse, never a second, divergent copy of the
#   evidence-rendering logic) -- then appends ONE new, mandatory question.
#   `build_adversary_prompt` itself is completely UNCHANGED by this
#   milestone -- still what Adversary A's own `RepoReadingAdversary` also
#   reuses as ITS base.
# - No repo access: this function takes exactly one `ClaimCard` parameter,
#   the same context-asymmetry, structurally-enforced-at-the-signature-level
#   guarantee as `build_adversary_prompt` -- Adversary B never reads a file,
#   one-hop or otherwise. It is the deliberately CHEAP half of the pair
#   (Fable: "~5k char prompt" -- the reused base alone already averages
#   ~5k chars across this project's own 14-case calibration corpus, see the
#   status doc's real numbers).
# - `ExternalAssumptionAdversary` mirrors `AnthropicAdversary` exactly
#   (temperature 0, forced tool call, the SAME `_ADVERSARY_TOOL_SCHEMA` --
#   no new tool schema, no new verdict values, nothing for
#   `run_adversary_check`/`requires_agreement`/`_ADVERSARY_VERDICT_TO_
#   LEDGER_TIER` to special-case) -- the only structural difference from
#   `AnthropicAdversary` is which prompt-builder it calls.
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# Shared-evidence-residue milestone (see
# bench/SHARED_EVIDENCE_RESIDUE_STATUS.md). Real recalibration of the
# role-diverse design above on the same 14-case corpus found recall had
# collapsed to 2/11 (from 10/11 naive-pairing), traced to two DISJOINT
# mechanisms (`bench/ROLE_DIVERSE_ADVERSARY_STATUS.md` Section 4):
#
#   1. Pure evidence asymmetry (3 of the 9 misses): Adversary B had ZERO
#      repo access, so a fact only visible past hunter.py's own bounded
#      excerpt (a missing `scope_registry.py`, an elided Go `...`, a
#      citation that omits `spawn.ts`'s real wiring) was invisible to B even
#      when it had nothing to do with any external-system question at all.
#   2. The mandatory question itself was too blunt: "does this depend on
#      external behavior" fires YES for the true AWS-shaped case (nothing
#      real remains once you subtract the external assumption) AND for
#      several cases that also cite a real external system but where a real,
#      independent, in-repo defect survives subtracting that assumption --
#      collapsing both to the same forced `unconfirmed`, when only the first
#      one should be.
#
# Two changes, fixing the two disjoint mechanisms:
#
# 1. Shared evidence: Adversary B's prompt now includes
#    `build_shared_repo_evidence_block(claim_card, repo_root)` -- the EXACT
#    same evidence Adversary A reads (same function, same repo_root) --
#    instead of nothing. `ExternalAssumptionAdversary` now takes a
#    `repo_root` at construction, exactly like `RepoReadingAdversary`
#    (`pipeline.py`'s `_ensure_repo_reading_backends` constructs both against
#    the SAME run's own `repo_root`). B is no longer "no repo access" -- it
#    is "repo access via the same shared block A already computed", which is
#    the real fix for mechanism 1 above: B can no longer honestly say
#    "unconfirmed, evidence insufficient" for a fact A's own full-file read
#    already settled. Both `RepoReadingAdversary.adjudicate` and
#    `ExternalAssumptionAdversary.adjudicate` send this identical block as
#    one `cache_control`-marked content block (see
#    `build_shared_repo_evidence_block`'s own docstring) -- a real Anthropic
#    prompt-cache hit on B's call is possible (not guaranteed -- depends on
#    live server-side cache state) whenever A's call for the same claim ran
#    first in the same `run_adversary_check()` pair, since both send the
#    exact same bytes up to the same breakpoint.
# 2. Residue reframing: the mandatory question is no longer a binary "does
#    this depend on external behavior" (too blunt -- see mechanism 2 above).
#    B is now told to STRIP every assumption about the remote/external
#    system's behavior from the claim, NAME what it stripped, and give its
#    confirmed/refuted/unconfirmed verdict on WHATEVER CLAIM REMAINS after
#    stripping -- not on the original claim. This distinguishes "the whole
#    claim IS the external assumption, nothing left once you subtract it"
#    (the true AWS-shaped case -- residue is empty, verdict on it can only
#    honestly be `unconfirmed`) from "a real external assumption is present,
#    but a real, independent defect survives subtraction" (the residual
#    claim can honestly be `confirmed`). Vocabulary is UNCHANGED
#    (`confirmed`/`refuted`/`unconfirmed`, still `_VALID_VERDICTS`, still
#    `_ADVERSARY_VERDICT_TO_LEDGER_TIER`, still feeds `requires_agreement()`
#    unchanged) -- what changed is what claim the verdict is ABOUT. A new,
#    purely ADDITIVE field, `impact_basis` (`AdversaryResult`, `ClaimCard`),
#    names what B stripped: `"in-repo"` (nothing stripped, or what was
#    stripped wasn't load-bearing to the claim) or `"external:<system>:
#    <step>"` (something real and load-bearing was stripped). This is NOT a
#    new verdict or tier -- `run_adversary_check` applies the SAME one-notch
#    -down severity discipline it already uses elsewhere (`critic.
#    _one_notch_down`, already imported) when `impact_basis` starts with
#    `"external:"`, nothing new invented.
# --------------------------------------------------------------------------

# Extends `_ADVERSARY_TOOL_SCHEMA`'s own verdict/severity/cwe/reasoning
# properties (reused by reference, not retyped) with ONE new required field,
# `impact_basis` -- required in THIS schema (B must always name what it
# stripped, even when the answer is "nothing") but `AdversaryResult.
# impact_basis`/`ClaimCard.impact_basis` both stay `str | None = None` so
# every other backend (`AnthropicAdversary`, `RepoReadingAdversary`, and
# every pre-existing `AdversaryResult`/`ClaimCard` construction site) that
# never sets it keeps working unchanged -- same "additive, never a required
# change elsewhere" discipline `severity`/`cwe` themselves established.
# `_ADVERSARY_TOOL_SCHEMA` itself, and every OTHER backend's use of it
# (`AnthropicAdversary`, `RepoReadingAdversary`), is completely untouched.
_RESIDUE_TEST_TOOL_SCHEMA = {
    "name": "submit_adversary_verdict",
    "description": (
        "Submit this independent adversarial review's verdict on the RESIDUE claim (after stripping any "
        "external-system assumption), what was stripped, plus your own severity/CWE judgment."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            **_ADVERSARY_TOOL_SCHEMA_V2["input_schema"]["properties"],
            "impact_basis": {
                "type": "string",
                "description": (
                    "What you stripped, if anything, and whether it was load-bearing. Either the literal "
                    "string 'in-repo' (you stripped nothing, or what you stripped was not load-bearing -- "
                    "the residual claim stands on the code shown alone), or 'external:<system>: <step>' "
                    "naming the specific external system and the specific interpretation step you stripped "
                    "(e.g. 'external:AWS IAM: whether a NotPrincipal+Effect:Allow statement is honored the "
                    "way the claim assumes')."
                ),
            },
        },
        "required": ["verdict", "severity", "cwe", "reasoning", "impact_basis"],
    },
}


def _parse_impact_basis(raw: Any) -> str | None:
    """Coerce a raw `impact_basis` tool-call value into `str | None` -- `None`
    for anything missing/blank, same "never guess, never fabricate" floor
    `_parse_adversary_cwe` already applies to the CWE field."""
    text = str(raw).strip() if raw is not None else ""
    return text or None


def build_external_assumption_adversary_prompt(claim_card: ClaimCard, repo_root: str | Path) -> str:
    """Adversary B's prompt (shared-evidence-residue milestone -- supersedes
    the role-diverse-adversary milestone's own, no-repo-access version of
    this function). Reuses `build_adversary_prompt(claim_card)` verbatim as
    its base, PLUS `build_shared_repo_evidence_block(claim_card, repo_root)`
    -- the exact same evidence block Adversary A's own
    `build_repo_reading_adversary_prompt` sends -- PLUS the residue-test
    question (this module's own section comment above has Fable's exact
    reframing and why). `build_adversary_prompt` itself is still completely
    UNCHANGED by this milestone. Raises `TypeError` for a non-`ClaimCard`
    first argument via the reused base call, same structural guarantee as
    every other prompt builder in this module."""
    prefix, suffix = _external_assumption_prompt_parts(claim_card, repo_root)
    return prefix + suffix


def _external_assumption_prompt_parts(claim_card: ClaimCard, repo_root: str | Path) -> tuple[str, str]:
    """The same (cacheable evidence prefix, residue-question suffix) split
    `ExternalAssumptionAdversary.adjudicate` uses to place its `cache_control`
    breakpoint -- `build_external_assumption_adversary_prompt` above is just
    these two pieces concatenated, so there is exactly one place this
    prompt's content is assembled, not two."""
    prefix = build_adversary_prompt(claim_card) + build_shared_repo_evidence_block(claim_card, repo_root)
    return prefix, _RESIDUE_TEST_QUESTION_SECTION


_RESIDUE_TEST_QUESTION_SECTION = """

## Additional, mandatory step -- do this BEFORE your verdict below
Strip every assumption about the remote/external system's behavior from this claim -- every place the \
claim's impact depends on how a system outside this repo (a cloud provider's own policy engine, a SaaS \
backend's own authorization logic, another party's own API) interprets or acts on something, beyond \
merely receiving it, where that interpretation is NOT established by the code shown above (you would be \
relying on your own general knowledge of that remote system, not a line cited above).

1. Name specifically what you stripped, if anything. Either nothing/nothing load-bearing was there, or \
name the exact external system and the exact interpretation step you are refusing to assume (e.g. "AWS's \
own IAM policy evaluator actually treats NotPrincipal+Effect:Allow as broad access" -- a real thing the \
claim assumes but this repo's code cannot establish).
2. Then give your confirmed/refuted/unconfirmed verdict on WHATEVER CLAIM REMAINS after that stripping --
not on the original claim as stated. If nothing real remains once the external assumption is removed (the \
whole claim WAS that assumption), your verdict on the empty residue can only honestly be "unconfirmed" -- \
say so explicitly, and say plainly that nothing is left. If a real, independent defect survives the \
stripping (the external system was involved, but is not the only thing propping the claim up), evaluate \
THAT residual defect on its own merits, using only the evidence shown, exactly as already instructed \
above -- do not force it to "unconfirmed" just because an external system was mentioned somewhere in the \
original claim.

Report which of these two shapes applied, and why, in your reasoning -- this must be inspectable after \
the fact, not just your final verdict.
"""


class ExternalAssumptionAdversary:
    """Real LLM backend for Adversary B (shared-evidence-residue milestone --
    supersedes the role-diverse-adversary milestone's own no-repo-access
    version). Same real-API-call, temperature-0, forced-tool-call discipline
    as `AnthropicAdversary`/`RepoReadingAdversary`, now with a `repo_root` at
    construction (like `RepoReadingAdversary`) so it can compute the SAME
    shared evidence block A computes -- see this module's own section
    comment above for why (evidence-asymmetry misses) and for why the
    question itself changed too (the residue test). Uses
    `_RESIDUE_TEST_TOOL_SCHEMA`, not the base `_ADVERSARY_TOOL_SCHEMA` --
    the one place this milestone's new `impact_basis` field is actually
    asked for."""

    def __init__(
        self,
        repo_root: str | Path,
        model: str = "claude-sonnet-4-5-20250929",
        api_key: str | None = None,
        *,
        cost_tracker: CostTracker | None = None,
    ):
        self._repo_root = Path(repo_root)
        self._model = model
        self._client = build_anthropic_client("ExternalAssumptionAdversary", api_key)
        self._cost_tracker = cost_tracker

    def adjudicate(self, claim_card: ClaimCard) -> AdversaryResult:
        # Shared-evidence-residue milestone: `prefix` here is BYTE-IDENTICAL
        # to `RepoReadingAdversary.adjudicate`'s own cached content block for
        # the same (claim_card, repo_root) -- same function, same inputs --
        # so this call's `cache_control` breakpoint sits at the same place in
        # the same bytes, letting a same-run (A, B) pair share the server
        # -side prompt cache instead of each paying full price (see
        # `build_shared_repo_evidence_block`'s own docstring).
        prefix, suffix = _external_assumption_prompt_parts(claim_card, self._repo_root)
        start = time.monotonic()
        response = self._client.messages.create(
            model=self._model,
            max_tokens=1500,
            temperature=0,
            tools=[_RESIDUE_TEST_TOOL_SCHEMA],
            tool_choice={"type": "tool", "name": "submit_adversary_verdict"},
            messages=[{"role": "user", "content": [
                {"type": "text", "text": prefix, "cache_control": {"type": "ephemeral"}},
                {"type": "text", "text": suffix},
            ]}],
        )
        if self._cost_tracker is not None:
            self._cost_tracker.record_from_response(
                "external-assumption-adversary", claim_card.target_sink, self._model, response, time.monotonic() - start
            )
        tool_use = next((b for b in response.content if getattr(b, "type", None) == "tool_use"), None)
        if tool_use is None:
            return AdversaryResult(
                verdict="unconfirmed",
                reasoning="model did not return the required submit_adversary_verdict tool call",
                model=self._model,
            )
        return _result_from_tool_input(tool_use.input, self._model, impact_basis=tool_use.input.get("impact_basis"))



# --------------------------------------------------------------------------
# WS5 (plan C3): cross-family adversary hook. Configurable, default unchanged:
# nothing in pipeline.py calls this unless a caller passes the backend in.
# No keys live in code -- only the NAME of the environment variable holding
# the key is configured. Speaks the OpenAI-compatible /chat/completions
# function-calling dialect (stdlib urllib, no new dependency), which most
# non-Anthropic providers and local servers expose. Uses the same prompt as
# Adversary A (repo-reading + deployment profile + conditional verdicts), so
# only the model family changes.
#
#   MCP_SAFEGUARD_ADVERSARY_PROVIDER     "openai-compatible" (unset => no hook)
#   MCP_SAFEGUARD_ADVERSARY_MODEL        model id at that provider
#   MCP_SAFEGUARD_ADVERSARY_BASE_URL     e.g. https://api.example.com/v1
#   MCP_SAFEGUARD_ADVERSARY_API_KEY_ENV  name of the env var holding the key
# --------------------------------------------------------------------------


class CrossFamilyAdversary:
    """Adversary backend on a different model family than the hunter."""

    def __init__(
        self,
        repo_root: str | Path,
        *,
        model: str,
        base_url: str,
        api_key: str,
        cost_tracker: CostTracker | None = None,
        post: Any = None,
        timeout: float = 120.0,
    ):
        self._repo_root = Path(repo_root)
        self._model = model
        self._url = base_url.rstrip("/") + "/chat/completions"
        self._api_key = api_key
        self._cost_tracker = cost_tracker
        self._post = post or self._http_post
        self._timeout = timeout

    def _http_post(self, url: str, headers: dict[str, str], body: dict[str, Any]) -> dict[str, Any]:
        req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # noqa: S310 -- operator-configured URL
            return json.loads(resp.read().decode())

    def adjudicate(self, claim_card: ClaimCard) -> AdversaryResult:
        prompt = build_repo_reading_adversary_prompt(claim_card, self._repo_root)
        schema = _ADVERSARY_TOOL_SCHEMA_V2
        body = {
            "model": self._model,
            "temperature": 0,
            "max_tokens": 2000,
            "messages": [{"role": "user", "content": prompt}],
            "tools": [{"type": "function", "function": {
                "name": schema["name"], "description": schema["description"], "parameters": schema["input_schema"],
            }}],
            "tool_choice": {"type": "function", "function": {"name": schema["name"]}},
        }
        start = time.monotonic()
        data = self._post(self._url, {"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"}, body)
        if self._cost_tracker is not None:
            usage = data.get("usage") or {}
            self._cost_tracker.record_usage_dict(
                "cross-family-adversary", claim_card.target_sink, self._model,
                {"input_tokens": usage.get("prompt_tokens", 0), "output_tokens": usage.get("completion_tokens", 0)},
                time.monotonic() - start,
            )
        try:
            call = data["choices"][0]["message"]["tool_calls"][0]["function"]
            args = json.loads(call["arguments"])
        except (KeyError, IndexError, TypeError, ValueError):
            return AdversaryResult(
                verdict="unconfirmed",
                reasoning="model did not return a parseable submit_adversary_verdict tool call",
                model=self._model,
            )
        return _result_from_tool_input(args, self._model)


def cross_family_adversary_from_env(
    repo_root: str | Path, *, cost_tracker: CostTracker | None = None, env: dict[str, str] | None = None
) -> CrossFamilyAdversary | None:
    """Build the hook from environment config, or `None` when unconfigured
    (the default: behavior is unchanged). Raises `ValueError` for a partial
    or unsupported configuration rather than silently falling back."""
    e = os.environ if env is None else env
    provider = e.get("MCP_SAFEGUARD_ADVERSARY_PROVIDER")
    if not provider:
        return None
    if provider != "openai-compatible":
        raise ValueError(f"unsupported MCP_SAFEGUARD_ADVERSARY_PROVIDER {provider!r}; supported: 'openai-compatible'")
    model, base_url, key_env = (
        e.get("MCP_SAFEGUARD_ADVERSARY_MODEL"),
        e.get("MCP_SAFEGUARD_ADVERSARY_BASE_URL"),
        e.get("MCP_SAFEGUARD_ADVERSARY_API_KEY_ENV"),
    )
    if not (model and base_url and key_env):
        raise ValueError("MCP_SAFEGUARD_ADVERSARY_MODEL, _BASE_URL and _API_KEY_ENV must all be set")
    key = e.get(key_env)
    if not key:
        raise ValueError(f"environment variable {key_env!r} (named by MCP_SAFEGUARD_ADVERSARY_API_KEY_ENV) is empty")
    return CrossFamilyAdversary(repo_root, model=model, base_url=base_url, api_key=key, cost_tracker=cost_tracker)
