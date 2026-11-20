"""Stage 4: grounded LLM verification of tier "S" static-taint findings.

taint_scanner.py (Stage 1-3) produces a real, structured evidence object for
every tier "S" finding: a `taint_path` list of `Step`s (source/assign/call/
sink, each with the actual line number and code text), reconstructed by
walking the enclosing function's own AST. This module's job is narrow: turn
ONE such finding into a verification PROMPT that puts the model in front of
that real evidence -- the traced path, the full source of the handler that
produced it, and the full source of any locally-defined helper function
called along the way -- and then score its answer against a hard grounding
rule: every claim must cite a line number that is actually visible in the
evidence shown, or it is treated as unconfirmed rather than as a "no".

This is deliberately the opposite of a judge that sees an isolated code
snippet or a bare textual description with no traced path -- this project's
own campaign found that shape (Cisco's mcp-scanner's LLM judge) runs at
~22-25% precision precisely because there is nothing in an isolated snippet
that lets a model check whether an earlier line already neutralized the
value, or fabricate a plausible-sounding "yes" with no way to catch it.

Nothing here mutates a `SourceFinding` in place or drops the original tier
"S" evidence -- `verify()`/`verify_with_agreement()` return a separate
`VerificationResult`/`AgreementResult` alongside the finding; the caller (see
`cli.py`'s `--verify`) decides how to fold that into its own output, but the
finding's own `taint_path` is never touched.
"""

from __future__ import annotations

import ast
import os
import time
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal, Protocol

from . import lexical
from .cost import CostTracker
from .entrypoints import McpEntrypoint, recover_entrypoints
from .source_scanner import SourceFinding

# Reuse Stage 3's own enclosing-function walk verbatim, so Stage 4 always
# looks at the EXACT function object Stage 3 reconstructed the path from --
# not a second, possibly-divergent re-implementation of "find the enclosing
# def". Module-private, but this stays inside the same package on purpose.
from .taint_scanner import _find_enclosing_function
from .untrusted_text import UNTRUSTED_CONTENT_WARNING, wrap_untrusted

Verdict = Literal["confirmed", "refuted", "unconfirmed", "adversary-reviewed"]
# "adversary-reviewed" (added by adversary.py's ledger-write gate, see
# `run_adversary_check`) is a DISTINCT tier from plain "confirmed": it is
# what a hunter-fleet LLM-angle ClaimCard (no execution evidence, so it can
# never legitimately earn Stage-5's own "confirmed") is promoted to when an
# independent adversary tried to refute it and could not. Every existing
# `Verdict`-typed call site in this module (`_score_answers`,
# `verify_with_agreement`, ...) only ever produces one of the original three
# values -- this is additive, not a behavior change to Stage 4 itself.

# Bounds for "bounded -- if it's huge, truncate sensibly and say so" (task
# spec). Generous enough for real handler functions (the validated real
# targets below are all well under this), small enough to keep a prompt from
# blowing up on a pathological outlier.
_MAX_EXCERPT_LINES = 200
_MAX_CALLED_FUNCTIONS = 6


# --------------------------------------------------------------------------
# Evidence gathering: re-read the real source, resolve the real call graph
# (bounded, same-file only -- see _resolve_called_functions), reconstruct
# exactly what the model is and is not allowed to cite.
# --------------------------------------------------------------------------


@dataclass
class SourceExcerpt:
    """A bounded, line-numbered slice of real source shown to the verifier.
    `start_line`/`end_line` bound exactly what is VISIBLE in `text` -- if the
    function was truncated, `end_line` is the last line actually shown, not
    the function's real end, so grounding checks never accept a citation to
    a line the model was never shown."""

    file: str
    function_name: str
    start_line: int
    end_line: int
    text: str
    truncated: bool


def _excerpt_for(file_path: Path, fn: ast.FunctionDef | ast.AsyncFunctionDef, lines: list[str]) -> SourceExcerpt:
    start = fn.lineno
    real_end = getattr(fn, "end_lineno", None) or start
    body = lines[start - 1 : real_end]
    truncated = len(body) > _MAX_EXCERPT_LINES
    if truncated:
        body = body[:_MAX_EXCERPT_LINES]
    shown_end = start + len(body) - 1
    numbered = "\n".join(f"{start + i:>5} | {text}" for i, text in enumerate(body))
    if truncated:
        numbered += (
            f"\n      | ... [TRUNCATED: showing lines {start}-{shown_end} of "
            f"{start}-{real_end}; the rest of this function is not shown]"
        )
    return SourceExcerpt(
        file=str(file_path), function_name=fn.name, start_line=start, end_line=shown_end,
        text=numbered, truncated=truncated,
    )


def _local_call_names_in(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Bare-name and self./cls.-method call names referenced anywhere in
    `fn`. Deliberately narrow, same discipline as entrypoints.py's own
    module docstring: a cross-file call, a call reached through an
    intermediate variable holding a function reference, or a call on an
    arbitrary object are NOT chased -- an unresolved call is simply not
    included, not guessed at."""
    names: set[str] = set()
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name):
            names.add(func.id)
        elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id in ("self", "cls"):
            names.add(func.attr)
    return names


def _resolve_called_functions(
    tree: ast.Module, fn: ast.FunctionDef | ast.AsyncFunctionDef, lines: list[str], file_path: Path
) -> list[SourceExcerpt]:
    """Full source of every locally-defined (same file) function/method
    called from `fn`, bounded to `_MAX_CALLED_FUNCTIONS`. This is what lets
    the verifier actually answer "is this neutralization complete" for a
    case like a handler that calls a same-file `is_allowed_path()` wrapper
    that itself does nothing but a bare `str.startswith()` -- Stage 3's own
    taint_path never surfaces that wrapper as a Step (it isn't one of the
    recognized sanitizer call NAMES), so without this, the verifier would
    never see what the wrapper actually does.
    """
    wanted = _local_call_names_in(fn) - {fn.name}
    if not wanted:
        return []
    found: list[SourceExcerpt] = []
    seen: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name in wanted and node.name not in seen:
            found.append(_excerpt_for(file_path, node, lines))
            seen.add(node.name)
            if len(found) >= _MAX_CALLED_FUNCTIONS:
                break
    return found


@lru_cache(maxsize=8)
def _cached_entrypoints(root: str) -> tuple[McpEntrypoint, ...]:
    return tuple(recover_entrypoints(root))


def _match_entrypoint(root: Path, file_path: Path, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> McpEntrypoint | None:
    for ep in _cached_entrypoints(str(root)):
        if ep.file == file_path and ep.line == fn.lineno:
            return ep
    return None


def _finding_file_and_line(finding: SourceFinding, root: Path) -> tuple[Path, int]:
    rel, _, line_str = finding.location.rpartition(":")
    return root / rel, int(line_str)


@dataclass
class VerificationPrompt:
    """Everything one verification call needs: the rendered prompt text, and
    the set of line numbers that are actually grounded in evidence shown to
    the model -- any answer citing a line outside this set is ungrounded and
    must not be trusted as-is (see `_score_answers`)."""

    finding_key: str
    text: str
    valid_lines: frozenset[int]
    excerpts: list[SourceExcerpt]
    entrypoint: McpEntrypoint | None


def build_prompt(finding: SourceFinding, root: str | Path) -> VerificationPrompt:
    """Build the Stage 4 verification prompt for one tier "S" finding.
    Raises ValueError if `finding` isn't a tier "S" finding with a
    `taint_path`, or if the source it points at can no longer be re-read --
    this module verifies a specific finding against the real file it was
    found in, it does not verify from the finding's own text alone."""
    if finding.tier != "S" or not finding.taint_path:
        raise ValueError("build_prompt requires a tier=\"S\" finding with a non-empty taint_path")

    root = Path(root)
    file_path, sink_line = _finding_file_and_line(finding, root)
    try:
        source = file_path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(source, filename=str(file_path))
    except (OSError, SyntaxError) as exc:
        raise ValueError(f"could not re-read/re-parse {file_path} to verify {finding.location}: {exc}") from exc

    # Lexical-wiring milestone: `_excerpt_for`/`_resolve_called_functions`
    # build the TEXT shown to the Stage 4 verifier from `stripped_lines`
    # (comments/docstrings blanked, see `lexical.strip_comments_and_docstrings`
    # -- same length/line-count as `source.splitlines()`, so every line-number
    # computation below that uses `tree`/`source`/`enclosing.start_line`/
    # `end_line` is unaffected). This is the one evidence path in this module
    # that re-reads and re-renders a function body wholesale (`enclosing`/
    # `called`), not just per-line taint_path steps (those already arrive
    # pre-stripped via taint_scanner.py's own `reconstruct_path` -- see
    # `_render_prompt`'s `path_lines`).
    stripped_lines = lexical.strip_comments_and_docstrings(source, file_path.suffix).splitlines()
    fn = _find_enclosing_function(tree, sink_line)
    if fn is None:
        raise ValueError(f"could not re-locate the enclosing function for {finding.location}")

    enclosing = _excerpt_for(file_path, fn, stripped_lines)
    called = _resolve_called_functions(tree, fn, stripped_lines, file_path)
    entrypoint = _match_entrypoint(root, file_path, fn)

    # `finding.location` is "<rel-to-root path>:<line>" -- the same relative
    # path taint_scanner.py stamps onto each of ITS OWN reconstructed Steps'
    # `file` field (see `_findings_from_raw`). Used below to tell a
    # same-file step from a cross-file-origin one.
    finding_rel_path = finding.location.rpartition(":")[0]

    valid_lines: set[int] = set(range(enclosing.start_line, enclosing.end_line + 1))
    for exc in called:
        valid_lines.update(range(exc.start_line, exc.end_line + 1))
    for step in finding.taint_path:
        # Cross-file milestone: a hop-derived finding's taint_path can carry
        # steps from TWO files (the origin entrypoint's own file, and this
        # finding's own file -- see taint_scanner.py's
        # `_cross_file_origin_steps`). This prompt shows and grounds only
        # `file_path`'s own source (`enclosing`/`called` above), not the
        # origin file's, so a step whose `file` says it belongs to a
        # DIFFERENT file must never be folded into `valid_lines` -- doing so
        # would falsely "ground" an answer against a line number in the
        # wrong file. Older findings with no `file` key on their steps are
        # same-file-only by construction (predate this milestone) and are
        # included exactly as before.
        step_file = step.get("file") or ""
        if step_file and step_file != finding_rel_path:
            continue
        valid_lines.add(int(step["line"]))

    text = _render_prompt(finding, enclosing, called, entrypoint)
    return VerificationPrompt(
        finding_key=f"{finding.rule_id}@{finding.location}",
        text=text,
        valid_lines=frozenset(valid_lines),
        excerpts=[enclosing, *called],
        entrypoint=entrypoint,
    )


def _render_prompt(
    finding: SourceFinding,
    enclosing: SourceExcerpt,
    called: list[SourceExcerpt],
    entrypoint: McpEntrypoint | None,
) -> str:
    # Injection-defense: every repo-derived string below (a source-code
    # excerpt, a file path, a function/parameter name, a taint-path code/note
    # line, the static engine's own finding description -- which itself
    # embeds repo-derived identifiers, see taint_scanner.py's `description`
    # assembly) is wrapped individually in `wrap_untrusted()` at its own
    # interpolation site, matching the field-level discipline this project
    # already uses for hunter.py's `unit_note`/leads-section fixes (see
    # bench/INJECTION_SYSTEMIC_FIX_STATUS.md) -- NOT the "compose raw, wrap
    # whole" pattern hunter.py's own `evidence` blob uses, because this
    # prompt interleaves multiple independently-labeled excerpts (one per
    # called function) rather than a single evidence section, so each excerpt
    # gets its own delimiter pair. `kind`/`line` (an int)/`start_line`/
    # `end_line`/`truncated`/`sdk_shape`/`confidence` are this project's own
    # synthetic labels (small fixed vocabularies or ints), never repo text,
    # and are left unwrapped -- same reasoning as `m.call_line`/`lead.line`
    # in the prior 3 fixes. Comment/docstring interiors inside every excerpt
    # below are already blanked before this point (`build_prompt`'s
    # `stripped_lines`/taint_scanner.py's own `reconstruct_path*` -- see
    # those functions' own docstrings), so `wrap_untrusted()` here closes the
    # remaining, structural half of the gap: marking real repo text as DATA,
    # not additionally re-stripping it.
    path_lines = "\n".join(
        f"  [{step['kind']:>6}] L{step['line']}: {wrap_untrusted(step['code'])}"
        + (f"   -- {wrap_untrusted(step['note'])}" if step.get("note") else "")
        for step in finding.taint_path
    )

    called_block = "\n\n".join(
        f"### {wrap_untrusted(c.function_name)}()  --  {wrap_untrusted(c.file)}, lines {c.start_line}-{c.end_line}"
        + ("  [TRUNCATED]" if c.truncated else "")
        + f"\n{wrap_untrusted(c.text)}"
        for c in called
    ) or (
        "(no locally-defined helper function is called along this path -- every step happens "
        "directly inside the handler shown below)"
    )

    if entrypoint is not None:
        params = ", ".join(entrypoint.parameter_names)
        entry_block = (
            f"- function: {wrap_untrusted(entrypoint.function_name)}\n"
            f"- parameters: {wrap_untrusted(params) if params else '(none)'}\n"
            f"- registration shape: {entrypoint.sdk_shape} (confidence: {entrypoint.confidence})\n"
            "- Note: this pipeline does not separately recover a structured tool schema/description "
            "for the MCP tool -- any docstring or Field(description=...) text IS visible inline in the "
            "handler source below; it is not restated here as a separate field."
        )
    else:
        entry_block = (
            "(could not re-match this finding to one specific recovered entrypoint -- rely on the "
            "handler source below.)"
        )

    severity = finding.severity.value if hasattr(finding.severity, "value") else finding.severity

    return f"""\
You are verifying ONE static-analysis security finding for an MCP (Model Context Protocol) tool \
server. This is a GROUNDED verification: you may reason ONLY from the evidence given below, and you \
MUST cite the specific line number(s) shown in the excerpts for every claim you make. An answer that \
cites no line numbers is INVALID and must be scored as unconfirmed -- never as a plain "no" or "yes".

{UNTRUSTED_CONTENT_WARNING}

## Finding
- Rule: {finding.rule_id} -- {finding.title}
- Severity: {severity} (CVSS {finding.cvss_score})
- Location: {wrap_untrusted(finding.location)}
- Static engine's own description: {wrap_untrusted(finding.description)}

## Traced evidence path (Stage 3 reconstruction)
This is a best-effort, statement-order approximation -- it has NO real control-flow graph and does \
not model branches/loops itself. Check the actual source below for the real branch conditions.
{path_lines}

## Enclosing handler function -- full source, {wrap_untrusted(enclosing.file)}, lines {enclosing.start_line}-{enclosing.end_line}{" [TRUNCATED]" if enclosing.truncated else ""}
{wrap_untrusted(enclosing.text)}

## Functions called along the path (full source, bounded to {_MAX_CALLED_FUNCTIONS} functions / {_MAX_EXCERPT_LINES} lines each)
{called_block}

## MCP tool metadata (Stage 1 entrypoint recovery)
{entry_block}

## Answer ALL FOUR questions below. Cite line numbers from the excerpts above for every claim.
1. Can the tainted source value reach the sink with attacker-chosen content, given the branch \
conditions actually present on this path?
2. Does any step on the path neutralize it, and is that neutralization actually complete for this \
specific sink class (e.g. does a startswith() check really prevent path traversal, or is it a \
weak/bypassable check)?
3. What concrete example input would demonstrate the vulnerability?
4. What single additional condition, if true, would make this a non-issue?

Respond ONLY by calling the submit_verification tool with your answers in its exact schema. Do not \
include any other text.
"""


# --------------------------------------------------------------------------
# Scoring: turn one parsed answer set into a VerificationResult, enforcing
# the citation/grounding contract above.
# --------------------------------------------------------------------------


@dataclass
class VerificationResult:
    verdict: Verdict
    reasoning: str
    answers: dict[str, Any]
    valid_lines: list[int]
    model: str
    grounded: bool


def _cited_ok(block: Any, valid_lines: frozenset[int]) -> bool:
    if not isinstance(block, dict):
        return False
    cited = block.get("cited_lines") or []
    return bool(cited) and all(isinstance(n, int) and n in valid_lines for n in cited)


def _score_answers(data: dict, valid_lines: frozenset[int], model: str) -> VerificationResult:
    """Apply the verdict contract from the task spec:
    - default: unconfirmed
    - confirmed requires a concrete example input (Q3) AND no valid
      neutralization found (Q2)
    - refuted requires citing the specific neutralizing step from Q2
    - any answer that fails the citation/grounding check is treated as
      invalid, not as a "no" -- forced to unconfirmed regardless of what the
      model's own `answer` field said.
    """
    valid_sorted = sorted(valid_lines)
    if not isinstance(data, dict):
        return VerificationResult("unconfirmed", "response was not a JSON object", {}, valid_sorted, model, False)

    q1 = data.get("q1_reachable")
    q2 = data.get("q2_neutralized")
    q3 = data.get("q3_example_input")
    if not isinstance(q1, dict) or not isinstance(q2, dict) or not isinstance(q3, dict):
        return VerificationResult(
            "unconfirmed", "malformed response: missing one of q1_reachable/q2_neutralized/q3_example_input",
            data, valid_sorted, model, False,
        )

    q1_ok = _cited_ok(q1, valid_lines)
    q2_ok = _cited_ok(q2, valid_lines)
    q3_ok = _cited_ok(q3, valid_lines)

    if not q1_ok:
        return VerificationResult(
            "unconfirmed",
            "Q1 (reachability) cited no line number that is actually in the evidence shown -- "
            "invalid per the prompt's grounding contract, treated as unconfirmed rather than a 'no'.",
            data, valid_sorted, model, False,
        )

    if str(q2.get("answer", "")).lower() == "yes":
        neutralizing_line = q2.get("neutralizing_line")
        if q2_ok and isinstance(neutralizing_line, int) and neutralizing_line in valid_lines:
            return VerificationResult(
                "refuted",
                f"Neutralized at line {neutralizing_line}: {q2.get('reasoning', '')}",
                data, valid_sorted, model, True,
            )
        return VerificationResult(
            "unconfirmed",
            "Claimed a neutralization but did not cite a valid, in-evidence neutralizing line -- "
            "invalid per the prompt's grounding contract.",
            data, valid_sorted, model, False,
        )

    reachable = str(q1.get("answer", "")).lower() == "yes"
    example_input = q3.get("input")
    if reachable and example_input and q3_ok:
        return VerificationResult(
            "confirmed",
            f"Reachable ({q1.get('reasoning', '')}); no valid neutralization found; "
            f"example input: {example_input!r} (cited lines {q3.get('cited_lines')}).",
            data, valid_sorted, model, True,
        )

    return VerificationResult(
        "unconfirmed",
        "Neither a grounded neutralization (Q2) nor a grounded reachable-plus-example case (Q1+Q3) "
        "was established.",
        data, valid_sorted, model, False,
    )


# --------------------------------------------------------------------------
# Pluggable backends
# --------------------------------------------------------------------------


def build_anthropic_client(class_name: str, api_key: str | None) -> Any:
    """Shared bootstrap for every Anthropic-backed class in this package:
    resolve the API key (explicit `api_key=` or `ANTHROPIC_API_KEY`), raise a
    clear `RuntimeError` if neither is set, lazily `import anthropic` with an
    install hint if the package is missing, and construct the client. Used by
    `AnthropicVerifier` (this module), `hunter.py`'s `AnthropicHunter`, and
    `critic.py`'s `AnthropicCriticVerifier` -- previously each reimplemented
    this same ~15-line block independently."""
    resolved_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not resolved_key:
        raise RuntimeError(
            f"ANTHROPIC_API_KEY is not set and no api_key was passed explicitly -- "
            f"{class_name} makes a real API call and is never invoked with a "
            f"fake/mocked response, so it refuses to run without real credentials."
        )
    try:
        import anthropic
    except ImportError as exc:
        raise RuntimeError(
            f"the `anthropic` package is required for {class_name} -- "
            f"install with `pip install mcp-safeguard[verify]`"
        ) from exc
    return anthropic.Anthropic(api_key=resolved_key)


class Verifier(Protocol):
    def verify(self, finding: SourceFinding, root: str | Path) -> VerificationResult: ...


# JSON Schema for the forced tool-call response -- see AnthropicVerifier.
_VERIFY_TOOL_SCHEMA = {
    "name": "submit_verification",
    "description": "Submit the grounded verification verdict for this static-taint finding.",
    "input_schema": {
        "type": "object",
        "properties": {
            "q1_reachable": {
                "type": "object",
                "properties": {
                    "answer": {"type": "string", "enum": ["yes", "no", "unclear"]},
                    "cited_lines": {"type": "array", "items": {"type": "integer"}},
                    "reasoning": {"type": "string"},
                },
                "required": ["answer", "cited_lines", "reasoning"],
            },
            "q2_neutralized": {
                "type": "object",
                "properties": {
                    "answer": {"type": "string", "enum": ["yes", "no", "unclear"]},
                    "neutralizing_line": {"type": ["integer", "null"]},
                    "cited_lines": {"type": "array", "items": {"type": "integer"}},
                    "reasoning": {"type": "string"},
                },
                "required": ["answer", "cited_lines", "reasoning"],
            },
            "q3_example_input": {
                "type": "object",
                "properties": {
                    "input": {"type": ["string", "null"]},
                    "cited_lines": {"type": "array", "items": {"type": "integer"}},
                    "reasoning": {"type": "string"},
                },
                "required": ["input", "cited_lines", "reasoning"],
            },
            "q4_non_issue_condition": {
                "type": "object",
                "properties": {
                    "condition": {"type": "string"},
                    "cited_lines": {"type": "array", "items": {"type": "integer"}},
                },
                "required": ["condition", "cited_lines"],
            },
        },
        "required": ["q1_reachable", "q2_neutralized", "q3_example_input", "q4_non_issue_condition"],
    },
}


class AnthropicVerifier:
    """Real LLM backend using the `anthropic` Python SDK, temperature 0, a
    forced tool-call for structured JSON (`tool_choice`, not free-text
    parsing). Requires `ANTHROPIC_API_KEY` (or an explicit `api_key=`) and
    the `anthropic` package (`pip install mcp-safeguard[verify]`) -- kept as
    its own optional extra, same reasoning as `static-taint`'s semgrep extra:
    this module should not force every user of the rest of the package to
    pull in an LLM SDK they may never use.
    """

    def __init__(self, model: str = "claude-sonnet-4-5-20250929", api_key: str | None = None, *, cost_tracker: CostTracker | None = None):
        self._model = model
        self._client = build_anthropic_client("AnthropicVerifier", api_key)
        self._cost_tracker = cost_tracker

    def verify(self, finding: SourceFinding, root: str | Path) -> VerificationResult:
        prompt = build_prompt(finding, root)
        start = time.monotonic()
        response = self._client.messages.create(
            model=self._model,
            max_tokens=1500,
            temperature=0,
            tools=[_VERIFY_TOOL_SCHEMA],
            tool_choice={"type": "tool", "name": "submit_verification"},
            messages=[{"role": "user", "content": prompt.text}],
        )
        if self._cost_tracker is not None:
            self._cost_tracker.record_from_response(
                "verify", prompt.finding_key, self._model, response, time.monotonic() - start
            )
        tool_use = next((block for block in response.content if getattr(block, "type", None) == "tool_use"), None)
        if tool_use is None:
            return VerificationResult(
                "unconfirmed", "model did not return the required submit_verification tool call",
                {}, sorted(prompt.valid_lines), self._model, False,
            )
        return _score_answers(tool_use.input, prompt.valid_lines, model=self._model)


class ManualRecordVerifier:
    """Playback backend for manual-walkthrough mode (no LLM API key
    available). Each `.verify()` call replays the NEXT recorded answer for
    that finding's key, in the order recorded. These answers were produced
    by a human/agent reading the ACTUAL prompt `build_prompt()` generated for
    that exact finding, and answering the same 4 questions in the same
    schema `_VERIFY_TOOL_SCHEMA` requires of a real model -- not by mocking
    or guessing what a model would say. Raises `KeyError` for any finding it
    has no recorded answer for; it never fabricates one. See
    `bench/run_verify_manual_walkthrough.py` for how the recorded answers in
    this project were actually produced.
    """

    def __init__(self, recorded: dict[str, list[dict]], *, cost_tracker: CostTracker | None = None):
        self._recorded = recorded
        self._calls: dict[str, int] = {}
        self._cost_tracker = cost_tracker

    def verify(self, finding: SourceFinding, root: str | Path) -> VerificationResult:
        prompt = build_prompt(finding, root)
        key = prompt.finding_key
        runs = self._recorded.get(key)
        if not runs:
            raise KeyError(
                f"no manually-recorded verification answer for {key!r} -- ManualRecordVerifier only "
                f"replays answers actually produced during this project's manual walkthrough, it does "
                f"not fabricate one for an unrecorded finding"
            )
        idx = self._calls.get(key, 0)
        data = runs[idx % len(runs)]
        self._calls[key] = idx + 1
        model = f"manual-walkthrough[pass {idx + 1}]"
        if self._cost_tracker is not None:
            # No real call was made -- this is a true no-op unless `data`
            # itself carries a "usage" dict of real, externally-supplied
            # token counts (see CostTracker.record_usage_dict's own
            # docstring). `data.get(...)` on a non-dict `data` would raise,
            # but `data` here is always the same dict shape `_score_answers`
            # below already requires.
            self._cost_tracker.record_usage_dict("verify", key, model, data.get("usage") if isinstance(data, dict) else None)
        return _score_answers(data, prompt.valid_lines, model=model)


# --------------------------------------------------------------------------
# Two-run agreement wrapper (task Step 3)
# --------------------------------------------------------------------------


@dataclass
class AgreementResult:
    verdict: Verdict
    run_a: VerificationResult
    run_b: VerificationResult
    agreed: bool


def verify_with_agreement(verifier: Verifier, finding: SourceFinding, root: str | Path, runs: int = 2) -> AgreementResult:
    """Call `verifier.verify()` `runs` times (fresh context each time -- each
    call re-renders the prompt and, for a real backend, is an independent API
    call with no shared conversation state) and only trust a `confirmed`/
    `refuted` verdict if both runs agree. On any disagreement, returns
    `unconfirmed` with both raw results attached for a human to review --
    this is the guard against a single non-deterministic or hallucinated
    judgment the task spec calls for.
    """
    if runs != 2:
        raise ValueError(
            "verify_with_agreement implements exactly the documented 2-run agreement check; "
            "call verifier.verify() directly for a single pass"
        )
    run_a = verifier.verify(finding, root)
    run_b = verifier.verify(finding, root)
    agreed = run_a.verdict == run_b.verdict
    return AgreementResult(verdict=(run_a.verdict if agreed else "unconfirmed"), run_a=run_a, run_b=run_b, agreed=agreed)
