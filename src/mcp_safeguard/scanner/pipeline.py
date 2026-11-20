"""S8 (fleet wiring): one real, end-to-end hunt pipeline.

Every stage this module calls already existed and was already independently
tested -- Stage 0-3 (`taint_scanner.run_static_taint_scan`), the Claim Card
data model (`claim_card.py`), Stage 4 grounded LLM verification
(`verify.py`), Stage 5 execution sandbox (`sandbox.py`), the S6 cross-tier
critic (`critic.py`), and the S7 append-only evidence ledger (`ledger.py`).
None of them imported each other (except S6 importing this module's own
`ClaimCard`/`OracleTrace` shapes, same as every other stage). This module is
the glue that runs them in sequence against one real repo:

    taint scan -> SourceFinding list
      -> for each finding, a ClaimCard (target_sink/tainted_source/etc.
         derived from the finding itself; caller_authority_assumed enriched,
         where a match exists, from threat_model.py's S2 declared-authority
         extraction -- `threat_model.py` itself has no ClaimCard-building
         logic of its own; that glue lives here, not there)
      -> for the sandbox-testable finding classes (TAINT-CMDI, TAINT-PATHTRAV,
         TAINT-SSRF, TAINT-CREDFWD), a real `run_in_sandbox()` call against
         the finding's own reconstructed sink location, with a PoC argument
         synthesized from the finding's own rule class and the callable
         function's own parameter shape -- see "PoC argument synthesis"
         below
      -> TAINT-IDOR findings explicitly SKIP the sandbox stage (absence
         -based; see taint_scanner.py's own module docstring) and get an
         impossibility_argument instead, never a fabricated oracle_trace
      -> if ANTHROPIC_API_KEY is set, Stage 4 (`verify_with_agreement`) also
         runs and its verdict is recorded; if not, this is recorded honestly
         ("LLM verification skipped, no API key") and the pipeline continues
      -> for every finding whose verdict is `"confirmed"` after Stage 4/5
         (a "survivor"), the S6 critic (`critic.py`) runs BEFORE the ledger
         write: its two deterministic mechanisms (severity recalibration,
         reachability/tautology soundness check) always apply, no API key
         needed; its cross-tier LLM pass (`AnthropicCriticVerifier`, a
         genuinely different/higher capability tier than Stage 4's own
         verifier) applies only when ANTHROPIC_API_KEY is set, same
         graceful-skip pattern as Stage 4 itself. A tautology-unsound,
         execution-confirmed finding is recalibrated from `"confirmed"` to
         `"unconfirmed"` here, flagged `TAUTOLOGY_RISK` in the ledger note --
         see `critic.py`'s own module docstring for the real deepseek-pp
         false positive this stage exists to catch.
      -> every resulting ClaimCard (oracle_trace and/or impossibility_argument,
         whatever real evidence actually exists) is written to the ledger with
         an HONEST verdict tier: `confirmed` only when execution evidence or
         an agreeing LLM pair actually confirms it AND the S6 critic did not
         flag it as an unsound tautology, never merely because a ClaimCard
         object was constructed.

## Two real, generalizable limitations found while wiring this

Stage 5 (`sandbox.py`) resolves a callable entrypoint via
`getattr(module, function_name)` (Python) or a dynamic ES-module `import()`
(JS/TS) -- both require the target function to be reachable as a MODULE
-LEVEL attribute. This pipeline therefore only ATTEMPTS Stage 5 when the
finding's own enclosing function (at its sink location, reusing
`taint_scanner._find_enclosing_function`/`entrypoints_js.find_enclosing_function`
-- the exact same function Stage 4's `verify.py` already re-locates for its
own prompt) is:
  - Python: a direct module-top-level `def`/`async def` (not a method, not
    a closure nested inside another function) -- `getattr(module, name)`
    cannot reach either of those.
  - JS/TS: a top-level, exported binding (`export function f(){}` or
    `export const f = (...) => {...}`, walked via the real tree-sitter
    parent chain, not a textual guess) -- a class method or a non-exported
    helper is not a property of the dynamically-imported module object.
When neither holds, this is recorded as a real, honest `impossibility_argument`
naming exactly which condition failed -- never a fabricated trace, and never
silently dropped. This is a real limitation this wiring surfaced, not a
hypothetical one: see `bench/PIPELINE_WIRING_STATUS.md` for the concrete case
(Aiven-Open/mcp-aiven's `askDocs`) it was found against.

## PoC argument synthesis

A sandbox-testable finding's callable target is invoked with ONE synthesized
argument list, built from the callable's own parameter names (or, for a
single object-shaped parameter -- e.g. `askDocs(opts)` where the body reads
`opts.origin`/`opts.apiKey` -- from the attribute names the function body
itself reads off that parameter): a credential-shaped name
(api_key/token/secret/...) gets a fake, clearly-marked, never-real value; a
url/host/path-shaped name gets the rule class's own malicious payload (a
shell metacharacter marker for TAINT-CMDI, a `../../` traversal string for
TAINT-PATHTRAV, an attacker-host URL for TAINT-SSRF/TAINT-CREDFWD); anything
else gets a benign placeholder. If nothing matched a shape at all, the first
parameter is still forced to carry the malicious payload, so a genuinely
single-parameter function is always exercised for real. This is a heuristic,
not a semantic understanding of the target code -- documented as exactly
that, same discipline the rest of this project applies to its own
static-analysis heuristics.
"""

from __future__ import annotations

import ast
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .adversary import (
    AdversaryBackend,
    AnthropicAdversary,
    ExternalAssumptionAdversary,
    RepoReadingAdversary,
    run_adversary_check,
)
from .claim_card import ClaimCard, ClaimCardValidationError
from .cost import CostTracker
from .critic import AnthropicCriticVerifier, CriticVerifier, critique_finding
from .ledger import DEFAULT_LEDGER_PATH, LedgerEntry, append_entry
from .retrieval import ExemplarIndex, build_exemplar_index, retrieve_exemplars
from .sandbox import OracleTrace, SandboxEntrypoint, SandboxUnavailableError, run_in_sandbox
from .source_scanner import SourceFinding
from .taint_scanner import Step, _find_enclosing_function, run_static_taint_scan
from .threat_model import (
    EntrypointProfile,
    ThreatModelDocument,
    _resolve_commit,
    build_threat_model,
)
from .verify import AnthropicVerifier, Verdict, verify_with_agreement

# Sandbox-testable finding classes (task's own list). Both languages share
# the SAME public rule_id strings (confirmed in taint_scanner.py -- the
# "-js"/"-anyfn" suffixes are internal semgrep rule keys, never surfaced on
# SourceFinding.rule_id itself), so one set covers Python and JS/TS.
SANDBOX_TESTABLE_RULE_IDS = frozenset({"TAINT-CMDI", "TAINT-PATHTRAV", "TAINT-SSRF", "TAINT-CREDFWD"})

# TAINT-IDOR is deliberately excluded from the set above: it is
# taint_scanner.py's own absence-based class ("no recognized authorization
# -check call was found on this path") -- a real, documented, deliberate
# limitation from when the class was built (see taint_scanner.py's module
# docstring), not something a generic dynamic oracle can confirm without a
# real multi-tenant test harness (two distinct caller identities, one
# resource, an expected 403). Never routed through Stage 5.
IDOR_RULE_ID = "TAINT-IDOR"

_PY_SUFFIX = ".py"
_JS_SUFFIXES = frozenset({".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"})

# `_MARKER_TOKEN`/`_MARKER_HOST` appear ONLY inside `_MALICIOUS_PAYLOAD`'s
# own values below -- `_interpret_trace` treats their presence anywhere in
# an oracle trace as proof the injected value actually reached the sink.
# `_FAKE_CREDENTIAL_VALUE`/`_BENIGN_PLACEHOLDER` (the values every OTHER
# synthesized argument gets -- see `_synth_value`) are deliberately built
# from DIFFERENT strings with no shared substring: a real bug this module
# hit while wiring is a benign/placeholder value that happened to contain
# the same marker text, which made `_interpret_trace` "confirm" a finding
# just because some unrelated, non-malicious argument showed up in the
# trace -- not because the real payload ever reached the sink.
_MARKER_TOKEN = "MCPSAFEGUARDPOCMARKER7F3A"
_MARKER_HOST = "169.254.169.254"  # classic SSRF/cloud-metadata marker host

_MALICIOUS_PAYLOAD: dict[str, str] = {
    "TAINT-CMDI": f"; echo {_MARKER_TOKEN} #",
    "TAINT-PATHTRAV": f"../../../../../../tmp/{_MARKER_TOKEN}",
    "TAINT-SSRF": f"http://{_MARKER_HOST}/{_MARKER_TOKEN}",
    "TAINT-CREDFWD": f"http://{_MARKER_HOST}/{_MARKER_TOKEN}",
}
_FAKE_CREDENTIAL_VALUE = "mcpsafeguard-poc-fakecred-d42e-do-not-use"
_BENIGN_PLACEHOLDER = "mcpsafeguard-poc-benign-b91c"

_CRED_PARAM_RE = re.compile(r"(api[_-]?key|token|secret|passwd|password|credential|bearer)", re.IGNORECASE)
_URL_HOST_PARAM_RE = re.compile(r"(url|uri|host|origin|endpoint|target)", re.IGNORECASE)
_PATH_PARAM_RE = re.compile(r"(path|file|dir)", re.IGNORECASE)


# --------------------------------------------------------------------------
# Result shapes
# --------------------------------------------------------------------------


@dataclass
class HuntFindingOutcome:
    """What happened for ONE tier-S finding during a `hunt()` run."""

    finding: SourceFinding
    claim_card: ClaimCard | None
    verdict: Verdict
    ledger_entry: LedgerEntry | None
    note: str


@dataclass
class HuntResult:
    repo_path: str
    commit: str
    findings_scanned: int
    outcomes: list[HuntFindingOutcome] = field(default_factory=list)
    ledger_path: str = str(DEFAULT_LEDGER_PATH)
    # Cost-instrumentation milestone: the SAME `CostTracker` this run's own
    # taint scan / Stage 4 verifier / S6 critic recorded into (see `hunt()`),
    # so a caller can read the real, aggregated token/cost/wall-time report
    # for this run (`.report()`/`.to_dict()`) straight off the result.
    cost_tracker: CostTracker | None = None

    def counts(self) -> dict[str, int]:
        out = {"confirmed": 0, "refuted": 0, "unconfirmed": 0}
        for o in self.outcomes:
            out[o.verdict] = out.get(o.verdict, 0) + 1
        return out


# --------------------------------------------------------------------------
# Entrypoint resolution: is the finding's sink-enclosing function actually
# something Stage 5 can call? See module docstring's "Two real,
# generalizable limitations" section.
# --------------------------------------------------------------------------


@dataclass
class _SandboxResolution:
    entrypoint: SandboxEntrypoint | None
    args: list[Any]
    error: str | None


def _finding_file_and_line(finding: SourceFinding, root: Path) -> tuple[Path, int] | None:
    rel, sep, line_str = finding.location.rpartition(":")
    if not sep:
        return None
    try:
        return root / rel, int(line_str)
    except ValueError:
        return None


def _object_shaped_attrs_python(fn: ast.FunctionDef | ast.AsyncFunctionDef, param_name: str) -> list[str]:
    attrs: list[str] = []
    seen: set[str] = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == param_name:
            if node.attr not in seen:
                seen.add(node.attr)
                attrs.append(node.attr)
    return attrs


def _resolve_python_entrypoint(finding: SourceFinding, file_path: Path, sink_line: int) -> _SandboxResolution:
    try:
        source = file_path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(source, filename=str(file_path))
    except (OSError, SyntaxError) as exc:
        return _SandboxResolution(None, [], f"could not re-parse {file_path} to resolve a callable entrypoint: {exc}")

    fn = _find_enclosing_function(tree, sink_line)
    if fn is None:
        return _SandboxResolution(None, [], f"could not re-locate the enclosing function for {finding.location}")
    if fn not in tree.body:
        return _SandboxResolution(None, [], (
            f"{fn.name}() at {finding.location} is not a module-top-level function (it is a method or a "
            f"nested closure) -- sandbox.py's Python runner resolves an entrypoint via "
            f"getattr(module, function_name), which cannot reach a bound method or a closure. This is a "
            f"real, current limitation of Stage 5 as wired, not attempted here."
        ))

    param_names = [a.arg for a in fn.args.args if a.arg not in ("self", "cls")]
    object_attrs = _object_shaped_attrs_python(fn, param_names[0]) if len(param_names) == 1 else None
    args = _build_poc_args(param_names, object_attrs, finding.rule_id)
    return _SandboxResolution(SandboxEntrypoint(file=file_path, function_name=fn.name, runtime="python"), args, None)


def _js_export_name(fn_node: Any, src: bytes, ejs: Any) -> str | None:
    """The name `fn_node` is reachable as on the dynamically-`import()`ed
    module's own namespace object, or None if it is not a directly-callable,
    top-level exported binding. Walks the REAL tree-sitter parent chain
    (never a textual/regex guess) -- returns None (silence, not a guess,
    same discipline as the rest of this project) for a class method, a
    nested closure, or a non-exported top-level function."""
    if fn_node.type == "function_declaration":
        name_node = fn_node.child_by_field_name("name")
        if name_node is None:
            return None
        parent = fn_node.parent
        if parent is not None and parent.type == "export_statement" and parent.parent is not None and parent.parent.type == "program":
            return ejs.node_text(name_node, src)
        return None
    if fn_node.type in ("arrow_function", "function_expression"):
        declarator = fn_node.parent
        if declarator is None or declarator.type != "variable_declarator":
            return None
        name_node = declarator.child_by_field_name("name")
        if name_node is None or name_node.type != "identifier":
            return None
        decl_list = declarator.parent
        if decl_list is None:
            return None
        stmt = decl_list.parent
        if stmt is not None and stmt.type == "export_statement" and stmt.parent is not None and stmt.parent.type == "program":
            return ejs.node_text(name_node, src)
        return None
    return None  # method_definition (class method), generator, or anything else -- not directly callable


def _object_shaped_attrs_js(fn_node: Any, src: bytes, param_name: str, ejs: Any) -> list[str]:
    attrs: list[str] = []
    seen: set[str] = set()
    for node in ejs.walk(fn_node):
        if node.type != "member_expression":
            continue
        obj = node.child_by_field_name("object")
        prop = node.child_by_field_name("property")
        if obj is None or prop is None or obj.type != "identifier" or ejs.node_text(obj, src) != param_name:
            continue
        name = ejs.node_text(prop, src)
        if name not in seen:
            seen.add(name)
            attrs.append(name)
    return attrs


def _resolve_js_entrypoint(finding: SourceFinding, file_path: Path, sink_line: int) -> _SandboxResolution:
    try:
        from . import entrypoints_js as ejs
    except ImportError as exc:
        return _SandboxResolution(None, [], (
            f"tree-sitter JS/TS support unavailable ({exc}) -- install `mcp-safeguard[static-taint]`"
        ))

    parsed = ejs.parse_file(file_path)
    if parsed is None:
        return _SandboxResolution(None, [], f"could not parse {file_path} to resolve a callable entrypoint")
    root_node, src = parsed

    fn_node = ejs.find_enclosing_function(root_node, sink_line)
    if fn_node is None:
        return _SandboxResolution(None, [], f"could not re-locate the enclosing function for {finding.location}")

    export_name = _js_export_name(fn_node, src, ejs)
    if export_name is None:
        return _SandboxResolution(None, [], (
            f"the enclosing function at {finding.location} is not a directly-callable, top-level exported "
            f"binding (it may be a class method, a nested closure, or simply not exported) -- Stage 5's JS "
            f"runner dynamically import()s the file and looks up a NAMED EXPORT on the resulting module "
            f"object; a non-exported function is not reachable that way. This is a real, current "
            f"limitation of Stage 5 as wired, not attempted here."
        ))

    param_names = ejs.function_params(fn_node, src)
    object_attrs = _object_shaped_attrs_js(fn_node, src, param_names[0], ejs) if len(param_names) == 1 else None
    args = _build_poc_args(param_names, object_attrs, finding.rule_id)
    runtime = "node"
    return _SandboxResolution(SandboxEntrypoint(file=file_path, function_name=export_name, runtime=runtime), args, None)


def resolve_sandbox_entrypoint(finding: SourceFinding, root: Path) -> _SandboxResolution:
    """Resolve `finding`'s sink location to a directly-callable
    `SandboxEntrypoint` plus a synthesized PoC argument list, or a real,
    specific reason it could not be resolved. Never raises."""
    located = _finding_file_and_line(finding, root)
    if located is None:
        return _SandboxResolution(None, [], f"could not parse a file:line location from {finding.location!r}")
    file_path, sink_line = located
    if not file_path.is_file():
        return _SandboxResolution(None, [], f"source file no longer exists: {file_path}")

    suffix = file_path.suffix
    if suffix == _PY_SUFFIX:
        return _resolve_python_entrypoint(finding, file_path, sink_line)
    if suffix in _JS_SUFFIXES:
        return _resolve_js_entrypoint(finding, file_path, sink_line)
    return _SandboxResolution(None, [], f"unrecognized source file type {suffix!r} -- Stage 5 supports .py and .js/.ts family files only")


# --------------------------------------------------------------------------
# PoC argument synthesis -- see module docstring.
# --------------------------------------------------------------------------


def _synth_value(name: str, rule_id: str) -> str:
    if _CRED_PARAM_RE.search(name):
        return _FAKE_CREDENTIAL_VALUE
    if _URL_HOST_PARAM_RE.search(name) or _PATH_PARAM_RE.search(name):
        return _MALICIOUS_PAYLOAD[rule_id]
    return _BENIGN_PLACEHOLDER


def _values_for_names(names: list[str], rule_id: str) -> list[str]:
    values = [_synth_value(n, rule_id) for n in names]
    if names and _MALICIOUS_PAYLOAD[rule_id] not in values:
        # Nothing matched a url/host/path shape -- force the first name to
        # carry the payload anyway, so a genuinely single-argument function
        # (however it's named) is still exercised for real.
        values[0] = _MALICIOUS_PAYLOAD[rule_id]
    return values


def _build_poc_args(param_names: list[str], object_attrs: list[str] | None, rule_id: str) -> list[Any]:
    if not param_names:
        return []
    if len(param_names) == 1 and object_attrs:
        values = _values_for_names(object_attrs, rule_id)
        return [dict(zip(object_attrs, values, strict=True))]
    return _values_for_names(param_names, rule_id)


# --------------------------------------------------------------------------
# Trace interpretation: did the injected PoC value actually reach a real
# effect the oracle observed? Only this -- never mere ClaimCard construction
# -- is allowed to set verdict="confirmed".
# --------------------------------------------------------------------------


# Adversary-repo-read milestone: these two "ran, produced no signal" note
# strings are shared constants (not just inline literals in `_interpret_trace`
# below) because `hunt_fleet`'s own `_is_sandbox_negative_pathtrav_ssrf_credfwd`
# routing check (see below) needs to recognize EXACTLY these two outcomes --
# sharing the literal string, rather than duplicating it, means the two call
# sites cannot silently drift apart if this wording ever changes.
_NOTE_PATHTRAV_NO_TRIGGER = "sandbox ran; no file open matched the PoC path or resolved outside the expected root"
_NOTE_SSRF_CREDFWD_NO_TRIGGER = "sandbox ran; no outbound request reached the PoC host and no credential flag was observed"

# Sandbox-fix milestone (2026-09): a THIRD, genuinely distinct outcome
# category, deliberately worded to never overlap with either "ran, no
# signal" negative above. `trace.exception` (set by sandbox.py whenever the
# TARGET's own code raised -- see OracleTrace's own field comment) means the
# target never got a real, clean chance to reach the sink at all (the classic
# case on this project's own real traces: a missing target dependency, e.g.
# `ModuleNotFoundError: fastmcp`, raised on import/construction, long before
# the PoC argument could ever reach the sink). That is NOT evidence the sink
# is unreachable -- it is a target-environment failure -- so it must never be
# worded like, counted like, or routed like a genuine sandbox negative.
# `_is_sandbox_negative_pathtrav_ssrf_credfwd` below (and any future
# consumer of `_interpret_trace`'s note text) must treat this as its own
# category, not as a variant of "ran, no signal".
_NOTE_INCONCLUSIVE_TARGET_EXCEPTION = "inconclusive: target raised before reaching the sink"


def _is_inconclusive_target_exception_note(note: str | None) -> bool:
    """True iff `note` (an `outcome.note`/`_interpret_trace` note) is this
    new "target raised before reaching the sink" category -- the single
    place that substring check lives, so every consumer (currently just
    `_is_sandbox_negative_pathtrav_ssrf_credfwd`, but any future one too)
    asks this function instead of re-deriving the marker text itself."""
    return _NOTE_INCONCLUSIVE_TARGET_EXCEPTION in (note or "")


def _interpret_trace(rule_id: str, trace: OracleTrace) -> tuple[bool, str]:
    if trace.error:
        return False, f"sandbox-level error, evidence inconclusive: {trace.error}"

    if rule_id == "TAINT-CMDI":
        hit = any(_MARKER_TOKEN in " ".join(str(x) for x in c.get("argv", [])) for c in trace.subprocess_calls)
        if hit:
            return True, "execution-confirmed: the PoC marker was observed in a real subprocess argv"
        if trace.exception:
            return False, f"{_NOTE_INCONCLUSIVE_TARGET_EXCEPTION}: {trace.exception}"
        return False, "sandbox ran; no subprocess call carried the injected PoC marker"
    if rule_id == "TAINT-PATHTRAV":
        hit = any(
            _MARKER_TOKEN in (str(fo.get("path", "")) + str(fo.get("resolved_path", ""))) or fo.get("outside_root")
            for fo in trace.file_opens
        )
        if hit:
            return True, "execution-confirmed: a file open resolved outside the expected root / matched the PoC path"
        if trace.exception:
            return False, f"{_NOTE_INCONCLUSIVE_TARGET_EXCEPTION}: {trace.exception}"
        return False, _NOTE_PATHTRAV_NO_TRIGGER
    if rule_id in ("TAINT-SSRF", "TAINT-CREDFWD"):
        host_hit = any(_MARKER_HOST in str(nc.get("host") or "") for nc in trace.network_connections) or any(
            _MARKER_HOST in str(hr.get("url") or "") + str(hr.get("host") or "") for hr in trace.http_requests
        )
        cred_hit = bool(trace.credential_flags)
        confirmed = host_hit or (rule_id == "TAINT-CREDFWD" and cred_hit)
        if confirmed:
            parts = []
            if host_hit:
                parts.append("an outbound request reached the attacker-controlled PoC host")
            if cred_hit:
                parts.append("a credential-shaped header/value was observed on an outbound request")
            return True, "execution-confirmed: " + ", ".join(parts)
        if trace.exception:
            return False, f"{_NOTE_INCONCLUSIVE_TARGET_EXCEPTION}: {trace.exception}"
        return False, _NOTE_SSRF_CREDFWD_NO_TRIGGER
    return False, f"no trace-interpretation rule for {rule_id!r}"


# Adversary-repo-read milestone: which real, sandbox-negative taint-shaped
# candidates get a second, repo-reading adversary look (see `hunt_fleet`'s
# own docstring/wiring below) -- ONLY PATHTRAV/SSRF/CREDFWD, per the task's
# own explicit scope, never CMDI (a distinct note string,
# "no subprocess call carried the injected PoC marker", deliberately not in
# this set) and never TAINT-IDOR (an absence-based class that never gets a
# real OracleTrace at all -- `isinstance(trace, OracleTrace)` below already
# excludes it, no separate rule_id check needed).
def _is_sandbox_negative_pathtrav_ssrf_credfwd(outcome) -> bool:
    """True iff `outcome` is a taint-shaped candidate whose Stage-5 sandbox
    genuinely RAN (no sandbox-level error) but did not trigger, for the
    PATHTRAV/SSRF/CREDFWD rule classes specifically -- Fable's own "ran, not
    triggered" routing condition for the repo-reading adversary path, as
    distinct from (a) a sandbox-level error (`trace.error` truthy --
    inconclusive, not a real negative result), (b) TAINT-IDOR's own
    absence-based class (no `OracleTrace` at all, see `_process_finding`'s
    own IDOR branch), and (c) TAINT-CMDI's own "ran, not triggered" case
    (deliberately excluded, per the task's own explicit CREDFWD/SSRF/PATHTRAV
    scope).

    Implemented by checking `outcome.card.oracle_trace` is a genuine
    `OracleTrace` (never a plain dict -- the "backward-compat" shape a
    hand-authored/back-filled ledger entry can carry, see `claim_card.py`'s
    own `_ORACLE_TRACE_REQUIRED_FIELDS` comment), that it carries no
    sandbox-level error, that the outcome's own verdict is `"unconfirmed"`
    (never `"confirmed"` -- a real trigger must never be re-routed here),
    and that its note contains one of the two shared "ran, no signal"
    constants `_interpret_trace` itself produces (see those constants' own
    comment for why they are shared, not duplicated, string literals).

    Sandbox-fix milestone: also excludes (d) `_interpret_trace`'s newer
    "target raised before reaching the sink" category
    (`_NOTE_INCONCLUSIVE_TARGET_EXCEPTION`, checked via
    `_is_inconclusive_target_exception_note` -- a target-level dependency/
    runtime failure, e.g. `ModuleNotFoundError`, recorded in `trace.exception`
    before the sink was ever reached) -- that is NOT a genuine sandbox
    negative (the target never got a real chance to run), so it must never
    reach the repo-reading adversary framed as "sandbox tried and failed".
    This check is defense in depth on top of the note text itself already
    being disjoint from the two "ran, no signal" constants below -- it stays
    correct even if a future edit ever made the wordings overlap."""
    card = outcome.card
    trace = card.oracle_trace if card is not None else None
    if not isinstance(trace, OracleTrace):
        return False
    if trace.error:
        return False
    if outcome.verdict != "unconfirmed":
        return False
    note = outcome.note or ""
    if _is_inconclusive_target_exception_note(note):
        return False
    return _NOTE_PATHTRAV_NO_TRIGGER in note or _NOTE_SSRF_CREDFWD_NO_TRIGGER in note


def _final_verdict(execution_confirmed: bool, llm_result) -> Verdict:
    if execution_confirmed:
        return "confirmed"
    if llm_result is not None:
        return llm_result.verdict
    return "unconfirmed"


# --------------------------------------------------------------------------
# ClaimCard construction -- minimal glue over threat_model.py's real S2
# output (declared_authority), not a reimplementation of it. threat_model.py
# itself has no ClaimCard-building logic; this is that glue.
# --------------------------------------------------------------------------


def _match_entrypoint_profile(tmd: ThreatModelDocument | None, finding: SourceFinding, source_step: dict | None) -> EntrypointProfile | None:
    if tmd is None or not tmd.entrypoints:
        return None
    target_file = source_step.get("file") if source_step else None
    if target_file:
        for ep in tmd.entrypoints:
            if ep.file.endswith(target_file) or target_file.endswith(ep.file):
                return ep
    rel = finding.location.rpartition(":")[0]
    for ep in tmd.entrypoints:
        if ep.file.endswith(rel) or rel.endswith(ep.file):
            return ep
    return None


def _authority_text(ep_profile: EntrypointProfile | None) -> str:
    if ep_profile is None:
        return (
            "no matching entrypoint profile found by S2 threat-model extraction (threat_model.py) -- "
            "authority is whatever any caller of this MCP tool is assumed to hold"
        )
    if ep_profile.declared_authority:
        c = ep_profile.declared_authority
        return f"{c.location}: {c.text!r} (S2 declared-authority claim nearest to {ep_profile.function_name}())"
    return (
        f"no declared safety/scope claim found within 25 lines of {ep_profile.function_name}() "
        f"({ep_profile.file}:{ep_profile.line}) by S2 threat-model extraction"
    )


def build_claim_card(
    finding: SourceFinding,
    tmd: ThreatModelDocument | None,
    *,
    oracle_trace: OracleTrace | None = None,
    impossibility_argument: str | None = None,
    enrich_with_exemplars: bool = False,
    exemplar_ledger_path: str | Path = DEFAULT_LEDGER_PATH,
    exemplar_k: int = 3,
    exemplar_index: ExemplarIndex | None = None,
) -> ClaimCard | None:
    """Build a `ClaimCard` for `finding`, enriched with threat_model.py's S2
    declared-authority context where a matching entrypoint profile exists.
    Exactly one of `oracle_trace`/`impossibility_argument` is expected
    (mirrors ClaimCard's own emit invariant); returns None only if neither
    was actually supplied (a caller bug, never expected in normal use).

    `enrich_with_exemplars` (default `False`, so `hunt()`'s existing default
    behavior and every existing caller/test is unaffected) is S7 retrieval's
    OPTIONAL hook: when set, this card's own `target_sink`/`violated_claim`
    text is used as a retrieval query (`retrieval.retrieve_exemplars`,
    confirmed/refuted-only by default -- see that module's own docstring on
    why) against `exemplar_ledger_path`, and the top `exemplar_k` results are
    attached as `retrieved_exemplars`. Best-effort: a retrieval failure
    (e.g. no ledger file yet) never prevents the card itself from being
    built -- matches this pipeline's own "auxiliary enrichment must never be
    fatal" discipline (see Stage 4 LLM verification's own try/except above).

    `exemplar_index`, if supplied, is a pre-built `retrieval.ExemplarIndex`
    (see `hunt()`'s own docstring) passed straight through to
    `retrieve_exemplars(index=...)` so a caller building many cards in one
    run (`hunt()`'s per-finding loop) doesn't re-read and re-tokenize the
    whole ledger for every single card."""
    taint_path = finding.taint_path or []
    source_step = next((s for s in taint_path if s.get("kind") == "source"), None)
    sink_step = next((s for s in reversed(taint_path) if s.get("kind") == "sink"), None)
    ep_profile = _match_entrypoint_profile(tmd, finding, source_step)

    target_sink = f"{finding.location} -- {finding.title}: {(sink_step or {}).get('code') or finding.evidence}"
    tainted_source_code = (source_step or {}).get("code") or finding.evidence
    tainted_source_note = f" -- {source_step['note']}" if source_step and source_step.get("note") else ""
    violated_claim = f"{finding.location}: {finding.title} -- {finding.description}"

    retrieved_exemplars: list[dict[str, Any]] | None = None
    if enrich_with_exemplars:
        try:
            result = retrieve_exemplars(
                f"{target_sink} {violated_claim}",
                k=exemplar_k,
                include_unconfirmed=False,
                ledger_path=exemplar_ledger_path,
                exclude_target_sink=target_sink,
                index=exemplar_index,
            )
            retrieved_exemplars = [e.to_dict() for e in result.exemplars] or None
        except Exception:  # noqa: BLE001 -- retrieval is best-effort context, never fatal to card construction
            retrieved_exemplars = None

    try:
        return ClaimCard(
            target_sink=target_sink,
            tainted_source=f"{tainted_source_code}{tainted_source_note}",
            caller_authority_assumed=_authority_text(ep_profile),
            precondition=finding.description,
            violated_claim=violated_claim,
            evidence_path=[Step(**s) for s in taint_path],
            oracle_trace=oracle_trace,
            impossibility_argument=impossibility_argument,
            retrieved_exemplars=retrieved_exemplars,
        )
    except ClaimCardValidationError:
        return None


# --------------------------------------------------------------------------
# Per-finding processing
# --------------------------------------------------------------------------


def _process_finding(
    finding: SourceFinding,
    root: Path,
    tmd: ThreatModelDocument | None,
    sandbox_timeout_seconds: int,
    run_llm_verification: bool,
    run_critic: bool = True,
    allow_unsafe_host_execution: bool = False,
    enrich_with_exemplars: bool = False,
    exemplar_ledger_path: str | Path = DEFAULT_LEDGER_PATH,
    exemplar_index: ExemplarIndex | None = None,
    cost_tracker: CostTracker | None = None,
) -> HuntFindingOutcome:
    if finding.rule_id == IDOR_RULE_ID:
        card = build_claim_card(finding, tmd, impossibility_argument=(
            "TAINT-IDOR is an absence-based finding class (no recognized authorization-check call found "
            "on the reconstructed path) -- deliberately excluded from Stage 5 sandbox testing: a generic "
            "dynamic oracle cannot confirm a MISSING authorization check without a real multi-tenant test "
            "harness (two distinct caller identities, one resource, an expected 403). This is a known, "
            "deliberate limitation stated in taint_scanner.py's own module docstring, not an oversight of "
            "this pipeline."
        ), enrich_with_exemplars=enrich_with_exemplars, exemplar_ledger_path=exemplar_ledger_path, exemplar_index=exemplar_index)
        return HuntFindingOutcome(finding, card, "unconfirmed", None, "TAINT-IDOR: sandbox stage skipped by design (absence-based)")

    if finding.rule_id not in SANDBOX_TESTABLE_RULE_IDS:
        card = build_claim_card(finding, tmd, impossibility_argument=(
            f"{finding.rule_id} is not one of this pipeline's sandbox-testable classes "
            f"({sorted(SANDBOX_TESTABLE_RULE_IDS)}) -- Stage 5 execution was not attempted for this finding."
        ), enrich_with_exemplars=enrich_with_exemplars, exemplar_ledger_path=exemplar_ledger_path, exemplar_index=exemplar_index)
        return HuntFindingOutcome(finding, card, "unconfirmed", None, f"{finding.rule_id}: not a sandbox-testable class")

    resolution = resolve_sandbox_entrypoint(finding, root)
    oracle_trace: OracleTrace | None = None
    execution_confirmed = False
    sandbox_note = resolution.error or ""

    if resolution.entrypoint is not None:
        try:
            oracle_trace = run_in_sandbox(
                root, resolution.entrypoint, resolution.args, timeout_seconds=sandbox_timeout_seconds,
                allow_unsafe_host_execution=allow_unsafe_host_execution,
            )
        except SandboxUnavailableError as exc:
            sandbox_note = str(exc)
        else:
            execution_confirmed, sandbox_note = _interpret_trace(finding.rule_id, oracle_trace)

    llm_result = None
    llm_note = "LLM verification skipped: no ANTHROPIC_API_KEY set"
    if run_llm_verification:
        if os.environ.get("ANTHROPIC_API_KEY"):
            try:
                llm_result = verify_with_agreement(AnthropicVerifier(cost_tracker=cost_tracker), finding, root)
                llm_note = f"Stage 4 LLM verification: {llm_result.verdict} (agreed={llm_result.agreed})"
            except Exception as exc:  # noqa: BLE001 -- Stage 4 is best-effort here; must never crash the hunt
                llm_note = f"Stage 4 LLM verification attempted but failed: {exc}"
        else:
            pass  # llm_note default above already says this honestly

    if oracle_trace is None:
        card = build_claim_card(finding, tmd, impossibility_argument=(
            f"Stage 5 sandbox execution could not be attempted: {sandbox_note} {llm_note}."
        ), enrich_with_exemplars=enrich_with_exemplars, exemplar_ledger_path=exemplar_ledger_path, exemplar_index=exemplar_index)
    else:
        card = build_claim_card(
            finding, tmd, oracle_trace=oracle_trace,
            enrich_with_exemplars=enrich_with_exemplars, exemplar_ledger_path=exemplar_ledger_path,
            exemplar_index=exemplar_index,
        )

    verdict = _final_verdict(execution_confirmed, llm_result)

    # S6 critic: runs on every "confirmed" survivor, after both Stage 4 and
    # Stage 5 above -- see critic.py's own module docstring for why this
    # gate is verdict=="confirmed" specifically (a refuted/unconfirmed
    # finding is not an accepted vulnerability, so recalibrating its
    # severity is moot) and for the real deepseek-pp false positive this
    # stage exists to catch.
    critic_note = ""
    if run_critic and verdict == "confirmed" and card is not None:
        critic_verifier: CriticVerifier | None = None
        if os.environ.get("ANTHROPIC_API_KEY"):
            try:
                critic_verifier = AnthropicCriticVerifier(cost_tracker=cost_tracker)
            except Exception:  # noqa: BLE001 -- the cross-tier LLM pass is best-effort, never fatal to the hunt
                critic_verifier = None
        critic_result = critique_finding(
            finding, card, oracle_trace, verdict, execution_confirmed, tmd,
            root=str(root), critic_verifier=critic_verifier,
        )
        verdict = critic_result.final_verdict
        critic_note = critic_result.note

    note = " | ".join(x for x in (sandbox_note, llm_note, critic_note) if x)
    return HuntFindingOutcome(finding, card, verdict, None, note)


# --------------------------------------------------------------------------
# Public entry point
# --------------------------------------------------------------------------


def hunt(
    repo_path: str | Path,
    *,
    ledger_path: str | Path = DEFAULT_LEDGER_PATH,
    include_low_confidence: bool = False,
    sandbox_timeout_seconds: int = 30,
    run_llm_verification: bool = True,
    run_critic: bool = True,
    use_threat_model_cache: bool = True,
    allow_unsafe_host_execution: bool = False,
    enrich_with_exemplars: bool = False,
    cost_tracker: CostTracker | None = None,
) -> HuntResult:
    """Run the real, end-to-end pipeline against one repo: Stage 0-3 taint
    scan -> per-finding ClaimCard (Stage 5 sandbox execution for the
    sandbox-testable classes, Stage 4 LLM verification if
    ANTHROPIC_API_KEY is set) -> S6 critic pass on every "confirmed"
    survivor (deterministic severity/reachability checks always, cross-tier
    LLM critic if ANTHROPIC_API_KEY is set -- see critic.py) -> append every
    resulting ClaimCard to the ledger. Never raises for an individual
    finding's own resolution/execution/verification/critique failure --
    every real failure is recorded as an honest note and/or
    `impossibility_argument`, not swallowed and not allowed to abort the
    rest of the run. `run_critic=False` disables the S6 pass entirely (e.g.
    for a caller that wants Stage 4/5's own raw verdicts unrecalibrated).

    `allow_unsafe_host_execution` (default `False`) is passed straight
    through to `run_in_sandbox()` (see `sandbox.py`): when Docker is
    unavailable, a Python Stage-5 entrypoint is refused
    (`SandboxUnavailableError`, recorded as an honest note, never a
    fabricated verdict) rather than silently executed on this host with no
    real isolation, unless this is explicitly set `True`.

    `enrich_with_exemplars` (default `False`) is S7 retrieval's OPTIONAL
    hook (see `build_claim_card`'s own docstring): when set, every
    `ClaimCard` built by this run queries `ledger_path` (the SAME ledger
    this run itself appends to, so later findings in one run can retrieve
    earlier ones as priors) for its top-3 confirmed/refuted exemplars before
    being written. Off by default so existing callers/tests see no change
    in behavior. The TF-IDF index this backs is built ONCE for the whole run
    (`retrieval.build_exemplar_index()`) and incrementally extended
    (`ExemplarIndex.add_entry()`) as each finding's own entry is appended,
    rather than every finding's own retrieval call re-reading and
    re-tokenizing the entire ledger from scratch -- this preserves the
    "later findings see earlier ones from this same run" behavior above
    exactly, it just avoids redoing the expensive read/tokenize step for
    ledger history that hasn't changed since the last finding.

    `cost_tracker` (cost-instrumentation milestone; default `None` -> this
    call builds its own fresh `CostTracker()`, so every existing caller/test
    sees no change in behavior) records real token/cost/wall-time data for
    this run's own taint scan, every Stage 4 `AnthropicVerifier` call, and
    every S6 critic `AnthropicCriticVerifier` call -- pulled straight off
    each real API response's own `usage` field, never estimated. Either way
    (caller-supplied or built here), the SAME tracker instance is returned
    on `HuntResult.cost_tracker` so a caller can read the aggregated report
    (`.report()`/`.to_dict()`) for this run."""
    root = Path(repo_path).resolve()
    commit = _resolve_commit(root)
    cost_tracker = cost_tracker or CostTracker()
    _t0 = time.monotonic()
    findings = run_static_taint_scan(root, include_low_confidence=include_low_confidence)
    cost_tracker.record("taint_scan", str(root), wall_seconds=time.monotonic() - _t0)

    try:
        tmd = build_threat_model(root, use_cache=use_threat_model_cache)
    except Exception:  # noqa: BLE001 -- S2 enrichment is best-effort context, never fatal to the hunt
        tmd = None

    exemplar_index: ExemplarIndex | None = None
    if enrich_with_exemplars:
        exemplar_index = build_exemplar_index(include_unconfirmed=False, ledger_path=ledger_path)

    outcomes: list[HuntFindingOutcome] = []
    for finding in findings:
        outcome = _process_finding(
            finding, root, tmd, sandbox_timeout_seconds, run_llm_verification, run_critic,
            allow_unsafe_host_execution=allow_unsafe_host_execution,
            enrich_with_exemplars=enrich_with_exemplars, exemplar_ledger_path=ledger_path,
            exemplar_index=exemplar_index, cost_tracker=cost_tracker,
        )
        if outcome.claim_card is not None:
            entry = append_entry(outcome.claim_card, outcome.verdict, commit, ledger_path=ledger_path, notes=outcome.note)
            outcome = HuntFindingOutcome(outcome.finding, outcome.claim_card, outcome.verdict, entry, outcome.note)
            if exemplar_index is not None:
                exemplar_index.add_entry(entry)
        outcomes.append(outcome)

    return HuntResult(
        repo_path=str(root), commit=commit, findings_scanned=len(findings), outcomes=outcomes,
        ledger_path=str(ledger_path), cost_tracker=cost_tracker,
    )


# Adversary-repo-read milestone: real, enforced per-target cap on how many
# sandbox-negative PATHTRAV/SSRF/CREDFWD taint-shaped candidates get routed
# through the (materially more expensive -- full files, not a 60-line
# excerpt, plus a one-hop call-graph read) `RepoReadingAdversary` path for
# ONE `hunt_fleet()` call. Picked at 8, the midpoint of the task's own
# suggested 5-10 range: real per-target counts of this exact candidate shape
# checked directly against this project's own prior forward-validation runs
# are small (low single digits per repo -- see
# bench/ADVERSARY_REPO_READ_STATUS.md for the real counts this was checked
# against, not assumed), so 8 gives real headroom above what any target has
# actually produced so far without being unbounded -- same "bounded, never
# unbounded" discipline as every other cap in this codebase
# (hunter.py's `_MAX_CRED_BLOCKS`/`_MAX_GROUPS_SHOWN`, critic.py's
# `_MAX_REVERSE_CALL_VISITS`). A candidate that would exceed the cap is left
# at its existing verdict/note with an honest note explaining the skip --
# never silently dropped, and never given a fabricated verdict.
_REPO_READING_ADVERSARY_PER_TARGET_CAP = 8

# Role-diverse-adversary milestone (NOT the adversary-repo-read milestone
# above -- see bench/ROLE_DIVERSE_ADVERSARY_STATUS.md). This SUPERSEDES the
# sibling candidate-widened-adversary-work clone's own design (still present,
# unmerged, in that sibling): its recommendation was "Pair, not single: keep
# `requires_agreement`, make both backends repo-reading" -- routing these
# same four angles through TWO independent `RepoReadingAdversary` instances,
# same prompt, same temperature-0, only a different model tier. Calibrated
# on the real 14-case ground-truth corpus, that pairing caught 0 of the
# errors it was meant to catch (bench/ROLE_DIVERSE_ADVERSARY_STATUS.md has
# the full comparison): both same-family, same-prompt reviewers converged on
# the identical wrong `confirmed` verdict for a claim (awslabs/mcp's IAM
# `NotPrincipal` case) whose correct refutation depends on AWS's own
# external policy-evaluation semantics -- something neither copy, however
# careful, could see by reading more of the repo, because it isn't IN the
# repo.
#
# Fable's fix (quoted, see adversary.py's own section comment for the full
# reasoning): "make the second member of the pair a different role, not a
# second copy. Adversary A stays the repo-reading refuter. Adversary B gets
# the lightweight (~5k char) prompt and one job: list the external
# assumptions the claimed impact depends on and say whether each is settled
# by the code shown; return 'unconfirmed' if any is not." As specified and
# calibrated (bench/ROLE_DIVERSE_ADVERSARY_STATUS.md), this fixed the
# awslabs/mcp safety failure completely but collapsed recall to 2/11 -- see
# the shared-evidence-residue milestone immediately below in adversary.py
# (bench/SHARED_EVIDENCE_RESIDUE_STATUS.md) for the two real, disjoint
# mechanisms that turned out to be responsible and the fix for each. Adversary
# B's actual prompt/backend described below is the CURRENT (shared-evidence
# -residue) design, not the lightweight/no-repo-access one Fable's quote above
# describes -- that quote is kept verbatim as the historical record of what
# was originally asked for and why role diversity (not model diversity) was
# the right axis; it is not a description of the code as it exists today.
#
# These angles' ClaimCards are routed through ONE `RepoReadingAdversary`
# (Adversary A, unchanged from the adversary-repo-read milestone) paired with
# ONE `ExternalAssumptionAdversary` (Adversary B, adversary.py's shared
# -evidence, residue-test role -- see that module's own shared-evidence
# -residue section comment for what it does today) via `run_adversary_check`'s
# existing two-backend path -- REPLACING the lightweight `adversary_backend`/
# `adversary_second_backend` gate for these angles entirely, not chaining
# the two: a candidate from one of these angles is never given to
# `adversary_backend`/`adversary_second_backend` at all. `claims-vs-
# enforcement` is deliberately excluded (stays on the pre-existing
# lightweight `adversary_backend`/`adversary_second_backend` pair, completely
# unchanged) -- same reason Fable originally gave for excluding it from the
# repo-reading path (it can cite an entire README with only `wrap_untrusted`
# as a defense), unaffected by this milestone.
#
# Transport-angle milestone: `transport-and-exposure` (the 7th hunter
# angle, hunter.py) is added here too, alongside the original four. Same
# reasoning Fable gave for the original four applies without modification:
# this angle's own citations are real, specific repo file:line locations
# (a bind/listen call site, a middleware registration, that middleware's
# own in-repo definition when found) -- exactly the kind of candidate a
# repo-reading adversary can actually check against the real surrounding
# code, unlike claims-vs-enforcement's own README-quoting shape. The one
# thing checked directly before adding it here (not assumed): `adversary.
# _reverse_hop_reachability_note` -- the one place `RepoReadingAdversary`'s
# own prompt reads anything entrypoint-shaped -- is gated on `isinstance(
# claim_card.oracle_trace, OracleTrace)`, which is never true for ANY
# LLM-angle card (see hunter.py's `parse_hunt_response`: every LLM-angle
# card carries an `impossibility_argument`, never a real `OracleTrace`), so
# a transport-and-exposure candidate -- which by design has no recovered
# entrypoint anywhere near it -- gets the same honest "not applicable, no
# real Stage-5 OracleTrace" note every other LLM angle's candidate already
# gets, never a false "unreachable from any entrypoint" penalty for citing
# code that was never supposed to be reachable from a tool handler in the
# first place.
_REPO_READING_ADVERSARY_ANGLES = frozenset({
    "credential-and-secrets",
    "cross-file-authority",
    "whole-handler-audit",
    "scope-selector-override",
    "transport-and-exposure",
})


def hunt_fleet(
    repo_path: str | Path,
    *,
    ledger_path: str | Path = DEFAULT_LEDGER_PATH,
    run_sandbox: bool = True,
    sandbox_timeout_seconds: int = 30,
    allow_unsafe_host_execution: bool = False,
    include_low_confidence: bool = False,
    enrich_with_exemplars: bool = False,
    adversary_backend: AdversaryBackend | None = None,
    adversary_second_backend: AdversaryBackend | None = None,
    repo_reading_adversary_backend: AdversaryBackend | None = None,
    role_diverse_adversary_backend: AdversaryBackend | None = None,
    cost_tracker: CostTracker | None = None,
):
    """S3 (fleet mode): dispatch ALL SEVEN hunter angles (`hunter.py`) against
    one repo, not just the deterministic taint-shaped engine `hunt()` above
    runs. Purely additive -- `hunt()` itself is untouched, so its existing
    behavior (and the tests that pin it) is unaffected either way.

    Every resulting `ClaimCard` (from any angle) is appended to the ledger
    with the REAL verdict `hunter.run_hunter_fleet()` computed for it
    (`FleetHuntResult.card_verdicts`, `hunter.HuntCardOutcome`) -- for the
    taint-shaped angle this is exactly what `_process_finding()` above would
    have produced for the same finding via the non-fleet `hunt()` pipeline:
    Stage 5 sandbox execution, THEN the S6 critic pass, which can
    recalibrate an execution-"confirmed" finding back down to
    `"unconfirmed"` (flagged `TAUTOLOGY_RISK`) when the sink it exercised
    isn't actually reachable from a genuine external MCP entrypoint -- see
    `critic.py`'s own module docstring for the real deepseek-pp false
    positive this closes. This never happened before: this function used to
    recompute its own approximate verdict from `isinstance(card.oracle_trace,
    OracleTrace)` alone, which ignored the critic entirely. The 5 non-taint
    angles have no dynamically-executable oracle at all (their cards always
    carry an `impossibility_argument`), so they are always recorded
    `"unconfirmed"`, never a fabricated `"confirmed"`. If `ANTHROPIC_API_KEY`
    is not set, the 5 non-taint angles are honestly recorded as not-run (see
    `hunter.run_hunter_fleet`'s own docstring) rather than silently skipped.
    A real failure on any one angle (e.g. an Anthropic API error) is
    isolated by `hunter._dispatch_angle` and recorded in
    `result.errors[angle]` -- it never loses another angle's already
    -computed findings.

    `enrich_with_exemplars` (default `False`) is S7 retrieval's OPTIONAL
    hook for the 5 LLM angles' own prompts (see `hunter.build_hunter_prompt`'s
    own docstring) -- mirrors `hunt()`'s own `enrich_with_exemplars` flag
    exactly (same name, same off-by-default). When set, each LLM angle's
    prompt is enriched with confirmed/refuted exemplars retrieved from this
    same `ledger_path` -- the ledger this run itself appends to, same as
    `hunt()`'s own behavior.

    `allow_unsafe_host_execution` (default `False`) mirrors `hunt()`'s own
    flag of the same name: passed through to `TaintShapedHunter`'s own
    Stage-5 sandbox call, it must be explicitly `True` for a Docker
    -unavailable Python entrypoint to run on this host with no real
    isolation; otherwise that entrypoint's Stage-5 execution is refused
    rather than silently run unsandboxed.

    `adversary_backend`/`adversary_second_backend` (both default `None`) are
    the LIGHTWEIGHT adversary GATE (`adversary.py`'s `run_adversary_check`
    paired with `build_adversary_prompt`, the bare-`ClaimCard` prompt with no
    repo access): as of the role-diverse-adversary milestone (see
    `bench/ROLE_DIVERSE_ADVERSARY_STATUS.md`) this is used for exactly ONE
    of the seven angles, `claims-vs-enforcement` -- the other five LLM angles
    now use the repo-reading-plus-role-diverse pair below instead (see
    `_REPO_READING_ADVERSARY_ANGLES`'s own comment for Fable's exact
    reasoning: claims-vs-enforcement is the one angle whose citations can be
    an entire README with only `wrap_untrusted()` as a defense, so it is
    deliberately held back rather than routed through either adversary path
    changed by that milestone). `"taint-shaped"` outcomes are never routed
    through either adversary gate here -- they already went through Stage 5
    execution and the S6 critic (see `TaintShapedHunter.hunt_with_verdicts`),
    a materially different (execution-based, not adversarial-re-derivation
    -based) kind of check. If neither backend is supplied and
    `ANTHROPIC_API_KEY` is set, this function builds its own default pair --
    two `AnthropicAdversary` instances at different model tiers (mirrors
    `AnthropicCriticVerifier`'s own "cross-family in practice means
    cross-model-tier within Claude" precedent, `critic.py`) -- so a real
    two-independent-adversary agreement check runs automatically once a key
    exists, same "no key, no LLM stage, say so" graceful-skip discipline as
    every other stage in this pipeline when neither backend is supplied and
    no key is set. A caller injecting its own backend(s) (e.g.
    `adversary.ManualRecordAdversary` for a recorded/offline run, or a test
    double) fully owns that choice, same as `llm_hunter` above.

    `repo_reading_adversary_backend` (default `None`) is Fable's own
    recommended repo-reading adversary path (`adversary.RepoReadingAdversary`
    -- Adversary A), used for TWO materially different kinds of candidate,
    both real, cross-referenced with the outcome's own `angle` to tell them
    apart -- never confused with each other:

    1. (adversary-repo-read milestone, unchanged by this or the widened
       -adversary milestone -- see that milestone's own status doc,
       `bench/ADVERSARY_REPO_READ_STATUS.md`) a `"taint-shaped"` outcome
       whose Stage-5 sandbox genuinely RAN but did not trigger, for the
       PATHTRAV/SSRF/CREDFWD rule classes specifically
       (`_is_sandbox_negative_pathtrav_ssrf_credfwd` above -- never a
       sandbox-level error, never TAINT-IDOR's own absence-based class,
       never CMDI), gets ONE more look (single backend,
       `repo_reading_adversary_backend` only -- `run_adversary_check`'s own
       single-adversary path, `second_backend=None`) from an adversary that
       reads the FULL content of every file its evidence cites plus one real
       call-graph hop out. Real, enforced per-target cap:
       `_REPO_READING_ADVERSARY_PER_TARGET_CAP` dispatches per `hunt_fleet()`
       call, shared across BOTH uses below (see that constant's own comment
       for why 8) -- this candidate class is the one the cap was sized
       against.
    2. (role-diverse-adversary milestone; transport-angle milestone added
       the 5th member) an outcome from one of the five
       `_REPO_READING_ADVERSARY_ANGLES` (`credential-and-secrets`,
       `cross-file-authority`, `whole-handler-audit`,
       `scope-selector-override`, `transport-and-exposure`) that is still `"unconfirmed"` after
       `hunter.py`'s own pass, run through `repo_reading_adversary_backend`
       (Adversary A, the repo-reading refuter) PAIRED WITH
       `role_diverse_adversary_backend` (Adversary B, `adversary.
       ExternalAssumptionAdversary` -- a different ROLE, not a second copy:
       shared-evidence-residue milestone -- sees the SAME shared repo
       -evidence block Adversary A does (`adversary.
       build_shared_repo_evidence_block`, no longer "no repo access"), and
       is asked to strip every external-system assumption from the claim,
       name what it stripped, and verdict on whatever residual claim
       remains -- see `adversary.py`'s own shared-evidence-residue section
       comment) via `run_adversary_check`'s existing two-backend path,
       REPLACING the lightweight gate for these four angles entirely (a
       candidate from one of these angles is never given to
       `adversary_backend`/`adversary_second_backend` at all). Uncapped by
       `_REPO_READING_ADVERSARY_PER_TARGET_CAP` -- that cap was sized for
       case 1's own real per-target counts (low single digits), which say
       nothing about how many `"unconfirmed"` LLM-angle candidates a real
       target produces; see `bench/ROLE_DIVERSE_ADVERSARY_STATUS.md` and
       `bench/SHARED_EVIDENCE_RESIDUE_STATUS.md` for the real, measured
       recalibration numbers each milestone produced, not an estimate.

    Both backends are lazily constructed together, ONCE, the first time
    either case above actually needs one (`_ensure_repo_reading_backends`
    below) -- not eagerly at the top of `hunt_fleet()`, and not twice:
    whichever case is encountered first in the per-angle loop builds both,
    so case 2 never pays to construct its own `RepoReadingAdversary` client
    if case 1 already built one (and vice versa) in the same run. If not
    supplied and `ANTHROPIC_API_KEY` is set, the default pair is one
    `RepoReadingAdversary` (Adversary A, bound to THIS run's own
    `repo_path`) and one `ExternalAssumptionAdversary` (Adversary B) --
    deliberately NOT two `RepoReadingAdversary` instances at different model
    tiers the way the lightweight pair's own default is (that was this
    milestone's predecessor design, and it is exactly what
    `bench/ROLE_DIVERSE_ADVERSARY_STATUS.md` found does not work for this
    specific failure class -- see `adversary.py`'s own section comment for
    Fable's full reasoning on why role diversity, not model diversity, is
    the fix). Same "no key, no LLM stage, say so" graceful-skip discipline
    as every other stage: with no key and no injected backend, both cases
    are left at their existing verdict/note with an honest skip note, never
    a fabricated one.

    A "confirmed" verdict from either use of this path is mapped by
    `run_adversary_check`'s own, PRE-EXISTING `_ADVERSARY_VERDICT_TO_LEDGER_
    TIER` to the `"adversary-reviewed"` tier -- NEVER plain `"confirmed"`
    (Fable's own risk (b) from the adversary-repo-read milestone, still true
    here: case 1's sandbox already tried and failed to trigger the finding,
    and case 2's candidate has no execution evidence at all -- neither is
    ever silently upgraded to a stronger tier than the evidence supports).
    For case 1, the original sandbox-negative note text stays in the final
    note (`f"{outcome.note} | ..."` -- appended, never replaced).

    Every `HuntCardOutcome` this function reads from `result.card_verdicts`
    is a plain mutable dataclass shared by reference with the `result` this
    function returns -- when the adversary gate changes an outcome's verdict/
    note, that mutation is applied to the SAME object before both the ledger
    write and the return, so a caller reading the returned `FleetHuntResult`
    (e.g. `cli.py`'s `--mode fleet` display, or `result.verdict_counts()`)
    sees the real post-adversary-gate verdict, never a stale pre-gate one
    that only the ledger file itself would have reflected.

    Adversary-severity milestone: when the adversary gate promotes an
    outcome to `"adversary-reviewed"`, `outcome.card.severity`/`.cwe` are
    also populated from the adversary's own real severity/CWE judgment
    (`ClaimCard`'s own new fields -- see `claim_card.py`) -- never for a
    refuted/unconfirmed outcome, and never invented here: `run_adversary_check`
    itself decides the value, already capped per its own docstring's
    "can only lower or match" discipline, this function only copies it onto
    the same shared card object.

    `cost_tracker` (cost-instrumentation milestone; default `None` -> this
    call builds its own fresh `CostTracker()`) is baked into this run's own
    `TaintShapedHunter` (taint scan wall-time + Stage 4/S6 critic calls, if
    any), the default `AnthropicHunter` this function builds when no
    `ANTHROPIC_API_KEY`-gated `llm_hunter` override exists, and the default
    `AnthropicAdversary` pair below -- so it accumulates real token/cost/
    wall-time data across every angle dispatch and the adversary gate, same
    single shared tracker `hunt()` returns on its own `HuntResult`. Attached
    to the returned `FleetHuntResult.cost_tracker` either way (caller
    -supplied or built here)."""
    from .hunter import AnthropicHunter, TaintShapedHunter, run_hunter_fleet

    root = Path(repo_path).resolve()
    commit = _resolve_commit(root)
    cost_tracker = cost_tracker or CostTracker()
    taint_hunter = TaintShapedHunter(
        include_low_confidence=include_low_confidence,
        run_sandbox=run_sandbox,
        sandbox_timeout_seconds=sandbox_timeout_seconds,
        allow_unsafe_host_execution=allow_unsafe_host_execution,
        cost_tracker=cost_tracker,
    )
    llm_hunter = (
        AnthropicHunter(enrich_with_exemplars=enrich_with_exemplars, exemplar_ledger_path=ledger_path, cost_tracker=cost_tracker)
        if os.environ.get("ANTHROPIC_API_KEY")
        else None
    )
    result = run_hunter_fleet(
        root, taint_hunter=taint_hunter, llm_hunter=llm_hunter,
        enrich_with_exemplars=enrich_with_exemplars, exemplar_ledger_path=ledger_path,
    )
    result.cost_tracker = cost_tracker

    if adversary_backend is None and os.environ.get("ANTHROPIC_API_KEY"):
        adversary_backend = AnthropicAdversary(cost_tracker=cost_tracker)
        if adversary_second_backend is None:
            adversary_second_backend = AnthropicAdversary(model="claude-opus-5", cost_tracker=cost_tracker)

    # Adversary-repo-read / role-diverse-adversary milestones: Adversary A
    # and Adversary B are deliberately NOT built by default the way
    # `adversary_backend` above is -- they are only ever needed when this
    # run's own outcomes actually contain a candidate for one of the two
    # real repo-reading-path uses (checked below, per-outcome), so BOTH are
    # built lazily, together, the first time EITHER use actually needs one
    # -- never twice, and never eagerly for a run that needs neither.
    _repo_reading_backends_built = (
        repo_reading_adversary_backend is not None or role_diverse_adversary_backend is not None
    )

    def _ensure_repo_reading_backends() -> None:
        nonlocal repo_reading_adversary_backend, role_diverse_adversary_backend, _repo_reading_backends_built
        if _repo_reading_backends_built:
            return
        if os.environ.get("ANTHROPIC_API_KEY"):
            if repo_reading_adversary_backend is None:
                repo_reading_adversary_backend = RepoReadingAdversary(repo_root=root, cost_tracker=cost_tracker)
            if role_diverse_adversary_backend is None:
                # Role-diverse-adversary milestone: Adversary B is a
                # DIFFERENT role, not a second `RepoReadingAdversary` at
                # another model tier -- see this function's own docstring
                # and adversary.py's section comment for why. Shared
                # -evidence-residue milestone: B now takes THIS run's own
                # `repo_root` too (like Adversary A) so it computes the
                # exact same shared evidence block A does, instead of no
                # repo access at all -- see adversary.py's own
                # shared-evidence-residue section comment.
                role_diverse_adversary_backend = ExternalAssumptionAdversary(repo_root=root, cost_tracker=cost_tracker)
        _repo_reading_backends_built = True

    repo_reading_routed = 0

    for angle, outcomes in result.card_verdicts.items():
        for outcome in outcomes:
            if angle == "claims-vs-enforcement" and outcome.verdict == "unconfirmed":
                # The one LLM angle deliberately held back on the
                # lightweight, bare-ClaimCard gate -- see
                # `_REPO_READING_ADVERSARY_ANGLES`'s own comment for why.
                adversary_result = run_adversary_check(outcome.card, adversary_backend, adversary_second_backend)
                outcome.verdict = adversary_result.verdict
                outcome.note = f"{outcome.note} | {adversary_result.note}"
                # Adversary-severity milestone: `run_adversary_check` only
                # ever sets `severity`/`cwe` when the outcome actually
                # reached the "adversary-reviewed" tier (see its own
                # docstring) -- copy them onto the SAME card object the
                # ledger write and the returned FleetHuntResult both read,
                # same mutation-by-reference discipline this function's own
                # docstring already documents for verdict/note above.
                if adversary_result.severity is not None:
                    outcome.card.severity = adversary_result.severity
                    outcome.card.cwe = adversary_result.cwe
            elif angle in _REPO_READING_ADVERSARY_ANGLES and outcome.verdict == "unconfirmed":
                # Role-diverse-adversary milestone (Fable's own
                # recommendation, quoted at `_REPO_READING_ADVERSARY_ANGLES`):
                # these five LLM angles are routed through Adversary A
                # (repo-reading refuter) PAIRED WITH Adversary B (role
                # -diverse external-assumption reviewer), REPLACING the
                # lightweight gate for them entirely -- never given to
                # `adversary_backend`/`adversary_second_backend` at all.
                # Deliberately uncapped by `_REPO_READING_ADVERSARY_PER_TARGET_CAP`
                # (that cap was sized for the taint-shaped case below's own
                # real per-target counts, a different candidate population --
                # see this function's own docstring and
                # bench/ROLE_DIVERSE_ADVERSARY_STATUS.md for the real,
                # measured volume/cost this produces).
                _ensure_repo_reading_backends()
                adversary_result = run_adversary_check(
                    outcome.card, repo_reading_adversary_backend, role_diverse_adversary_backend,
                )
                outcome.verdict = adversary_result.verdict
                outcome.note = f"{outcome.note} | {adversary_result.note}"
                if adversary_result.severity is not None:
                    outcome.card.severity = adversary_result.severity
                    outcome.card.cwe = adversary_result.cwe
                # Shared-evidence-residue milestone: `impact_basis` is copied
                # onto the same shared card object whenever the two-backend
                # path actually ran, regardless of the final tier -- unlike
                # severity/cwe, it is not gated on "adversary-reviewed" (see
                # `AdversaryCheckResult.impact_basis`'s own docstring for
                # why: the residue test must be inspectable even on an
                # `unconfirmed` outcome).
                if adversary_result.impact_basis is not None:
                    outcome.card.impact_basis = adversary_result.impact_basis
            elif angle == "taint-shaped" and _is_sandbox_negative_pathtrav_ssrf_credfwd(outcome):
                # Adversary-repo-read milestone (Fable's own recommendation),
                # UNCHANGED by the candidate-widened-adversary milestone or
                # this role-diverse-adversary milestone: a taint-shaped
                # candidate whose Stage-5 sandbox genuinely RAN
                # but did not trigger, for the PATHTRAV/SSRF/CREDFWD classes
                # specifically, gets ONE more, single-backend, repo-reading
                # look before being left at "unconfirmed" -- still real,
                # enforced per-target cap (`_REPO_READING_ADVERSARY_PER_TARGET_CAP`),
                # still single- not paired-backend (see `RepoReadingAdversary`'s
                # own docstring for why this specific use stays single).
                _ensure_repo_reading_backends()
                if repo_reading_adversary_backend is None:
                    outcome.note = f"{outcome.note} | repo-reading adversary check skipped, no backend configured"
                elif repo_reading_routed >= _REPO_READING_ADVERSARY_PER_TARGET_CAP:
                    outcome.note = (
                        f"{outcome.note} | repo-reading adversary check skipped: this target's own "
                        f"per-target cap of {_REPO_READING_ADVERSARY_PER_TARGET_CAP} repo-reading-adversary "
                        "dispatches was already reached by other sandbox-negative candidates in this same run"
                    )
                else:
                    repo_reading_routed += 1
                    adversary_result = run_adversary_check(outcome.card, repo_reading_adversary_backend, None)
                    # `run_adversary_check`'s own `_ADVERSARY_VERDICT_TO_LEDGER_TIER`
                    # already maps a "confirmed" adversary opinion to the
                    # distinct `"adversary-reviewed"` tier, never plain
                    # `"confirmed"` -- Fable's own risk (b), satisfied by
                    # reuse, not by a second mapping here. `outcome.note`'s
                    # own `f"{outcome.note} | ..."` join (below) PRESERVES the
                    # original sandbox-negative note text
                    # (`_NOTE_PATHTRAV_NO_TRIGGER`/`_NOTE_SSRF_CREDFWD_NO_TRIGGER`)
                    # rather than replacing it -- the sandbox-already-tried
                    # -and-failed fact stays visible in the final note even
                    # when the repo-reading adversary goes on to confirm the
                    # claim by a different route (a real repo-wide read, not
                    # execution).
                    outcome.verdict = adversary_result.verdict
                    outcome.note = f"{outcome.note} | {adversary_result.note}"
                    if adversary_result.severity is not None:
                        outcome.card.severity = adversary_result.severity
                        outcome.card.cwe = adversary_result.cwe
            append_entry(
                outcome.card, outcome.verdict, commit,
                ledger_path=ledger_path, notes=f"hunter-fleet angle={angle} | {outcome.note}",
            )
    return result
