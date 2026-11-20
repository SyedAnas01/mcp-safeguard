"""Claim Card data model (fleet design's own S3 artifact).

From `mcp-safeguard-agent-fleet-design-2026-09-05`'s S3 stage: "hunter fleet,
one non-overlapping angle per hunter, output as structured 'Claim Cards'
(target sink, tainted source, precondition, violated claim + file:line,
oracle trace or explicit impossibility argument -- cards with neither are
dropped before they're even emitted)".

This module is pure data model plus validation -- nothing here calls an
LLM or runs any code. A future live hunter agent constructs a `ClaimCard`
from its own findings; this module enforces, in real code rather than in a
comment, the same rule a human reviewer would enforce by hand: "did you
actually run something to confirm this, or can you argue in writing why you
couldn't" -- before the card is ever accepted, serialized, handed to the
adversary stage (`adversary.py`), or written to the evidence ledger
(`ledger.py`).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, TypedDict

from .prompt_injection import Severity
from .sandbox import OracleTrace
from .taint_scanner import Step
from .verify import Verdict

# The exact shape `retrieval.Exemplar.to_dict()` produces and
# `ClaimCard.retrieved_exemplars` stores below -- a single source of truth so
# the two modules' independent field lists cannot silently drift apart.
# Defined here (not in retrieval.py) because retrieval.py already imports
# from this module (`from .claim_card import ClaimCard`) via `ledger.py`
# (which itself imports `.claim_card`) -- the reverse direction (this module
# importing `retrieval.py`) would be a circular import; see
# `retrieved_exemplars`'s own field comment below for the same reasoning
# applied to `Exemplar` itself.
class ExemplarDict(TypedDict):
    verdict: Verdict
    score: float
    target_sink: str
    violated_claim: str
    precondition: str
    commit: str
    evidence_ref: str | None
    notes: str | None

# A raw oracle_trace dict is reconstructed as a real OracleTrace only when it
# carries all three of OracleTrace's own non-defaulted fields -- a real
# `run_in_sandbox()` result always has them, so their presence is a genuine
# signal, not a coincidence. A dict missing any of these is a free-form,
# hand-written/back-filled trace (the ledger's own pre-Stage-5 entries and
# `mcp-safeguard ledger add`'s manual-entry flow both produce exactly this
# shape) and is kept as a plain dict rather than forced through
# `OracleTrace.from_dict` (which would raise on the missing required fields).
_ORACLE_TRACE_REQUIRED_FIELDS = frozenset({"sandbox_kind", "runtime", "entrypoint"})

# Every free-text field below ultimately traces back to a scanned target's
# own README/SECURITY.md prose or source comments (via threat_model.py's
# claim extraction and hunter.py's evidence-gathering), echoed through a
# hunter's own free-text answer -- there was previously no length cap
# anywhere on this path, so a single huge injected comment/README sentence
# could grow one of these fields (and, via ledger.py's `append_entry`, the
# ledger's own `notes` field and retrieval.py's exemplar bank it feeds)
# without bound. Capped here, once, at construction time -- the one place
# every ClaimCard is guaranteed to pass through regardless of which caller
# (AnthropicHunter, ManualRecordHunter, a hand-authored entry, ...) built it.
MAX_UNTRUSTED_FIELD_CHARS = 4000
_TRUNCATED_SUFFIX = f"... [truncated: exceeded the {MAX_UNTRUSTED_FIELD_CHARS}-char safety cap]"


def cap_untrusted_text(text: str) -> str:
    """Truncate `text` to `MAX_UNTRUSTED_FIELD_CHARS`, appending a visible
    marker so truncation is never silent. Shared by `ClaimCard`'s own
    `__post_init__` below and `ledger.py`'s `append_entry` (the `notes`
    field), so the one cap applies consistently on both sides of a ledger
    write."""
    if len(text) <= MAX_UNTRUSTED_FIELD_CHARS:
        return text
    return text[:MAX_UNTRUSTED_FIELD_CHARS] + _TRUNCATED_SUFFIX


class ClaimCardValidationError(ValueError):
    """Raised when a ClaimCard violates the design's own emit invariant:
    neither an `oracle_trace` nor an `impossibility_argument` is present."""


@dataclass
class ClaimCard:
    """One hunter agent's structured claim about one specific finding.

    `violated_claim` is expected to carry its own "file:line" citation
    inline (the same convention `SafetyClaim.location` uses in
    `threat_model.py`) -- e.g. `"README.md:51 claims 'read-only mode', but
    this handler has no read-only check"` -- so a card is self-contained
    evidence, not something that needs a second lookup to make sense of.

    `evidence_path` reuses `taint_scanner.py`'s own `Step` dataclass
    verbatim (not a re-invented shape) -- the same reconstructed
    source/assign/call/sink path Stage 3 and Stage 4 (`verify.py`) already
    use.
    """

    target_sink: str
    tainted_source: str
    caller_authority_assumed: str
    precondition: str
    violated_claim: str
    evidence_path: list[Step] = field(default_factory=list)
    # A real Stage-5 execution result (`sandbox.py`'s `run_in_sandbox()`) is
    # an `OracleTrace`; a manually-authored/back-filled ledger entry (this
    # project's own pre-Stage-5 ledger data, and `mcp-safeguard ledger add`'s
    # free-form manual-entry flow) is a plain dict -- both are real evidence
    # a human/agent actually produced, so both remain valid here. See
    # `_ORACLE_TRACE_REQUIRED_FIELDS` above for how `from_dict` tells them apart.
    oracle_trace: OracleTrace | dict[str, Any] | None = None
    impossibility_argument: str | None = None
    # S7 retrieval (`retrieval.py`) enrichment: the top-k ledger priors most
    # lexically similar to this card's own mechanism, as plain dicts shaped
    # like `ExemplarDict` above (each produced by `retrieval.Exemplar.to_dict()`)
    # rather than an imported `Exemplar` type -- `retrieval.py` itself imports
    # `ledger.py`, which imports this module, so importing `retrieval.Exemplar`
    # back here would be a circular import; `ExemplarDict` is the shared,
    # drift-proof shape both modules reference instead. Genuinely optional and
    # `None` by default: every ledger entry written before this field existed
    # still reads back unchanged via `from_dict`'s `.get()` below, and nothing
    # that only reads `target_sink`/`tainted_source`/etc. is affected by its
    # presence or absence. Populated only when a caller (e.g. `pipeline.py`'s
    # optional `enrich_with_exemplars` flag) explicitly asks for it -- never
    # computed as a side effect of plain construction.
    retrieved_exemplars: list[ExemplarDict] | None = None
    # Adversary-severity milestone: `None` by default -- every ClaimCard
    # written before this field existed still round-trips unchanged via
    # `from_dict`'s `.get()` below. `adversary.py`'s `run_adversary_check`
    # populates these two fields on an "adversary-reviewed" outcome (see
    # `pipeline.hunt_fleet`) from the adversary's OWN structured severity/CWE
    # judgment (`build_adversary_prompt`'s "Your task" section now asks for
    # one), never invented here -- and never by plain construction of a card
    # with no adversary/critic pass. `severity` uses the same CVSS-aligned
    # `Severity` ladder `critic.py`'s `recalibrate_severity()` already
    # applies to execution-confirmed findings; `cwe` is a short free-text CWE
    # id (e.g. `"CWE-863"`) or `None` when no CWE applies -- capped the same
    # as every other untrusted-adjacent free-text field below.
    severity: Severity | None = None
    cwe: str | None = None
    # Shared-evidence-residue milestone: `None` by default -- every ClaimCard
    # written before this field existed (all 349 existing real ledger
    # entries included) still round-trips unchanged via `from_dict`'s
    # `.get()` below. Populated only by `adversary.py`'s `run_adversary_check`
    # from Adversary B's (`ExternalAssumptionAdversary`) own residue-test
    # answer -- `"in-repo"` (nothing load-bearing was stripped) or
    # `"external:<system>: <step>"` (a real, load-bearing external-system
    # assumption was stripped) -- never invented here, and never for a card
    # no adversary B ever reviewed. This is an ADDITIVE field: no existing
    # verdict, tier, or ledger schema requirement changes because of it.
    impact_basis: str | None = None

    def __post_init__(self) -> None:
        self.target_sink = cap_untrusted_text(self.target_sink)
        self.tainted_source = cap_untrusted_text(self.tainted_source)
        self.caller_authority_assumed = cap_untrusted_text(self.caller_authority_assumed)
        self.precondition = cap_untrusted_text(self.precondition)
        self.violated_claim = cap_untrusted_text(self.violated_claim)
        if self.impossibility_argument is not None:
            self.impossibility_argument = cap_untrusted_text(self.impossibility_argument)
        if self.cwe is not None:
            self.cwe = cap_untrusted_text(self.cwe)
        if self.impact_basis is not None:
            self.impact_basis = cap_untrusted_text(self.impact_basis)
        self.validate()

    def validate(self) -> None:
        """Enforce the design's own drop rule as a real invariant: a card
        with neither a real oracle trace (something was actually executed
        or reproduced against a running instance) nor an explicit, written
        argument for why execution isn't possible for this class of
        finding is incomplete, and must never exist as a `ClaimCard`
        object -- not "should be treated as low-confidence", an actual
        `ClaimCardValidationError`."""
        if not self.oracle_trace and not self.impossibility_argument:
            raise ClaimCardValidationError(
                "ClaimCard has neither oracle_trace nor impossibility_argument -- per "
                "the fleet design's own S3 rule ('cards with neither are dropped before "
                "they're even emitted'), this card must not be constructed. Provide a "
                "real oracle_trace (from S5's execution gate) or a written "
                "impossibility_argument before creating this card."
            )

    @classmethod
    def try_create(cls, **kwargs: Any) -> ClaimCard | None:
        """Same construction as `ClaimCard(**kwargs)`, but returns `None`
        instead of raising when the emit invariant is violated -- lets a
        hunter loop literally "drop" an incomplete candidate
        (`card = ClaimCard.try_create(...); if card is None: continue`)
        rather than needing its own try/except around every candidate."""
        try:
            return cls(**kwargs)
        except ClaimCardValidationError:
            return None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ClaimCard:
        raw_trace = data.get("oracle_trace")
        if isinstance(raw_trace, dict) and _ORACLE_TRACE_REQUIRED_FIELDS <= raw_trace.keys():
            oracle_trace: OracleTrace | dict[str, Any] | None = OracleTrace.from_dict(raw_trace)
        else:
            oracle_trace = raw_trace
        return cls(
            target_sink=data["target_sink"],
            tainted_source=data["tainted_source"],
            caller_authority_assumed=data["caller_authority_assumed"],
            precondition=data["precondition"],
            violated_claim=data["violated_claim"],
            evidence_path=[Step(**s) for s in data.get("evidence_path", [])],
            oracle_trace=oracle_trace,
            impossibility_argument=data.get("impossibility_argument"),
            retrieved_exemplars=data.get("retrieved_exemplars"),
            severity=Severity(data["severity"]) if data.get("severity") else None,
            cwe=data.get("cwe"),
            impact_basis=data.get("impact_basis"),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, text: str) -> ClaimCard:
        return cls.from_dict(json.loads(text))
