"""S7 (fleet design): the append-only evidence ledger.

From `mcp-safeguard-agent-fleet-design-2026-09-05`: "an append-only evidence
ledger (every finding AND every refutation, with commit digest and eventual
GHSA/CVE/maintainer-confirmation reference -- this ledger is simultaneously
the disclosure record, the RAG exemplar bank, and the registry-receipt
feed)" and, from the conservative companion design: "Refuted candidates are
kept and auditable, not deleted -- a refutation you'd have made differently
is only a check if you can see it."

This module is a real, working, dependency-free JSON-lines file store --
one `LedgerEntry` (a `ClaimCard` + its final verdict + timestamp + commit +
an optional evidence_ref) per line, opened in append mode and never
rewritten. `append_entry` is deliberately the ONLY way to add to the file;
there is no `update_entry`/`delete_entry` in this module, on purpose --
"append-only" is enforced by what functions exist, not by a comment saying
so.

Nothing here calls an LLM. `ledger_stats()`/`query_entries()` are exactly
the read-side primitives the fleet design's own retrieval-bank idea
("retrieve the k most similar priors") would be built on top of -- actual
similarity retrieval (embeddings, a vector index, few-shot prompt
assembly) is explicitly NOT implemented here; see FLEET_SCAFFOLD_STATUS.md
for what a future retrieval layer would need to add.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .claim_card import ClaimCard, cap_untrusted_text
from .verify import Verdict

# Relative to the current working directory when the caller doesn't pass
# `ledger_path` explicitly -- every bench script in this project is already
# run from the repo root (see FINAL_V2_STATUS.md's own reproduction
# commands), so this resolves to the real project ledger there. Tests
# always pass an explicit `tmp_path`-based `ledger_path` instead.
DEFAULT_LEDGER_PATH = Path("bench/ledger/findings.jsonl")

_VALID_VERDICTS = frozenset(("confirmed", "refuted", "unconfirmed", "adversary-reviewed"))


@dataclass
class LedgerEntry:
    """One immutable record: a `ClaimCard`, its final verdict, when it was
    recorded, which commit it was found at, and an optional external
    reference (a GHSA/CVE id, or a maintainer-confirmation link/date) added
    later once a `confirmed` finding is actually disclosed.

    `notes` (added by the ledger-populate milestone, kept optional/`None`-
    default so every entry written before this field existed still reads
    back unchanged -- see "ThreatModelDocument/ClaimCard schema versioning"
    in FLEET_SCAFFOLD_STATUS.md's own "What's NOT built"): free-text room
    for exactly two things the small, closed-set `Verdict` type can't carry
    on its own -- (1) a nuance on the verdict itself (e.g. a "confirmed" bug
    whose original claim overstated something and was corrected on review),
    and (2) an honest provenance note when an entry was back-filled from a
    written report rather than produced by a live Hunter/Adversary run.
    Never used to smuggle in an UNLISTED verdict value -- a genuinely new
    tier (e.g. `"adversary-reviewed"`, added by `adversary.py`'s ledger-
    write gate) is added to `Verdict`/`_VALID_VERDICTS` explicitly instead,
    same as the original three; `verdict` alone still answers the question,
    `notes` never carries verdict information `verdict` itself doesn't."""

    claim_card: ClaimCard
    verdict: Verdict
    timestamp: str
    commit: str
    evidence_ref: str | None = None
    notes: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LedgerEntry:
        return cls(
            claim_card=ClaimCard.from_dict(data["claim_card"]),
            verdict=data["verdict"],
            timestamp=data["timestamp"],
            commit=data["commit"],
            evidence_ref=data.get("evidence_ref"),
            notes=data.get("notes"),
        )


def append_entry(
    claim_card: ClaimCard,
    verdict: Verdict,
    commit: str,
    *,
    evidence_ref: str | None = None,
    notes: str | None = None,
    ledger_path: str | Path = DEFAULT_LEDGER_PATH,
    timestamp: str | None = None,
) -> LedgerEntry:
    """Append ONE entry and return it. Opens in append (`"a"`) mode and
    writes exactly one JSON object as one line -- an existing line is never
    read back, rewritten, or reordered by this function. `verdict` may be
    `"confirmed"`, `"refuted"`, `"unconfirmed"`, or `"adversary-reviewed"`
    (survived an independent adversary's attempt to refute it -- see
    `adversary.py`'s `run_adversary_check`): a refuted or unconfirmed
    candidate is recorded through this exact same call, not a different
    (or skipped) path -- see module docstring, "keep refutations, don't
    delete them". `notes` is the free-text nuance/provenance field -- see
    `LedgerEntry.notes`'s own docstring."""
    if verdict not in _VALID_VERDICTS:
        raise ValueError(f"not a recognized verdict: {verdict!r} -- expected one of {sorted(_VALID_VERDICTS)}")
    entry = LedgerEntry(
        claim_card=claim_card,
        verdict=verdict,
        timestamp=timestamp or datetime.now(UTC).isoformat(),
        commit=commit,
        evidence_ref=evidence_ref,
        # `notes` often carries free text written by an LLM stage (adversary/
        # critic reasoning) that itself quotes a ClaimCard field -- the same
        # untrusted-content path `claim_card.py`'s own fields are capped
        # against (see `cap_untrusted_text`'s own comment there); capped
        # here too, once, at the one place every ledger write passes
        # through, so this field can't grow unbounded either -- it is read
        # back verbatim into a LATER hunt's prompt via `retrieval.py`'s
        # exemplar bank (`hunter._format_exemplar`).
        notes=cap_untrusted_text(notes) if notes is not None else None,
    )
    path = Path(ledger_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry.to_dict()) + "\n")
    return entry


def read_entries(ledger_path: str | Path = DEFAULT_LEDGER_PATH) -> list[LedgerEntry]:
    """Every entry in the ledger, in append order. `[]` (not an error) for
    a ledger that doesn't exist yet -- no entries have ever been appended,
    which is a valid, silent starting state, not a failure."""
    path = Path(ledger_path)
    if not path.is_file():
        return []
    entries: list[LedgerEntry] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            entries.append(LedgerEntry.from_dict(json.loads(line)))
    return entries


def query_entries(
    ledger_path: str | Path = DEFAULT_LEDGER_PATH,
    *,
    verdict: Verdict | None = None,
    commit: str | None = None,
    target_sink_contains: str | None = None,
) -> list[LedgerEntry]:
    """`read_entries()` filtered by any combination of verdict / commit / a
    case-insensitive substring of `target_sink` -- the simple query surface
    the task asks for, not a query language."""
    entries = read_entries(ledger_path)
    if verdict is not None:
        entries = [e for e in entries if e.verdict == verdict]
    if commit is not None:
        entries = [e for e in entries if e.commit == commit]
    if target_sink_contains is not None:
        needle = target_sink_contains.lower()
        entries = [e for e in entries if needle in e.claim_card.target_sink.lower()]
    return entries


def ledger_stats(ledger_path: str | Path = DEFAULT_LEDGER_PATH) -> dict[str, int]:
    """Counts by verdict, plus `total`. Always reports all three verdict
    keys (0 if absent), so a caller can read `stats["refuted"]` without a
    `KeyError` on a ledger that happens to hold only confirmed findings so
    far."""
    stats = {"total": 0, "confirmed": 0, "refuted": 0, "unconfirmed": 0}
    for entry in read_entries(ledger_path):
        stats["total"] += 1
        stats[entry.verdict] = stats.get(entry.verdict, 0) + 1
    return stats
