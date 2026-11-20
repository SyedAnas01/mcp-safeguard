"""Tests for the append-only evidence ledger (ledger.py).

Real filesystem I/O against `tmp_path` -- no mocking of the append/read
path, since the whole point being tested is "is this file actually
append-only and does it actually retain refutations".
"""

from __future__ import annotations

import json

import pytest

from mcp_safeguard.scanner.claim_card import ClaimCard
from mcp_safeguard.scanner.ledger import (
    LedgerEntry,
    append_entry,
    ledger_stats,
    query_entries,
    read_entries,
)


def _card(**overrides) -> ClaimCard:
    kwargs = {
        "target_sink": "subprocess.run(script, shell=True)",
        "tainted_source": 'request.params.arguments["script"]',
        "caller_authority_assumed": "tool caller only",
        "precondition": "no sanitizer recognized on the path to the sink",
        "violated_claim": "README.md:10 claims this tool is read-only, but it executes shell commands",
        "oracle_trace": {"executed": True},
    }
    kwargs.update(overrides)
    return ClaimCard(**kwargs)


def test_read_entries_on_a_nonexistent_ledger_returns_empty_list_not_error(tmp_path):
    assert read_entries(ledger_path=tmp_path / "does_not_exist.jsonl") == []


def test_append_entry_writes_one_json_line(tmp_path):
    path = tmp_path / "findings.jsonl"
    append_entry(_card(), "confirmed", "abc123", ledger_path=path)
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    data = json.loads(lines[0])
    assert data["verdict"] == "confirmed"
    assert data["commit"] == "abc123"
    assert data["claim_card"]["target_sink"] == "subprocess.run(script, shell=True)"


def test_append_is_additive_not_overwriting(tmp_path):
    path = tmp_path / "findings.jsonl"
    append_entry(_card(), "confirmed", "commit1", ledger_path=path)
    append_entry(_card(), "refuted", "commit2", ledger_path=path)
    append_entry(_card(), "unconfirmed", "commit3", ledger_path=path)
    entries = read_entries(ledger_path=path)
    assert len(entries) == 3
    assert [e.verdict for e in entries] == ["confirmed", "refuted", "unconfirmed"]
    assert [e.commit for e in entries] == ["commit1", "commit2", "commit3"]


def test_refuted_entries_are_retained_not_dropped(tmp_path):
    """The design's explicit rule: 'keep refutations, don't delete them'."""
    path = tmp_path / "findings.jsonl"
    refuted_card = _card(
        oracle_trace=None,
        impossibility_argument="reproduced: the string is escaped before use, sink is not reachable",
    )
    append_entry(refuted_card, "refuted", "commit1", ledger_path=path)

    entries = read_entries(ledger_path=path)
    assert len(entries) == 1
    assert entries[0].verdict == "refuted"
    assert entries[0].claim_card.impossibility_argument is not None

    refuted_only = query_entries(ledger_path=path, verdict="refuted")
    assert len(refuted_only) == 1


def test_evidence_ref_is_optional_and_persists_when_given(tmp_path):
    path = tmp_path / "findings.jsonl"
    append_entry(_card(), "confirmed", "commit1", ledger_path=path, evidence_ref="GHSA-xxxx-yyyy-zzzz")
    entries = read_entries(ledger_path=path)
    assert entries[0].evidence_ref == "GHSA-xxxx-yyyy-zzzz"

    append_entry(_card(), "confirmed", "commit2", ledger_path=path)
    entries = read_entries(ledger_path=path)
    assert entries[1].evidence_ref is None


def test_timestamp_is_recorded_for_every_entry(tmp_path):
    path = tmp_path / "findings.jsonl"
    append_entry(_card(), "confirmed", "commit1", ledger_path=path)
    entries = read_entries(ledger_path=path)
    assert entries[0].timestamp  # non-empty; exact format is an implementation detail


def test_query_entries_filters_by_commit(tmp_path):
    path = tmp_path / "findings.jsonl"
    append_entry(_card(), "confirmed", "commit1", ledger_path=path)
    append_entry(_card(), "refuted", "commit2", ledger_path=path)
    assert len(query_entries(ledger_path=path, commit="commit1")) == 1
    assert len(query_entries(ledger_path=path, commit="commit2")) == 1
    assert len(query_entries(ledger_path=path, commit="nope")) == 0


def test_query_entries_filters_by_target_sink_substring(tmp_path):
    path = tmp_path / "findings.jsonl"
    append_entry(_card(target_sink="subprocess.run(cmd, shell=True)"), "confirmed", "c1", ledger_path=path)
    append_entry(_card(target_sink="open(path, 'w')"), "confirmed", "c2", ledger_path=path)
    matches = query_entries(ledger_path=path, target_sink_contains="subprocess")
    assert len(matches) == 1
    assert "subprocess" in matches[0].claim_card.target_sink


def test_ledger_stats_counts_by_verdict(tmp_path):
    path = tmp_path / "findings.jsonl"
    append_entry(_card(), "confirmed", "c1", ledger_path=path)
    append_entry(_card(), "confirmed", "c2", ledger_path=path)
    append_entry(_card(), "refuted", "c3", ledger_path=path)
    append_entry(_card(oracle_trace=None, impossibility_argument="x"), "unconfirmed", "c4", ledger_path=path)

    stats = ledger_stats(ledger_path=path)
    assert stats == {"total": 4, "confirmed": 2, "refuted": 1, "unconfirmed": 1}


def test_ledger_stats_on_empty_ledger_reports_all_zero_counts(tmp_path):
    stats = ledger_stats(ledger_path=tmp_path / "empty.jsonl")
    assert stats == {"total": 0, "confirmed": 0, "refuted": 0, "unconfirmed": 0}


def test_append_entry_rejects_invalid_verdict(tmp_path):
    with pytest.raises(ValueError):
        append_entry(_card(), "maybe", "commit1", ledger_path=tmp_path / "findings.jsonl")


def test_notes_is_optional_and_persists_when_given(tmp_path):
    """`notes` (verdict-nuance / back-fill-provenance free text) is optional
    and defaults to `None` for entries that don't set it, same contract as
    `evidence_ref`."""
    path = tmp_path / "findings.jsonl"
    append_entry(_card(), "confirmed", "commit1", ledger_path=path, notes="confirmed, but needs revision")
    entries = read_entries(ledger_path=path)
    assert entries[0].notes == "confirmed, but needs revision"

    append_entry(_card(), "confirmed", "commit2", ledger_path=path)
    entries = read_entries(ledger_path=path)
    assert entries[1].notes is None


def test_ledger_entry_roundtrips_claim_card_including_evidence_path(tmp_path):
    from mcp_safeguard.scanner.taint_scanner import Step

    card = _card(evidence_path=[Step(kind="sink", line=42, code="subprocess.run(...)", file="server.py")])
    path = tmp_path / "findings.jsonl"
    append_entry(card, "confirmed", "commit1", ledger_path=path)
    entries = read_entries(ledger_path=path)
    assert entries[0].claim_card.evidence_path[0].line == 42
    assert isinstance(entries[0], LedgerEntry)


def test_notes_is_length_capped_same_as_a_claim_card_field(tmp_path):
    """Prompt-injection fix: `notes` often carries free text written by an
    LLM stage (adversary/critic reasoning) that may itself quote a
    ClaimCard field -- read back verbatim into a LATER hunt's prompt via
    retrieval.py's exemplar bank. Capped here at the same
    `MAX_UNTRUSTED_FIELD_CHARS` ClaimCard's own fields use, so this field
    can't grow unbounded either."""
    from mcp_safeguard.scanner.claim_card import MAX_UNTRUSTED_FIELD_CHARS

    path = tmp_path / "findings.jsonl"
    huge_note = "Y" * (MAX_UNTRUSTED_FIELD_CHARS + 1000)
    append_entry(_card(), "confirmed", "commit1", ledger_path=path, notes=huge_note)
    entries = read_entries(ledger_path=path)
    assert len(entries[0].notes) < len(huge_note)
    assert "truncated" in entries[0].notes
