"""Tests for S7 mechanism-indexed exemplar retrieval (retrieval.py).

Real filesystem I/O against `tmp_path` ledgers built with `append_entry` --
same discipline as `test_ledger.py` (no mocking of the read path). These
tests use small, synthetic ledgers so they run in milliseconds; the real,
honest precision check against the actual 281-entry campaign ledger lives
in `bench/S7_RETRIEVAL_STATUS.md`, not here.
"""

from __future__ import annotations

from mcp_safeguard.scanner.claim_card import ClaimCard
from mcp_safeguard.scanner.ledger import append_entry
from mcp_safeguard.scanner.retrieval import retrieve_exemplars


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


def test_empty_ledger_returns_no_exemplars_not_an_error(tmp_path):
    result = retrieve_exemplars("anything", ledger_path=tmp_path / "empty.jsonl")
    assert result.exemplars == []
    assert result.candidate_pool_size == 0


def test_default_excludes_unconfirmed_entries(tmp_path):
    path = tmp_path / "findings.jsonl"
    append_entry(
        _card(target_sink="shell command injection via subprocess", violated_claim="subprocess shell injection"),
        "confirmed", "c1", ledger_path=path,
    )
    append_entry(
        _card(target_sink="shell command injection unconfirmed", violated_claim="subprocess shell injection noise",
              oracle_trace=None, impossibility_argument="not sandbox-testable"),
        "unconfirmed", "c2", ledger_path=path,
    )
    result = retrieve_exemplars("shell command injection via subprocess", ledger_path=path)
    assert result.candidate_pool_size == 1
    assert all(e.verdict != "unconfirmed" for e in result.exemplars)


def test_include_unconfirmed_true_widens_the_pool_and_labels_verdict(tmp_path):
    path = tmp_path / "findings.jsonl"
    append_entry(
        _card(target_sink="shell command injection via subprocess", violated_claim="subprocess shell injection"),
        "confirmed", "c1", ledger_path=path,
    )
    append_entry(
        _card(target_sink="shell command injection unconfirmed", violated_claim="subprocess shell injection noise",
              oracle_trace=None, impossibility_argument="not sandbox-testable"),
        "unconfirmed", "c2", ledger_path=path,
    )
    result = retrieve_exemplars("shell command injection via subprocess", include_unconfirmed=True, ledger_path=path)
    assert result.candidate_pool_size == 2
    verdicts = {e.verdict for e in result.exemplars}
    assert "unconfirmed" in verdicts
    assert "confirmed" in verdicts


def test_top1_is_the_mechanically_similar_entry_not_an_unrelated_one(tmp_path):
    path = tmp_path / "findings.jsonl"
    append_entry(
        _card(
            target_sink="pg-run-query.ts validateReadQuery only checks the outermost AST node type",
            tainted_source="caller-supplied SQL query string",
            precondition="EXPLAIN ANALYZE DELETE or a writable CTE bypasses the outermost-node check",
            violated_claim="description claims only SELECT/EXPLAIN allowed, but a writable CTE still executes",
        ),
        "confirmed", "sql-guard-commit", ledger_path=path,
    )
    append_entry(
        _card(
            target_sink="oauth-client.ts fetch() forwards a bearer token to a caller-controlled URL",
            tainted_source="caller-supplied redirect URL parameter",
            precondition="no host allowlist on the outbound fetch call",
            violated_claim="README claims outbound requests are restricted to the vendor's own API host",
        ),
        "confirmed", "ssrf-commit", ledger_path=path,
    )
    result = retrieve_exemplars(
        "a read-only SQL guard only checks the outermost AST node type of the query, so a "
        "writable CTE or EXPLAIN ANALYZE wrapper bypasses it",
        k=2, ledger_path=path,
    )
    assert result.exemplars[0].commit == "sql-guard-commit"
    assert result.exemplars[0].score > result.exemplars[1].score


def test_exclude_target_sink_removes_self_match(tmp_path):
    path = tmp_path / "findings.jsonl"
    append_entry(_card(target_sink="self sink"), "confirmed", "c1", ledger_path=path)
    append_entry(_card(target_sink="other sink"), "confirmed", "c2", ledger_path=path)
    result = retrieve_exemplars("shell command injection", ledger_path=path, exclude_target_sink="self sink")
    assert all(e.target_sink != "self sink" for e in result.exemplars)
    assert result.candidate_pool_size == 1


def test_refuted_entries_are_retrievable_by_default():
    """Refutations are real signal (per ledger.py's own docstring: 'a
    refutation you'd have made differently is only a check if you can see
    it') -- `include_unconfirmed=False` must not also exclude `refuted`."""
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "findings.jsonl"
        append_entry(
            _card(
                target_sink="iam trust policy checks Principal wildcard",
                violated_claim="NotPrincipal was claimed as a bypass but is not reachable in practice",
                oracle_trace=None,
                impossibility_argument="reproduced: NotPrincipal path is unreachable given the fixed statement shape",
            ),
            "refuted", "c1", ledger_path=path,
        )
        result = retrieve_exemplars("iam trust policy Principal wildcard NotPrincipal bypass", ledger_path=path)
        assert result.exemplars
        assert result.exemplars[0].verdict == "refuted"
