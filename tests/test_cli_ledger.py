"""Tests for the `mcp-safeguard ledger` CLI subcommand (cli.py's `_run_ledger`
and its `add`/`list`/`stats`/`show` helpers).

Same style as test_cli.py: call the internal `_run_*` functions directly
(not `main()`/sys.argv) and assert on `capsys`-captured stdout/stderr plus
the real ledger file under `tmp_path` -- no mocking of ledger.py itself,
since the whole point is proving the CLI drives the real append-only file
store correctly.
"""

from __future__ import annotations

import json

from mcp_safeguard.cli import (
    _run_ledger,
    _run_ledger_add,
    _run_ledger_list,
    _run_ledger_show,
    _run_ledger_stats,
)
from mcp_safeguard.scanner.ledger import read_entries


def _entry_dict(**overrides) -> dict:
    base = {
        "claim_card": {
            "target_sink": "subprocess.run(cmd, shell=True)",
            "tainted_source": 'request.params.arguments["cmd"]',
            "caller_authority_assumed": "tool caller only",
            "precondition": "no sanitizer recognized on the path to the sink",
            "violated_claim": "README.md:10 claims this tool is read-only, but it executes shell commands",
            "evidence_path": [],
            "oracle_trace": {"executed": True},
            "impossibility_argument": None,
        },
        "verdict": "confirmed",
        "commit": "abc123",
        "evidence_ref": None,
        "notes": None,
    }
    base.update(overrides)
    return base


def _write_entry_file(tmp_path, name="entry.json", **overrides) -> str:
    path = tmp_path / name
    path.write_text(json.dumps(_entry_dict(**overrides)), encoding="utf-8")
    return str(path)


# --------------------------------------------------------------------------
# ledger add
# --------------------------------------------------------------------------

def test_ledger_add_from_file_appends_a_real_entry(tmp_path, capsys):
    ledger_path = str(tmp_path / "findings.jsonl")
    entry_file = _write_entry_file(tmp_path)

    code = _run_ledger_add(entry_file, ledger_path)

    assert code == 0
    entries = read_entries(ledger_path)
    assert len(entries) == 1
    assert entries[0].verdict == "confirmed"
    assert entries[0].commit == "abc123"
    out = capsys.readouterr().out
    assert "Appended entry #1" in out


def test_ledger_add_via_dispatcher_and_ledger_path_flag(tmp_path, capsys):
    """`mcp-safeguard ledger add --file X --ledger-path Y` end to end through
    the real argv dispatcher, `--ledger-path` extracted correctly."""
    ledger_path = tmp_path / "custom.jsonl"
    entry_file = _write_entry_file(tmp_path)

    code = _run_ledger(["add", "--file", entry_file, "--ledger-path", str(ledger_path)])

    assert code == 0
    assert ledger_path.is_file()
    assert len(read_entries(str(ledger_path))) == 1


def test_ledger_add_rejects_missing_file(tmp_path, capsys):
    code = _run_ledger_add(str(tmp_path / "does_not_exist.json"), str(tmp_path / "findings.jsonl"))
    assert code == 1
    assert "not found" in capsys.readouterr().err.lower()


def test_ledger_add_rejects_invalid_json(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{not valid json", encoding="utf-8")
    code = _run_ledger_add(str(bad), str(tmp_path / "findings.jsonl"))
    assert code == 1
    assert "invalid json" in capsys.readouterr().err.lower()


def test_ledger_add_rejects_claim_card_violating_the_emit_invariant(tmp_path, capsys):
    """Neither oracle_trace nor impossibility_argument -- ClaimCard's own
    ClaimCardValidationError must surface as a clean CLI error, not a
    traceback, and nothing must be written to the ledger."""
    entry_file = _write_entry_file(tmp_path)
    data = json.loads((tmp_path / "entry.json").read_text())
    data["claim_card"]["oracle_trace"] = None
    data["claim_card"]["impossibility_argument"] = None
    (tmp_path / "entry.json").write_text(json.dumps(data))

    ledger_path = str(tmp_path / "findings.jsonl")
    code = _run_ledger_add(entry_file, ledger_path)

    assert code == 1
    assert "oracle_trace" in capsys.readouterr().err
    assert read_entries(ledger_path) == []


def test_ledger_add_rejects_missing_verdict(tmp_path, capsys):
    entry_file = _write_entry_file(tmp_path)
    data = json.loads((tmp_path / "entry.json").read_text())
    del data["verdict"]
    (tmp_path / "entry.json").write_text(json.dumps(data))

    code = _run_ledger_add(entry_file, str(tmp_path / "findings.jsonl"))
    assert code == 1
    assert "verdict" in capsys.readouterr().err.lower()


def test_ledger_add_rejects_invalid_verdict_value(tmp_path, capsys):
    entry_file = _write_entry_file(tmp_path, verdict="maybe")
    code = _run_ledger_add(entry_file, str(tmp_path / "findings.jsonl"))
    assert code == 1
    assert "not a recognized verdict" in capsys.readouterr().err


# --------------------------------------------------------------------------
# ledger list
# --------------------------------------------------------------------------

def test_ledger_list_filters_by_verdict(tmp_path, capsys):
    ledger_path = str(tmp_path / "findings.jsonl")
    _run_ledger_add(_write_entry_file(tmp_path, "a.json", verdict="confirmed", commit="c1"), ledger_path)
    _run_ledger_add(
        _write_entry_file(
            tmp_path, "b.json", verdict="refuted", commit="c2",
            claim_card={**_entry_dict()["claim_card"], "oracle_trace": None, "impossibility_argument": "not reachable"},
        ),
        ledger_path,
    )
    capsys.readouterr()

    code = _run_ledger_list("confirmed", None, None, None, None, "text", ledger_path)
    out = capsys.readouterr().out
    assert code == 0
    assert "#1" in out
    assert "#2" not in out
    assert "1 of 2 total" in out


def test_ledger_list_filters_by_target_substring(tmp_path, capsys):
    ledger_path = str(tmp_path / "findings.jsonl")
    _run_ledger_add(
        _write_entry_file(tmp_path, "a.json", claim_card={**_entry_dict()["claim_card"], "target_sink": "open(path, 'w')"}),
        ledger_path,
    )
    _run_ledger_add(
        _write_entry_file(tmp_path, "b.json", claim_card={**_entry_dict()["claim_card"], "target_sink": "subprocess.run(cmd)"}),
        ledger_path,
    )
    capsys.readouterr()

    code = _run_ledger_list(None, "subprocess", None, None, None, "text", ledger_path)
    out = capsys.readouterr().out
    assert code == 0
    assert "subprocess.run(cmd)" in out
    assert "open(path" not in out


def test_ledger_list_ids_are_original_ledger_positions_even_when_filtered(tmp_path, capsys):
    """Filtering must not renumber -- entry #2's id stays 2 even when #1 is
    filtered out, since id == position in the append-only file."""
    ledger_path = str(tmp_path / "findings.jsonl")
    _run_ledger_add(_write_entry_file(tmp_path, "a.json", verdict="confirmed"), ledger_path)
    _run_ledger_add(_write_entry_file(tmp_path, "b.json", verdict="unconfirmed"), ledger_path)
    capsys.readouterr()

    _run_ledger_list(None, None, None, None, None, "json", ledger_path)
    data = json.loads(capsys.readouterr().out)
    assert [d["id"] for d in data] == [1, 2]

    _run_ledger_list("unconfirmed", None, None, None, None, "json", ledger_path)
    data = json.loads(capsys.readouterr().out)
    assert data[0]["id"] == 2


def test_ledger_list_on_empty_ledger_reports_no_matches(tmp_path, capsys):
    code = _run_ledger_list(None, None, None, None, None, "text", str(tmp_path / "empty.jsonl"))
    assert code == 0
    assert "no matching" in capsys.readouterr().out.lower()


# --------------------------------------------------------------------------
# ledger stats
# --------------------------------------------------------------------------

def test_ledger_stats_text_and_json_agree(tmp_path, capsys):
    ledger_path = str(tmp_path / "findings.jsonl")
    _run_ledger_add(_write_entry_file(tmp_path, "a.json", verdict="confirmed"), ledger_path)
    _run_ledger_add(_write_entry_file(tmp_path, "b.json", verdict="confirmed"), ledger_path)
    _run_ledger_add(
        _write_entry_file(
            tmp_path, "c.json", verdict="refuted",
            claim_card={**_entry_dict()["claim_card"], "oracle_trace": None, "impossibility_argument": "x"},
        ),
        ledger_path,
    )
    capsys.readouterr()

    _run_ledger_stats("json", ledger_path)
    stats = json.loads(capsys.readouterr().out)
    assert stats == {"total": 3, "confirmed": 2, "refuted": 1, "unconfirmed": 0}

    _run_ledger_stats("text", ledger_path)
    text_out = capsys.readouterr().out
    assert "total:" in text_out
    assert "confirmed:" in text_out


def test_ledger_stats_on_empty_ledger_reports_all_zero(tmp_path, capsys):
    _run_ledger_stats("json", str(tmp_path / "empty.jsonl"))
    stats = json.loads(capsys.readouterr().out)
    assert stats == {"total": 0, "confirmed": 0, "refuted": 0, "unconfirmed": 0}


# --------------------------------------------------------------------------
# ledger show
# --------------------------------------------------------------------------

def test_ledger_show_prints_the_full_entry(tmp_path, capsys):
    ledger_path = str(tmp_path / "findings.jsonl")
    _run_ledger_add(_write_entry_file(tmp_path, evidence_ref="GHSA-xxxx-yyyy-zzzz", notes="a note"), ledger_path)
    capsys.readouterr()

    code = _run_ledger_show("1", "text", ledger_path)
    out = capsys.readouterr().out
    assert code == 0
    assert "Entry #1" in out
    assert "subprocess.run(cmd, shell=True)" in out
    assert "GHSA-xxxx-yyyy-zzzz" in out
    assert "a note" in out


def test_ledger_show_json_format_round_trips(tmp_path, capsys):
    ledger_path = str(tmp_path / "findings.jsonl")
    _run_ledger_add(_write_entry_file(tmp_path), ledger_path)
    capsys.readouterr()

    _run_ledger_show("1", "json", ledger_path)
    data = json.loads(capsys.readouterr().out)
    assert data["id"] == 1
    assert data["claim_card"]["target_sink"] == "subprocess.run(cmd, shell=True)"


def test_ledger_show_out_of_range_id_errors_cleanly(tmp_path, capsys):
    ledger_path = str(tmp_path / "findings.jsonl")
    _run_ledger_add(_write_entry_file(tmp_path), ledger_path)
    capsys.readouterr()

    code = _run_ledger_show("99", "text", ledger_path)
    assert code == 1
    assert "no entry #99" in capsys.readouterr().err.lower()


def test_ledger_show_non_integer_id_errors_cleanly(tmp_path, capsys):
    code = _run_ledger_show("not-a-number", "text", str(tmp_path / "findings.jsonl"))
    assert code == 1
    assert "must be an integer" in capsys.readouterr().err.lower()


def test_ledger_show_prints_evidence_path_and_oracle_trace(tmp_path, capsys):
    ledger_path = str(tmp_path / "findings.jsonl")
    entry = _entry_dict()
    entry["claim_card"]["evidence_path"] = [
        {"kind": "source", "line": 5, "code": "query = params['query']", "note": "attacker-controlled", "file": "schemas.ts"},
        {"kind": "sink", "line": 22, "code": "client.post(path, body)", "note": "", "file": "pg-run-query.ts"},
    ]
    (tmp_path / "entry.json").write_text(json.dumps(entry))
    _run_ledger_add(str(tmp_path / "entry.json"), ledger_path)
    capsys.readouterr()

    _run_ledger_show("1", "text", ledger_path)
    out = capsys.readouterr().out
    assert "schemas.ts:5" in out
    assert "pg-run-query.ts:22" in out
    assert "attacker-controlled" in out
    assert "oracle_trace" in out


def test_ledger_show_text_format_handles_a_real_oracle_trace_object(tmp_path, capsys):
    """Regression: ClaimCard.oracle_trace can now be a real, typed
    OracleTrace (from scanner/pipeline.py's hunt()) after round-tripping
    through the ledger's JSON storage, not only a plain free-form dict --
    `ledger show`'s text-format path used to `json.dumps(card.oracle_trace,
    ...)` directly, which raised TypeError for a real OracleTrace object
    (dataclasses.asdict() only auto-flattens dataclass fields on the
    OUTER to_dict() call, not on a raw attribute access like this one)."""
    ledger_path = str(tmp_path / "findings.jsonl")
    entry = _entry_dict()
    entry["claim_card"]["oracle_trace"] = {
        "sandbox_kind": "docker", "runtime": "python", "entrypoint": "x.py:f",
        "timed_out": False, "started_at": 0.0, "ended_at": 0.0, "duration_seconds": 0.0,
        "return_value": None, "return_value_repr": None, "exception": None, "error": None,
        "stdout": "", "stderr": "", "subprocess_calls": [], "file_opens": [],
        "network_connections": [], "http_requests": [], "credential_flags": [], "extra": {},
    }
    (tmp_path / "entry.json").write_text(json.dumps(entry))
    _run_ledger_add(str(tmp_path / "entry.json"), ledger_path)
    capsys.readouterr()

    code = _run_ledger_show("1", "text", ledger_path)
    out = capsys.readouterr().out
    assert code == 0
    assert '"sandbox_kind": "docker"' in out


# --------------------------------------------------------------------------
# dispatcher
# --------------------------------------------------------------------------

def test_ledger_dispatch_missing_subcommand_errors(capsys):
    code = _run_ledger([])
    assert code == 1
    assert "missing ledger subcommand" in capsys.readouterr().err.lower()


def test_ledger_dispatch_unknown_subcommand_errors(capsys):
    code = _run_ledger(["bogus"])
    assert code == 1
    assert "unknown ledger subcommand" in capsys.readouterr().err.lower()


def test_ledger_dispatch_show_missing_id_errors(capsys):
    code = _run_ledger(["show"])
    assert code == 1
    assert "missing <id>" in capsys.readouterr().err.lower()
