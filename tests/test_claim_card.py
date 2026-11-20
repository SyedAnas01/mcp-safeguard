"""Tests for the Claim Card data model (claim_card.py)."""

from __future__ import annotations

import pytest

from mcp_safeguard.scanner.claim_card import (
    MAX_UNTRUSTED_FIELD_CHARS,
    ClaimCard,
    ClaimCardValidationError,
    cap_untrusted_text,
)
from mcp_safeguard.scanner.prompt_injection import Severity
from mcp_safeguard.scanner.sandbox import OracleTrace
from mcp_safeguard.scanner.taint_scanner import Step

_BASE_KWARGS = {
    "target_sink": "subprocess.run(script, shell=True)",
    "tainted_source": 'request.params.arguments["script"]',
    "caller_authority_assumed": "tool caller only, no elevated scope",
    "precondition": "no sanitizer recognized on the path to the sink",
    "violated_claim": "README.md:10 claims this tool is read-only, but it executes shell commands",
}


def test_card_with_oracle_trace_only_is_valid():
    card = ClaimCard(**_BASE_KWARGS, oracle_trace={"executed": True, "stdout": "pwned"})
    assert card.oracle_trace == {"executed": True, "stdout": "pwned"}
    assert card.impossibility_argument is None


def test_card_with_impossibility_argument_only_is_valid():
    card = ClaimCard(**_BASE_KWARGS, impossibility_argument="no sandbox available to execute this class of bug")
    assert card.impossibility_argument is not None
    assert card.oracle_trace is None


def test_card_with_neither_oracle_trace_nor_impossibility_argument_raises():
    with pytest.raises(ClaimCardValidationError):
        ClaimCard(**_BASE_KWARGS)


def test_card_with_both_present_is_valid():
    card = ClaimCard(**_BASE_KWARGS, oracle_trace={"executed": True}, impossibility_argument="also documented")
    assert card.oracle_trace is not None
    assert card.impossibility_argument is not None


def test_try_create_returns_none_instead_of_raising():
    assert ClaimCard.try_create(**_BASE_KWARGS) is None


def test_try_create_returns_card_when_valid():
    card = ClaimCard.try_create(**_BASE_KWARGS, oracle_trace={"executed": True})
    assert isinstance(card, ClaimCard)


def test_evidence_path_reuses_taint_scanner_step_type():
    step = Step(kind="sink", line=42, code="subprocess.run(script, shell=True)", file="server.py")
    card = ClaimCard(**_BASE_KWARGS, evidence_path=[step], oracle_trace={"executed": True})
    assert card.evidence_path == [step]
    assert isinstance(card.evidence_path[0], Step)


def test_to_dict_from_dict_roundtrip():
    step = Step(kind="sink", line=42, code="subprocess.run(script, shell=True)", file="server.py")
    original = ClaimCard(**_BASE_KWARGS, evidence_path=[step], oracle_trace={"executed": True, "stdout": "pwned"})
    restored = ClaimCard.from_dict(original.to_dict())
    assert restored == original
    assert isinstance(restored.evidence_path[0], Step)


def test_to_json_from_json_roundtrip():
    original = ClaimCard(**_BASE_KWARGS, impossibility_argument="cannot execute in this sandbox")
    restored = ClaimCard.from_json(original.to_json())
    assert restored == original


# --------------------------------------------------------------------------
# A real OracleTrace (from sandbox.py's run_in_sandbox()), not a free-form
# placeholder dict -- oracle_trace's type is `OracleTrace | dict | None`
# precisely so a real Stage-5 result is preserved as a typed object AND a
# manually-authored/back-filled ledger entry's free-form dict (tested above)
# both remain valid, distinguished by from_dict via
# `_ORACLE_TRACE_REQUIRED_FIELDS` (a real OracleTrace always carries all
# three of sandbox_kind/runtime/entrypoint; a free-form dict is not expected
# to coincidentally carry all three under those exact names).
# --------------------------------------------------------------------------


def test_card_accepts_a_real_oracle_trace_object():
    trace = OracleTrace(sandbox_kind="docker", runtime="python", entrypoint="server.py:handler", subprocess_calls=[{"argv": ["sh", "-c", "id"]}])
    card = ClaimCard(**_BASE_KWARGS, oracle_trace=trace)
    assert isinstance(card.oracle_trace, OracleTrace)
    assert card.oracle_trace.sandbox_kind == "docker"


def test_real_oracle_trace_roundtrips_as_oracle_trace_not_a_plain_dict():
    trace = OracleTrace(sandbox_kind="docker", runtime="node", entrypoint="handlers.ts:askDocs", credential_flags=[{"destination": "evil.example:443"}])
    original = ClaimCard(**_BASE_KWARGS, oracle_trace=trace)
    restored = ClaimCard.from_dict(original.to_dict())
    assert restored == original
    assert isinstance(restored.oracle_trace, OracleTrace)
    assert restored.oracle_trace.credential_flags == [{"destination": "evil.example:443"}]


def test_free_form_placeholder_dict_still_roundtrips_as_a_plain_dict():
    """A manually-authored/back-filled entry's oracle_trace (this project's
    own real ledger data, and `mcp-safeguard ledger add`'s free-form manual
    flow) does NOT carry sandbox_kind/runtime/entrypoint -- from_dict must
    never force it through OracleTrace.from_dict (which would raise on the
    missing required fields), and must keep it as the plain dict it was."""
    original = ClaimCard(**_BASE_KWARGS, oracle_trace={"description": "reproduced by hand", "result": "3 rows -> 0 rows"})
    restored = ClaimCard.from_dict(original.to_dict())
    assert restored == original
    assert isinstance(restored.oracle_trace, dict)


# --------------------------------------------------------------------------
# Prompt-injection fix: every untrusted free-text field is length-capped at
# construction time -- a single huge injected README/comment sentence
# cannot grow a ClaimCard field (and, via ledger.py's append_entry, the
# ledger's own `notes` field) without bound. See cap_untrusted_text's own
# comment in claim_card.py and bench/PROMPT_INJECTION_FIX_STATUS.md.
# --------------------------------------------------------------------------


def test_cap_untrusted_text_leaves_short_text_unchanged():
    assert cap_untrusted_text("short") == "short"


def test_cap_untrusted_text_truncates_and_marks_long_text():
    huge = "A" * (MAX_UNTRUSTED_FIELD_CHARS + 500)
    capped = cap_untrusted_text(huge)
    assert len(capped) > MAX_UNTRUSTED_FIELD_CHARS  # the truncation marker itself adds length
    assert capped.startswith("A" * MAX_UNTRUSTED_FIELD_CHARS)
    assert "truncated" in capped


def test_claim_card_fields_are_capped_at_construction_time():
    huge_claim = "README.md:1 claims something. " + ("X" * (MAX_UNTRUSTED_FIELD_CHARS + 1000))
    card = ClaimCard(
        target_sink="x" * (MAX_UNTRUSTED_FIELD_CHARS + 1000),
        tainted_source="short",
        caller_authority_assumed="short",
        precondition="short",
        violated_claim=huge_claim,
        impossibility_argument="short",
    )
    assert len(card.target_sink) < MAX_UNTRUSTED_FIELD_CHARS + 1000
    assert len(card.violated_claim) < len(huge_claim)
    assert "truncated" in card.violated_claim


def test_from_dict_of_a_dropped_card_still_enforces_the_invariant():
    """A hand-crafted dict with neither field can't be smuggled past
    validation just by going through from_dict instead of the
    constructor -- from_dict still calls the real dataclass constructor."""
    bad_dict = {**_BASE_KWARGS, "evidence_path": [], "oracle_trace": None, "impossibility_argument": None}
    with pytest.raises(ClaimCardValidationError):
        ClaimCard.from_dict(bad_dict)


# --------------------------------------------------------------------------
# Adversary-severity milestone: `severity`/`cwe` fields (real gap fixed --
# an "adversary-reviewed" card previously carried no severity/CVSS/CWE data
# at all). `None` by default so every pre-existing card/ledger entry built
# before this milestone still constructs and round-trips unchanged.
# --------------------------------------------------------------------------


def test_severity_and_cwe_default_to_none():
    card = ClaimCard(**_BASE_KWARGS, oracle_trace={"executed": True})
    assert card.severity is None
    assert card.cwe is None


def test_severity_and_cwe_can_be_set_at_construction():
    card = ClaimCard(**_BASE_KWARGS, oracle_trace={"executed": True}, severity=Severity.HIGH, cwe="CWE-863")
    assert card.severity is Severity.HIGH
    assert card.cwe == "CWE-863"


def test_severity_and_cwe_roundtrip_through_to_dict_from_dict():
    original = ClaimCard(
        **_BASE_KWARGS, oracle_trace={"executed": True}, severity=Severity.MEDIUM, cwe="CWE-441",
    )
    restored = ClaimCard.from_dict(original.to_dict())
    assert restored == original
    assert restored.severity is Severity.MEDIUM
    assert restored.cwe == "CWE-441"


def test_severity_and_cwe_roundtrip_through_to_json_from_json():
    original = ClaimCard(
        **_BASE_KWARGS, oracle_trace={"executed": True}, severity=Severity.CRITICAL, cwe="CWE-89",
    )
    restored = ClaimCard.from_json(original.to_json())
    assert restored == original
    assert restored.severity is Severity.CRITICAL


def test_none_severity_and_cwe_roundtrip_as_none_not_a_string():
    original = ClaimCard(**_BASE_KWARGS, oracle_trace={"executed": True})
    restored = ClaimCard.from_dict(original.to_dict())
    assert restored.severity is None
    assert restored.cwe is None


def test_pre_existing_ledger_entry_dict_with_no_severity_key_still_reads_back_unchanged():
    """A real ledger entry written before this milestone has no `severity`/
    `cwe` keys in its serialized `claim_card` at all -- `from_dict` must
    read it back exactly as before, not raise or invent a value."""
    original = ClaimCard(**_BASE_KWARGS, oracle_trace={"executed": True})
    legacy_dict = original.to_dict()
    del legacy_dict["severity"]
    del legacy_dict["cwe"]
    restored = ClaimCard.from_dict(legacy_dict)
    assert restored.severity is None
    assert restored.cwe is None


def test_cwe_field_is_capped_at_construction_time_like_other_free_text_fields():
    huge_cwe = "CWE-" + ("9" * (MAX_UNTRUSTED_FIELD_CHARS + 500))
    card = ClaimCard(**_BASE_KWARGS, oracle_trace={"executed": True}, cwe=huge_cwe)
    assert len(card.cwe) < len(huge_cwe)
    assert "truncated" in card.cwe
