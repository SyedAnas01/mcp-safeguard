"""Synthetic positive / patched-negative fixtures for the WS4 detectors."""

from pathlib import Path

import pytest

from mcp_safeguard.scanner import (
    oauth_confused_deputy,
    state_handle_ownership,
    token_passthrough,
    tool_description_mutation,
)

FIX = Path(__file__).parent / "fixtures" / "ws4"

CASES = [
    (oauth_confused_deputy, "confused_deputy", "SRC-046"),
    (token_passthrough, "passthrough", "SRC-041"),
    (state_handle_ownership, "handle", "SRC-042"),
    (tool_description_mutation, "rugpull", "SRC-043"),
]


def _scan(mod, name):
    p = FIX / name
    return mod.scan_text(name, p.read_text())


@pytest.mark.parametrize("mod,prefix,rule", CASES)
def test_fires_on_vulnerable(mod, prefix, rule):
    found = _scan(mod, f"{prefix}_vuln.py")
    assert [f.rule_id for f in found] == [rule]
    assert found[0].location.startswith(f"{prefix}_vuln.py:")


@pytest.mark.parametrize("mod,prefix,rule", CASES)
def test_silent_on_patched(mod, prefix, rule):
    assert _scan(mod, f"{prefix}_patched.py") == []


@pytest.mark.parametrize("mod,prefix,rule", CASES)
def test_rule_ids_registered(mod, prefix, rule):
    assert rule in dict(mod.RULE_IDS)


def test_experimental_flags():
    assert state_handle_ownership.EXPERIMENTAL == {"SRC-042"}
    assert tool_description_mutation.EXPERIMENTAL == {"SRC-043"}
    assert not oauth_confused_deputy.EXPERIMENTAL
    assert not token_passthrough.EXPERIMENTAL


@pytest.mark.parametrize("mod,prefix,rule", CASES)
def test_scan_tree_vuln_only(mod, prefix, rule, tmp_path):
    (tmp_path / "srv.py").write_text((FIX / f"{prefix}_vuln.py").read_text())
    (tmp_path / "ok.py").write_text((FIX / f"{prefix}_patched.py").read_text())
    ids = [(Path(f.location).name.split(":")[0], f.rule_id) for f in mod.scan_tree(tmp_path)]
    assert ids == [("srv.py", rule)]


from mcp_safeguard.scanner import cache_scope_public, mrtr_request_state  # noqa: E402

TS_CASES = [
    (mrtr_request_state, "mrtr", "SRC-044"),
    (cache_scope_public, "cache", "SRC-045"),
]


@pytest.mark.parametrize("mod,prefix,rule", TS_CASES)
def test_ts_fires_on_vulnerable(mod, prefix, rule):
    found = mod.scan_text(f"{prefix}_vuln.ts", (FIX / f"{prefix}_vuln.ts").read_text())
    assert [f.rule_id for f in found] == [rule]
    assert rule in mod.EXPERIMENTAL


@pytest.mark.parametrize("mod,prefix,rule", TS_CASES)
def test_ts_silent_on_patched(mod, prefix, rule):
    assert mod.scan_text(f"{prefix}_patched.ts", (FIX / f"{prefix}_patched.ts").read_text()) == []


@pytest.mark.parametrize("mod,prefix,rule", TS_CASES)
def test_ts_scan_tree(mod, prefix, rule, tmp_path):
    (tmp_path / "srv.ts").write_text((FIX / f"{prefix}_vuln.ts").read_text())
    (tmp_path / "ok.ts").write_text((FIX / f"{prefix}_patched.ts").read_text())
    assert [(Path(f.location).name.split(":")[0], f.rule_id) for f in mod.scan_tree(tmp_path)] == [("srv.ts", rule)]


def test_mrtr_go_and_python():
    go = "func h(req *Req) { if req.Params.RequestState == \"x\" { grant() } }"
    assert [f.rule_id for f in mrtr_request_state.scan_text("a.go", go, ".go")] == ["SRC-044"]
    assert mrtr_request_state.scan_text("a.go", go + "\nmac := hmac.New(sha256.New, k)", ".go") == []
    assert mrtr_request_state.scan_text("a.py", "x = requestState()", ".py") == []
