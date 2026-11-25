"""WS5: deployment profile, conditional verdicts, cross-family hook."""
import json

import pytest

from mcp_safeguard.scanner import adversary as adv
from mcp_safeguard.scanner.adversary import (
    AdversaryResult, CrossFamilyAdversary, cross_family_adversary_from_env,
    requires_agreement, run_adversary_check, _result_from_tool_input,
)
from mcp_safeguard.scanner.claim_card import ClaimCard
from mcp_safeguard.scanner.deployment_profile import compute_deployment_profile
from mcp_safeguard.scanner.prompt_injection import Severity


def test_profile_stdio_only(tmp_path):
    (tmp_path / "server.py").write_text("from mcp.server.stdio import stdio_server\nasync with stdio_server() as s: pass\n")
    p = compute_deployment_profile(tmp_path)
    assert (p.transport, p.isolation, p.multi_tenant_exposure) == ("stdio-only", "per-process-local", "no")


def test_profile_http_shared_state(tmp_path):
    (tmp_path / "srv.ts").write_text(
        "import express from 'express'; const app = express();\n"
        "const sessions = new Map(); // Mcp-Session-Id\napp.listen(3000)\n")
    p = compute_deployment_profile(tmp_path)
    assert p.transport == "http-capable" and p.isolation == "shared-state-capable"
    assert p.multi_tenant_exposure in ("conditional", "likely")
    assert "Deployment profile" in p.render()


def test_agreement_conditional_semantics():
    f = requires_agreement("confirmed", "confirmed-conditional")
    assert f.verdict == "confirmed-conditional" and f.agreed
    assert requires_agreement("confirmed-conditional", "confirmed-conditional").verdict == "confirmed-conditional"
    assert requires_agreement("confirmed", "confirmed").verdict == "confirmed"
    assert requires_agreement("confirmed-conditional", "refuted").verdict == "unconfirmed"
    assert requires_agreement("confirmed-conditional", "unconfirmed").verdict == "unconfirmed"


def test_conditional_without_assumption_downgrades():
    r = _result_from_tool_input({"verdict": "confirmed-conditional", "severity": "HIGH", "cwe": "CWE-639", "reasoning": "x"}, "m")
    assert r.verdict == "unconfirmed"
    r = _result_from_tool_input({"verdict": "confirmed-conditional", "assumption": "shared instance", "severity": "HIGH", "cwe": "CWE-639", "reasoning": "x"}, "m")
    assert r.verdict == "confirmed-conditional" and r.assumption == "shared instance"


class _Stub:
    def __init__(self, r): self.r = r
    def adjudicate(self, card): return self.r


def _card():
    return ClaimCard(target_sink="s", tainted_source="t", precondition="p", violated_claim="v", caller_authority_assumed="c", impossibility_argument="i", evidence_path=[])


def test_gate_conditional_survives_with_assumption_and_lower_severity():
    a = AdversaryResult("confirmed-conditional", "r", "m", Severity.HIGH, "CWE-639", assumption="shared transport")
    b = AdversaryResult("confirmed-conditional", "r", "m2", Severity.HIGH, "CWE-639", assumption="shared transport")
    out = run_adversary_check(_card(), _Stub(a), _Stub(b))
    assert out.verdict == "adversary-reviewed" and out.conditional and out.assumption == "shared transport"
    assert out.severity == Severity.LOW or out.severity == Severity.MEDIUM
    plain = run_adversary_check(_card(), _Stub(AdversaryResult("confirmed", "r", "m", Severity.HIGH, "CWE-639")),
                                _Stub(AdversaryResult("confirmed", "r", "m", Severity.HIGH, "CWE-639")))
    assert not plain.conditional and plain.severity == Severity.HIGH


def test_cross_family_hook_default_off_and_config_errors():
    assert cross_family_adversary_from_env("/x", env={}) is None
    with pytest.raises(ValueError):
        cross_family_adversary_from_env("/x", env={"MCP_SAFEGUARD_ADVERSARY_PROVIDER": "openai-compatible"})
    with pytest.raises(ValueError):
        cross_family_adversary_from_env("/x", env={"MCP_SAFEGUARD_ADVERSARY_PROVIDER": "nope"})


def test_cross_family_adjudicate_parses_tool_call(tmp_path):
    seen = {}

    def post(url, headers, body):
        seen.update(url=url, auth=headers["Authorization"], model=body["model"])
        args = {"verdict": "confirmed-conditional", "assumption": "A", "severity": "MEDIUM", "cwe": "CWE-639", "reasoning": "r"}
        return {"choices": [{"message": {"tool_calls": [{"function": {"arguments": json.dumps(args)}}]}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1}}

    env = {"MCP_SAFEGUARD_ADVERSARY_PROVIDER": "openai-compatible", "MCP_SAFEGUARD_ADVERSARY_MODEL": "other-1",
           "MCP_SAFEGUARD_ADVERSARY_BASE_URL": "https://x.test/v1", "MCP_SAFEGUARD_ADVERSARY_API_KEY_ENV": "K", "K": "sekret"}
    be = cross_family_adversary_from_env(tmp_path, env=env)
    be._post = post
    r = be.adjudicate(_card())
    assert r.verdict == "confirmed-conditional" and r.assumption == "A"
    assert seen["url"] == "https://x.test/v1/chat/completions" and seen["model"] == "other-1"


def test_shared_block_includes_profile_and_conditional_section(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    block = adv.build_shared_repo_evidence_block(_card(), tmp_path)
    assert "Deployment profile" in block and "confirmed-conditional" in block
