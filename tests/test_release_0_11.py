"""0.11: research detectors wired into scan_source_tree, plus SS-004 precision."""
from pathlib import Path

import pytest

from mcp_safeguard.scanner.source_scanner import scan_source_tree

FIX = Path(__file__).parent / "fixtures"


def _ids(root):
    return sorted({f.rule_id for f in scan_source_tree(root)})


@pytest.mark.parametrize(
    "fixture,rule",
    [
        ("confused_deputy", "SRC-046"),
        ("passthrough", "SRC-041"),
        ("handle", "SRC-042"),
        ("rugpull", "SRC-043"),
        ("mrtr", "SRC-044"),
        ("cache", "SRC-045"),
    ],
)
def test_spec_detectors_fire_on_vuln_and_not_on_patched(tmp_path, fixture, rule):
    src = next((FIX / "ws4").glob(f"{fixture}_vuln.*"))
    pat = next((FIX / "ws4").glob(f"{fixture}_patched.*"))
    (tmp_path / "v").mkdir()
    (tmp_path / "p").mkdir()
    (tmp_path / "v" / src.name).write_text(src.read_text())
    (tmp_path / "p" / pat.name).write_text(pat.read_text())
    assert rule in _ids(tmp_path / "v")
    assert rule not in _ids(tmp_path / "p")


def test_ss004_wired_and_high_for_caller_chosen_client_id(tmp_path):
    (tmp_path / "a.py").write_text(
        "import requests\ndef f(client_id):\n    return requests.get(client_id).json()\n"
    )
    hits = [f for f in scan_source_tree(tmp_path) if f.rule_id == "SS-004"]
    assert hits and hits[0].severity.name == "HIGH"


def test_ss004_ignores_operator_constants_and_wellknown_base(tmp_path):
    (tmp_path / "a.ts").write_text(
        "const OAUTH_JWKS_URL = process.env.JWKS;\n"
        "const jwks = createRemoteJWKSet(new URL(OAUTH_JWKS_URL));\n"
        "async function d() { return fetch(`${authServerUrl}/.well-known/oauth-authorization-server`); }\n"
    )
    assert not [f for f in scan_source_tree(tmp_path) if f.rule_id == "SS-004"]


def test_ss004_issuer_without_visible_caller_input_is_medium_lead(tmp_path):
    (tmp_path / "a.ts").write_text(
        "function getJwks(issuer: string) {\n"
        "  return createRemoteJWKSet(new URL(`${issuer}/.well-known/jwks`));\n}\n"
    )
    hits = [f for f in scan_source_tree(tmp_path) if f.rule_id == "SS-004"]
    assert hits and all(f.severity.name == "MEDIUM" for f in hits)


def test_ss004_issuer_with_request_input_stays_high(tmp_path):
    (tmp_path / "a.ts").write_text(
        "async function h(req) {\n  const issuer = req.body.issuer;\n"
        "  return fetch(`${issuer}/.well-known/openid-configuration`);\n}\n"
    )
    hits = [f for f in scan_source_tree(tmp_path) if f.rule_id == "SS-004"]
    assert hits and hits[0].severity.name == "HIGH"
