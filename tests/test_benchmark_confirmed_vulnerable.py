"""
A small, real-world benchmark: scan fixtures reproduced from ACTUAL,
independently-confirmed vulnerable MCP servers found during this project's
own coordinated-disclosure campaign, and assert the expected rule fires at
the expected location and severity.

This is different from every other test in this suite -- those use synthetic
fixtures written to exercise a rule's logic in isolation. This one is the
opposite: it proves a rule survives contact with real, messy, production
code (indirection through helper functions, multi-line calls, unrelated
surrounding logic) rather than only the clean shape a hand-written unit test
happens to produce. Fixtures are added here specifically because an earlier
version of a rule looked correct against its own unit tests but MISSED (or,
for SRC-020, falsely flagged) the real code when actually run against it --
see the git history / SRC-014, SRC-017, SRC-020 comments in source_scanner.py
for what each fix corrected.

Each fixture is a minimal, attributed excerpt of real, permissively-licensed
(MIT) open-source code -- see the fixture file's own header comment for the
source repo, commit, license, and the real disclosed finding it reproduces.
Nothing here is synthetic or hypothetical.
"""

from pathlib import Path

from mcp_safeguard.scanner.source_scanner import scan_source_tree

_FIXTURES = Path(__file__).parent / "fixtures" / "confirmed_vulnerable"


def test_microsoft_retail_sample_src017_fires_at_the_real_vulnerable_line():
    """
    microsoft/MCP-Server-and-PostgreSQL-Sample-Retail, commit
    1b6e188622fe413d9a882d6224be8bb23a537a44 -- the server's ONLY access
    control is a client-supplied x-rls-user-id header with no authentication
    anywhere in the request path. Independently confirmed (live-tested
    against the project's own shipped sample data): omitting the header
    returns all 50,000 customers instead of ~20,000 for one store.
    """
    target = _FIXTURES / "microsoft_retail_sample"
    findings = scan_source_tree(target)

    src017 = [f for f in findings if f.rule_id == "SRC-017"]
    assert src017, f"Expected SRC-017 to fire on the real vulnerable code, got: {findings}"

    finding = src017[0]
    assert finding.severity.value == "CRITICAL"
    assert "sales_analysis.py:" in finding.location
    # The finding must anchor at the actual assignment line (get_rls_user_id's
    # `rls_user_id = get_header(ctx, "x-rls-user-id")`), not somewhere else
    # in the file -- confirm the line number is in get_rls_user_id, not
    # inside the earlier get_header() helper it calls into.
    line_no = int(finding.location.rsplit(":", 1)[-1])
    source_lines = (target / "sales_analysis.py").read_text().splitlines()
    assert "rls_user_id" in source_lines[line_no - 1]
