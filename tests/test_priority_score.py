"""Tests for the S0 cheap pre-audit priority scorer (priority_score.py)."""

from __future__ import annotations

import subprocess
import textwrap

from mcp_safeguard.scanner.priority_score import (
    _combine,
    _compute_novelty_score,
    _compute_popularity_score,
    score_repo,
)


def _write(path, text):
    path.write_text(textwrap.dedent(text))


def _git(root, *args):
    subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, check=True)


def _init_git_repo(root):
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "test@example.com")
    _git(root, "config", "user.name", "Test")


def _commit_all(root, message="commit"):
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", message)
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


# --------------------------------------------------------------------------
# Attack surface: handler recovery + dangerous-sink categories
# --------------------------------------------------------------------------


def test_many_handlers_zero_dangerous_sinks_scores_near_zero(tmp_path):
    """The explicit design requirement: a repo with plenty of MCP handlers
    but no dangerous-sink category anywhere is low-value to deep-audit, and
    the multiplicative attack-surface formula must reflect that -- not just
    a middling score from averaging a high handler count against zero
    sinks. (Overall tier also depends on popularity/novelty -- see
    `test_zero_attack_surface_and_known_low_popularity_yields_skip_tier`
    for the full-pipeline "skip" case.)"""
    _write(
        tmp_path / "server.py",
        """
        from fastmcp import FastMCP
        mcp = FastMCP("demo")

        @mcp.tool()
        def add(a: int, b: int) -> int:
            return a + b

        @mcp.tool()
        def multiply(a: int, b: int) -> int:
            return a * b
        """,
    )
    result = score_repo(tmp_path)
    assert result.attack_surface.handler_count == 2
    assert result.attack_surface.dangerous_sink_categories == []
    assert result.attack_surface.score == 0.0
    assert result.tier != "deep_audit_candidate"


def test_zero_attack_surface_and_known_low_popularity_yields_skip_tier(tmp_path):
    """With popularity actually KNOWN to be low (not merely unset/neutral),
    a zero-attack-surface repo reaches the "skip" tier end to end."""
    _write(tmp_path / "server.py", "x = 1\n")
    result = score_repo(tmp_path, repo_metadata={"is_official_org": False})
    assert result.attack_surface.score == 0.0
    assert result.tier == "skip"


def test_handlers_plus_dangerous_sinks_scores_high(tmp_path):
    _write(
        tmp_path / "server.py",
        """
        import subprocess
        import requests
        from fastmcp import FastMCP
        mcp = FastMCP("demo")

        @mcp.tool()
        def run_cmd(cmd: str) -> str:
            api_key = "sk-abc123"
            requests.get("https://api.example.com", headers={"Authorization": api_key})
            return subprocess.check_output(cmd, shell=True)
        """,
    )
    result = score_repo(tmp_path)
    assert result.attack_surface.handler_count == 1
    assert set(result.attack_surface.dangerous_sink_categories) >= {
        "process_exec",
        "network_outbound",
        "credential_handling",
    }
    assert result.attack_surface.score > 0.0


def test_sink_pattern_in_comment_or_docstring_is_not_counted(tmp_path):
    """A comment or docstring merely mentioning a dangerous call must not
    inflate the count -- strip_comments_and_docstrings is applied before
    grepping."""
    _write(
        tmp_path / "server.py",
        '''
        from fastmcp import FastMCP
        mcp = FastMCP("demo")

        @mcp.tool()
        def safe_tool(x: str) -> str:
            """This tool never calls subprocess.run(cmd, shell=True)."""
            # os.system(x) is explicitly NOT used here, see SECURITY.md
            return x
        '''
    )
    result = score_repo(tmp_path)
    assert result.attack_surface.dangerous_sink_categories == []
    assert result.attack_surface.dangerous_sink_hits["process_exec"] == 0


def test_dangerous_sink_in_test_dir_is_skipped(tmp_path):
    """A `_SKIP_DIR_PARTS`-matched directory (e.g. `tests/`) is excluded
    before it ever reaches file-role classification -- reflected in a lower
    candidate-file count, not `files_skipped_non_production` (that field
    counts files classify_file() itself rejected, see the sibling test
    below for that path)."""
    _write(
        tmp_path / "server.py",
        """
        from fastmcp import FastMCP
        mcp = FastMCP("demo")

        @mcp.tool()
        def echo(x: str) -> str:
            return x
        """,
    )
    (tmp_path / "tests").mkdir()
    _write(
        tmp_path / "tests" / "test_server.py",
        """
        import subprocess

        def test_something():
            subprocess.run(["echo", "hi"], shell=True)
        """,
    )
    result = score_repo(tmp_path)
    assert result.attack_surface.dangerous_sink_categories == []
    assert result.attack_surface.files_scanned == 1


def test_dangerous_sink_in_jest_style_test_filename_is_skipped(tmp_path):
    """lexical.py's filename-based test classification (`.test.ts`) must
    actually be applied even OUTSIDE a directory named tests/ -- exercises
    `classify_file()` itself, not just the directory-name pre-filter."""
    _write(
        tmp_path / "server.ts",
        """
        function echo(x: string): string { return x; }
        """,
    )
    _write(
        tmp_path / "server.test.ts",
        """
        import { exec } from "child_process";
        test("runs a command", () => { exec("echo hi"); });
        """,
    )
    result = score_repo(tmp_path)
    assert result.attack_surface.dangerous_sink_categories == []
    assert result.attack_surface.files_skipped_non_production >= 1


def test_database_query_requires_db_shaped_receiver_not_bare_array_find(tmp_path):
    """Regression test for a real false positive found during this module's
    own validation pass (grab/cursor-talk-to-figma-mcp): a bare `.find(`/
    `.findOne(` is also plain Array.prototype.find / a scene-graph API in
    any JS/TS codebase, not necessarily a database call."""
    _write(
        tmp_path / "server.ts",
        """
        const serverArg = args.find(arg => arg.startsWith('--server='));
        const cursorNode = importedNode.findOne(node => node.type === 'VECTOR');
        """,
    )
    result = score_repo(tmp_path)
    assert "database_query" not in result.attack_surface.dangerous_sink_categories


def test_database_query_detects_qualified_pool_construction(tmp_path):
    """Regression test for a real false negative found during this module's
    own validation pass (Aiven-Open/mcp-aiven): `new pg.Pool(...)` must
    match, not just the unqualified `new Pool(...)`."""
    _write(
        tmp_path / "db.ts",
        """
        import pg from "pg";
        const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
        """,
    )
    result = score_repo(tmp_path)
    assert "database_query" in result.attack_surface.dangerous_sink_categories


def test_single_dispatcher_handler_is_not_scored_as_near_zero_surface(tmp_path):
    """A low-level single-dispatcher shape (one recovered function serving
    every tool call) should not be scored as if it had almost no attack
    surface just because entrypoint recovery resolved to one function --
    the log-scaled handler factor exists specifically for this shape."""
    _write(
        tmp_path / "server.py",
        """
        import subprocess

        @server.call_tool()
        async def handle_call_tool(name: str, arguments: dict):
            return subprocess.run(arguments["cmd"], shell=True)
        """,
    )
    result = score_repo(tmp_path)
    assert result.attack_surface.handler_count == 1
    assert result.attack_surface.score > 0.0


# --------------------------------------------------------------------------
# Popularity / blast radius
# --------------------------------------------------------------------------


def test_popularity_defaults_to_neutral_unknown_without_metadata():
    result = _compute_popularity_score(None)
    assert result.score == 50.0
    assert result.basis == "unknown"


def test_popularity_empty_dict_is_also_unknown():
    result = _compute_popularity_score({})
    assert result.score == 50.0
    assert result.basis == "unknown"


def test_popularity_official_org_boosts_score():
    result = _compute_popularity_score({"is_official_org": True})
    assert result.basis == "metadata"
    assert result.score == 90.0


def test_popularity_non_official_org_scores_lower_than_unknown():
    result = _compute_popularity_score({"is_official_org": False})
    assert result.score == 20.0


def test_popularity_takes_max_of_available_signals():
    """A quiet star count should not drag down a repo an official org
    backs -- the strongest available signal wins, not an average."""
    result = _compute_popularity_score({"stars": 3, "is_official_org": True})
    assert result.score == 90.0


def test_popularity_stars_are_log_scaled_and_saturate():
    low = _compute_popularity_score({"stars": 10})
    high = _compute_popularity_score({"stars": 50_000})
    assert 0 < low.score < high.score
    assert high.score == 100.0


# --------------------------------------------------------------------------
# Novelty / freshness
# --------------------------------------------------------------------------


def test_novelty_never_scanned_scores_high(tmp_path):
    result = _compute_novelty_score(tmp_path, None)
    assert result.score == 100.0
    assert result.basis == "never_scanned"


def test_novelty_no_commit_info_for_non_git_directory_scores_high(tmp_path):
    result = _compute_novelty_score(tmp_path, "deadbeef")
    assert result.score == 100.0
    assert result.basis == "no_commit_info"
    assert result.current_commit is None


def test_novelty_unchanged_commit_scores_near_zero(tmp_path):
    _init_git_repo(tmp_path)
    (tmp_path / "a.py").write_text("x = 1\n")
    commit = _commit_all(tmp_path)

    result = _compute_novelty_score(tmp_path, commit)
    assert result.changed is False
    assert result.basis == "unchanged"
    assert result.score < 10.0


def test_novelty_changed_commit_scores_high(tmp_path):
    _init_git_repo(tmp_path)
    (tmp_path / "a.py").write_text("x = 1\n")
    old_commit = _commit_all(tmp_path, "first")
    (tmp_path / "a.py").write_text("x = 2\n")
    new_commit = _commit_all(tmp_path, "second")

    assert old_commit != new_commit
    result = _compute_novelty_score(tmp_path, old_commit)
    assert result.changed is True
    assert result.basis == "changed"
    assert result.score == 100.0


def test_score_repo_unchanged_commit_drops_tier_toward_skip(tmp_path):
    """End-to-end: a repo with real attack surface that hasn't changed
    since the last scan should be recommended for skipping THIS run, even
    though its attack-surface/popularity sub-scores alone would justify a
    deep audit -- this is what makes diff-triggered re-scanning cheap."""
    _init_git_repo(tmp_path)
    _write(
        tmp_path / "server.py",
        """
        import subprocess
        from fastmcp import FastMCP
        mcp = FastMCP("demo")

        @mcp.tool()
        def run_cmd(cmd: str) -> str:
            return subprocess.check_output(cmd, shell=True)
        """,
    )
    commit = _commit_all(tmp_path)

    unscanned = score_repo(tmp_path)
    already_scanned = score_repo(tmp_path, last_scanned_commit=commit)

    assert already_scanned.novelty.basis == "unchanged"
    assert already_scanned.combined_score < unscanned.combined_score
    assert already_scanned.tier == "skip"


# --------------------------------------------------------------------------
# Combination / tier thresholds
# --------------------------------------------------------------------------


def test_combine_reports_all_three_tiers():
    skip_combined, skip_tier = _combine(0.0, 0.0, 100.0)
    cheap_combined, cheap_tier = _combine(30.0, 50.0, 100.0)
    deep_combined, deep_tier = _combine(90.0, 90.0, 100.0)

    assert skip_tier == "skip"
    assert cheap_tier == "cheap_taint_pass"
    assert deep_tier == "deep_audit_candidate"
    assert skip_combined < cheap_combined < deep_combined


def test_priority_score_to_dict_never_collapses_into_one_number(tmp_path):
    """The design's own explicit requirement: sub-scores must always be
    reported individually, never only the combined number."""
    _write(tmp_path / "server.py", "x = 1\n")
    result = score_repo(tmp_path)
    payload = result.to_dict()
    assert set(payload) == {"repo_path", "attack_surface", "popularity", "novelty", "combined_score", "tier"}
    assert "score" in payload["attack_surface"]
    assert "score" in payload["popularity"]
    assert "score" in payload["novelty"]
