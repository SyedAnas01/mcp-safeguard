"""Tests for S2 Threat Model Document generation (threat_model.py).

Deterministic, no LLM call, no network. `test_threat_model.py` mirrors the
project's own `_write`/`tmp_path` convention (see test_entrypoints.py).
"""

from __future__ import annotations

import subprocess
import textwrap

import pytest

from mcp_safeguard.scanner.threat_model import (
    ThreatModelDocument,
    _iter_sentences_with_lines,
    build_threat_model,
)


def _write(path, text):
    path.write_text(textwrap.dedent(text))


# --------------------------------------------------------------------------
# Entrypoint recovery reuse + declared-authority / safety-claim extraction
# --------------------------------------------------------------------------


def test_python_entrypoint_is_recovered_via_stage1_reuse(tmp_path):
    _write(
        tmp_path / "server.py",
        """
        from fastmcp import FastMCP
        mcp = FastMCP("demo")

        @mcp.tool()
        def get_weather(city: str) -> str:
            return city
        """,
    )
    tmd = build_threat_model(tmp_path, use_cache=False)
    assert len(tmd.entrypoints) == 1
    ep = tmd.entrypoints[0]
    assert ep.function_name == "get_weather"
    assert ep.parameter_names == ["city"]
    assert ep.sdk_shape == "fastmcp_decorator"


def test_readme_and_security_md_claims_extracted_with_correct_line(tmp_path):
    _write(
        tmp_path / "README.md",
        """
        # Demo server

        This tool is read-only and never writes to disk.
        Every request requires a valid API token.
        """,
    )
    _write(
        tmp_path / "SECURITY.md",
        """
        # Security

        All file paths must not escape the sandbox directory.
        """,
    )
    tmd = build_threat_model(tmp_path, use_cache=False)
    claim_texts = {c.text for c in tmd.claims}
    assert "This tool is read-only and never writes to disk." in claim_texts
    assert "Every request requires a valid API token." in claim_texts
    assert "All file paths must not escape the sandbox directory." in claim_texts

    readme_claim = next(c for c in tmd.claims if "read-only" in c.text)
    assert readme_claim.source_file.endswith("README.md")
    assert readme_claim.source_line == 4  # blank line 1, "# Demo server" 2, blank 3, claim 4
    assert readme_claim.keyword == "read-only"

    security_claim = next(c for c in tmd.claims if "sandbox" in c.text)
    assert security_claim.source_file.endswith("SECURITY.md")
    assert security_claim.source_line == 4
    assert security_claim.keyword == "must not"


def test_declared_authority_is_nearest_claim_in_same_file(tmp_path):
    """A docstring claim on the handler's own function is picked up as
    `declared_authority` -- via the same generic claim-extraction pass, not
    a second docstring-specific code path (see module docstring)."""
    _write(
        tmp_path / "server.py",
        """
        from fastmcp import FastMCP
        mcp = FastMCP("demo")

        @mcp.tool()
        def list_files(directory: str) -> list[str]:
            \"\"\"List files. This tool is read-only and only if the directory
            is inside the sandbox root.\"\"\"
            return []
        """,
    )
    tmd = build_threat_model(tmp_path, use_cache=False)
    ep = tmd.entrypoints[0]
    assert ep.declared_authority is not None
    assert "read-only" in ep.declared_authority.text.lower()
    assert ep.declared_authority.source_file.endswith("server.py")


def test_no_claims_found_is_an_empty_list_not_an_error(tmp_path):
    _write(tmp_path / "README.md", "# Demo\n\nNothing special here.\n")
    tmd = build_threat_model(tmp_path, use_cache=False)
    assert tmd.claims == []


# --------------------------------------------------------------------------
# Credential-access / permission-check inference (Python)
# --------------------------------------------------------------------------


def test_module_global_credential_access_with_no_permission_check_is_flagged(tmp_path):
    _write(
        tmp_path / "server.py",
        """
        from fastmcp import FastMCP
        mcp = FastMCP("demo")

        API_TOKEN = "super-secret"

        @mcp.tool()
        def call_upstream(payload: str) -> str:
            return upstream_request(API_TOKEN, payload)
        """,
    )
    tmd = build_threat_model(tmp_path, use_cache=False)
    ep = tmd.entrypoints[0]
    assert ep.has_unchecked_credential_access is True
    assert len(ep.credential_access) == 1
    access = ep.credential_access[0]
    assert access.name == "API_TOKEN"
    assert access.kind == "module_global"
    assert access.permission_check_before is False
    assert access.guarding_call is None


def test_credential_access_with_permission_check_before_is_not_flagged(tmp_path):
    _write(
        tmp_path / "server.py",
        """
        from fastmcp import FastMCP
        mcp = FastMCP("demo")

        API_TOKEN = "super-secret"

        @mcp.tool()
        def call_upstream(payload: str, caller: str) -> str:
            require_auth(caller)
            return upstream_request(API_TOKEN, payload)
        """,
    )
    tmd = build_threat_model(tmp_path, use_cache=False)
    ep = tmd.entrypoints[0]
    assert ep.has_unchecked_credential_access is False
    access = ep.credential_access[0]
    assert access.permission_check_before is True
    assert access.guarding_call == "require_auth(...)"


def test_self_attribute_credential_via_constructor_kwarg_is_recognized(tmp_path):
    """A generically-named `self.client` is still recognized as
    credential-shaped because its OWN constructor call passes a
    credential-shaped keyword argument."""
    _write(
        tmp_path / "server.py",
        """
        from fastmcp import FastMCP
        mcp = FastMCP("demo")

        class Handlers:
            def __init__(self):
                self.client = SomeSDK(api_key="secret-value")

            @mcp.tool()
            def do_thing(self, arg: str) -> str:
                return self.client.call(arg)
        """,
    )
    tmd = build_threat_model(tmp_path, use_cache=False)
    ep = next(e for e in tmd.entrypoints if e.function_name == "do_thing")
    assert ep.has_unchecked_credential_access is True
    assert ep.credential_access[0].name == "self.client"
    assert ep.credential_access[0].kind == "self_attribute"


def test_no_credential_shaped_names_yields_empty_credential_access(tmp_path):
    _write(
        tmp_path / "server.py",
        """
        from fastmcp import FastMCP
        mcp = FastMCP("demo")

        GREETING = "hello"

        @mcp.tool()
        def greet(name: str) -> str:
            return GREETING + name
        """,
    )
    tmd = build_threat_model(tmp_path, use_cache=False)
    ep = tmd.entrypoints[0]
    assert ep.credential_access == []
    assert ep.has_unchecked_credential_access is False


# --------------------------------------------------------------------------
# Commit resolution + caching
# --------------------------------------------------------------------------


def test_commit_falls_back_to_content_hash_outside_a_git_repo(tmp_path):
    _write(tmp_path / "server.py", "x = 1\n")
    tmd = build_threat_model(tmp_path, use_cache=False)
    assert tmd.commit.startswith("nogit-")


def test_commit_uses_real_git_rev_parse_inside_a_git_repo(tmp_path):
    _write(tmp_path / "server.py", "x = 1\n")
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "a@b.c"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=tmp_path, check=True)
    real_commit = subprocess.run(
        ["git", "-C", str(tmp_path), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()

    tmd = build_threat_model(tmp_path, use_cache=False)
    assert tmd.commit == real_commit
    assert not tmd.commit.startswith("nogit-")


def test_cache_is_reused_on_second_call_without_recomputing(tmp_path, monkeypatch):
    _write(
        tmp_path / "server.py",
        """
        from fastmcp import FastMCP
        mcp = FastMCP("demo")

        @mcp.tool()
        def get_weather(city: str) -> str:
            return city
        """,
    )
    import mcp_safeguard.scanner.threat_model as tm

    first = build_threat_model(tmp_path)
    # The cache must land in the global cache dir (redirected to an
    # isolated dir for tests by the autouse `_isolate_tmd_cache` fixture in
    # conftest.py), NEVER inside the scanned repo itself -- that in-target
    # location is exactly the cache-poisoning vulnerability this module's
    # "Security" docstring note describes.
    cache_files = list(tm._DEFAULT_CACHE_DIR.glob("*.json"))
    assert len(cache_files) == 1
    assert not (tmp_path / ".mcp_safeguard_cache").exists()

    def _boom(*_a, **_kw):
        raise AssertionError("recover_entrypoints was called -- the cache was not used")

    monkeypatch.setattr(tm, "recover_entrypoints", _boom)
    second = build_threat_model(tmp_path)
    assert second.entrypoints == first.entrypoints
    assert second.commit == first.commit


def test_cache_disabled_recomputes_every_call(tmp_path):
    import mcp_safeguard.scanner.threat_model as tm

    _write(
        tmp_path / "server.py",
        """
        from fastmcp import FastMCP
        mcp = FastMCP("demo")

        @mcp.tool()
        def get_weather(city: str) -> str:
            return city
        """,
    )
    build_threat_model(tmp_path, use_cache=False)
    assert not (tmp_path / ".mcp_safeguard_cache").exists()
    assert not tm._DEFAULT_CACHE_DIR.exists() or not list(tm._DEFAULT_CACHE_DIR.glob("*.json"))


def test_to_dict_from_dict_roundtrip_preserves_data(tmp_path):
    _write(
        tmp_path / "server.py",
        """
        from fastmcp import FastMCP
        mcp = FastMCP("demo")

        API_TOKEN = "secret"

        @mcp.tool()
        def call_upstream(payload: str) -> str:
            \"\"\"This tool requires no auth.\"\"\"
            return upstream_request(API_TOKEN, payload)
        """,
    )
    original = build_threat_model(tmp_path, use_cache=False)
    restored = ThreatModelDocument.from_dict(original.to_dict())
    assert restored == original


# --------------------------------------------------------------------------
# Sentence/line extraction primitive
# --------------------------------------------------------------------------


def test_iter_sentences_with_lines_never_crosses_a_newline():
    text = "First sentence here.\nSecond line, unrelated.\nThird one too."
    pairs = list(_iter_sentences_with_lines(text))
    assert ("First sentence here.", 1) in pairs
    assert ("Second line, unrelated.", 2) in pairs
    assert ("Third one too.", 3) in pairs


def test_iter_sentences_with_lines_splits_multiple_sentences_on_one_line():
    text = "Requires auth. Also validates input."
    pairs = list(_iter_sentences_with_lines(text))
    assert ("Requires auth.", 1) in pairs
    assert ("Also validates input.", 1) in pairs


# --------------------------------------------------------------------------
# JS/TS support (best-effort; skipped if the static-taint extra isn't
# installed, same discipline as build_threat_model's own ImportError
# tolerance).
# --------------------------------------------------------------------------

tree_sitter = pytest.importorskip("tree_sitter")


def test_js_entrypoint_is_recovered_via_stage1_reuse(tmp_path):
    _write(
        tmp_path / "server.js",
        """
        server.registerTool("get_weather", {}, async (args) => {
            return args.city;
        });
        """,
    )
    tmd = build_threat_model(tmp_path, use_cache=False)
    assert len(tmd.entrypoints) == 1
    assert tmd.entrypoints[0].file.endswith("server.js")


def test_js_module_global_credential_access_with_no_permission_check_is_flagged(tmp_path):
    _write(
        tmp_path / "server.js",
        """
        const API_TOKEN = "super-secret";

        server.registerTool("call_upstream", {}, async (args) => {
            return upstreamRequest(API_TOKEN, args.payload);
        });
        """,
    )
    tmd = build_threat_model(tmp_path, use_cache=False)
    ep = tmd.entrypoints[0]
    assert ep.has_unchecked_credential_access is True
    access = ep.credential_access[0]
    assert access.name == "API_TOKEN"
    assert access.kind == "module_global"
    assert access.permission_check_before is False


def test_js_credential_access_with_permission_check_before_is_not_flagged(tmp_path):
    _write(
        tmp_path / "server.js",
        """
        const API_TOKEN = "super-secret";

        server.registerTool("call_upstream", {}, async (args) => {
            requireAuth(args.caller);
            return upstreamRequest(API_TOKEN, args.payload);
        });
        """,
    )
    tmd = build_threat_model(tmp_path, use_cache=False)
    ep = tmd.entrypoints[0]
    assert ep.has_unchecked_credential_access is False
    assert ep.credential_access[0].permission_check_before is True


# --------------------------------------------------------------------------
# Go entrypoint reuse (Stage 1's entrypoints_go.py, reused verbatim --
# `_go_profile_for` attaches no credential_access/delegates_to inference,
# see that function's own docstring for why).
# --------------------------------------------------------------------------


def test_go_entrypoint_is_recovered_via_stage1_reuse(tmp_path):
    _write(
        tmp_path / "start.go",
        """
        package main

        func registerTools(s *server.MCPServer) {
            s.AddTool(
                mcp.Tool{Name: "get_weather"},
                handleGetWeather,
            )
        }

        func handleGetWeather(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
            return nil, nil
        }
        """,
    )
    tmd = build_threat_model(tmp_path, use_cache=False)
    assert len(tmd.entrypoints) == 1
    ep = tmd.entrypoints[0]
    assert ep.file.endswith("start.go")
    assert ep.function_name == "handleGetWeather"
    assert ep.credential_access == []
    assert ep.delegates_to is None


# --------------------------------------------------------------------------
# Kotlin entrypoint reuse (v10 consolidation-merge fix -- see
# bench/FINAL_COMPLETE_V10_STATUS.md's "Kotlin entrypoints not reaching the
# LLM hunter angles" section). The kotlin-support-work milestone wired
# `entrypoints_kotlin.py` into `taint_scanner.py` only; this module's own
# `build_threat_model()`/`_kotlin_profile_for` wiring is what makes a
# Kotlin repo's real entrypoints visible to the 4 LLM-based hunter angles
# via `hunter.build_hunter_prompt()`, which reads ONLY the TMD, never
# taint_scanner.py's own Stage 1 pass.
# --------------------------------------------------------------------------


def test_kotlin_entrypoint_is_recovered_via_stage1_reuse(tmp_path):
    _write(
        tmp_path / "FeedbackTool.kt",
        """
        package jetbrains.buildServer.ai.mcp.tools

        class FeedbackTool : McpTool {
            companion object {
                internal const val NAME = "feedback"
            }
            override val name = NAME
            override suspend fun execute(arguments: JsonObject?): McpToolResult {
                return McpToolResult()
            }
        }
        """,
    )
    tmd = build_threat_model(tmp_path, use_cache=False)
    assert len(tmd.entrypoints) == 1
    ep = tmd.entrypoints[0]
    assert ep.file.endswith("FeedbackTool.kt")
    assert ep.function_name == "execute"
    assert ep.credential_access == []
    assert ep.delegates_to is None


def test_kotlin_entrypoints_reach_hunter_prompts_not_just_taint_scanner(tmp_path):
    """The real gap this fix closes: before it, `hunter.build_hunter_prompt()`
    for any of the 4 LLM angles would show the "(no MCP entrypoints were
    recovered)" boilerplate for a Kotlin-only repo even though
    taint_scanner.py's own Stage 1 pass (entrypoints_kotlin.py) DID recover
    real entrypoints -- because build_hunter_prompt reads the TMD
    (threat_model.py), which never called entrypoints_kotlin.py at all until
    this fix. whole-handler-audit (a full, unwindowed file dump per
    recovered handler) is the most direct angle to prove this on."""
    from mcp_safeguard.scanner import hunter

    _write(
        tmp_path / "BuildLogTool.kt",
        """
        package jetbrains.buildServer.ai.mcp.tools.rest

        class BuildLogTool : McpTool {
            companion object {
                internal const val NAME = "teamcity_build_log"
            }
            override val name = NAME
            override suspend fun execute(arguments: JsonObject?): McpToolResult {
                return McpToolResult()
            }
        }
        """,
    )
    tmd = build_threat_model(tmp_path, use_cache=False)
    assert len(tmd.entrypoints) == 1

    prompt = hunter.build_hunter_prompt("whole-handler-audit", str(tmp_path), tmd).text
    assert "no MCP entrypoints were recovered" not in prompt
    assert "BuildLogTool" in prompt
    assert "execute" in prompt
