"""Tests for Stage 1 MCP entrypoint recovery (Kotlin, entrypoints_kotlin.py).

No entrypoint recovery for Kotlin existed anywhere in this project before
this milestone -- these are the first tests for it. Every catch-case fixture
below is modeled directly on a real shape read from either the official
`io.modelcontextprotocol:kotlin-sdk` builder call or JetBrains/teamcity-mcp's
own real source (see entrypoints_kotlin.py's own module docstring and
bench/KOTLIN_SUPPORT_STATUS.md for the full real-target validation record).
"""

import textwrap

from mcp_safeguard.scanner.entrypoints_kotlin import recover_kotlin_entrypoints


def _write(path, text):
    path.write_text(textwrap.dedent(text))


def test_add_tool_trailing_lambda_is_recovered(tmp_path):
    """Shape A: the official kotlin-sdk's own `server.addTool(...) { }`
    builder call, trailing-lambda form, named arguments before it."""
    _write(
        tmp_path / "Setup.kt",
        """
        class Setup {
            fun configure(server: Server) {
                server.addTool(name = "echo", description = "d") { request ->
                    doWork(request)
                }
            }
        }
        """,
    )
    eps = recover_kotlin_entrypoints(tmp_path)
    assert len(eps) == 1
    ep = eps[0]
    assert ep.sdk_shape == "add_tool_call"
    assert ep.confidence == "high"
    assert ep.parameter_names == ["request"]


def test_add_tool_no_parens_bare_identifier_callee_is_recovered(tmp_path):
    """Shape A's other callee form: a bare `addTool { }` with no preceding
    parenthesized call at all (no named arguments)."""
    _write(
        tmp_path / "Setup2.kt",
        """
        fun configure() {
            addTool { z -> handle(z) }
        }
        """,
    )
    eps = recover_kotlin_entrypoints(tmp_path)
    assert len(eps) == 1
    assert eps[0].parameter_names == ["z"]


def test_add_tool_implicit_it_param_is_not_recovered(tmp_path):
    """Over-match guard / silence-not-a-guess: an implicit, undeclared `it`
    lambda parameter (no `lambda_parameters` node to read a name from) must
    not be recovered with a guessed parameter name."""
    _write(
        tmp_path / "Setup3.kt",
        """
        class Setup {
            fun configure(server: Server) {
                server.addTool(name = "echo") {
                    doWork(it)
                }
            }
        }
        """,
    )
    assert recover_kotlin_entrypoints(tmp_path) == []


def test_unrelated_trailing_lambda_call_is_not_recovered(tmp_path):
    """Over-match guard: a trailing-lambda call whose callee is NOT
    `addTool` must not be treated as shape A."""
    _write(
        tmp_path / "Other.kt",
        """
        fun setup() {
            registerSomethingElse(name = "echo") { request ->
                doWork(request)
            }
        }
        """,
    )
    assert recover_kotlin_entrypoints(tmp_path) == []


def test_class_name_property_with_companion_const_and_execute_is_recovered(tmp_path):
    """Shape B, the real teamcity-mcp/BuildLogTool.kt shape: `override val
    name = NAME` referencing a companion-object `const val` (NOT an inline
    string literal) paired with a sibling `execute()` method. Unlike
    entrypoints.py's/entrypoints_js.py's own version of this shape, the
    anchor property's value is never required to resolve to a literal --
    see entrypoints_kotlin.py's own module docstring for why."""
    _write(
        tmp_path / "BuildLogTool.kt",
        """
        class BuildLogTool : McpTool {
            companion object {
                internal const val NAME = "teamcity_build_log"
            }
            override val name = NAME
            override suspend fun execute(arguments: JsonObject?): McpToolResult {
                val buildId = arguments
                return doStuff(buildId)
            }
        }
        """,
    )
    eps = recover_kotlin_entrypoints(tmp_path)
    assert len(eps) == 1
    ep = eps[0]
    assert ep.function_name == "execute"
    assert ep.parameter_names == ["arguments"]
    assert ep.sdk_shape == "class_attribute_registration"
    assert ep.confidence == "medium"


def test_class_name_property_referencing_another_classs_const_is_recovered(tmp_path):
    """Shape B, the real teamcity-mcp/RestPostBraveTool.kt shape:
    `override val name = RestPostTool.NAME` -- a DIFFERENT class's companion
    constant. This module's own same-file-only discipline never resolves
    this reference, but recovery must not be blocked by that failure (the
    anchor is the property NAME, not its resolved value)."""
    _write(
        tmp_path / "RestPostBraveTool.kt",
        """
        class RestPostBraveTool : McpTool {
            override val name = RestPostTool.NAME
            override suspend fun execute(arguments: JsonObject?): McpToolResult {
                return doStuff(arguments)
            }
        }
        """,
    )
    eps = recover_kotlin_entrypoints(tmp_path)
    assert len(eps) == 1
    assert eps[0].sdk_shape == "class_attribute_registration"


def test_class_without_name_property_is_not_recovered(tmp_path):
    """Over-match guard: a class with an `execute` method but no
    `name`/`toolName`/`tool_name`/`TOOL_NAME` property must not produce an
    entrypoint."""
    _write(
        tmp_path / "Helper.kt",
        """
        class QueryHelper {
            suspend fun execute(query: String): String {
                return run(query)
            }
        }
        """,
    )
    assert recover_kotlin_entrypoints(tmp_path) == []


def test_interface_abstract_method_is_not_recovered(tmp_path):
    """Regression guard for a real bug found while validating against
    teamcity-mcp: tree-sitter-kotlin parses `interface X { ... }` as the
    SAME `class_declaration` node type as a real class, and an interface's
    own abstract method signature (e.g. teamcity-mcp's own McpTool.kt:
    `suspend fun execute(arguments: JsonObject?): McpToolResult`, no body at
    all) has no `function_body` child. Without excluding it, EVERY MCP-tool
    interface definition would be wrongly recovered as an entrypoint
    alongside its real implementations, with no actual code for a sink to
    ever be in."""
    _write(
        tmp_path / "McpTool.kt",
        """
        interface McpTool {
            val name: String
            suspend fun execute(arguments: JsonObject?): McpToolResult
        }
        """,
    )
    assert recover_kotlin_entrypoints(tmp_path) == []


def test_shape_a_and_shape_b_together_do_not_collide(tmp_path):
    """The real teamcity-mcp shape end to end: a generic dispatch wrapper
    (shape A) that just forwards into each concrete tool's own `execute()`
    (shape B) -- both must be recovered, at their own distinct lines, with
    neither downgrading the other."""
    _write(
        tmp_path / "McpServerConfigurator.kt",
        """
        class McpServerConfigurator {
            fun configureServer(): Server {
                for (tool in getEnabledTools()) {
                    server.addTool(name = tool.name, description = tool.description) { request ->
                        tool.execute(request.arguments)
                    }
                }
                return server
            }
        }
        """,
    )
    _write(
        tmp_path / "FeedbackTool.kt",
        """
        class FeedbackTool : McpTool {
            companion object {
                internal const val NAME = "feedback"
            }
            override val name = NAME
            override suspend fun execute(arguments: JsonObject?): McpToolResult {
                return McpToolResult.success(arguments.toString())
            }
        }
        """,
    )
    eps = recover_kotlin_entrypoints(tmp_path)
    assert len(eps) == 2
    shapes = {ep.sdk_shape for ep in eps}
    assert shapes == {"add_tool_call", "class_attribute_registration"}
