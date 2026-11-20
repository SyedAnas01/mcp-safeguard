"""Tests for Stage 1 MCP entrypoint recovery (entrypoints.py)."""

import textwrap

from mcp_safeguard.scanner.entrypoints import recover_entrypoints


def _write(path, text):
    path.write_text(textwrap.dedent(text))


def test_fastmcp_decorator_is_recovered(tmp_path):
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
    eps = recover_entrypoints(tmp_path)
    assert len(eps) == 1
    ep = eps[0]
    assert ep.function_name == "get_weather"
    assert ep.parameter_names == ["city"]
    assert ep.sdk_shape == "fastmcp_decorator"
    assert ep.confidence == "high"


def test_low_level_dispatcher_decorator_is_recovered_distinctly(tmp_path):
    """@server.call_tool() decorates a single dispatcher, not a per-tool
    handler -- tagged with its own sdk_shape rather than lumped in with
    FastMCP's per-tool decorator."""
    _write(
        tmp_path / "server.py",
        """
        @server.call_tool()
        async def handle_call_tool(name: str, arguments: dict):
            ...
        """,
    )
    eps = recover_entrypoints(tmp_path)
    assert len(eps) == 1
    assert eps[0].function_name == "handle_call_tool"
    assert eps[0].parameter_names == ["name", "arguments"]
    assert eps[0].sdk_shape == "low_level_dispatcher"


def test_direct_add_tool_call_is_resolved_in_same_file(tmp_path):
    _write(
        tmp_path / "server.py",
        """
        def get_weather(city: str) -> str:
            return city

        mcp.add_tool(get_weather)
        """,
    )
    eps = recover_entrypoints(tmp_path)
    assert len(eps) == 1
    assert eps[0].function_name == "get_weather"
    assert eps[0].sdk_shape == "add_tool_call"
    assert eps[0].confidence == "high"


def test_tool_from_function_call_is_resolved(tmp_path):
    _write(
        tmp_path / "server.py",
        """
        def get_weather(city: str) -> str:
            return city

        t = Tool.from_function(get_weather)
        """,
    )
    eps = recover_entrypoints(tmp_path)
    assert any(e.function_name == "get_weather" and e.sdk_shape == "tool_from_function" for e in eps)


def test_cross_file_list_then_loop_registration_is_recovered(tmp_path):
    """The exact registration shape behind the real aliyun/alibaba-cloud-
    ops-mcp-server command-injection bug: handlers are appended to a list in
    one file, and a SEPARATE file loops over that list to register them."""
    _write(
        tmp_path / "local_tools.py",
        """
        tools = []

        @tools.append
        def LOCAL_RunShellScript(script: str, timeout: int = 60):
            pass
        """,
    )
    _write(
        tmp_path / "server.py",
        """
        from . import local_tools

        for t in local_tools.tools:
            mcp.tool(t)
        """,
    )
    eps = recover_entrypoints(tmp_path)
    assert len(eps) == 1
    ep = eps[0]
    assert ep.function_name == "LOCAL_RunShellScript"
    assert ep.parameter_names == ["script", "timeout"]
    assert ep.sdk_shape == "list_loop_registration"
    assert ep.confidence == "medium"


def test_appended_but_never_looped_list_is_not_an_entrypoint(tmp_path):
    """Shape C requires BOTH halves -- appended to a list AND that list
    looped over somewhere. A list that's only ever appended to (never
    registered) must not be reported as an entrypoint."""
    _write(
        tmp_path / "local_tools.py",
        """
        tools = []

        @tools.append
        def some_helper(x: str):
            pass
        """,
    )
    eps = recover_entrypoints(tmp_path)
    assert eps == []


def test_test_directories_are_skipped(tmp_path):
    (tmp_path / "tests").mkdir()
    _write(
        tmp_path / "tests" / "test_server.py",
        """
        @mcp.tool()
        def not_a_real_handler(x: str):
            pass
        """,
    )
    eps = recover_entrypoints(tmp_path)
    assert eps == []


def test_plain_helper_function_is_not_an_entrypoint(tmp_path):
    _write(
        tmp_path / "server.py",
        """
        def helper(x: str) -> str:
            return x
        """,
    )
    assert recover_entrypoints(tmp_path) == []


# --------------------------------------------------------------------------
# Tool-name anchoring (shapes F/G) -- additive strategies for registry-
# dispatch shapes A-C's registration-CALL syntax cannot recognize. Real
# CrowdStrike/falcon-mcp (shape F) and mongodb-mcp-server-style (shape G)
# holdout targets -- see bench/TOOLNAME_ANCHOR_STATUS.md.
# --------------------------------------------------------------------------


def test_keyword_registration_with_self_bound_method_is_recovered(tmp_path):
    """The real CrowdStrike/falcon-mcp shape: a project-specific wrapper
    method (`_add_tool`, not one of `_REGISTRATION_CALL_NAMES`) called with
    ALL-keyword arguments -- `method=self.<handler>` paired with a literal
    `name="..."` in the SAME call."""
    _write(
        tmp_path / "module.py",
        """
        class CorrelationRulesModule(BaseModule):
            def register_tools(self, server):
                self._add_tool(
                    server=server,
                    method=self.create_correlation_rule,
                    name="create_correlation_rule",
                )

            def create_correlation_rule(self, customer_id: str, search_filter: str):
                pass
        """,
    )
    eps = recover_entrypoints(tmp_path)
    assert len(eps) == 1
    ep = eps[0]
    assert ep.function_name == "create_correlation_rule"
    assert ep.parameter_names == ["customer_id", "search_filter"]
    assert ep.sdk_shape == "keyword_registration"
    assert ep.confidence == "medium"


def test_keyword_registration_unresolvable_handler_is_not_an_entrypoint(tmp_path):
    """Over-match guard: a `name=`/`method=` pairing whose handler value
    does not resolve to any real function (module-level OR a method on the
    enclosing class) must not fabricate an entrypoint."""
    _write(
        tmp_path / "module.py",
        """
        class SomeModule:
            def register_tools(self, server):
                self._add_tool(server=server, method=self.does_not_exist, name="ghost_tool")
        """,
    )
    assert recover_entrypoints(tmp_path) == []


def test_keyword_registration_requires_handler_keyword_not_just_name(tmp_path):
    """Over-match guard: a literal string that happens to be a `name=`
    keyword value, with NO paired `method=`/`handler=`/... keyword in the
    SAME call, must not spuriously become an entrypoint even though a
    same-named function exists elsewhere in the file."""
    _write(
        tmp_path / "module.py",
        """
        def create_correlation_rule(customer_id: str):
            pass

        some_call(name="create_correlation_rule", other_kwarg=1)
        """,
    )
    assert recover_entrypoints(tmp_path) == []


def test_class_static_name_attribute_with_execute_method_is_recovered(tmp_path):
    """A class-per-tool OOP pattern (Python analog of the real
    mongodb-mcp-server shape): a `name = "..."` class attribute paired with
    an `execute` method defined directly in the SAME class."""
    _write(
        tmp_path / "tool.py",
        """
        class ListConnectionsTool:
            name = "list-connections"

            def execute(self):
                return self.session.connections
        """,
    )
    eps = recover_entrypoints(tmp_path)
    assert len(eps) == 1
    ep = eps[0]
    assert ep.function_name == "execute"
    assert ep.sdk_shape == "class_attribute_registration"
    assert ep.confidence == "medium"


def test_class_attribute_without_handler_method_is_not_an_entrypoint(tmp_path):
    """Over-match guard: a `name = "..."` class attribute with NO
    execute/run/call/handle/invoke method defined in that same class must
    not produce an entrypoint out of an unrelated method."""
    _write(
        tmp_path / "tool.py",
        """
        class NotATool:
            name = "just_a_label"

            def unrelated_method(self):
                return 1
        """,
    )
    assert recover_entrypoints(tmp_path) == []
