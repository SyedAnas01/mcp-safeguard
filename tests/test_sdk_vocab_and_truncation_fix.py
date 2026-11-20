"""Regression tests for the SDK-vocab-and-truncation-fix milestone (merged
from `milestone-sdk-vocab-and-truncation-fix-work`, commit `01ca49e`; see
`bench/SDK_VOCAB_AND_TRUNCATION_FIX_STATUS.md`).

Four new code paths landed with zero dedicated unit tests -- validated only
by real cold-dispatch proof runs (see that status doc's own honest
Section 4 "Honest gap"). This file closes that gap:

  1. `entrypoints_go.py` shape F, `_try_interface_method_override`
  2. `entrypoints_js.py` shape I, `_interface_method_override_entries`
  3. `entrypoints.py` shape H, `_try_registry_subscript_assignment`
  4. `hunter.py`'s `_highest_density_window`

The positive case for each of the three new entrypoint shapes is tested
against a REAL, minimal, attributed excerpt of the actual upstream MCP SDK
source each shape was built to recover (`tests/fixtures/real_sdk_shapes/`),
not a synthetic recreation -- reproduced under each source repo's own
permissive license (MIT for modelcontextprotocol/*-sdk, Apache-2.0 for
PrefectHQ/fastmcp), the same "real, not synthetic" fixture discipline
`tests/test_benchmark_confirmed_vulnerable.py` already established for this
project. Each fixture file's own header comment carries the source repo,
commit, and license. Over-match guards (the negative case each shape's own
module docstring documents) use small synthetic snippets, matching this
project's existing convention for every other entrypoint shape's own guard
tests (see test_entrypoints.py/test_entrypoints_go.py/test_entrypoints_js.py).

`_highest_density_window` is tested three ways: a small hand-verifiable
synthetic case (exact window mechanics), the zero-hits fallback case, and a
real-file case read directly (read-only) from the actual, on-disk, pinned
-commit `PrefectHQ-fastmcp-oauth-token-reuse` target under
`sealed_holdout_v1/targets/` -- reproducing the exact documented real
result (window 1150-1210, not containing the real bug's own lines 808-810)
byte-for-byte against the real 2189-line file, not a trimmed excerpt (a
window's contents depend on the WHOLE file's own keyword distribution, so a
trimmed fixture could not reproduce the real result faithfully). That
target is read only, never modified.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_safeguard.scanner.entrypoints import recover_entrypoints
from mcp_safeguard.scanner.entrypoints_go import recover_go_entrypoints
from mcp_safeguard.scanner.entrypoints_js import recover_js_entrypoints
from mcp_safeguard.scanner.hunter import _highest_density_window, _read_lines, build_hunter_prompt

_FIXTURES = Path(__file__).parent / "fixtures" / "real_sdk_shapes"

# The real modelcontextprotocol/python-sdk / go-sdk / typescript-sdk clones
# this milestone's own real proof runs were built against (see
# bench/SDK_VOCAB_AND_TRUNCATION_FIX_STATUS.md) -- read-only in every test
# below, never written to.
_SEALED_HOLDOUT_TARGETS = Path("/Users/mr.syedanas/o1a/mcp-safeguard-bench-work/sealed_holdout_v1/targets")


def _write(path, text):
    import textwrap

    path.write_text(textwrap.dedent(text))


# --------------------------------------------------------------------------
# 1. Go shape F, interface_method_override (entrypoints_go.py)
# --------------------------------------------------------------------------


def test_go_interface_method_override_recovers_real_go_sdk_servehttp():
    """Real modelcontextprotocol/go-sdk shape (CVE-2026-33252):
    `StreamableHTTPHandler.ServeHTTP(w http.ResponseWriter, req *http.Request)`
    is a raw `http.Handler` interface override -- no `AddTool`/`ServerTool{}`
    call or literal anywhere in the type, so shapes A-E have no vocabulary
    for it at all. Real excerpt of the actual upstream source, see
    tests/fixtures/real_sdk_shapes/go_sdk/streamable_excerpt.go's own header."""
    eps = recover_go_entrypoints(_FIXTURES / "go_sdk")
    assert len(eps) == 1
    ep = eps[0]
    assert ep.function_name == "ServeHTTP"
    assert ep.sdk_shape == "interface_method_override"
    assert ep.confidence == "medium"
    assert ep.parameter_names == ["w", "req"]


def test_go_interface_method_override_wrong_first_param_type_is_not_recovered(tmp_path):
    """Over-match guard: a `ServeHTTP` method whose first parameter is NOT
    `http.ResponseWriter` (the one fixed, unambiguous vocabulary entry in
    `_INTERFACE_METHOD_SIGNATURES`) must not be treated as an interface
    -method override."""
    _write(
        tmp_path / "thing.go",
        """
        package mcp

        type Thing struct{}

        func (t *Thing) ServeHTTP(w SomeOtherWriter, req *Request) {
        }
        """,
    )
    assert recover_go_entrypoints(tmp_path) == []


def test_go_interface_method_override_plain_function_not_a_method_is_not_recovered(tmp_path):
    """Over-match guard: only a `method_declaration` (has a receiver) can
    implement a Go interface -- a receiver-less `ServeHTTP` function must
    not match shape F, per this shape's own module comment."""
    _write(
        tmp_path / "thing.go",
        """
        package mcp

        func ServeHTTP(w http.ResponseWriter, req *http.Request) {
        }
        """,
    )
    assert recover_go_entrypoints(tmp_path) == []


# --------------------------------------------------------------------------
# 2. TypeScript/JS shape I, interface_method_override_entries (entrypoints_js.py)
# --------------------------------------------------------------------------


def test_js_interface_method_override_recovers_real_typescript_sdk_transport():
    """Real modelcontextprotocol/typescript-sdk shape (CVE-2026-25536):
    `WebStandardStreamableHTTPServerTransport implements Transport` with a
    `handleRequest` method -- never registered via `registerTool`/`.tool()`/
    `setRequestHandler` (shapes A-H have no vocabulary for it). Real
    excerpt, see tests/fixtures/real_sdk_shapes/typescript_sdk/
    web_standard_streamable_http_excerpt.ts's own header."""
    eps = recover_js_entrypoints(_FIXTURES / "typescript_sdk")
    assert len(eps) == 1
    ep = eps[0]
    assert ep.function_name == "handleRequest"
    assert ep.sdk_shape == "interface_method_override"
    assert ep.confidence == "medium"
    assert ep.parameter_names == ["req", "options"]


def test_js_interface_method_override_no_transport_heritage_or_suffix_is_not_recovered(tmp_path):
    """Over-match guard: a class with NEITHER a `Transport`-heritage clause
    NOR a name ending in `Transport`/`Handler` must not be recovered, even
    though it has a `handleRequest` method -- the anchor signal
    (`_class_has_transport_signal`) requires one or the other."""
    _write(
        tmp_path / "thing.ts",
        """
        export class MyThing {
            async handleRequest(req: Request): Promise<Response> {
                return new Response();
            }
        }
        """,
    )
    assert recover_js_entrypoints(tmp_path) == []


def test_js_interface_method_override_transport_class_without_handler_method_is_not_recovered(tmp_path):
    """Over-match guard: a class implementing `Transport` with NO
    `handleRequest`/`handleConnection` method defined directly in it must
    not produce an entrypoint out of an unrelated method."""
    _write(
        tmp_path / "thing.ts",
        """
        export class MyTransport implements Transport {
            async otherMethod(req: Request): Promise<Response> {
                return new Response();
            }
        }
        """,
    )
    assert recover_js_entrypoints(tmp_path) == []


# --------------------------------------------------------------------------
# 3. Python shape H, registry_subscript_assignment (entrypoints.py)
# --------------------------------------------------------------------------


def test_python_registry_subscript_bare_closure_recovers_real_python_sdk_handler():
    """Real modelcontextprotocol/python-sdk shape (CVE-2026-52870):
    `self._request_handlers[GetTaskRequest] = _default_get_task`, a bare
    same-file closure reference (resolution step 1, identical to shape B's
    own resolution). Real excerpt, see
    tests/fixtures/real_sdk_shapes/python_sdk/experimental_excerpt.py's own
    header."""
    eps = recover_entrypoints(_FIXTURES / "python_sdk")
    assert len(eps) == 1
    ep = eps[0]
    assert ep.function_name == "_default_get_task"
    assert ep.sdk_shape == "registry_subscript_assignment"
    assert ep.confidence == "medium"
    assert ep.parameter_names == ["req"]


def test_python_registry_subscript_cross_file_constructor_hop_recovers_real_fastmcp_tool():
    """Real PrefectHQ/fastmcp shape: `tool = OpenAPITool(...)` (a local
    constructor call) then `self._tools[tool.name] = tool` two statements
    later, resolution step 2 (ONE bounded hop through a local
    -constructor-call variable, `OpenAPITool` resolved to its own `run`
    method DEFINED IN A DIFFERENT FILE -- the deliberate, narrow, cross-file
    exception this resolution step's own docstring documents). Real
    excerpt pair, see tests/fixtures/real_sdk_shapes/fastmcp_openapi/
    provider_excerpt.py and components_excerpt.py's own headers."""
    eps = recover_entrypoints(_FIXTURES / "fastmcp_openapi")
    assert len(eps) == 1
    ep = eps[0]
    assert ep.function_name == "run"
    assert ep.sdk_shape == "registry_subscript_assignment"
    assert ep.confidence == "medium"
    # the cross-file resolution must record the entry at the FILE the
    # handler method actually lives in (components_excerpt.py), never at
    # the registration call's own file (provider_excerpt.py) -- see
    # `_try_registry_subscript_assignment`'s own docstring.
    assert str(ep.file).endswith("components_excerpt.py")


def test_python_registry_subscript_unlisted_attribute_is_not_recovered(tmp_path):
    """Over-match guard: `self.<attr>[...] = <value>` where `<attr>` is NOT
    in `_REGISTRY_DICT_ATTRS` (`_request_handlers`/`_tools`/`tools`/
    `_handlers`) must not be treated as a registry assignment."""
    _write(
        tmp_path / "server.py",
        """
        class Server:
            def register(self):
                def some_handler(req):
                    pass
                self._other_registry[GetTaskRequest] = some_handler
        """,
    )
    assert recover_entrypoints(tmp_path) == []


def test_python_registry_subscript_unresolved_imported_value_is_not_recovered(tmp_path):
    """Over-match guard: an unresolved `<value>` -- here, a name imported
    from elsewhere, with no same-file function definition and no local
    constructor-call assignment -- must not fabricate an entrypoint.
    Silence, not a guess, same rule as every other shape in this module."""
    _write(
        tmp_path / "server.py",
        """
        from external import imported_handler

        class Server:
            def register(self):
                self._request_handlers[GetTaskRequest] = imported_handler
        """,
    )
    assert recover_entrypoints(tmp_path) == []


def test_python_registry_subscript_never_downgrades_an_existing_high_confidence_entry(tmp_path):
    """A function ALREADY recovered at `"high"` confidence by shape A
    (`@mcp.tool()`) that is ALSO registered via a dict-key subscript
    assignment elsewhere in the same file must keep its `"high"` shape-A
    entry -- shape H must never downgrade an entry shapes A-G already
    recovered at the same (file, function), per this module's own
    documented invariant."""
    _write(
        tmp_path / "server.py",
        """
        from fastmcp import FastMCP
        mcp = FastMCP("demo")

        class Server:
            def register(self):
                self._request_handlers[GetTaskRequest] = get_weather

        @mcp.tool()
        def get_weather(city: str) -> str:
            return city
        """,
    )
    eps = recover_entrypoints(tmp_path)
    assert len(eps) == 1
    ep = eps[0]
    assert ep.function_name == "get_weather"
    assert ep.sdk_shape == "fastmcp_decorator"
    assert ep.confidence == "high"


# --------------------------------------------------------------------------
# 4. hunter.py's _highest_density_window (Fix 2)
# --------------------------------------------------------------------------


def test_highest_density_window_centers_on_the_real_densest_hit_cluster():
    """Small, hand-verifiable synthetic case for the pure window-selection
    mechanics: two clusters of `_CREDENTIAL_NAME_RE` hits (`api_key`/
    `token`), a sparse one near the top and a denser one further down --
    the returned window must center on the DENSER cluster, not the first
    one encountered."""
    lines = ["line"] * 300
    # Sparse cluster: 2 hits, far apart, around line 20.
    lines[9] = "token = load()"  # line 10
    lines[39] = "api_key = load()"  # line 40
    # Dense cluster: 4 hits close together, around line 200.
    lines[194] = "token_a = load()"  # line 195
    lines[197] = "token_b = load()"  # line 198
    lines[200] = "api_key_a = load()"  # line 201
    lines[203] = "api_key_b = load()"  # line 204

    window = _highest_density_window(lines, 60)
    assert window is not None
    start, end = window
    # centered on the dense cluster (window/2 = 30 either side of the
    # densest hit line) -- must cover all 4 dense-cluster hits and none of
    # the sparse-cluster hits, confirming density (not first-seen order)
    # drives the choice.
    assert start <= 195 and end >= 204
    assert not (start <= 10 <= end)
    assert not (start <= 40 <= end)


def test_highest_density_window_returns_none_when_the_file_has_zero_hits():
    """The documented never-worse-than-before fallback: a file with no
    `_CREDENTIAL_NAME_RE`/`_PERMISSION_CHECK_NAME_RE` hit anywhere must
    return `None`, so the caller keeps the original flat top-of-file dump
    unchanged."""
    lines = [f"plain line {i}" for i in range(100)]
    assert _highest_density_window(lines, 60) is None


def test_highest_density_window_reproduces_the_real_documented_fastmcp_oauth_result():
    """Real-file, read-only regression check against the actual, on-disk,
    pinned-commit `PrefectHQ-fastmcp-oauth-token-reuse` target (never
    modified) -- reproduces the exact real result
    bench/SDK_VOCAB_AND_TRUNCATION_FIX_STATUS.md documents for
    `oauth_proxy.py`: the densest credential/permission-keyword cluster
    sits at lines 1150-1210, NOT at the real CVE-2025-69196 bug's own lines
    808-810. This is the honest, real, documented limitation of Fix 2 (a
    file with more than one dense credential region can have the wrong one
    win) -- locked in here as a real regression fixture, not re-derived
    from a trimmed excerpt (the winning window depends on the WHOLE file's
    keyword distribution, so only the real, complete file reproduces it
    faithfully)."""
    target = _SEALED_HOLDOUT_TARGETS / "PrefectHQ-fastmcp-oauth-token-reuse"
    oauth_proxy = target / "src" / "fastmcp" / "server" / "auth" / "oauth_proxy.py"
    if not oauth_proxy.is_file():
        pytest.skip(f"sealed_holdout_v1 target not present locally: {oauth_proxy}")

    lines = _read_lines(oauth_proxy)
    assert lines is not None
    window = _highest_density_window(lines, 60)

    assert window == (1150, 1210)
    start, end = window
    assert not (start <= 808 <= end) and not (start <= 810 <= end), (
        "the real bug's own lines (808-810) are documented as NOT inside the winning window -- "
        "if this now fails, Fix 2's window selection changed and "
        "bench/SDK_VOCAB_AND_TRUNCATION_FIX_STATUS.md section 2.3 needs re-checking, not this test loosened"
    )


def test_credential_and_secrets_evidence_shows_density_centered_window_for_path_matched_file(tmp_path):
    """End-to-end: a file matched only by PATH keyword (`auth` in the
    filename, per `_CRED_PATH_KEYWORDS`) with no recovered MCP entrypoint
    reaching it -- `build_hunter_prompt("credential-and-secrets", ...)`
    must show the new density-centered window and label, not the old flat
    `lines 1-N` dump, once a real credential-keyword hit exists."""
    lines = ["# padding line" for _ in range(80)]
    lines[75] = "api_key = os.environ['DEMO_KEY']"  # line 76, near the end
    _write(tmp_path / "auth_helper.py", "\n".join(lines) + "\n")

    prompt = build_hunter_prompt("credential-and-secrets", tmp_path)

    assert "centered on this file's highest-density credential/permission-keyword cluster" in prompt.text
    assert "api_key" in prompt.text
    # the old, unconditional flat dump would have shown only lines 1-60 and
    # never reached line 76's real hit at all.
    assert "showing lines 1-60" not in prompt.text
