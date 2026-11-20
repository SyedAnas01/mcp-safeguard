"""Tests for the recognition-gap-fix Part 1 primitive-inventory scanner
(primitive_inventory.py) -- see that module's own docstring and
bench/RECOGNITION_GAP_FIX_STATUS.md for the full design rationale. Same
discipline as test_cross_file.py: real tmp_path repos reproducing the
actual shapes this mechanism was validated against (loadPyodide/pyodide,
JWTIssuer/Fernet, a self-defined transport class with instance fields),
not mocked -- these tests prove the real scan/classify/render pipeline
works end to end, not just that it doesn't crash.
"""

from __future__ import annotations

import textwrap

import pytest

from mcp_safeguard.scanner.primitive_inventory import (
    PRIMITIVE_INSTRUCTION_TEXT,
    render_primitive_inventory_section,
    scan_primitive_inventory,
)


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text))


# --------------------------------------------------------------------------
# Python
# --------------------------------------------------------------------------


def test_python_third_party_call_site_is_inventoried(tmp_path):
    """A real third-party package (never resolvable to a local file at
    all) constructing a category-matching symbol must be flagged."""
    _write(
        tmp_path / "server.py",
        """
        from cryptography.fernet import Fernet

        def encrypt(key):
            return Fernet(key=key)
        """,
    )
    matches = scan_primitive_inventory(tmp_path, ["server.py"])
    assert len(matches) == 1
    m = matches[0]
    assert m.symbol == "Fernet"
    assert m.package == "cryptography.fernet"
    assert m.category == "tls-crypto-session-config"
    assert m.call_line == 5
    assert m.import_line == 2
    assert m.kind == "call"


def test_python_local_import_within_unit_is_not_flagged(tmp_path):
    """A category-matching symbol imported from a file that IS part of
    this unit's own shown evidence is not opaque -- its real
    implementation is right there, so it must not be inventoried."""
    _write(
        tmp_path / "jwt_issuer.py",
        """
        class JWTIssuer:
            def __init__(self, issuer, audience, signing_key):
                pass
        """,
    )
    _write(
        tmp_path / "oauth_proxy.py",
        """
        from jwt_issuer import JWTIssuer

        def make():
            return JWTIssuer(issuer="x", audience="y", signing_key="z")
        """,
    )
    matches = scan_primitive_inventory(tmp_path, ["oauth_proxy.py", "jwt_issuer.py"])
    # No CALL-SITE match for JWTIssuer -- its own real implementation is
    # part of this unit's evidence, so the call site is not opaque. (A
    # separate, correct self-defined-class hit on jwt_issuer.py's own
    # class declaration is expected and orthogonal -- see
    # test_python_self_defined_class_matching_category_is_inventoried.)
    call_matches = [m for m in matches if m.kind == "call"]
    assert call_matches == []


def test_python_local_import_outside_unit_is_flagged(tmp_path):
    """The real PrefectHQ/fastmcp shape: `JWTIssuer` is a real, LOCAL
    (first-party, same-repo) class -- but when the dispatch unit's own
    shown evidence is JUST oauth_proxy.py (not jwt_issuer.py, the
    credential-and-secrets angle's per-FILE unit granularity), the
    hunter cannot see JWTIssuer's real implementation either way. This is
    the exact case that motivates "opaque to THIS unit", not "third-party
    to the whole repo"."""
    _write(
        tmp_path / "jwt_issuer.py",
        """
        class JWTIssuer:
            def __init__(self, issuer, audience, signing_key):
                pass
        """,
    )
    _write(
        tmp_path / "oauth_proxy.py",
        """
        from jwt_issuer import JWTIssuer

        def make():
            return JWTIssuer(issuer="x", audience="y", signing_key="z")
        """,
    )
    # Only oauth_proxy.py is in this unit's own evidence -- jwt_issuer.py
    # is a real sibling file in the SAME repo, but not shown here.
    matches = scan_primitive_inventory(tmp_path, ["oauth_proxy.py"])
    assert len(matches) == 1
    assert matches[0].symbol == "JWTIssuer"
    assert matches[0].package == "jwt_issuer"
    assert matches[0].category == "token-issuer-or-verifier"


def test_python_stdlib_import_is_never_flagged(tmp_path):
    """Python's own standard library is never a 'third-party package' by
    any framing -- ssl.SSLContext-shaped code must not spam the table."""
    _write(
        tmp_path / "server.py",
        """
        import ssl

        def make():
            return ssl.SSLContext()
        """,
    )
    matches = scan_primitive_inventory(tmp_path, ["server.py"])
    assert matches == []


def test_python_call_with_no_category_match_is_not_inventoried(tmp_path):
    """A real third-party call that doesn't match any of the 4 fixed
    categories must not be inventoried -- this is a narrow, 4-category
    scan, not a general import inventory."""
    _write(
        tmp_path / "server.py",
        """
        import requests

        def fetch(url):
            return requests.get(url)
        """,
    )
    matches = scan_primitive_inventory(tmp_path, ["server.py"])
    assert matches == []


def test_python_self_defined_class_matching_category_is_inventoried(tmp_path):
    """A class DEFINED directly in this unit's own file, whose name
    matches one of the 4 categories, is inventoried even though nothing
    was imported (the typescript-sdk shape, mirrored for Python for
    consistency)."""
    _write(
        tmp_path / "server.py",
        """
        class TokenIssuer:
            def __init__(self):
                pass
        """,
    )
    matches = scan_primitive_inventory(tmp_path, ["server.py"])
    assert len(matches) == 1
    assert matches[0].symbol == "TokenIssuer"
    assert matches[0].kind == "self-defined-class"
    assert matches[0].category == "token-issuer-or-verifier"


# --------------------------------------------------------------------------
# JS/TS
# --------------------------------------------------------------------------

tree_sitter = pytest.importorskip("tree_sitter", reason="tree-sitter (static-taint extra) not installed")


def test_js_bare_package_import_call_site_is_inventoried(tmp_path):
    """The real Pydantic mcp-run-python shape: `loadPyodide` imported
    from the bare npm package `pyodide` (never resolvable to a local
    file) and called with no `jsglobals` key."""
    _write(
        tmp_path / "runCode.ts",
        """
        import { loadPyodide } from 'pyodide'

        async function run() {
          const pyodide = await loadPyodide({ stdout: console.log })
        }
        """,
    )
    matches = scan_primitive_inventory(tmp_path, ["runCode.ts"])
    assert len(matches) == 1
    m = matches[0]
    assert m.symbol == "loadPyodide"
    assert m.package == "pyodide"
    assert m.category == "interpreter-or-sandbox-loader"
    assert m.import_line == 2
    assert m.call_line == 5


def test_js_relative_import_within_unit_is_not_flagged(tmp_path):
    _write(
        tmp_path / "transport.ts",
        """
        export class McpServer {
          constructor() {}
        }
        """,
    )
    _write(
        tmp_path / "main.ts",
        """
        import { McpServer } from './transport'

        const server = new McpServer()
        """,
    )
    matches = scan_primitive_inventory(tmp_path, ["main.ts", "transport.ts"])
    # No CALL-SITE match for McpServer -- its own real implementation
    # (transport.ts) is part of this unit's evidence. A separate,
    # correct self-defined-class hit on transport.ts's own class
    # declaration is expected and orthogonal.
    call_matches = [m for m in matches if m.kind == "call"]
    assert call_matches == []


def test_js_relative_import_outside_unit_is_flagged(tmp_path):
    """Same 'opaque to THIS unit' shape as the Python JWTIssuer test,
    for a real local (relative-import) JS/TS module."""
    _write(
        tmp_path / "transport.ts",
        """
        export class McpServer {
          constructor() {}
        }
        """,
    )
    _write(
        tmp_path / "main.ts",
        """
        import { McpServer } from './transport'

        const server = new McpServer()
        """,
    )
    matches = scan_primitive_inventory(tmp_path, ["main.ts"])  # transport.ts NOT in this unit
    assert len(matches) == 1
    assert matches[0].symbol == "McpServer"
    assert matches[0].category == "transport-or-server-constructor"


def test_js_self_defined_class_and_fields_are_inventoried(tmp_path):
    """The real typescript-sdk shape: the audited unit's OWN file defines
    the transport/server-constructor class itself (no import at all), and
    its own instance fields (e.g. a request-ID -> stream map) are
    surfaced as candidate primitives too."""
    _write(
        tmp_path / "webStandardStreamableHttp.ts",
        """
        export class WebStandardStreamableHTTPServerTransport implements Transport {
          private sessionIdGenerator: (() => string) | undefined;
          private _requestToStreamMapping: Map<string, string> = new Map();
        }
        """,
    )
    matches = scan_primitive_inventory(tmp_path, ["webStandardStreamableHttp.ts"])
    kinds = {(m.symbol, m.kind) for m in matches}
    assert ("WebStandardStreamableHTTPServerTransport", "self-defined-class") in kinds
    assert ("_requestToStreamMapping", "self-defined-field") in kinds
    for m in matches:
        assert m.category == "transport-or-server-constructor"
        assert m.import_line is None


def test_js_unrelated_sdk_symbol_is_not_flagged_by_package_fallback(tmp_path):
    """A real regression this project's own dev process caught: an
    unrelated symbol (a type-guard function, not a constructor) imported
    from the SAME package path as a real transport class must not be
    swept in just because the package path contains an SDK name."""
    _write(
        tmp_path / "main.ts",
        """
        import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js'

        function check(msg) {
          return isInitializeRequest(msg)
        }
        """,
    )
    matches = scan_primitive_inventory(tmp_path, ["main.ts"])
    assert matches == []


def test_unsupported_language_is_scanned_as_empty_not_crash(tmp_path):
    _write(tmp_path / "main.go", "package main\n\nfunc main() {}\n")
    matches = scan_primitive_inventory(tmp_path, ["main.go"])
    assert matches == []


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------


def test_render_empty_inventory_says_so_honestly():
    section = render_primitive_inventory_section([], [])
    assert "No primitive matching" in section
    assert "|" not in section  # no table rendered when there's nothing to show


def test_render_inventory_renders_table_and_notes(tmp_path):
    _write(
        tmp_path / "server.py",
        """
        from cryptography.fernet import Fernet

        def encrypt(key):
            return Fernet(key=key)
        """,
    )
    matches = scan_primitive_inventory(tmp_path, ["server.py"])
    section = render_primitive_inventory_section(matches, ["a real contract note"])
    assert "Fernet" in section
    assert "cryptography.fernet" in section
    assert "server.py:5" in section
    assert "a real contract note" in section
    assert "Dependency notes" in section


def test_primitive_instruction_text_matches_experiment_wording():
    """The exact, validated Arm-2 instruction, reused byte-for-byte from
    RECOGNITION_GAP_EXPERIMENT_RESULTS.md Section 1a -- a regression test
    against silent rewording."""
    assert PRIMITIVE_INSTRUCTION_TEXT == (
        'ADDITIONAL INSTRUCTION FOR THIS DISPATCH: For each inventoried primitive above, before disposing any '
        'property as "holds", state its documented safe configuration, state whether this specific call site '
        'sets it, and cite the line. If you do not know the primitive\'s safe configuration, say '
        '"unknown-contract" rather than "holds".'
    )
