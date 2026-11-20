"""Part 1 of the recognition-gap fix -- a deterministic, no-LLM "primitive
inventory" pass for the per-unit hunter dispatch path (whole-handler-audit,
credential-and-secrets). See bench/RECOGNITION_GAP_FIX_STATUS.md and the
controlled experiment that validated this,
bench/RECOGNITION_GAP_EXPERIMENT_RESULTS_REFERENCE.md (copied verbatim into
this clone from mcp-safeguard-bench-work/recognition_gap_experiment/bench/
RECOGNITION_GAP_EXPERIMENT_RESULTS.md), for the full research motivation and
the exact real answers this mechanism is meant to reproduce.

The problem this closes: a hunter dispatch, shown a call site that
constructs a security-relevant primitive (a sandbox loader, a JWT issuer, a
transport/server constructor, a TLS/crypto/session config object), too
readily disposes the matching `property_dispositions` entry "holds" by
default -- reasoning about an ADJACENT, correctly-implemented property
(e.g. "the code checks the Origin header") and never separately checking
whether THIS SPECIFIC primitive's own documented safe-configuration
contract is actually satisfied at THIS call site. The experiment's Arm 2
(this mechanism, with no injected facts) cleanly flipped 1 of 3 real
misses (Pydantic mcp-run-python's missing `jsglobals`) at zero
maintenance cost and caused NO regression on 2 already-working targets.

What this module does, mechanically, with no LLM involved:

1. For every file in a dispatch unit's own shown evidence (one file for a
   `CredentialUnit`; the entrypoint file + its one-hop delegation files for
   a `HandlerUnit`), parse real imports (Python: `ast` + `cross_file.py`'s
   `build_python_import_map`; JS/TS: tree-sitter + `cross_file.py`'s
   `build_js_import_map` -- the SAME resolvers this module's own
   demand-driven `read_definition` tool already reuses, not a new parser).
2. Find every call/construction site (`Symbol(...)`, `new Symbol(...)`,
   `ns.Symbol(...)`) whose callee is bound by one of those imports.
3. Keep only the call sites whose import is OPAQUE to this unit's own
   evidence: either it doesn't resolve to a real local file in the repo at
   all (a genuine third-party package -- pyodide, cryptography.fernet, an
   npm package), OR it resolves to a real local file that is simply NOT
   part of THIS unit's own shown evidence set (e.g. a first-party sibling
   module whose own implementation this specific dispatch never shows --
   PrefectHQ/fastmcp's `JWTIssuer`, defined in a sibling `jwt_issuer.py`
   the `credential-and-secrets` unit for `oauth_proxy.py` never displays).
   From the dispatched model's own point of view both cases are equally
   opaque: it cannot see that symbol's real definition/contract in what it
   was given, so it must not silently assume the symbol's safe
   configuration "holds". This is a deliberate generalization of "third-
   party" beyond the strict whole-repo sense -- applied identically to
   every unit of every target, not special-cased to any one case (see
   bench/RECOGNITION_GAP_FIX_STATUS.md Section on this exact design
   decision, and why it's needed for the JWTIssuer case in particular).
   Python's standard-library modules (`sys.stdlib_module_names`) are never
   flagged this way; they are not a "third-party package" by any framing.
4. Classify each remaining call site into exactly one of the 4 fixed
   categories the experiment used (see `_CATEGORY_PATTERNS` below), keyed
   by matching the constructed symbol's own name (and, as a secondary
   signal, the package/module specifier) against a fixed keyword pattern
   per category. A call site matching none of the 4 categories is not
   inventoried -- this is intentionally narrow, not a general import
   inventory.
5. Separately (a deliberate, still-fully-mechanical extension beyond
   literal "imported from a third-party package", needed for the
   typescript-sdk case where the audited unit's OWN file defines the
   primitive rather than importing it -- see module docstring section
   "self-defined primitives" below): flag a class declared directly in the
   unit's own file whose NAME matches one of the 4 category patterns, and
   its own non-method instance-field declarations, as "self-defined"
   primitive rows.

No candidate/finding/severity judgment happens here -- this module only
produces a short, honest FACT table (line, package, symbol, call) to
prepend to a unit's evidence. See `contract_table.py` for Part 2, which
optionally attaches a real, externally-sourced contract note to a matched
`(package, symbol)` pair.

unwrapped-content-fix milestone: the rendered table's cells (call-site
snippet, package specifier, file path, symbol name) are all real repo-
derived text, taken from the scanned target's own source -- untrusted the
same way every other piece of repo-derived evidence in this codebase is
(see `untrusted_text.py`'s module docstring). Two fixes closed the gap
proven by `bench/v21_merge_verification/primitive_table_unwrapped_repro.py`:
`call_snippet` is now taken from a `lexical.strip_comments_and_docstrings()`-
stripped copy of the source (same discipline `hunter._read_lines`/
`_read_file_text` already apply, so an inline trailing comment on a matched
call line can no longer ride into the snippet), and
`render_primitive_inventory_section()` now wraps the table itself (not the
curated, hand-authored contract notes, which are trusted analyst content)
in `wrap_untrusted()` before returning it.
"""

from __future__ import annotations

import ast
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from .cross_file import (
    _JS_EXTS,
    build_js_import_map,
    build_python_import_map,
    resolve_js_module_file,
    resolve_python_module_file,
)
from .lexical import strip_comments_and_docstrings
from .untrusted_text import wrap_untrusted

# The 4 fixed categories the recognition-gap experiment used (see
# RECOGNITION_GAP_EXPERIMENT_RESULTS.md Section 0's own "4 arms" description
# and the Arm 2/3 primitive-inventory tables in Section 1b). Deliberately
# fixed and small -- this is NOT a general import inventory.
PRIMITIVE_CATEGORIES: tuple[str, ...] = (
    "interpreter-or-sandbox-loader",
    "token-issuer-or-verifier",
    "transport-or-server-constructor",
    "tls-crypto-session-config",
)

# Keyword patterns per category, matched against the constructed symbol's
# own name first, then (if that doesn't match) the raw package/module
# specifier text -- both real, observed examples from the experiment
# (loadPyodide/pyodide; JWTIssuer/Fernet; StreamableHTTPServerTransport,
# StdioServerTransport, McpServer, Server) and reasonable, honestly-generic
# widenings of the same shape, not per-target hardcoding. Plain
# case-insensitive SUBSTRING matching (no `\b` word-boundary anchoring):
# real class names in this space are routinely compound camelCase/PascalCase
# identifiers with no word-break character at all between components (e.g.
# typescript-sdk's actual class is `WebStandardStreamableHTTPServerTransport`
# -- a `\bserver\b`/`\btransport\b` boundary check would never match inside
# it, since nothing but letters separates "...Standard" from "Streamable..."
# or "...Server" from "Transport..."). A short generic word appearing as a
# substring of an unrelated identifier is a false positive with a low real
# cost here -- this only adds one row to a FACT table for the model to
# separately verify, never an accusation -- so substring matching is the
# right trade for this specific, bounded use.
_CATEGORY_PATTERNS: dict[str, re.Pattern[str]] = {
    "interpreter-or-sandbox-loader": re.compile(
        r"(?i)("
        r"loadpyodide|pyodide|vm2|isolated[-_]?vm|quickjs|duktape|"
        r"sandbox|interpreter|evalmachine|runinnewcontext|runinsandbox|"
        r"newcontext|eval_code"
        r")"
    ),
    "token-issuer-or-verifier": re.compile(
        r"(?i)("
        r"jwtissuer|jwtverifier|tokenissuer|tokenverifier|jsonwebtoken|"
        r"jose|pyjwt|authlib|oauthproxy|oauth2?(client|provider)?"
        r")"
    ),
    "transport-or-server-constructor": re.compile(
        r"(?i)("
        r"streamablehttpservertransport|stdioservertransport|mcpserver|"
        r"transport|server|createserver|httpserver|grpcserver|"
        r"websocketserver|listener"
        r")"
    ),
    "tls-crypto-session-config": re.compile(
        r"(?i)("
        r"fernet|cipher|tlscontext|sslcontext|createcipher|createhash|"
        r"createhmac|tls|ssl|sessionmiddleware|cookiesession|"
        r"secretkey"
        r")"
    ),
}

# A DELIBERATELY NARROWER fallback, checked against the raw package/module
# specifier only when the symbol name itself didn't already match anything
# above. Real Python package paths routinely contain a generic
# organizational word from `_CATEGORY_PATTERNS` above as an unrelated path
# SEGMENT (e.g. PrefectHQ/fastmcp's own `mcp.server.auth.provider` module,
# home to totally unrelated symbols like `TokenError`/`AuthorizeError`) --
# reusing the full, generic pattern set against the package string would
# misclassify every symbol imported from such a module. This fallback set
# keeps only compound/specific terms that are not routine path-naming noise.
_CATEGORY_PACKAGE_PATTERNS: dict[str, re.Pattern[str]] = {
    "interpreter-or-sandbox-loader": re.compile(r"(?i)(pyodide|vm2|isolated[-_]?vm|quickjs|duktape)"),
    "token-issuer-or-verifier": re.compile(r"(?i)(jwt|jose|pyjwt|authlib|oauth)"),
    # NOT bare "modelcontextprotocol"/"grpc"/"websocket" -- those would flag
    # EVERY symbol imported from an entire SDK package (e.g.
    # `isInitializeRequest`, a type-guard function, imported from
    # `@modelcontextprotocol/sdk/types.js`), not just transport/server
    # constructors. "streamablehttp"/"stdioserver" are specific submodule
    # path segments, unlikely to appear for an unrelated symbol.
    "transport-or-server-constructor": re.compile(r"(?i)(streamablehttp|stdioserver)"),
    "tls-crypto-session-config": re.compile(r"(?i)(fernet|cryptography)"),
}

_SNIPPET_MAX_CHARS = 160


@dataclass(frozen=True)
class PrimitiveMatch:
    """One row of the primitive-inventory table: a real call/construction
    site (or, for `kind="self-defined-*"`, a real declaration site) in one
    of the 4 fixed categories, opaque to the dispatch unit that surfaces
    it."""

    file: str
    import_line: int | None  # None for a self-defined primitive (nothing was imported)
    call_line: int
    package: str
    symbol: str
    call_snippet: str
    category: str
    kind: str  # "call" | "self-defined-class" | "self-defined-field"


def _classify(symbol: str, package: str = "") -> str | None:
    """Classify by the constructed SYMBOL's own name first (the meaningful
    signal); fall back to the narrower `_CATEGORY_PACKAGE_PATTERNS` against
    the raw package/module specifier only if the symbol name alone didn't
    match anything (see that dict's own comment for why the fallback must
    stay narrower than the symbol-name pattern set)."""
    for category, pattern in _CATEGORY_PATTERNS.items():
        if symbol and pattern.search(symbol):
            return category
    for category, pattern in _CATEGORY_PACKAGE_PATTERNS.items():
        if package and pattern.search(package):
            return category
    return None


def _bounded_line(lines: list[str], lineno: int, max_len: int = _SNIPPET_MAX_CHARS) -> str:
    text = lines[lineno - 1].strip() if 1 <= lineno <= len(lines) else ""
    if len(text) > max_len:
        text = text[: max_len - 3] + "..."
    return text


def _relpath(root: Path, raw: str) -> str:
    try:
        return str(Path(raw).resolve().relative_to(root))
    except ValueError:
        return raw


# --------------------------------------------------------------------------
# Python
# --------------------------------------------------------------------------


def _python_import_lines(tree: ast.Module) -> dict[str, int]:
    """Mirrors `cross_file.build_python_import_map`'s own walk, but records
    the import STATEMENT's line number for each local alias instead of what
    it refers to -- `build_python_import_map` doesn't carry a line number,
    and this module needs one for the inventory table's "Import line"
    column."""
    out: dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "*":
                    continue
                out[alias.asname or alias.name] = node.lineno
        elif isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".", 1)[0]
                out[local] = node.lineno
    return out


def _python_is_opaque(root: Path, current_file: Path, module: str | None, level: int, unit_files: set[str]) -> bool:
    if level and level > 0:
        # Relative import -- almost always resolves within the same
        # package. Still checked against unit_files below (not assumed
        # local-to-this-unit just because it's a relative import).
        pass
    elif not module:
        return False
    elif module.split(".", 1)[0] in sys.stdlib_module_names:
        return False
    resolved = resolve_python_module_file(root, current_file, module, level)
    if resolved is None:
        return True
    return _relpath(root, str(resolved)) not in unit_files


def _scan_python_calls(root: Path, rel_file: str, unit_files: set[str]) -> list[PrimitiveMatch]:
    abs_path = root / rel_file
    try:
        src = abs_path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(src)
    except (OSError, SyntaxError):
        return []
    # unwrapped-content-fix: `call_snippet` (below) must never surface an
    # inline trailing comment -- strip it first, same discipline
    # `hunter._read_lines`/`_read_file_text` already apply to every other
    # evidence excerpt this project shows a model.
    lines = strip_comments_and_docstrings(src, ".py").splitlines()
    import_map = build_python_import_map(tree)
    import_lines = _python_import_lines(tree)

    out: list[PrimitiveMatch] = []
    seen: set[tuple[int, str]] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        callee = node.func
        if isinstance(callee, ast.Name):
            local_name, attr = callee.id, None
        elif isinstance(callee, ast.Attribute) and isinstance(callee.value, ast.Name):
            local_name, attr = callee.value.id, callee.attr
        else:
            continue
        ref = import_map.get(local_name)
        if ref is None:
            continue
        symbol = attr if attr is not None else (ref.imported_name or local_name)
        category = _classify(symbol, ref.module or "")
        if category is None:
            continue
        if not _python_is_opaque(root, abs_path, ref.module, ref.level, unit_files):
            continue
        call_line = node.lineno
        key = (call_line, symbol)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            PrimitiveMatch(
                file=rel_file,
                import_line=import_lines.get(local_name),
                call_line=call_line,
                package=ref.module or local_name,
                symbol=symbol,
                call_snippet=_bounded_line(lines, call_line),
                category=category,
                kind="call",
            )
        )
    return out


def _scan_python_self_defined(rel_file: str, tree: ast.Module, lines: list[str]) -> list[PrimitiveMatch]:
    out: list[PrimitiveMatch] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        category = _classify(node.name)
        if category is None:
            continue
        out.append(
            PrimitiveMatch(
                file=rel_file,
                import_line=None,
                call_line=node.lineno,
                package="(self-defined in this file)",
                symbol=node.name,
                call_snippet=_bounded_line(lines, node.lineno),
                category=category,
                kind="self-defined-class",
            )
        )
    return out


def _scan_python_file(root: Path, rel_file: str, unit_files: set[str]) -> list[PrimitiveMatch]:
    abs_path = root / rel_file
    try:
        src = abs_path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(src)
    except (OSError, SyntaxError):
        return []
    # unwrapped-content-fix: same stripped-snippet discipline as
    # `_scan_python_calls` above.
    lines = strip_comments_and_docstrings(src, ".py").splitlines()
    return _scan_python_calls(root, rel_file, unit_files) + _scan_python_self_defined(rel_file, tree, lines)


# --------------------------------------------------------------------------
# JS/TS
# --------------------------------------------------------------------------


def _js_import_lines(root_node, src: bytes) -> dict[str, int]:
    """Same idea as `_python_import_lines`, walking `import_statement`
    nodes directly (mirrors `cross_file.build_js_import_map`'s own walk)
    to record each local binding's import-statement line."""
    from . import entrypoints_js as ejs

    out: dict[str, int] = {}
    for node in ejs.walk(root_node):
        if node.type != "import_statement":
            continue
        line = node.start_point[0] + 1
        clause = next((c for c in node.named_children if c.type == "import_clause"), None)
        if clause is None:
            continue
        for child in clause.children:
            if child.type == "identifier":
                out[ejs.node_text(child, src)] = line
            elif child.type == "namespace_import":
                idents = [c for c in child.named_children if c.type == "identifier"]
                if idents:
                    out[ejs.node_text(idents[-1], src)] = line
            elif child.type == "named_imports":
                for spec in child.named_children:
                    if spec.type != "import_specifier":
                        continue
                    name_node = spec.child_by_field_name("name")
                    alias_node = spec.child_by_field_name("alias")
                    if name_node is None:
                        continue
                    local = ejs.node_text(alias_node, src) if alias_node is not None else ejs.node_text(name_node, src)
                    out[local] = line
    return out


def _js_callee_parts(func_node, src: bytes) -> tuple[str, str | None] | None:
    if func_node.type == "identifier":
        from . import entrypoints_js as ejs

        return ejs.node_text(func_node, src), None
    if func_node.type == "member_expression":
        from . import entrypoints_js as ejs

        obj = func_node.child_by_field_name("object")
        prop = func_node.child_by_field_name("property")
        if obj is not None and prop is not None and obj.type == "identifier":
            return ejs.node_text(obj, src), ejs.node_text(prop, src)
    return None


def _scan_js_calls(root: Path, rel_file: str, root_node, src: bytes, unit_files: set[str]) -> list[PrimitiveMatch]:
    from . import entrypoints_js as ejs

    abs_path = root / rel_file
    import_map = build_js_import_map(root_node, src)
    import_lines = _js_import_lines(root_node, src)
    # unwrapped-content-fix: same stripped-snippet discipline as the Python
    # scan functions above -- `call_snippet` (below) must never surface an
    # inline trailing comment.
    lines = strip_comments_and_docstrings(src.decode("utf-8", errors="ignore"), Path(rel_file).suffix).splitlines()

    out: list[PrimitiveMatch] = []
    seen: set[tuple[int, str]] = set()
    for node in ejs.walk(root_node):
        if node.type == "new_expression":
            func_node = node.child_by_field_name("constructor")
        elif node.type == "call_expression":
            func_node = node.child_by_field_name("function")
        else:
            continue
        if func_node is None:
            continue
        parts = _js_callee_parts(func_node, src)
        if parts is None:
            continue
        base, attr = parts
        ref = import_map.get(base)
        if ref is None:
            continue
        if attr is not None and not (ref.is_namespace or ref.is_default):
            continue
        symbol = attr if attr is not None else (ref.imported_name or base)
        category = _classify(symbol, ref.source)
        if category is None:
            continue

        is_relative = ref.source.startswith("./") or ref.source.startswith("../")
        if is_relative:
            resolved = resolve_js_module_file(abs_path, ref.source)
            opaque = resolved is None or _relpath(root, str(resolved)) not in unit_files
        else:
            opaque = True  # bare package specifier -- always third-party/opaque
        if not opaque:
            continue

        call_line = node.start_point[0] + 1
        key = (call_line, symbol)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            PrimitiveMatch(
                file=rel_file,
                import_line=import_lines.get(base),
                call_line=call_line,
                package=ref.source,
                symbol=symbol,
                call_snippet=_bounded_line(lines, call_line),
                category=category,
                kind="call",
            )
        )
    return out


_JS_FIELD_NODE_TYPES = frozenset({"public_field_definition", "field_definition"})
_MAX_SELF_DEFINED_FIELDS_PER_CLASS = 5


def _scan_js_self_defined(rel_file: str, root_node, src: bytes) -> list[PrimitiveMatch]:
    from . import entrypoints_js as ejs

    # unwrapped-content-fix: same stripped-snippet discipline as
    # `_scan_js_calls` above.
    lines = strip_comments_and_docstrings(src.decode("utf-8", errors="ignore"), Path(rel_file).suffix).splitlines()
    out: list[PrimitiveMatch] = []
    for node in ejs.walk(root_node):
        if node.type not in ("class_declaration", "class"):
            continue
        name_node = node.child_by_field_name("name")
        if name_node is None:
            continue
        class_name = ejs.node_text(name_node, src)
        category = _classify(class_name)
        if category is None:
            continue
        class_line = node.start_point[0] + 1
        out.append(
            PrimitiveMatch(
                file=rel_file,
                import_line=None,
                call_line=class_line,
                package="(self-defined in this file)",
                symbol=class_name,
                call_snippet=_bounded_line(lines, class_line),
                category=category,
                kind="self-defined-class",
            )
        )
        body = node.child_by_field_name("body")
        if body is None:
            continue
        field_count = 0
        for child in body.named_children:
            if child.type not in _JS_FIELD_NODE_TYPES:
                continue
            field_count += 1
            if field_count > _MAX_SELF_DEFINED_FIELDS_PER_CLASS:
                break
            field_line = child.start_point[0] + 1
            field_name_node = child.child_by_field_name("name") or child.child_by_field_name("property")
            field_name = ejs.node_text(field_name_node, src) if field_name_node is not None else f"<field of {class_name}>"
            out.append(
                PrimitiveMatch(
                    file=rel_file,
                    import_line=None,
                    call_line=field_line,
                    package=f"(self-defined in this file, instance field of {class_name})",
                    symbol=field_name,
                    call_snippet=_bounded_line(lines, field_line),
                    category=category,
                    kind="self-defined-field",
                )
            )
    return out


def _scan_js_file(root: Path, rel_file: str, unit_files: set[str]) -> list[PrimitiveMatch]:
    try:
        from . import entrypoints_js as ejs
    except ImportError:
        return []
    parsed = ejs.parse_file(root / rel_file)
    if parsed is None:
        return []
    root_node, src = parsed
    return _scan_js_calls(root, rel_file, root_node, src, unit_files) + _scan_js_self_defined(rel_file, root_node, src)


# --------------------------------------------------------------------------
# Public entry point
# --------------------------------------------------------------------------


def scan_primitive_inventory(root: Path, unit_files: list[str]) -> list[PrimitiveMatch]:
    """The real, deterministic, no-LLM primitive-inventory scan for one
    dispatch unit. `unit_files` is the exact set of relative file paths
    that ARE shown in that unit's own evidence (see module docstring for
    what "opaque to this unit" means and why). Languages this project has
    no import resolver for (Go, Kotlin, Java, ...) are silently not
    scanned -- an honest, documented limitation (see
    `render_primitive_inventory_section` for how that's surfaced in the
    rendered table), not a crash or a guess."""
    unit_file_set = set(unit_files)
    matches: list[PrimitiveMatch] = []
    seen_files: set[str] = set()
    for rel in unit_files:
        if rel in seen_files:
            continue
        seen_files.add(rel)
        suffix = Path(rel).suffix
        if suffix == ".py":
            matches.extend(_scan_python_file(root, rel, unit_file_set))
        elif suffix in _JS_EXTS:
            matches.extend(_scan_js_file(root, rel, unit_file_set))
    return matches


def render_primitive_inventory_section(matches: list[PrimitiveMatch], contract_notes: list[str]) -> str:
    """Render the block placed directly under the prompt's `## Evidence`
    header, before the wrapped untrusted evidence -- exactly the placement
    the recognition-gap experiment validated (RECOGNITION_GAP_EXPERIMENT_RESULTS.md
    Section 1b/1c). Only the surrounding prose here and `contract_notes`
    (curated, hand-written safety guidance -- see contract_table.py's own
    module docstring) are trusted, analyst-authored content. The table
    itself is built entirely from repo-derived text (file paths, package/
    import specifiers, symbol names, call-site snippets, all taken
    verbatim from the scanned target's own source), so it is wrapped in
    `wrap_untrusted()` -- same discipline every other piece of repo-derived
    evidence in this project's prompts already gets (see this module's own
    docstring, "unwrapped-content-fix milestone", for the gap this closed)."""
    lines: list[str] = [
        "### Primitive inventory (deterministic scan -- no LLM involved)",
        (
            "This table was built by a fixed, non-LLM scanner: every call/construction site in this unit's "
            "own evidence whose callee is bound by an import that is opaque to this unit (a genuine "
            "third-party package, or a first-party module this unit's own evidence does not show), "
            "restricted to 4 fixed categories (interpreter/sandbox loaders, token issuers/verifiers, "
            "transport/server constructors, TLS/crypto/session config). It is a mechanical FACT list, not a "
            "safety judgment -- use it to make sure you actually check each primitive's own real "
            "configuration at its call site before disposing any related property, rather than assuming it "
            "\"holds\" by default."
        ),
    ]
    if not matches:
        lines.append(
            "\nNo primitive matching these 4 categories was found in this unit's own evidence (only "
            "local/resolvable/stdlib code was found, or this unit's files are in a language this scanner "
            "does not parse imports for)."
        )
    else:
        table_lines = ["| Import line | Call/declaration site | Package | Symbol | Call |", "|---|---|---|---|---|"]
        for m in matches:
            imp = f"{m.file}:{m.import_line}" if m.import_line else "(n/a -- self-defined in this unit's own file)"
            call_col = f"{m.file}:{m.call_line}"
            snippet = m.call_snippet.replace("|", "\\|") or "(n/a)"
            symbol = m.symbol.replace("|", "\\|")
            table_lines.append(f"| {imp} | {call_col} | {m.package} | `{symbol}` | `{snippet}` |")
        lines.append("\n" + wrap_untrusted("\n".join(table_lines)))
    if contract_notes:
        lines.append("\n#### Dependency notes for the primitive(s) matched above\n")
        lines.append("\n\n".join(contract_notes))
    return "\n".join(lines) + "\n\n"


# The exact, validated Arm-2 instruction (RECOGNITION_GAP_EXPERIMENT_RESULTS.md
# Section 1a), reused byte-for-byte -- reproduced here rather than only in
# hunter.py so a test importing this module can assert the exact wording
# without importing hunter.py's much larger module.
PRIMITIVE_INSTRUCTION_TEXT = (
    'ADDITIONAL INSTRUCTION FOR THIS DISPATCH: For each inventoried primitive above, before disposing any '
    'property as "holds", state its documented safe configuration, state whether this specific call site '
    'sets it, and cite the line. If you do not know the primitive\'s safe configuration, say '
    '"unknown-contract" rather than "holds".'
)
