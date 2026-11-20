"""Bounded, single-hop cross-file import resolution (Python + JS/TS).

Both `entrypoints.py`/`entrypoints_js.py` (Stage 1) and `taint_scanner.py`'s
own `reconstruct_path`/`reconstruct_path_js` (Stage 3) are explicit, on the
record, about NOT chasing a handler or a helper call across files -- see
their own module docstrings ("Deliberately NOT attempted: a general call
graph, type inference, or resolving a handler passed through several layers
of indirection"). Two independent validations found the SAME real-world
consequence of that boundary: a JS/TS holdout target whose real bug is split
between a handler file and a shared client/utility module (see
`bench/MILESTONE_2_STATUS.md`), and a plausible root cause for some of
TAINT-IDOR's false positives (a real auth-check call that exists, just in a
helper imported from another file).

This module is the bounded fix: given a call this project's own AST/
tree-sitter walk already knows is tainted, and that resolves to a plain
`from X import Y` / `import X` (Python) or `import {Y} from './x'` /
`import * as X from './x'` (JS/TS) pointing at an actual file IN THIS SAME
REPO, follow the call ONE level deep into that file's matching function
definition and answer exactly one question: does the forwarded parameter
reach a dangerous sink there, or get cleared by a recognized sanitizer/
auth-check there? It deliberately does NOT do any of:

  - General call-graph construction, type inference, or resolving a handler
    passed through a factory/decorator/HOC -- exactly `entrypoints.py`'s own
    stated non-goals, just re-affirmed here for the one new case this module
    adds (a resolvable static import).
  - A SECOND hop. If the resolved callee's own body calls out to yet
    another cross-file or otherwise-unresolvable function along the tainted
    path, this module reports that fact (`"deeper_indirection"`) and stops
    -- taint_scanner.py records that as an explicit
    `unresolved_deeper_indirection` Step, never silently guessed at.
  - Resolving a third-party package import (`import requests`, `from
    zod import z`, bare-specifier JS package imports without a `./`/`../`
    prefix). Those are reported as `"external_call_unresolved"` --
    inconclusive, not "safe" and not "dangerous".
  - Any dynamic import shape (`importlib.import_module(...)`, `require(...)`
    with a computed argument, dynamic `import()`), namespace packages, or
    walking `sys.path`/`node_modules` resolution algorithms. Only the two
    concrete shapes the task names are handled: relative-or-simple-absolute
    Python imports resolved against the repo root (and a top-level `src/`
    if present), and relative (`./`, `../`) JS/TS specifiers resolved
    against the importing file's own directory -- both real, common,
    heuristic-but-reliable approximations of what Python/Node actually do,
    not a full reimplementation of either module system.

This module only does RESOLUTION (import maps, module-to-file lookup,
call-argument-to-callee-parameter mapping, function lookup by name). It has
no notion of a vulnerability class, a sink, or a sanitizer -- that logic
already lives in `taint_scanner.py` (`_call_name`, `_matches_sanitizer_name`,
`_VulnClass`), and keeping it there (rather than duplicating it here) avoids
a circular import between the two modules while still sharing the one
underlying design.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from .entrypoints import McpEntrypoint

_JS_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts")


@dataclass
class CrossFileHop:
    """One resolved single-hop jump from a real, Stage-1-recovered
    entrypoint into a locally-imported helper function, carrying a tainted
    argument built directly from that entrypoint's own parameter(s). Used
    to synthesize an ADDITIONAL entrypoint for the helper's own file (fed
    into the existing per-file rule generation exactly like a real
    entrypoint would be -- see taint_scanner.py's `run_static_taint_scan`),
    so semgrep can find a genuinely cross-file source-to-sink flow that its
    own intra-procedural, per-file-scoped rules could never see otherwise.
    """

    origin_entrypoint: McpEntrypoint
    call_line: int
    call_code: str
    target_file: Path
    target_function_name: str
    target_line: int
    mapped_params: list[str]
    synthetic_entrypoint: McpEntrypoint


def _relpath(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


# --------------------------------------------------------------------------
# Python: import resolution
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class PyImportRef:
    module: str | None  # dotted module path (e.g. "utils", "mypkg.utils"); None only for a
    # bare relative `from . import name`.
    imported_name: str | None  # the name imported FROM `module` (`from X import Y` -> "Y");
    # None means this local alias refers to the WHOLE MODULE (`import X`).
    level: int  # relative-import level (0 = absolute).


def build_python_import_map(tree: ast.Module) -> dict[str, PyImportRef]:
    """Map every local alias a `from`/plain `import` statement introduces
    to what it refers to. Walks the WHOLE tree (not just module-level
    statements), matching this project's existing no-scope-awareness
    discipline elsewhere (e.g. reconstruct_path's own `ast.walk(fn)`).
    Star imports (`from X import *`) are not resolved -- an unresolvable
    shape, not a guess."""
    out: dict[str, PyImportRef] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "*":
                    continue
                local = alias.asname or alias.name
                out[local] = PyImportRef(module=node.module, imported_name=alias.name, level=node.level or 0)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    out[alias.asname] = PyImportRef(module=alias.name, imported_name=None, level=0)
                else:
                    # `import a.b.c` (no alias) binds only the TOP name "a"
                    # in the importing scope -- Python's own binding rule.
                    # Deeper dotted access (`a.b.c.func()`) is out of scope
                    # (see module docstring); only a plain `import module`
                    # (one component) or an explicit alias is resolved.
                    top = alias.name.split(".", 1)[0]
                    out[top] = PyImportRef(module=top, imported_name=None, level=0)
    return out


def _resolve_module_path(candidate: Path) -> Path | None:
    py = candidate.with_suffix(".py")
    if py.is_file():
        return py
    init = candidate / "__init__.py"
    if init.is_file():
        return init
    return None


def resolve_python_module_file(root: Path, current_file: Path, module: str | None, level: int) -> Path | None:
    """Resolve an import's MODULE to a real local .py file. A relative
    import (`level > 0`) is resolved directly against `current_file`'s own
    directory -- Python's own rule, always reliable. An absolute import is
    tried against the repo root and, if present, a top-level `src/`
    directory -- the two overwhelmingly common real-world layouts, not a
    general sys.path/namespace-package resolver (see module docstring)."""
    if level and level > 0:
        base = current_file.parent
        for _ in range(level - 1):
            base = base.parent
        candidate = base.joinpath(*module.split(".")) if module else base
        return _resolve_module_path(candidate)
    if not module:
        return None
    parts = module.split(".")
    candidate_roots = [root]
    src_dir = root / "src"
    if src_dir.is_dir():
        candidate_roots.append(src_dir)
    for base in candidate_roots:
        resolved = _resolve_module_path(base.joinpath(*parts))
        if resolved is not None:
            return resolved
    return None


def resolve_python_call_target(
    call: ast.Call, import_map: dict[str, PyImportRef], root: Path, current_file: Path
) -> tuple[Path, str] | None:
    """Return `(resolved_file, function_name)` for a call whose callee is
    either a bare name imported via `from module import func` or an
    attribute access on a name imported via `import module`. Returns None
    for anything else (a same-file call, a builtin, a bare non-imported
    name, a chain deeper than one dot past the bound alias) -- not a
    resolvable cross-file call at all, so the existing same-file-only
    behavior applies unchanged."""
    func = call.func
    if isinstance(func, ast.Name):
        ref = import_map.get(func.id)
        if ref is None or ref.imported_name is None:
            return None
        target = resolve_python_module_file(root, current_file, ref.module, ref.level)
        return (target, ref.imported_name) if target is not None else None
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        ref = import_map.get(func.value.id)
        if ref is None or ref.imported_name is not None:
            return None
        target = resolve_python_module_file(root, current_file, ref.module, ref.level)
        return (target, func.attr) if target is not None else None
    return None


def find_python_function(
    file: Path, name: str
) -> tuple[ast.FunctionDef | ast.AsyncFunctionDef, ast.Module, list[str]] | None:
    """The named top-level-or-nested `def`/`async def` in `file`, plus the
    parsed tree and source lines (both needed by the caller to keep
    walking). None if the file can't be read/parsed or has no such
    function (a class, a re-exported name, a constant -- not a plain
    function this module can walk)."""
    try:
        source = file.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(source, filename=str(file))
    except (OSError, SyntaxError):
        return None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == name:
            return node, tree, source.splitlines()
    return None


def map_python_call_args(call: ast.Call, tainted: set[str], callee_params: list[str]) -> list[str]:
    """Which of `callee_params` (the target function's own formal
    parameter names, in order) receive a tainted value at this call site --
    a direct positional match, or a keyword-argument name match. An
    argument this can't confidently attribute to a specific callee
    parameter (e.g. `**kwargs` forwarding) is skipped, not guessed at."""
    mapped: set[str] = set()
    for i, arg in enumerate(call.args):
        if i >= len(callee_params):
            break
        names = {n.id for n in ast.walk(arg) if isinstance(n, ast.Name)}
        if names & tainted:
            mapped.add(callee_params[i])
    for kw in call.keywords:
        if kw.arg is None or kw.arg not in callee_params or kw.value is None:
            continue
        names = {n.id for n in ast.walk(kw.value) if isinstance(n, ast.Name)}
        if names & tainted:
            mapped.add(kw.arg)
    return sorted(mapped)


def find_python_cross_file_hops(entrypoints: list[McpEntrypoint], root: Path) -> list[CrossFileHop]:
    """For every recovered Python entrypoint, look for a call in its own
    body that forwards one of ITS OWN parameters (referenced directly, not
    tracked through an intermediate reassignment -- see module docstring's
    scope) into a function imported from another file in this repo. Each
    match becomes a `CrossFileHop` whose `synthetic_entrypoint` is fed into
    the SAME per-file rule generation `taint_scanner.py` already uses for
    real entrypoints, so a genuinely cross-file source-to-sink flow (the
    dominant real-world limiting factor this module exists to fix) gets a
    real chance at a semgrep hit in the callee's own file."""
    hops: list[CrossFileHop] = []
    seen: set[tuple] = set()
    parsed_cache: dict[Path, ast.Module | None] = {}

    for ep in entrypoints:
        if ep.file not in parsed_cache:
            try:
                parsed_cache[ep.file] = ast.parse(
                    ep.file.read_text(encoding="utf-8", errors="ignore"), filename=str(ep.file)
                )
            except (OSError, SyntaxError):
                parsed_cache[ep.file] = None
        tree = parsed_cache[ep.file]
        if tree is None:
            continue

        fn = next(
            (
                n
                for n in ast.walk(tree)
                if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)
                and n.name == ep.function_name
                and n.lineno == ep.line
            ),
            None,
        )
        if fn is None:
            continue

        import_map = build_python_import_map(tree)
        origin_params = set(ep.parameter_names)
        try:
            origin_lines = ep.file.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            origin_lines = []

        for call in sorted((n for n in ast.walk(fn) if isinstance(n, ast.Call)), key=lambda n: n.lineno):
            target = resolve_python_call_target(call, import_map, root, ep.file)
            if target is None:
                continue
            target_file, function_name = target
            found = find_python_function(target_file, function_name)
            if found is None:
                continue
            callee_fn, _, _ = found
            callee_params = [a.arg for a in callee_fn.args.args if a.arg not in ("self", "cls")]
            mapped = map_python_call_args(call, origin_params, callee_params)
            if not mapped:
                continue
            key = (target_file, callee_fn.lineno, tuple(mapped))
            if key in seen:
                continue
            seen.add(key)
            call_code = (
                origin_lines[call.lineno - 1].strip() if 0 < call.lineno <= len(origin_lines) else ""
            )
            hops.append(
                CrossFileHop(
                    origin_entrypoint=ep,
                    call_line=call.lineno,
                    call_code=call_code,
                    target_file=target_file,
                    target_function_name=function_name,
                    target_line=callee_fn.lineno,
                    mapped_params=mapped,
                    synthetic_entrypoint=McpEntrypoint(
                        file=target_file,
                        function_name=function_name,
                        line=callee_fn.lineno,
                        parameter_names=mapped,
                        sdk_shape="cross_file_hop",
                        confidence="medium",
                    ),
                )
            )
    return hops


# --------------------------------------------------------------------------
# JS/TS: import resolution
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class JsImportRef:
    source: str  # raw module specifier text, e.g. "./utils/labels.js"
    imported_name: str | None  # the original exported name for a named import; None for
    # a default or namespace import (see is_default/is_namespace).
    is_namespace: bool = False
    is_default: bool = False


def build_js_import_map(root_node, src: bytes) -> dict[str, JsImportRef]:
    """Map every local binding a JS/TS `import` statement introduces --
    named (`import { a, b as c } from './x'`), namespace
    (`import * as ns from './x'`), and default (`import def from './x'`)
    -- to the raw module specifier and (for a named import) the original
    exported name."""
    from . import entrypoints_js as ejs

    out: dict[str, JsImportRef] = {}
    for node in ejs.walk(root_node):
        if node.type != "import_statement":
            continue
        source_node = node.child_by_field_name("source")
        if source_node is None:
            continue
        source_text = ejs.node_text(source_node, src).strip("'\"")
        clause = next((c for c in node.named_children if c.type == "import_clause"), None)
        if clause is None:
            continue
        for child in clause.children:
            if child.type == "identifier":
                local = ejs.node_text(child, src)
                out[local] = JsImportRef(source=source_text, imported_name=None, is_default=True)
            elif child.type == "namespace_import":
                idents = [c for c in child.named_children if c.type == "identifier"]
                if idents:
                    local = ejs.node_text(idents[-1], src)
                    out[local] = JsImportRef(source=source_text, imported_name=None, is_namespace=True)
            elif child.type == "named_imports":
                for spec in child.named_children:
                    if spec.type != "import_specifier":
                        continue
                    name_node = spec.child_by_field_name("name")
                    alias_node = spec.child_by_field_name("alias")
                    if name_node is None:
                        continue
                    original = ejs.node_text(name_node, src)
                    local = ejs.node_text(alias_node, src) if alias_node is not None else original
                    out[local] = JsImportRef(source=source_text, imported_name=original)
    return out


def resolve_js_module_file(current_file: Path, source_spec: str) -> Path | None:
    """Resolve a relative (`./`, `../`) JS/TS import specifier to a real
    local file, trying the specifier as-is, each recognized extension
    appended, a recognized extension in the specifier itself SWAPPED for
    each other recognized extension, and an `index.<ext>` inside it if it's
    a directory. A bare package specifier (no `./`/`../` prefix) is a
    third-party import, never resolved here (see module docstring).

    Adversary-repo-read milestone: the extension-SWAP fallback (real,
    on-disk `.ts` source, imported via an explicit `.js`-suffixed
    specifier, e.g. `import { x } from './y.js'` resolving to the real
    `./y.ts`) is TypeScript's own standard ESM (`"moduleResolution":
    "node16"`/`"bundler"`) convention -- a source file keeps writing the
    specifier with the extension it will have AFTER compilation, not the
    one it has on disk today. Found as a real, confirmed gap while building
    the repo-reading adversary's own one-hop-out forward-call resolution
    (this exact function, reused via `resolve_js_call_target`) against a
    real target (auth0-mcp-server): `applications.ts`'s own
    `import { maskSensitiveFields } from '../utils/response-masker.js'`
    -- a real, everyday import in that repo -- silently failed to resolve
    to the real `response-masker.ts` before this fix, purely because the
    old code only ever APPENDED an extension to an already-extension-less
    specifier, never swapped one that was already present. This is a real
    correctness fix to shared, pre-existing machinery (also used by
    critic.py's/taint_scanner.py's own cross-file JS/TS resolution), not
    new behavior invented for the adversary path alone -- every specifier
    this function already resolved correctly still resolves exactly the
    same way (this is a new, additive fallback tried only after the
    existing as-is/append-extension checks both fail)."""
    if not (source_spec.startswith("./") or source_spec.startswith("../")):
        return None
    base = current_file.parent / source_spec
    try:
        base = base.resolve()
    except OSError:
        pass
    if base.is_file():
        return base
    for ext in _JS_EXTS:
        candidate = Path(str(base) + ext)
        if candidate.is_file():
            return candidate
    if base.suffix in _JS_EXTS:
        stem = base.with_suffix("")
        for ext in _JS_EXTS:
            candidate = Path(str(stem) + ext)
            if candidate.is_file():
                return candidate
    if base.is_dir():
        for ext in _JS_EXTS:
            candidate = base / f"index{ext}"
            if candidate.is_file():
                return candidate
    return None


def resolve_js_call_target(
    callee_node, import_map: dict[str, JsImportRef], current_file: Path, src: bytes
) -> tuple[Path, str] | None:
    """Return `(resolved_file, function_name)` for a call whose callee is
    either a bare identifier bound by a named/default import (the call IS
    the imported function) or a `namespace.func(...)`/`default.func(...)`
    member access on a namespace/default import. None for anything else."""
    from . import entrypoints_js as ejs

    if callee_node.type == "identifier":
        ref = import_map.get(ejs.node_text(callee_node, src))
        if ref is None or ref.is_namespace:
            return None
        target = resolve_js_module_file(current_file, ref.source)
        if target is None:
            return None
        return target, ref.imported_name if ref.imported_name is not None else "default"
    if callee_node.type == "member_expression":
        obj = callee_node.child_by_field_name("object")
        prop = callee_node.child_by_field_name("property")
        if obj is None or prop is None or obj.type != "identifier":
            return None
        ref = import_map.get(ejs.node_text(obj, src))
        if ref is None or not (ref.is_namespace or ref.is_default):
            return None
        target = resolve_js_module_file(current_file, ref.source)
        if target is None:
            return None
        return target, ejs.node_text(prop, src)
    return None


def _unwrap_param_node(node):
    if node.type in ("required_parameter", "optional_parameter"):
        inner = node.named_children[0] if node.named_children else None
        return inner if inner is not None else node
    if node.type in ("assignment_pattern", "object_assignment_pattern"):
        left = node.child_by_field_name("left")
        return left if left is not None else node
    return node


def _raw_param_nodes(fn_node) -> list:
    params = fn_node.child_by_field_name("parameters")
    if params is not None:
        return list(params.named_children)
    if fn_node.type == "arrow_function":
        body = fn_node.child_by_field_name("body")
        for child in fn_node.named_children:
            if child == body:
                break
            return [child]
    return []


def _object_pattern_key_map(node, src: bytes) -> dict[str, str]:
    """`{sourceKey: localName}` for an object-destructuring parameter node,
    e.g. `{ filenameStem }` -> `{"filenameStem": "filenameStem"}`,
    `{ filenameStem: stem }` -> `{"filenameStem": "stem"}`."""
    from . import entrypoints_js as ejs

    out: dict[str, str] = {}
    node = _unwrap_param_node(node)
    if node is None or node.type != "object_pattern":
        return out
    for child in node.named_children:
        if child.type == "shorthand_property_identifier_pattern":
            name = ejs.node_text(child, src)
            out[name] = name
        elif child.type == "pair_pattern":
            key_node = child.child_by_field_name("key")
            value_node = child.child_by_field_name("value")
            if key_node is None:
                continue
            key_text = ejs.node_text(key_node, src).strip("'\"")
            names = ejs.pattern_names(value_node, src) if value_node is not None else []
            if names:
                out[key_text] = names[0]
    return out


def _object_literal_tainted_keys(node, tainted: set[str], src: bytes) -> set[str]:
    """Property KEYS of an object-literal call argument whose value
    expression references a tainted identifier, e.g. for
    ``{ filenameStem: `${orderIdentifier}` }`` with `orderIdentifier`
    tainted -> `{"filenameStem"}`."""
    from . import entrypoints_js as ejs

    keys: set[str] = set()
    if node.type != "object":
        return keys
    for child in node.named_children:
        if child.type == "pair":
            key_node = child.child_by_field_name("key")
            value_node = child.child_by_field_name("value")
            if key_node is None or value_node is None:
                continue
            names = {ejs.node_text(n, src) for n in ejs.walk(value_node) if n.type == "identifier"}
            if names & tainted:
                keys.add(ejs.node_text(key_node, src).strip("'\""))
        elif child.type == "shorthand_property_identifier":
            name = ejs.node_text(child, src)
            if name in tainted:
                keys.add(name)
    return keys


def map_js_call_args(args_node, tainted: set[str], args_src: bytes, callee_fn, callee_src: bytes) -> list[str]:
    """Which of `callee_fn`'s own parameter name(s) receive a tainted
    value at this call site -- a direct positional identifier match, or
    (the common real shape per this milestone's own JS/TS work) an
    object-literal argument's property key matched against the callee's
    destructured parameter at that position, e.g.
    `save({ filenameStem: \\`${orderIdentifier}\\` })` into
    `function save({ filenameStem }) {...}`. A bare tainted identifier
    passed where the callee destructures an object is deliberately NOT
    mapped -- too imprecise to attribute to one specific field.

    `args_node` (the call site's own argument list) and `callee_fn` (the
    resolved target function) are two DIFFERENT files' tree-sitter nodes
    for a genuine cross-file call -- `args_src`/`callee_src` are their
    respective source-byte buffers, each used ONLY to decode nodes from
    its own tree. Passing the wrong buffer for either would silently slice
    the wrong byte range and produce garbage text that never matches
    anything (a real bug caught during this milestone's own JS validation,
    not a hypothetical -- see bench/MILESTONE_CROSSFILE_STATUS.md)."""
    from . import entrypoints_js as ejs

    if args_node is None:
        return []
    param_nodes = [_unwrap_param_node(p) for p in _raw_param_nodes(callee_fn)]
    mapped: set[str] = set()
    for i, arg in enumerate(args_node.named_children):
        if i >= len(param_nodes):
            break
        param_node = param_nodes[i]
        if arg.type == "object" and param_node.type == "object_pattern":
            key_map = _object_pattern_key_map(param_node, callee_src)
            for key in _object_literal_tainted_keys(arg, tainted, args_src):
                if key in key_map:
                    mapped.add(key_map[key])
        else:
            arg_names = {ejs.node_text(n, args_src) for n in ejs.walk(arg) if n.type == "identifier"}
            if arg_names & tainted and param_node.type == "identifier":
                mapped.add(ejs.node_text(param_node, callee_src))
    return sorted(mapped)


def find_js_cross_file_hops(entrypoints: list[McpEntrypoint], root: Path) -> list[CrossFileHop]:
    """The JS/TS sibling of `find_python_cross_file_hops` -- same job, same
    one-hop, direct-reference-only scope (see that function's docstring)."""
    from . import entrypoints_js as ejs

    hops: list[CrossFileHop] = []
    seen: set[tuple] = set()
    parsed_cache: dict[Path, tuple | None] = {}

    for ep in entrypoints:
        if ep.file not in parsed_cache:
            parsed_cache[ep.file] = ejs.parse_file(ep.file)
        parsed = parsed_cache[ep.file]
        if parsed is None:
            continue
        root_node, src = parsed

        fn = ejs.find_enclosing_function(root_node, ep.line)
        if fn is None:
            continue

        import_map = build_js_import_map(root_node, src)
        origin_params = set(ep.parameter_names)
        lines = src.decode("utf-8", errors="ignore").splitlines()

        calls = sorted((n for n in ejs.walk(fn) if n.type == "call_expression"), key=lambda n: n.start_byte)
        for call in calls:
            callee = call.child_by_field_name("function")
            args_node = call.child_by_field_name("arguments")
            if callee is None:
                continue
            target = resolve_js_call_target(callee, import_map, ep.file, src)
            if target is None:
                continue
            target_file, function_name = target
            target_parsed = ejs.parse_file(target_file)
            if target_parsed is None:
                continue
            target_root, target_src = target_parsed
            callee_fn = ejs.find_function_by_name(target_root, function_name, target_src)
            if callee_fn is None:
                continue
            mapped = map_js_call_args(args_node, origin_params, src, callee_fn, target_src)
            if not mapped:
                continue
            target_line = callee_fn.start_point[0] + 1
            key = (target_file, target_line, tuple(mapped))
            if key in seen:
                continue
            seen.add(key)
            call_line = call.start_point[0] + 1
            call_code = lines[call_line - 1].strip() if 0 < call_line <= len(lines) else ""
            hops.append(
                CrossFileHop(
                    origin_entrypoint=ep,
                    call_line=call_line,
                    call_code=call_code,
                    target_file=target_file,
                    target_function_name=function_name,
                    target_line=target_line,
                    mapped_params=mapped,
                    synthetic_entrypoint=McpEntrypoint(
                        file=target_file,
                        function_name=function_name,
                        line=target_line,
                        parameter_names=mapped,
                        sdk_shape="cross_file_hop",
                        confidence="medium",
                    ),
                )
            )
    return hops
