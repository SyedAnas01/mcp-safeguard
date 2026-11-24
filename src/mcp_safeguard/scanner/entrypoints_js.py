"""Stage 1: MCP entrypoint recovery (TypeScript/JavaScript).

The JS/TS sibling of `entrypoints.py` -- same job ("which functions in this
repository actually run when an MCP client calls a tool?"), same output
shape (`McpEntrypoint`, imported from that module rather than redefined), a
different language and a different parser. `entrypoints.py` uses Python's
own `ast` module because Python source is trivial to parse without a third
-party dependency; JS/TS has no such stdlib parser, and its syntax
(destructuring, arrow functions, optional chaining, TS type annotations)
is exactly the kind of thing regex cannot reliably walk, so this module
uses `tree-sitter` with the real `tree-sitter-javascript`/
`tree-sitter-typescript` grammars instead.

This module also exports a handful of small tree-sitter helpers (`parse_file`,
`find_enclosing_function`, `function_signature_pattern`, `pattern_names`,
`dotted_chain`, `node_text`, `walk`) that Stage 2/3 in taint_scanner.py
reuses for JS/TS rule generation and path reconstruction, rather than each
re-implementing its own tree walk -- the same "one shared parse, several
consumers" relationship entrypoints.py has with Python's own `ast` module,
just made explicit here since tree-sitter has no stdlib equivalent to lean
on implicitly.

Recognized registration shapes, each named in this milestone's own task
spec (the modern MCP TypeScript SDK's real call shapes) plus one addition
found necessary by validating against a real target (see shape E below):

  A. `server.registerTool(name, {...}, HANDLER)` -- the modern SDK shape.
     The last positional argument is the handler; earlier arguments (name,
     tool-config object) are not inspected further.
  B. `server.tool(name, ..., HANDLER)` -- the legacy SDK's `.tool()`, which
     has several positional-argument overloads (with/without a description
     string, with/without a Zod schema). Handled the same way as A: take
     the last positional argument as the handler, whatever came before it.
  C. `server.setRequestHandler(CallToolRequestSchema, HANDLER)` -- the
     low-level SDK's single-dispatcher shape, structurally the same
     concept as `entrypoints.py`'s Python `@server.call_tool()` case (one
     function serves every tool call): recognized by the first argument's
     own source text containing "calltool" (case-insensitive substring,
     e.g. `CallToolRequestSchema`), not by the exact schema import, since
     this module never resolves imports -- checking the literal name a
     project chose to alias it as would be a real regression there. Also
     matches the first argument being the bare JSON-RPC method-name string
     `"tools/call"` -- found necessary validating against a real target
     (Verantu-Labs/kenya-law-mcp) whose own lightweight `setRequestHandler`
     wrapper dispatches on the literal wire-protocol method name instead of
     importing the SDK's schema constant.
  D. In ALL of A-C, HANDLER is EITHER an inline function/arrow expression
     (the common case) OR a bare identifier referencing a function/const
     -arrow definition elsewhere in the SAME file (resolved by name --
     never across files, mirroring `entrypoints.py`'s explicit same-file
     -only discipline for its own shape B). An unresolved identifier
     (defined in another file, imported, or produced by a call) is simply
     not counted as an entrypoint -- silence, not a guess, same rule
     `entrypoints.py`'s own module docstring already states.
     Destructured handler parameters (`({ a, b }) => ...`) are extracted
     to their bound names either way -- per this milestone's own task
     spec this is the MOST common real shape, not an edge case, so
     `pattern_names()` below treats object/array-destructuring, default
     values, and rest parameters as first-class, not a fallback.
  E. `dispatch_call_arguments` (NOT one of the SDK's own shapes -- an
     addition made necessary by a real validation target, gomission/mcp,
     which hand-rolls its own zero-dependency MCP transport instead of
     using `@modelcontextprotocol/sdk` at all: no `registerTool`/`tool`/
     `setRequestHandler` call exists anywhere in that codebase). The real
     shape actually used there is a plain JSON-RPC dispatch: a `tools/
     call` branch invokes some `callTool(name, args)`-shaped function,
     passing the raw `params.arguments` (or `request.params.arguments`,
     or with a `|| {}` default-value fallback) straight through as one of
     the call's positional arguments. This shape recognizes exactly that:
     a call `F(..., X.arguments, ...)` (optionally `X.arguments || {}`)
     where `F` is a bare identifier resolved against a function/const
     -arrow definition IN THE SAME FILE (same same-file-only discipline as
     D) -- and recovers ONLY the positionally-aligned parameter of `F`
     (the one at the same argument index the `.arguments` expression was
     passed at), not every parameter of `F`, to avoid overtainting
     unrelated positional parameters (e.g. a leading `workspace`/`name`
     argument) that merely happen to sit in the same call. Tagged with
     its own `sdk_shape` and "medium" confidence (never "high"), the same
     way `entrypoints.py`'s own shape C (list-then-loop registration) is
     downgraded for the identical reason: matching a bare textual pattern
     across independent call sites is inherently more collision-prone
     than resolving a named decorator/registration call. Deliberately
     bounded to ONE hop, same as everything else in this module -- it
     does not chase `F` forwarding its own argument into a further
     function two calls deep. Validated directly against gomission/mcp:
     recovers `serve.mjs`'s `callTool(workspace, name, args = {})`, whose
     `args.receipt_id` path-traversal sink lives in that same function, so
     tier S catches it; `proxy.mjs`'s independent duplicate of the same
     bug sits one hop further inside `callBuiltin()` (`callTool` there
     only forwards to it), which this deliberately-bounded shape does not
     chase -- see MILESTONE_2_STATUS.md for the full accounting.

Per-file rule scoping (`generate_taint_rule_yaml_js` in taint_scanner.py)
re-applies the exact fix this project's Python milestone already had to
make for the identical class of bug (a same-shaped handler in an unrelated
file wrongly treated as the same entrypoint): every JS/TS taint rule this
module's output feeds into is scoped to the one file its entrypoints were
recovered from via `paths: include:`, not matched by shape alone repo-wide.

Deliberately NOT attempted, matching `entrypoints.py`'s own stated scope:
a general call graph, type inference, resolving a handler passed through
several layers of indirection (a factory function, a HOC, a decorator
-returning-decorator), or import resolution (a same-file name match is
required; `import { handler } from "./tools"` is not chased into `./
tools.ts`).

Tool-name anchoring (shapes F/G/H) -- a SECOND, ADDITIVE recovery strategy,
symmetric with `entrypoints.py`'s own shapes F/G: shapes A-E above all
require a *specific*, statically-resolvable registration-CALL syntax. Real,
campaign-confirmed holdout targets (Auth0, Aiven, mongodb-mcp-server -- see
bench/TOOLNAME_ANCHOR_STATUS.md for the full read of each one's actual
source) instead dispatch through a runtime name-to-handler mapping that
never appears as one of those call shapes at all. Every one of them still
declares its tool names as string literals somewhere, so this strategy
anchors on that literal instead of on call syntax:

  F. Object-literal registry entry (the real Aiven shape: `{ name:
     PgToolName.Read, handler: async (params, context) => {...} }` inside
     an array of such objects). Recognized by an object literal having BOTH
     a `name`/`toolName`/`tool_name` property AND a sibling `handler`/
     `execute`/`fn`/`callback`/`run` property in the SAME object -- the
     co-occurrence of both vocabulary keys on one object, with the handler
     resolving to a real function, IS the signal; the `name` value is
     resolved best-effort into a literal (directly, or through ONE hop --
     same file only, matching this module's own single-hop discipline
     elsewhere -- into a `const X = "..."` or `enum E { Member = "..." }`
     it references) but resolution failing does NOT block recovery. Real
     testing found Aiven's own `PgToolName` enum lives in a DIFFERENT file
     (`types.ts`) than the object literals referencing it (`handlers.ts`)
     -- requiring resolution to succeed would make this shape miss the
     exact real target it exists to catch, so the structural pairing alone
     is treated as sufficient (see the code comment at the one place this
     matters). The `handler` value is resolved the same way shapes A/B
     already do (`_resolve_handler`): inline, or a same-file identifier.
  G. Class static-attribute tool-name + sibling method (the real
     mongodb-mcp-server shape: `class ListConnectionsTool extends
     MongoDBToolBase { static toolName = "list-connections"; protected
     override async execute() {...} }`). Recognized by a class having a
     STATIC field named `toolName`/`name`/`TOOL_NAME` with a string-literal
     value, paired with a method DEFINED DIRECTLY in that same class named
     `execute`/`run`/`call`/`handle`/`invoke`. Unlike every other shape in
     this module, this one does NOT require the method to have any
     parameters -- confirmed by reading the real target: `execute()` reads
     from `this.session`/`this.config`, not from formal parameters, and
     `_resolve_handler`'s own `if not params: return` guard would silently
     drop the exact entrypoint this shape exists to recover.
  H. Tool-name-keyed registry object (the real Auth0 shape:
     `RESOURCE_SERVER_TOOLS: Tool[] = [{ name: 'auth0_get_resource_server',
     ... }, ...]` in one const, `RESOURCE_SERVER_HANDLERS: Record<string,
     ...> = { auth0_get_resource_server: async (request, config) => {...}
     }` in a SEPARATE const, same file). This is the shape closest to
     Fable's original literal spec: collect every string literal that is
     the `name` property of an object inside an array literal (a real
     `Tool[]`-schema signature) into a per-file `known_tool_names` set,
     then for every OTHER object literal in the same file, treat any
     property whose KEY TEXT (not a `name:` field -- the key itself IS the
     tool name here) is in that set as a registry entry and resolve its
     value as the handler, same as shape F.

All three require the literal-valued name signal AND a resolvable handler
reference to co-occur in the SAME lexical unit (one object literal's own
properties, or one class's own body) -- this bounds false positives to a
coincidental same-object/same-class collision of both signals at once, not
a stray string literal alone. All three are tagged "medium" confidence,
never "high" -- a naming-convention cross-reference is inherently more
collision-prone than resolving one of the SDK's own recognized calls, the
same reasoning `entrypoints.py`'s shape C already uses. An entrypoint
already recovered by shapes A-E at the same (file, line) is never
downgraded -- these three shapes only ever ADD entrypoints A-E missed.

Interface-method-override anchoring (shape I) -- SDK-vocab-and-truncation
-fix milestone, Fix 1a, a FOURTH additive strategy in the same tool-name
-anchoring family as F/G/H but anchored on the SDK's own TRANSPORT/protocol
-interface layer instead of a tool-registry shape at all:

  I. `interface_method_override` -- the real modelcontextprotocol/
     typescript-sdk shape (CVE-2026-25536): `export class
     WebStandardStreamableHTTPServerTransport implements Transport { ...
     async handleRequest(req: Request, ...): Promise<Response> {...} }`.
     None of shapes A-H apply: there is no `registerTool`/`.tool()`/
     `setRequestHandler` call anywhere in the class (it IS the transport a
     caller's own `server.connect(transport)` talks THROUGH, not a tool
     handler registered on one), no object-literal/class-static tool-name
     literal exists anywhere near it either. Recognized instead by a class
     whose heritage clause (`implements`/`extends`) names a type in
     `_TRANSPORT_HERITAGE_NAMES` (`Transport`) OR whose OWN class name ends
     in `_TRANSPORT_CLASS_NAME_SUFFIXES` (`Transport`/`Handler`), paired
     with a method DEFINED DIRECTLY in that class named `handleRequest`/
     `handleConnection`. Tagged "medium", same reasoning as F/G/H: the
     heritage/name signal alone does not confirm the method is actually
     invoked as a live MCP transport, only that it implements the SDK's own
     named interface contract.
"""

from __future__ import annotations

from pathlib import Path

from tree_sitter import Language, Node, Parser

from .entrypoints import _SKIP_DIR_PARTS as _PY_SKIP_DIR_PARTS
from .entrypoints import McpEntrypoint, _is_skip_dir_part

# JS/TS-specific additions on top of the shared skip list (node_modules,
# dist, vendor, .git, test(s), venv/.venv, benchmarks/examples/docs/.github
# are already covered there).
_SKIP_DIR_PARTS = _PY_SKIP_DIR_PARTS | frozenset({"build", "out", "coverage", ".next", "__tests__"})

EXTENSION_LANGUAGE = {
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".tsx": "tsx",
}

# Call names (last dotted component) whose LAST positional argument is the
# handler -- shapes A and B. Both `registerTool` and `tool` are tagged with
# distinct sdk_shapes below even though the recovery logic is identical,
# for the same reason entrypoints.py distinguishes add_tool_call from
# tool_from_function: an honest record of which real SDK call produced
# each entrypoint, not a claim that the mechanics differ.
_LAST_ARG_HANDLER_CALLS = {"registerTool": "registerTool_handler", "tool": "tool_call"}

_LOW_LEVEL_CALL_NAME = "setRequestHandler"

# Tool-name anchoring (shapes F/G/H, see module docstring). Object-literal
# property-key vocabularies for shape F.
_OBJ_LITERAL_NAME_KEYS = frozenset({"name", "toolName", "tool_name"})
_OBJ_LITERAL_HANDLER_KEYS = frozenset({"handler", "execute", "fn", "callback", "run"})

# Class static-field / method-name vocabularies for shape G.
_CLASS_STATIC_NAME_ATTRS = frozenset({"toolName", "name", "TOOL_NAME"})
_CLASS_HANDLER_METHOD_NAMES = frozenset({"execute", "run", "call", "handle", "invoke"})

# Interface-method-override vocabulary for shape I (see module docstring
# section above `_interface_method_override_entries`): a heritage-clause
# type name that marks a class as an SDK transport/protocol implementation,
# and the method name(s) real targets use for that interface's own single
# request-handling method.
_TRANSPORT_HERITAGE_NAMES = frozenset({"Transport"})
_TRANSPORT_METHOD_NAMES = frozenset({"handleRequest", "handleConnection"})
_TRANSPORT_CLASS_NAME_SUFFIXES = ("Transport", "Handler")

FUNCTION_LIKE_TYPES = frozenset(
    {"function_declaration", "function_expression", "arrow_function", "method_definition",
     "generator_function_declaration", "generator_function"}
)

_langs: dict[str, Language] = {}
_parsers: dict[str, Parser] = {}


def _language(name: str) -> Language:
    if name not in _langs:
        if name == "javascript":
            import tree_sitter_javascript as tsjavascript

            _langs[name] = Language(tsjavascript.language())
        else:
            import tree_sitter_typescript as tstypescript

            fn = tstypescript.language_tsx if name == "tsx" else tstypescript.language_typescript
            _langs[name] = Language(fn())
    return _langs[name]


def _parser(name: str) -> Parser:
    if name not in _parsers:
        _parsers[name] = Parser(_language(name))
    return _parsers[name]


def parse_file(path: Path) -> tuple[Node, bytes] | None:
    """Parse one JS/TS file by its extension. Returns (root_node, source
    -bytes), or None for an unsupported extension, an unreadable file, or
    a parse failure -- shared by this module's own recovery pass and by
    taint_scanner.py's Stage 2/3, which both need "give me a tree for this
    file" and nothing more."""
    lang = EXTENSION_LANGUAGE.get(path.suffix)
    if lang is None:
        return None
    try:
        src = path.read_bytes()
    except OSError:
        return None
    try:
        tree = _parser(lang).parse(src)
    except Exception:
        return None
    return tree.root_node, src


def iter_js_files(root: Path):
    for p in root.rglob("*"):
        if p.suffix not in EXTENSION_LANGUAGE or not p.is_file():
            continue
        try:
            rel_parts = p.relative_to(root).parts[:-1]
        except ValueError:
            rel_parts = p.parts[:-1]
        if any(_is_skip_dir_part(part, _SKIP_DIR_PARTS) for part in rel_parts):
            continue
        yield p


def walk(node: Node):
    """All descendants of `node`, including itself. Order is not source
    order (a stack-based traversal) -- callers that need source order
    (Stage 3's path reconstruction) sort by start_byte themselves,
    mirroring how entrypoints.py/taint_scanner.py sort by lineno."""
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(n.children)


def node_text(node: Node, src: bytes) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", errors="ignore")


def dotted_chain(node: Node, src: bytes) -> str:
    """Render a `member_expression` chain (`a.b.c`, `this.a.b`) or a bare
    `identifier`/`this` back to a dotted string, walking the `object`/
    `property` fields (not positional children, which include the `.`
    token itself). Anything else (a call result, a subscript, ...) yields
    ''. Mirrors entrypoints.py's `_dotted_chain` for the Python AST, plus a
    `this` root -- found necessary validating against real targets: the
    common class-wrapped server shape (`class X { m() { this.server.
    setRequestHandler(CallToolRequestSchema, ...) } }`) roots its call
    chain in `this`, not a plain identifier, and without this a `this.
    server.setRequestHandler(...)` call's chain came back '' and the whole
    call was silently invisible to every shape below."""
    parts: list[str] = []
    cur: Node | None = node
    while cur is not None and cur.type == "member_expression":
        prop = cur.child_by_field_name("property")
        if prop is None:
            return ""
        parts.append(node_text(prop, src))
        cur = cur.child_by_field_name("object")
    if cur is not None and cur.type in ("identifier", "this"):
        parts.append(node_text(cur, src))
        return ".".join(reversed(parts))
    return ""


# --------------------------------------------------------------------------
# Parameter-name / destructuring-target extraction: identifiers, TS's
# required/optional_parameter wrapper, destructuring (object/array
# patterns, incl. renamed/`pair_pattern` keys), default values
# (`assignment_pattern`/`object_assignment_pattern`), and rest parameters.
# Per this module's docstring, destructuring is a first-class shape here,
# not an edge case -- and Stage 3 (taint_scanner.py) reuses this same
# function to name the targets of a destructuring assignment, not just a
# handler's own formal parameters.
# --------------------------------------------------------------------------


def pattern_names(node: Node | None, src: bytes) -> list[str]:
    if node is None:
        return []
    t = node.type
    if t in ("required_parameter", "optional_parameter"):  # TS grammar's wrapper
        inner = node.named_children[0] if node.named_children else None
        return pattern_names(inner, src)
    if t == "identifier":
        return [node_text(node, src)]
    if t in ("assignment_pattern", "object_assignment_pattern"):  # `x = default`
        return pattern_names(node.child_by_field_name("left"), src)
    if t == "rest_pattern" or t == "rest_element":
        inner = node.named_children[0] if node.named_children else None
        return pattern_names(inner, src)
    if t == "object_pattern":
        names: list[str] = []
        for child in node.named_children:
            if child.type == "shorthand_property_identifier_pattern":
                names.append(node_text(child, src))
            elif child.type == "pair_pattern":
                names.extend(pattern_names(child.child_by_field_name("value"), src))
            else:  # object_assignment_pattern, rest_pattern
                names.extend(pattern_names(child, src))
        return names
    if t == "array_pattern":
        names = []
        for child in node.named_children:
            names.extend(pattern_names(child, src))
        return names
    return []


def function_params(fn_node: Node, src: bytes) -> list[str]:
    params = fn_node.child_by_field_name("parameters")
    if params is not None:
        names = []
        for child in params.named_children:
            names.extend(pattern_names(child, src))
        return names
    # Arrow functions with a single, unparenthesized, untyped parameter
    # (`x => ...`) have no `formal_parameters` wrapper at all -- the bare
    # pattern is the function node's own first named child, positioned
    # before its body.
    if fn_node.type == "arrow_function":
        body = fn_node.child_by_field_name("body")
        for child in fn_node.named_children:
            if child == body:
                break
            return pattern_names(child, src)
    return []


def function_signature_pattern(fn_node: Node, src: bytes) -> str | None:
    """Verbatim source text of `fn_node` from its start up to (not
    including) its own body, with the body itself replaced by a `{ ... }`
    ellipsis -- used as an exact, single-purpose `pattern-inside` anchor
    for Stage 2's generated taint rule (see taint_scanner.py). This is
    deliberately NOT a name-based anchor the way entrypoints.py/
    taint_scanner.py's Python source patterns are (`pattern-inside: def
    $F(...): ...` + a metavariable-regex over recovered names): most real
    JS/TS handlers are anonymous inline arrow/function expressions with no
    name to regex against at all. Matching the handler's own literal
    parameter-list text instead is at least as precise for a single
    recovered entrypoint, and combined with per-file `paths: include:`
    scoping (see taint_scanner.py's generate_taint_rule_yaml_js) it cannot
    cross-contaminate a same-shaped, differently-behaved handler in
    another file -- the same real bug this project's Python milestone
    found and fixed for its own (name-based) scoping.

    Returns None (an unresolved entrypoint, not a guess) if the body is
    not a `{ ... }` block -- a concise-body arrow (`x => x.foo()`) has no
    such block to anchor on, and is rare enough for a real multi-step tool
    handler (which needs to read args, do work, and return a result) that
    this module does not special-case it.
    """
    body = fn_node.child_by_field_name("body")
    if body is None or body.type != "statement_block":
        return None
    prefix = src[fn_node.start_byte : body.start_byte].decode("utf-8", errors="ignore").rstrip()
    if not prefix:
        return None
    return prefix + " { ... }"


# --------------------------------------------------------------------------
# Same-file identifier resolution (mirrors entrypoints.py's shape-B
# same-file-only discipline).
# --------------------------------------------------------------------------


def find_function_by_name(root_node: Node, name: str, src: bytes) -> Node | None:
    """A function declaration `function name(...) {...}`, or a
    const/let/var-bound arrow/function expression `const name = (...) =>
    {...}`, matching `name`, anywhere in the file (export wrappers included
    -- this walks the whole tree, not just top-level statements)."""
    for node in walk(root_node):
        if node.type == "function_declaration":
            name_node = node.child_by_field_name("name")
            if name_node is not None and node_text(name_node, src) == name:
                return node
        elif node.type == "variable_declarator":
            name_node = node.child_by_field_name("name")
            value_node = node.child_by_field_name("value")
            if (
                name_node is not None
                and name_node.type == "identifier"
                and node_text(name_node, src) == name
                and value_node is not None
                and value_node.type in ("arrow_function", "function_expression")
            ):
                return value_node
    return None


def find_enclosing_function(root_node: Node, line: int) -> Node | None:
    """Innermost function-like node (by largest start row) whose span
    contains `line` (1-indexed) -- the JS/TS analog of taint_scanner.py's
    `_find_enclosing_function` for the Python AST."""
    best: Node | None = None
    for node in walk(root_node):
        if node.type in FUNCTION_LIKE_TYPES:
            start = node.start_point[0] + 1
            end = node.end_point[0] + 1
            if start <= line <= end and (best is None or start >= best.start_point[0] + 1):
                best = node
    return best


# --------------------------------------------------------------------------
# Stage 1 orchestration
# --------------------------------------------------------------------------


def _resolve_handler(
    handler_arg: Node, root_node: Node, src: bytes, file: Path, shape: str,
    entrypoints: dict[tuple[Path, int], McpEntrypoint],
    confidence: str = "high",
) -> None:
    node = handler_arg
    if node.type == "identifier":
        fn_node = find_function_by_name(root_node, node_text(node, src), src)
        if fn_node is None:
            return  # unresolved (cross-file or otherwise) -- silence, not a guess
    elif node.type in FUNCTION_LIKE_TYPES:
        fn_node = node
    else:
        return
    params = function_params(fn_node, src)
    if not params:
        return
    line = fn_node.start_point[0] + 1
    name_node = fn_node.child_by_field_name("name")
    function_name = node_text(name_node, src) if name_node is not None else f"<handler@{file.name}:{line}>"
    key = (file, line)
    existing = entrypoints.get(key)
    if existing is not None and existing.confidence == "high" and confidence != "high":
        return  # already recovered by a stronger, SDK-call-based shape -- don't downgrade
    entrypoints[key] = McpEntrypoint(file, function_name, line, params, shape, confidence)


def recover_js_entrypoints(root: str | Path) -> list[McpEntrypoint]:
    """Walk a JS/TS source tree and recover the set of functions that are
    real MCP tool handlers, via the shapes documented in this module's
    docstring. Per-file (unlike entrypoints.py's Python pass, which has a
    genuinely cross-file shape C to resolve) -- every shape here resolves
    within a single file, so this could be parallelized per file if it
    ever needs to be; it isn't, to keep this a straightforward, auditable
    walk like entrypoints.py's own.
    """
    root = Path(root)
    entrypoints: dict[tuple[Path, int], McpEntrypoint] = {}

    for path in iter_js_files(root):
        parsed = parse_file(path)
        if parsed is None:
            continue
        root_node, src = parsed

        _recover_tool_name_anchored(root_node, src, path, entrypoints)

        for node in walk(root_node):
            if node.type != "call_expression":
                continue
            callee = node.child_by_field_name("function")
            args_node = node.child_by_field_name("arguments")
            if callee is None or args_node is None:
                continue
            chain = dotted_chain(callee, src)
            if not chain:
                continue
            last = chain.rsplit(".", 1)[-1]
            arg_nodes = args_node.named_children

            if last in _LAST_ARG_HANDLER_CALLS and len(arg_nodes) >= 2:
                _resolve_handler(arg_nodes[-1], root_node, src, path, _LAST_ARG_HANDLER_CALLS[last], entrypoints)
                continue

            if last == _LOW_LEVEL_CALL_NAME and len(arg_nodes) >= 2:
                schema_text = node_text(arg_nodes[0], src).lower()
                if "calltool" in schema_text or "tools/call" in schema_text:
                    _resolve_handler(arg_nodes[-1], root_node, src, path, "low_level_dispatcher", entrypoints)
                continue

            # Shape E: dispatch_call_arguments -- see module docstring.
            if callee.type != "identifier":
                continue
            for idx, arg in enumerate(arg_nodes):
                candidate = arg
                if candidate.type == "binary_expression":
                    op = candidate.child_by_field_name("operator")
                    if op is not None and node_text(op, src) == "||":
                        left = candidate.child_by_field_name("left")
                        if left is not None:
                            candidate = left
                if dotted_chain(candidate, src).rsplit(".", 1)[-1] != "arguments":
                    continue
                fn_node = find_function_by_name(root_node, node_text(callee, src), src)
                if fn_node is None:
                    continue
                params = function_params(fn_node, src)
                if idx >= len(params):
                    continue
                line = fn_node.start_point[0] + 1
                name_node = fn_node.child_by_field_name("name")
                function_name = node_text(name_node, src) if name_node is not None else f"<handler@{path.name}:{line}>"
                entrypoints[(path, line)] = McpEntrypoint(
                    path, function_name, line, [params[idx]], "dispatch_call_arguments", "medium"
                )

    return sorted(entrypoints.values(), key=lambda e: (str(e.file), e.line))


# --------------------------------------------------------------------------
# Tool-name anchoring (shapes F/G/H, see module docstring).
# --------------------------------------------------------------------------


def _string_literal_text(node: Node, src: bytes) -> str | None:
    """The literal text of a `string` node with its quotes stripped, or
    None if `node` isn't a string literal at all."""
    if node.type != "string":
        return None
    text = node_text(node, src)
    if len(text) >= 2 and text[0] in "'\"`" and text[-1] == text[0]:
        return text[1:-1]
    return text


def _pair_key_text(pair: Node, src: bytes) -> str | None:
    """The key text of an object-literal `pair` node -- an identifier-style
    key (`property_identifier`) used verbatim, or a quoted `string` key
    with its quotes stripped. None for a computed/spread key."""
    key = pair.child_by_field_name("key")
    if key is None:
        return None
    if key.type in ("property_identifier", "identifier", "private_property_identifier"):
        return node_text(key, src)
    if key.type == "string":
        return _string_literal_text(key, src)
    return None


def _resolve_name_literal_one_hop(value_node: Node, root_node: Node, src: bytes) -> str | None:
    """Resolve a `name:`/`toolName:`-style property value to its
    string-literal tool name: directly if it already IS a string literal,
    otherwise ONE hop (same file only) through a `member_expression`
    (`Enum.Member`) resolved against a same-file `enum_declaration`, or a
    bare identifier resolved against a same-file `const X = "..."`
    declaration. Returns None (not a guess) for anything else, or if the
    referenced enum/const isn't found or isn't itself a plain string
    literal -- mirrors this module's existing one-hop disciplines
    (`dispatch_call_arguments`, `cross_file.py`'s own resolvers)."""
    if value_node.type == "string":
        return _string_literal_text(value_node, src)

    chain = dotted_chain(value_node, src)
    parts = chain.split(".") if chain else []

    if len(parts) == 2:
        obj_name, member_name = parts
        for node in walk(root_node):
            if node.type != "enum_declaration":
                continue
            name_node = node.child_by_field_name("name")
            if name_node is None or node_text(name_node, src) != obj_name:
                continue
            body = node.child_by_field_name("body")
            if body is None:
                continue
            for member in body.named_children:
                if member.type != "enum_assignment":
                    continue
                m_name = member.child_by_field_name("name")
                m_val = member.child_by_field_name("value")
                if (
                    m_name is not None
                    and node_text(m_name, src) == member_name
                    and m_val is not None
                    and m_val.type == "string"
                ):
                    return _string_literal_text(m_val, src)
        return None

    if len(parts) == 1 and value_node.type == "identifier":
        for node in walk(root_node):
            if node.type != "variable_declarator":
                continue
            n = node.child_by_field_name("name")
            v = node.child_by_field_name("value")
            if (
                n is not None
                and n.type == "identifier"
                and node_text(n, src) == parts[0]
                and v is not None
                and v.type == "string"
            ):
                return _string_literal_text(v, src)
        return None

    return None


def _recover_tool_name_anchored(root_node: Node, src: bytes, path: Path, entrypoints: dict[tuple[Path, int], McpEntrypoint]) -> None:
    """Shapes F, G, H, I (see module docstring) -- all four additive to
    shapes A-E, all keeping their own recovered entrypoints at "medium"
    confidence and never downgrading an entry already recovered above."""
    _object_literal_registry_entries(root_node, src, path, entrypoints)
    _class_attribute_registry_entries(root_node, src, path, entrypoints)
    _tool_name_keyed_registry_entries(root_node, src, path, entrypoints)
    _interface_method_override_entries(root_node, src, path, entrypoints)


def _object_literal_registry_entries(
    root_node: Node, src: bytes, path: Path, entrypoints: dict[tuple[Path, int], McpEntrypoint]
) -> None:
    """Shape F: an object literal with both a `name`-vocabulary property
    and a sibling `handler`-vocabulary property (the real Aiven shape)."""
    for node in walk(root_node):
        if node.type != "object":
            continue
        name_value: Node | None = None
        handler_value: Node | None = None
        for child in node.named_children:
            if child.type != "pair":
                continue
            key = _pair_key_text(child, src)
            if key is None:
                continue
            value = child.child_by_field_name("value")
            if value is None:
                continue
            if key in _OBJ_LITERAL_NAME_KEYS and name_value is None:
                name_value = value
            elif key in _OBJ_LITERAL_HANDLER_KEYS and handler_value is None:
                handler_value = value
        if name_value is None or handler_value is None:
            continue
        # Best-effort: if the name value resolves to a literal (directly, or
        # one hop through a same-file const/enum), that's stronger evidence
        # this object really is a tool-registry entry. But real testing
        # against Aiven-Open/mcp-aiven found its `PgToolName` enum is
        # declared in a DIFFERENT file (types.ts) than the object literals
        # that reference it (handlers.ts) -- an ordinary, common pattern
        # this module's own same-file-only, no-import-resolution discipline
        # correctly declines to chase. Requiring resolution to succeed would
        # make this shape systematically miss exactly the real target it
        # was built to catch, so resolution failure does NOT block recovery
        # here -- the structural signal (a `name`-vocabulary key AND a
        # `handler`-vocabulary key on the SAME object, with the handler
        # resolving to a real function) is treated as sufficient on its own.
        _resolve_name_literal_one_hop(name_value, root_node, src)
        _resolve_handler(handler_value, root_node, src, path, "object_literal_registry", entrypoints, confidence="medium")


def _class_attribute_registry_entries(
    root_node: Node, src: bytes, path: Path, entrypoints: dict[tuple[Path, int], McpEntrypoint]
) -> None:
    """Shape G: a class with a STATIC `toolName`/`name`/`TOOL_NAME` field
    holding a string literal, paired with an `execute`/`run`/`call`/
    `handle`/`invoke` method defined directly in that same class (the real
    mongodb-mcp-server shape). Unlike `_resolve_handler`, this does NOT
    require the method to have any parameters -- see module docstring."""
    for node in walk(root_node):
        if node.type not in ("class_declaration", "class"):
            continue
        body = node.child_by_field_name("body")
        if body is None:
            continue
        has_name_attr = False
        for child in body.named_children:
            if child.type != "public_field_definition":
                continue
            if not any(c.type == "static" for c in child.children):
                continue
            name_field = child.child_by_field_name("name")
            value_field = child.child_by_field_name("value")
            if name_field is None or value_field is None:
                continue
            if node_text(name_field, src) in _CLASS_STATIC_NAME_ATTRS and value_field.type == "string":
                has_name_attr = True
                break
        if not has_name_attr:
            continue

        for child in body.named_children:
            if child.type != "method_definition":
                continue
            name_field = child.child_by_field_name("name")
            if name_field is None or node_text(name_field, src) not in _CLASS_HANDLER_METHOD_NAMES:
                continue
            line = child.start_point[0] + 1
            key = (path, line)
            existing = entrypoints.get(key)
            if existing is not None and existing.confidence == "high":
                continue
            entrypoints[key] = McpEntrypoint(
                path, node_text(name_field, src), line, function_params(child, src), "class_attribute_registration", "medium"
            )


def _tool_name_keyed_registry_entries(
    root_node: Node, src: bytes, path: Path, entrypoints: dict[tuple[Path, int], McpEntrypoint]
) -> None:
    """Shape H: an object literal whose KEYS are the literal tool names
    (the real Auth0 shape, `RESOURCE_SERVER_HANDLERS`), validated by
    cross-referencing those keys against tool names collected from a
    `Tool[]`-shaped array literal elsewhere in the same file (each element
    an object with a `name:` string-literal property -- the real
    `RESOURCE_SERVER_TOOLS`)."""
    known_names: set[str] = set()
    for node in walk(root_node):
        if node.type != "array":
            continue
        for element in node.named_children:
            if element.type != "object":
                continue
            for child in element.named_children:
                if child.type != "pair" or _pair_key_text(child, src) != "name":
                    continue
                value = child.child_by_field_name("value")
                text = _string_literal_text(value, src) if value is not None else None
                if text:
                    known_names.add(text)
    if not known_names:
        return

    for node in walk(root_node):
        if node.type != "object":
            continue
        for child in node.named_children:
            if child.type != "pair":
                continue
            key = _pair_key_text(child, src)
            if key is None or key not in known_names:
                continue
            value = child.child_by_field_name("value")
            if value is None:
                continue
            _resolve_handler(value, root_node, src, path, "tool_name_keyed_registry", entrypoints, confidence="medium")


def _class_has_transport_signal(node: Node, src: bytes) -> bool:
    """True if class-like `node` (`class_declaration`/`class`) carries
    shape I's own anchor signal -- see module docstring: its heritage
    clause (`implements`/`extends`) names a type in
    `_TRANSPORT_HERITAGE_NAMES`, OR its own declared name ends in one of
    `_TRANSPORT_CLASS_NAME_SUFFIXES`."""
    name_field = node.child_by_field_name("name")
    if name_field is not None and node_text(name_field, src).endswith(_TRANSPORT_CLASS_NAME_SUFFIXES):
        return True
    for child in node.named_children:
        if child.type != "class_heritage":
            continue
        for descendant in walk(child):
            if descendant.type == "type_identifier" and node_text(descendant, src) in _TRANSPORT_HERITAGE_NAMES:
                return True
    return False


def _interface_method_override_entries(
    root_node: Node, src: bytes, path: Path, entrypoints: dict[tuple[Path, int], McpEntrypoint]
) -> None:
    """Shape I -- see module docstring. Unlike `_resolve_handler`, this does
    NOT require the method to have any parameters, same exception shape G
    already makes for the identical reason (a real transport's
    `handleRequest` can read from `this.*` instead of formal parameters, as
    `webStandardStreamableHttp.ts`'s own real `handleRequest(req: Request,
    options?: HandleRequestOptions)` shows it need not, but a stricter
    param-count requirement would be a real regression risk for a same
    -shaped target that reads request state off `this` alone)."""
    for node in walk(root_node):
        if node.type not in ("class_declaration", "class"):
            continue
        if not _class_has_transport_signal(node, src):
            continue
        body = node.child_by_field_name("body")
        if body is None:
            continue
        for child in body.named_children:
            if child.type != "method_definition":
                continue
            name_field = child.child_by_field_name("name")
            if name_field is None or node_text(name_field, src) not in _TRANSPORT_METHOD_NAMES:
                continue
            line = child.start_point[0] + 1
            key = (path, line)
            existing = entrypoints.get(key)
            if existing is not None and existing.confidence == "high":
                continue
            entrypoints[key] = McpEntrypoint(
                path, node_text(name_field, src), line, function_params(child, src), "interface_method_override", "medium"
            )


if __name__ == "__main__":
    import sys

    for ep in recover_js_entrypoints(sys.argv[1] if len(sys.argv) > 1 else "."):
        print(
            f"{ep.file}:{ep.line}  {ep.function_name}({', '.join(ep.parameter_names)})  "
            f"via={ep.sdk_shape} confidence={ep.confidence}"
        )
