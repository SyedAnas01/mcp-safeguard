"""Stage 1: MCP entrypoint recovery (Kotlin).

The Kotlin sibling of `entrypoints_js.py` -- same job ("which functions in
this repository actually run when an MCP client calls a tool?"), same output
shape (`McpEntrypoint`, imported from `entrypoints.py` rather than
redefined), a tree-sitter-based parse (`tree-sitter-kotlin`) for the same
reason entrypoints_js.py gives: Kotlin has no stdlib parser to lean on the
way `entrypoints.py` leans on Python's own `ast` module, and Kotlin's syntax
(trailing lambdas, named arguments, companion objects, nullable types) is
not something regex can reliably walk.

Built to close a confirmed, real blocker: JetBrains/teamcity-mcp -- audited
in round 45 (see mcp-watchtower-targets/round45-official-orgs-findings/
02-jetbrains-teamcity-mcp-NOT-FILED-refuted-on-verification.md and this
project's own ledger entry, bench/ledger/entries/
jetbrains-teamcity-mcp-buildlogtool-refuted.json) -- had ZERO entrypoint
recovery for its language (Kotlin) before this module existed, so this
project could not even structurally confirm or deny the refuted BuildLogTool
claim itself; only re-derive the same javadoc/coroutine-context argument the
original write-up already made by hand. See bench/KOTLIN_SUPPORT_STATUS.md
for the real before/after count against that exact target and an honest
accounting of what this module does and does not change about that
refutation.

Recognized registration shapes, both confirmed by reading real source (the
official `io.modelcontextprotocol:kotlin-sdk` and JetBrains/teamcity-mcp's
own real, non-fixture source at commit c499f11e7ff00a5eacf7415e736b7e4760f5e206
-- the ledger entry's own written report gives no commit SHA; this is HEAD
at time of writing, ~2 hours after the PR #26 merge the report cites --
never assumed from the SDK's own docs alone):

  A. `server.addTool(name, ..., ) { request -> ... }` -- the official SDK's
     own builder call: a trailing-lambda call whose callee's last dotted
     component is `addTool` (mirrors entrypoints_js.py's shape A/B: the
     lambda IS the handler, whatever positional/named arguments precede it
     are not inspected further). Recovered params are the lambda's own
     declared parameters (`request ->`) -- an implicit, undeclared `it` or a
     destructured `(a, b) ->` lambda parameter list are both left
     unresolved (no `lambda_parameters` node to read a name from) rather
     than guessed at, the same "silence, not a guess" rule
     `entrypoints.py`'s own module docstring already states. Tagged
     `"high"` confidence -- a real, statically-resolvable SDK call, same as
     entrypoints_js.py's shape A/B.

     Real validation target found this shape ONCE, in
     `McpServerConfigurator.kt`, and it is a GENERIC per-tool dispatch
     wrapper, not a real tool handler's own logic:
       for (tool in getEnabledTools()) {
           server.addTool(name = tool.name, description = tool.description,
               inputSchema = ...) { request ->
               tool.execute(request.arguments)   // <-- just forwards
           }
       }
     Recovering this lambda alone (params: `["request"]`) is honest but
     nearly useless on its own -- the real per-tool logic lives one hop
     further, inside each concrete `McpTool` implementation's own
     `execute()`. Shape B below is what actually recovers those.

  B. Tool-name anchoring (mirrors entrypoints.py's/entrypoints_js.py's own
     shape G, "class-attribute tool-name + sibling handler method") --
     ADDITIVE, never downgrading a shape-A entry at the same (file, line).
     A class body declaring a property named `name`/`toolName`/`tool_name`/
     `TOOL_NAME` (Kotlin's real, near-universal MCP-tool idiom: a Spring
     `@Component`-annotated class implementing a small `McpTool`-shaped
     interface -- `override val name = NAME`, `override val description =
     ...`, `override suspend fun execute(arguments: ...): ...`), paired
     with a method DEFINED DIRECTLY in that SAME class named `execute`/
     `run`/`call`/`handle`/`invoke`.

     One real, deliberate departure from entrypoints.py's/entrypoints_js.py's
     own version of this shape: THEIR shape G requires the anchor property's
     VALUE to be an actual string-literal constant. Reading all 10 real
     `McpTool` implementations in teamcity-mcp found NONE of them do that --
     every one assigns `override val name = NAME` (a companion-object
     `const val` in the SAME class) or, once (`RestPostBraveTool.kt`),
     `override val name = RestPostTool.NAME` (a DIFFERENT class's companion
     constant entirely -- cross-file in spirit even though same directory).
     Requiring a literal value here, like the Python/JS version does, would
     recover ZERO of the 10 real targets -- the exact failure this
     milestone exists to fix. So this shape anchors on the PROPERTY NAME
     alone (co-occurring with a sibling handler method in the same class
     body) and does not require, or even attempt, resolving its value to a
     literal -- a real, deliberate widening from the Python/JS convention,
     made necessary by validating against a real target rather than assumed.
     The bound against false positives is the same one entrypoints.py's own
     shape G already relies on without a literal-value requirement either
     (Python's `_try_class_attribute_registration` doesn't require one): the
     co-occurrence itself, of a name-vocabulary property AND a handler-
     vocabulary method, in the SAME class body.

     Unlike `_resolve_handler`'s general-purpose path, this does NOT require
     the method to have any parameters (same reasoning entrypoints_js.py's
     own shape G documents: `execute()` here always has one, `arguments:
     JsonObject?`, but the shape itself makes no assumption either way).
     Tagged `"medium"` confidence, same as every other tool-name-anchoring
     shape in this project -- a naming-convention cross-reference, not a
     resolved SDK call.

Deliberately NOT attempted, matching entrypoints.py's/entrypoints_js.py's
own stated scope: a general call graph, import/cross-file resolution (a
same-file-only discipline throughout, e.g. `RestPostTool.NAME` above is
never chased into `RestPostTool.kt`), destructured/implicit lambda
parameters, or object-declaration (`object Foo : McpTool`) singletons --
teamcity-mcp's own real targets are all plain classes, not `object`s.

Per-file rule scoping in taint_scanner.py's `generate_taint_rule_yaml_kotlin`
re-applies the exact same-name-different-file collision fix
entrypoints_js.py's own docstring already describes -- every Kotlin taint
rule this module's output feeds into is scoped to the one file its
entrypoints were recovered from via `paths: include:`.
"""

from __future__ import annotations

from pathlib import Path

from tree_sitter import Language, Node, Parser

from .entrypoints import _SKIP_DIR_PARTS as _PY_SKIP_DIR_PARTS
from .entrypoints import McpEntrypoint, _is_skip_dir_part

# Kotlin/Gradle-specific additions on top of the shared skip list
# (node_modules, dist, vendor, .git, test(s), venv/.venv, benchmarks/
# examples/docs/.github are already covered there).
_SKIP_DIR_PARTS = _PY_SKIP_DIR_PARTS | frozenset({"build", "out", ".gradle", "generated"})

EXTENSION_LANGUAGE = {".kt": "kotlin", ".kts": "kotlin"}

# Shape A: the official kotlin-sdk's own builder call. Last dotted component
# of the callee chain.
_ADD_TOOL_CALL_NAMES = frozenset({"addTool"})

# Shape B (tool-name anchoring). Property-name vocabulary for the anchor,
# and method-name vocabulary for the paired handler -- same vocabularies
# entrypoints.py/entrypoints_js.py already use for their own shape G.
_CLASS_NAME_PROPS = frozenset({"name", "toolName", "tool_name", "TOOL_NAME"})
_CLASS_HANDLER_METHOD_NAMES = frozenset({"execute", "run", "call", "handle", "invoke"})

_lang: Language | None = None
_ts_parser: Parser | None = None


def _language() -> Language:
    global _lang
    if _lang is None:
        import tree_sitter_kotlin as tsk

        _lang = Language(tsk.language())
    return _lang


def _get_parser() -> Parser:
    global _ts_parser
    if _ts_parser is None:
        _ts_parser = Parser(_language())
    return _ts_parser


def parse_file(path: Path) -> tuple[Node, bytes] | None:
    """Parse one Kotlin file. Returns (root_node, source_bytes), or None for
    an unsupported extension, an unreadable file, or a parse failure --
    shared by this module's own recovery pass and by taint_scanner.py's
    Stage 2/3 Kotlin support, mirroring entrypoints_js.py's `parse_file`."""
    if path.suffix not in EXTENSION_LANGUAGE:
        return None
    try:
        src = path.read_bytes()
    except OSError:
        return None
    try:
        tree = _get_parser().parse(src)
    except Exception:
        return None
    return tree.root_node, src


def iter_kotlin_files(root: Path):
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
    """All descendants of `node`, including itself -- same stack-based,
    non-source-order traversal as entrypoints_js.py's own `walk`."""
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(n.children)


def node_text(node: Node, src: bytes) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", errors="ignore")


def dotted_chain(node: Node | None, src: bytes) -> str:
    """Render a `navigation_expression` chain (`server.addTool`,
    `obj.server.addTool`) or a bare `identifier` back to a dotted string.
    tree-sitter-kotlin defines no field names for `navigation_expression`'s
    two parts (verified directly against the grammar) -- the object is
    always its FIRST named child, the property name its LAST, unlike
    entrypoints_js.py's `dotted_chain` which reads JS/TS's own named
    `object`/`property` fields. Anything else yields ''."""
    if node is None:
        return ""
    if node.type == "navigation_expression":
        parts = node.named_children
        if len(parts) < 2:
            return ""
        prop = parts[-1]
        if prop.type != "identifier":
            return ""
        obj_chain = dotted_chain(parts[0], src)
        prop_text = node_text(prop, src)
        return f"{obj_chain}.{prop_text}" if obj_chain else prop_text
    if node.type == "identifier":
        return node_text(node, src)
    return ""


# --------------------------------------------------------------------------
# Parameter-name extraction.
# --------------------------------------------------------------------------


def function_params(fn_node: Node, src: bytes) -> list[str]:
    """Parameter names of a `function_declaration`'s own
    `function_value_parameters` -- each `parameter` node's first named child
    is its `identifier` (verified directly: the grammar defines no field
    name for it, unlike entrypoints_js.py's TS grammar). Destructured
    parameters do not exist for Kotlin function parameters (only for lambda
    parameters and `for` loops), so unlike entrypoints_js.py's
    `pattern_names` this needs no destructuring case."""
    for child in fn_node.named_children:
        if child.type != "function_value_parameters":
            continue
        names = []
        for p in child.named_children:
            if p.type != "parameter" or not p.named_children:
                continue
            ident = p.named_children[0]
            if ident.type == "identifier":
                names.append(node_text(ident, src))
        return names
    return []


def lambda_params(lambda_literal: Node, src: bytes) -> list[str]:
    """Parameter names of a `lambda_literal`'s own `lambda_parameters`. Each
    plain `x ->` binding is a `variable_declaration` wrapping one
    `identifier` (the same node shape a class property's own name uses --
    see `_class_attribute_registry_entries` below). A destructured lambda
    parameter (`{ (a, b) -> ... }`, a `multi_variable_declaration`) or
    Kotlin's implicit unnamed `it` (no `lambda_parameters` node present at
    all) are both left unresolved -- neither is the shape the real
    validated target (teamcity-mcp's own `addTool { request -> ... }`)
    uses, and per this module's own "silence, not a guess" discipline an
    unresolved shape recovers no parameters rather than a guessed one."""
    for child in lambda_literal.named_children:
        if child.type != "lambda_parameters":
            continue
        names = []
        for vd in child.named_children:
            if vd.type == "variable_declaration" and vd.named_children:
                ident = vd.named_children[0]
                if ident.type == "identifier":
                    names.append(node_text(ident, src))
        return names
    return []


def find_enclosing_function(root_node: Node, line: int) -> Node | None:
    """Innermost `function_declaration` (by largest start row) whose span
    contains `line` (1-indexed) -- the Kotlin analog of entrypoints_js.py's
    `find_enclosing_function`. Deliberately does NOT also match a bare
    `lambda_literal` the way entrypoints_js.py's `FUNCTION_LIKE_TYPES`
    matches an arrow function -- see taint_scanner.py's
    `_source_block_kotlin` for why shape-A (addTool lambda) entrypoints are
    not given a taint-rule source anchor at all in this milestone."""
    best: Node | None = None
    for node in walk(root_node):
        if node.type == "function_declaration":
            start = node.start_point[0] + 1
            end = node.end_point[0] + 1
            if start <= line <= end and (best is None or start >= best.start_point[0] + 1):
                best = node
    return best


def function_signature_pattern(fn_node: Node, src: bytes) -> str | None:
    """Verbatim source text of `fn_node` from its start up to (not
    including) its own `function_body`'s `block`, with the body replaced by
    a `{ ... }` ellipsis -- the Kotlin analog of entrypoints_js.py's
    `function_signature_pattern`, used the same way: an exact, single
    -purpose `pattern-inside` anchor for Stage 2's generated taint rule
    (taint_scanner.py's `_source_block_kotlin`). Returns None if `fn_node`
    isn't a `function_declaration`, has no `function_body`, or that body
    isn't a `{ ... }` block (a concise `fun f() = expr` body has no block to
    anchor on) -- an unresolved entrypoint, not a guess, same as
    entrypoints_js.py's own version of this function."""
    if fn_node.type != "function_declaration":
        return None
    body = None
    for c in fn_node.named_children:
        if c.type == "function_body":
            body = c
            break
    if body is None:
        return None
    block = None
    for c in body.named_children:
        if c.type == "block":
            block = c
            break
    if block is None:
        return None
    prefix = src[fn_node.start_byte : block.start_byte].decode("utf-8", errors="ignore").rstrip()
    if not prefix:
        return None
    return prefix + " { ... }"


# --------------------------------------------------------------------------
# Stage 1 orchestration.
# --------------------------------------------------------------------------


def recover_kotlin_entrypoints(root: str | Path) -> list[McpEntrypoint]:
    """Walk a Kotlin source tree and recover the set of functions/lambdas
    that are real MCP tool handlers, via the two shapes documented in this
    module's docstring. Per-file, like entrypoints_js.py -- neither shape
    here is cross-file."""
    root = Path(root)
    entrypoints: dict[tuple[Path, int], McpEntrypoint] = {}

    for path in iter_kotlin_files(root):
        parsed = parse_file(path)
        if parsed is None:
            continue
        root_node, src = parsed

        _recover_add_tool_calls(root_node, src, path, entrypoints)
        _class_attribute_registry_entries(root_node, src, path, entrypoints)

    return sorted(entrypoints.values(), key=lambda e: (str(e.file), e.line))


def _recover_add_tool_calls(
    root_node: Node, src: bytes, path: Path, entrypoints: dict[tuple[Path, int], McpEntrypoint]
) -> None:
    """Shape A -- see module docstring. A trailing-lambda call renders in
    tree-sitter-kotlin as an outer `call_expression` with exactly two named
    children: the callee part (itself a `call_expression`, for `f(...) {
    }`, or a bare `identifier`, for the rare no-parens `f { }`) and an
    `annotated_lambda` wrapping the actual `lambda_literal` -- verified
    directly against the grammar, since no field names exist to read this
    from more directly."""
    for node in walk(root_node):
        if node.type != "call_expression":
            continue
        named = node.named_children
        if len(named) != 2 or named[1].type != "annotated_lambda":
            continue
        callee_part = named[0]
        if callee_part.type == "call_expression":
            inner = callee_part.named_children
            if not inner:
                continue
            chain = dotted_chain(inner[0], src)
        else:
            chain = dotted_chain(callee_part, src)
        if not chain or chain.rsplit(".", 1)[-1] not in _ADD_TOOL_CALL_NAMES:
            continue

        lambda_literal = None
        for c in named[1].named_children:
            if c.type == "lambda_literal":
                lambda_literal = c
                break
        if lambda_literal is None:
            continue

        params = lambda_params(lambda_literal, src)
        if not params:
            continue  # unresolved (implicit `it` / destructured) -- silence, not a guess

        line = named[1].start_point[0] + 1
        key = (path, line)
        entrypoints[key] = McpEntrypoint(
            path, f"<addTool_handler@{path.name}:{line}>", line, params, "add_tool_call", "high"
        )


def _class_attribute_registry_entries(
    root_node: Node, src: bytes, path: Path, entrypoints: dict[tuple[Path, int], McpEntrypoint]
) -> None:
    """Shape B (tool-name anchoring) -- see module docstring for why this
    does NOT require the anchor property to resolve to a string literal,
    unlike entrypoints.py's/entrypoints_js.py's own version of this shape."""
    for node in walk(root_node):
        if node.type != "class_declaration":
            continue
        class_body = None
        for c in node.named_children:
            if c.type == "class_body":
                class_body = c
                break
        if class_body is None:
            continue

        has_name_prop = False
        for child in class_body.named_children:
            if child.type != "property_declaration":
                continue
            vd = None
            for c in child.named_children:
                if c.type == "variable_declaration":
                    vd = c
                    break
            if vd is None or not vd.named_children:
                continue
            prop_name_node = vd.named_children[0]
            if prop_name_node.type == "identifier" and node_text(prop_name_node, src) in _CLASS_NAME_PROPS:
                has_name_prop = True
                break
        if not has_name_prop:
            continue

        for child in class_body.named_children:
            if child.type != "function_declaration":
                continue
            name_node = child.child_by_field_name("name")
            if name_node is None or node_text(name_node, src) not in _CLASS_HANDLER_METHOD_NAMES:
                continue
            # An abstract member (an interface's own signature, e.g. this
            # real target's McpTool.kt: `suspend fun execute(...): T`, no
            # body at all) has no `function_body` child -- verified directly
            # against the grammar, which parses `interface X { ... }` as the
            # SAME `class_declaration` node type as a real class, so without
            # this check every MCP-tool INTERFACE definition would itself be
            # wrongly recovered as an entrypoint alongside its real
            # implementations, with no actual code for a sink to ever be in.
            if not any(c.type == "function_body" for c in child.named_children):
                continue
            line = child.start_point[0] + 1
            key = (path, line)
            existing = entrypoints.get(key)
            if existing is not None and existing.confidence == "high":
                continue  # already recovered by shape A -- don't downgrade
            entrypoints[key] = McpEntrypoint(
                path,
                node_text(name_node, src),
                line,
                function_params(child, src),
                "class_attribute_registration",
                "medium",
            )


if __name__ == "__main__":
    import sys

    for ep in recover_kotlin_entrypoints(sys.argv[1] if len(sys.argv) > 1 else "."):
        print(
            f"{ep.file}:{ep.line}  {ep.function_name}({', '.join(ep.parameter_names)})  "
            f"via={ep.sdk_shape} confidence={ep.confidence}"
        )
