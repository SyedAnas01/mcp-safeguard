"""Stage 1: MCP entrypoint recovery (Python).

The other scanners in this package read a config JSON, or scan raw source text
line-by-line. This module answers a different, narrower question first: *which
functions in this repository actually run when an MCP client calls a tool?*
Knowing that precisely is what lets Stage 2 (`taint_scanner.py`) generate taint
rules whose SOURCES are real MCP tool-handler parameters instead of a generic
"any function argument" pattern -- the same source/sink over-genericity this
project's own architecture research found in Cisco's mcp-scanner.

A plain AST walk (not semgrep) is used here on purpose: semgrep CE's taint mode
is intra-procedural, so it cannot see a handler that is registered in a
DIFFERENT file than the one it's defined in -- the "define tools in module A,
loop over them and register in module B" shape real code uses (see shape C
below). This module is the ~100-line piece that recovers that cross-file fact;
everything after entrypoint recovery (which parameter reaches which sink) is
semgrep's job, not this module's.

Recognized registration shapes, each seen in real, campaign-audited MCP
servers:
  A. FastMCP / low-level decorator directly on the handler:
       @mcp.tool() / @server.tool() / @app.tool
       def handler(...): ...
     Also recognizes the low-level SDK's single dispatcher decorator,
       @server.call_tool()
       async def handle_call_tool(name: str, arguments: dict): ...
     which is structurally different (one function serves every tool, `name`/
     `arguments` are the real taint sources) but uses the identical decorator
     shape, so it is tagged with its own `sdk_shape` rather than lumped in
     with per-tool decorators.
  B. Direct registration call passing an already-defined function object:
       mcp.add_tool(handler)  /  mcp.tool(handler)  /  Tool.from_function(handler)
     Resolved by name against a `def`/`async def` in the SAME file.
  C. Cross-file list-then-loop registration -- a list of handler functions is
     built with `@some_list.append` in one file, and a SEPARATE file loops
     over that list and registers each entry:
       # tools.py
       local_tools = []
       @local_tools.append
       def LOCAL_RunShellScript(script: str): ...
       # server.py
       from . import tools
       for t in tools.local_tools:
           mcp.tool(t)
     This is the exact registration shape behind the real, previously-missed
     aliyun/alibaba-cloud-ops-mcp-server command-injection bug this milestone
     validates against (`local_tools.py:129`) -- confirmed by this module
     correctly resolving it in a `nextgen-poc` prototype pass before being
     ported here.

Deliberately NOT attempted: a general call graph, type inference, or
resolving a handler passed through several layers of indirection (a factory
function, a decorator-returning-decorator, etc). An unresolved registration
call is simply not counted as an entrypoint -- silence, not a guess. That
mirrors this project's existing discipline (source_scanner.py's own module
docstring: "a non-firing result must never be read as ... only 'no positive
signal was found'").

Tool-name anchoring (shapes F/G) -- a SECOND, ADDITIVE recovery strategy:
shapes A-C above all require a *specific*, statically-resolvable
registration-CALL syntax. A real, campaign-confirmed failure mode is a
"registry dispatch" shape where a tool is registered through a wrapper
method or a class's own static/class attribute rather than one of the
recognized call names -- confirmed by reading the real source of 6 holdout
targets (see bench/TOOLNAME_ANCHOR_STATUS.md), not assumed. Every real MCP
server still declares its tool names as string literals SOMEWHERE, even
when the dispatch itself is a wrapper call or class attribute, so this
strategy anchors on that literal instead of on the call syntax:

  F. Keyword-argument registration pairing (the real CrowdStrike/falcon-mcp
     shape: `self._add_tool(server=server, method=self.create_rule,
     name="create_rule", ...)`). `_add_tool` is a project-specific wrapper
     method, not one of `_REGISTRATION_CALL_NAMES`, and every argument is a
     keyword, not a positional `node.args[0]` -- shape B never even looks at
     it. Recognized instead by keyword-ARGUMENT co-occurrence within the
     SAME call: a keyword named `name`/`tool_name` whose value is a string
     literal (the anchor), paired with a sibling keyword named
     `method`/`handler`/`fn`/`func`/`callback` whose value is either a bare
     `Name` (resolved same-file, like shape B) or a `self.<method>`/
     `cls.<method>` attribute (resolved against the method's OWN, nearest
     enclosing class -- the real binding mechanism this shape uses, since
     the actual handler is a bound method, not a free function). An
     unresolved handler value is not counted -- same silence rule as A-C.
  G. Class-attribute tool-name + sibling handler method (a class-per-tool
     OOP pattern real Python MCP frameworks also use, symmetric with the
     JS/TS shape of the same name in `entrypoints_js.py`, which the real
     mongodb-mcp-server target uses): a class body assignment named
     `name`/`tool_name`/`TOOL_NAME` to a string literal, paired with a
     method DEFINED DIRECTLY in that same class named `execute`/`run`/
     `call`/`handle`/`invoke`. The class attribute is the anchor; the
     method is the entrypoint.

Both shapes require the literal-valued name AND a resolvable handler
reference to co-occur in the SAME lexical unit (a call's own keywords, or a
class's own body) -- this bounds false positives to a coincidental
same-call/same-class collision of both signals at once, not just a stray
string literal. Both are tagged "medium" confidence, never "high" (matching
shape C's own precedent: a naming-convention cross-reference is inherently
more collision-prone than resolving a single recognized call), and an
entrypoint already recovered by shapes A-C at the same (file, function) is
never downgraded -- these two shapes only ever ADD entrypoints shapes A-C
missed. Deliberately NOT attempted here: decorator-argument binding (no
real corpus target exhibited it) and cross-file resolution of the `self.`
target's class (mirrors this module's own same-file-only discipline).

Dict-key registry assignment (shape H) -- a THIRD, ADDITIVE recovery
strategy, SDK-vocab-and-truncation-fix milestone Fix 1b: shapes A-G above
all require either a registration CALL or a class-body/call-keyword STRING
LITERAL co-occurring with a handler. A real, confirmed gap (see
`bench/remaining_misses_diagnosis/REMAINING_MISSES_DIAGNOSIS.md` targets 2
and 6): the official `modelcontextprotocol/python-sdk` registers its own
built-in task handlers via plain dict-key SUBSCRIPT ASSIGNMENT --
`mcp/server/lowlevel/experimental.py`'s real
`self._request_handlers[GetTaskRequest] = _default_get_task` (confirmed
directly by reading that file, not assumed) -- and `PrefectHQ/fastmcp`'s
OpenAPI-provider tool registration uses the identical AST shape,
`self._tools[tool.name] = tool` (`provider.py`, confirmed directly). Neither
is a call (shape B/F) or a class-body literal (shape G) -- there is no
recognized call name, and the target isn't a class body at all, it's a
`Subscript` assignment target.

  H. `registry_subscript_assignment`: `self.<attr>[...] = <value>` (or
     `cls.<attr>[...] = <value>`) where `<attr>` is in a small, real,
     confirmed vocabulary, `_REGISTRY_DICT_ATTRS` (`_request_handlers`,
     `_tools` -- BOTH names taken directly from the two real targets above,
     `tools`/`_handlers` added as the same small-generalization step shape
     C's own `_HANDLER_FIELD_KEYS` already takes over a single confirmed
     real name) -- the same "recognize a small, real, confirmed vocabulary
     rather than any subscript at all" discipline `_CRED_PATH_KEYWORDS`/
     `_CLASS_HANDLER_METHODS` already use elsewhere in this project.
     `<value>` is resolved two ways, tried in order:
       1. A bare same-file function/closure reference, EXACTLY shape B's
          own resolution (`ast.walk(tree)` finds a `def`/`async def` of
          that name anywhere in the file, nested closures included --
          covers python-sdk's `_default_get_task` shape completely, since
          it is a closure nested directly inside the very function that
          registers it).
       2. Only if (1) finds nothing: ONE hop through a local variable's own
          same-enclosing-function assignment to a class-constructor `Call`
          (`tool = OpenAPITool(...)`, then `self._tools[tool.name] = tool`
          two statements later -- the real fastmcp-openapi-ssrf shape),
          resolving the constructed class's own `execute`/`run`/`call`/
          `handle`/`invoke` method (the SAME `_CLASS_HANDLER_METHODS`
          vocabulary shape G already uses) as the real handler. This is a
          single, bounded local-variable hop -- the same "ONE hop, never
          chased further" discipline `entrypoints_js.py`'s own
          `_resolve_name_literal_one_hop`/Go's receiver-method resolution
          already apply elsewhere in this project, not a general call
          -graph or def-use analysis.
     An unresolved `<value>` (imported, a bare parameter with no local
     constructor, produced by an unrecognized expression) is not counted --
     silence, not a guess, same rule as every other shape in this module.
     Tagged "medium", never "high", same reasoning as shapes F/G. Never
     downgrades an entry shapes A-G already recovered at the same (file,
     function).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

# Decorator names (last dotted component) that mark a function as an MCP
# handler directly. "call_tool" is the low-level SDK's single-dispatcher
# decorator and is tagged with a distinct sdk_shape below, not conflated with
# the FastMCP per-tool decorators.
_HANDLER_DECORATOR_NAMES = frozenset({"tool", "resource", "prompt", "call_tool"})

# Call names (last dotted component) whose first positional argument is a
# handler function object being registered directly (shape B).
_REGISTRATION_CALL_NAMES = frozenset({"tool", "add_tool", "from_function"})

# Directories never worth walking for entrypoint recovery -- same component-
# based matching discipline as source_scanner.py's _SKIP_DIRS (a substring
# match on "test" would also skip a real "testUtils/" package or any
# directory that merely starts with "test"). "benchmarks"/"examples"/"docs"/
# ".github" added after a real coverage-measurement run found these directory
# names flooding evidence packs with irrelevant monorepo noise (confirmed
# real cause of misses on Stripe/CrowdStrike/MongoDB holdout targets -- see
# bench/STAGE1_EVIDENCE_FIX_STATUS.md).
_SKIP_DIR_PARTS = frozenset({
    "node_modules", "dist", "vendor", ".git", "__pycache__", "test", "tests", ".venv", "venv",
    "benchmarks", "examples", "docs", ".github",
})


# Tool-name anchoring (shapes F/G, see module docstring). Keyword names
# whose STRING-LITERAL value is treated as a tool-name anchor (shape F),
# and keyword names whose value is the paired handler reference.
_KEYWORD_NAME_ARGS = frozenset({"name", "tool_name"})
_KEYWORD_HANDLER_ARGS = frozenset({"method", "handler", "fn", "func", "callback"})

# Class-body attribute names whose STRING-LITERAL value is treated as a
# tool-name anchor (shape G), and method names treated as the paired
# handler when defined directly in that same class.
_CLASS_NAME_ATTRS = frozenset({"name", "tool_name", "TOOL_NAME"})
_CLASS_HANDLER_METHODS = frozenset({"execute", "run", "call", "handle", "invoke"})

# Dict-key registry-assignment vocabulary (shape H, see module docstring).
# `_request_handlers`/`_tools` are the two real, confirmed attribute names
# (modelcontextprotocol/python-sdk, PrefectHQ/fastmcp); `tools`/`_handlers`
# are the same small generalization step `_CLASS_HANDLER_METHODS` already
# takes over a single confirmed real name, not an unbounded guess.
_REGISTRY_DICT_ATTRS = frozenset({"_request_handlers", "_tools", "tools", "_handlers"})


def _is_skip_dir_part(part: str, skip_set: frozenset[str] = _SKIP_DIR_PARTS) -> bool:
    """True if a single path component should never be walked for entrypoint
    recovery -- membership in `skip_set`, or a "*-tests"/"*_tests" suffix
    (e.g. "integration-tests", "e2e-tests", "accuracy-tests") that a real
    monorepo target (mongodb-mcp-server) used but the literal "test"/"tests"
    set alone doesn't catch."""
    return part in skip_set or part.endswith(("-tests", "_tests"))


@dataclass
class McpEntrypoint:
    """A function recovered as a real MCP tool/resource/prompt handler."""

    file: Path
    function_name: str
    line: int
    parameter_names: list[str]
    sdk_shape: str  # "fastmcp_decorator" | "low_level_dispatcher" | "tool_call" |
    # "add_tool_call" | "tool_from_function" | "list_loop_registration"
    confidence: str  # "high" | "medium"


def _dotted_chain(node: ast.expr) -> str:
    """Render `a.b.c` (an Attribute/Name chain) back to a dotted string.
    Anything else (a subscript, a call result, ...) yields ''."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    else:
        return ""
    return ".".join(reversed(parts))


def _params_of(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    return [a.arg for a in fn.args.args if a.arg not in ("self", "cls")]


def _iter_python_files(root: Path):
    for p in root.rglob("*.py"):
        if not p.is_file():
            continue
        try:
            rel_parts = p.relative_to(root).parts[:-1]
        except ValueError:
            rel_parts = p.parts[:-1]
        if any(_is_skip_dir_part(part) for part in rel_parts):
            continue
        yield p


def recover_entrypoints(root: str | Path) -> list[McpEntrypoint]:
    """Walk a Python source tree and recover the set of functions that are
    real MCP tool/resource/prompt handlers, via the three registration shapes
    documented in this module's docstring. Repo-wide (not per-file): shape C
    is inherently cross-file.
    """
    root = Path(root)
    trees: dict[Path, ast.Module] = {}
    for p in _iter_python_files(root):
        try:
            trees[p] = ast.parse(p.read_text(encoding="utf-8", errors="ignore"), filename=str(p))
        except SyntaxError:
            continue

    entrypoints: dict[tuple[Path, str], McpEntrypoint] = {}

    # Shape C bookkeeping: (defining-module-stem, list-attribute-name) -> the
    # handler functions appended to it, and, separately, which such
    # (module, list) pairs are actually looped over and registered somewhere.
    appended_to_list: dict[tuple[str, str], list[tuple[Path, ast.FunctionDef | ast.AsyncFunctionDef]]] = {}
    looped_lists: set[tuple[str, str]] = set()

    for path, tree in trees.items():
        for node in ast.walk(tree):
            # --- Shape A and shape C's "append" half: decorators on a def ---
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                for deco in node.decorator_list:
                    target = deco.func if isinstance(deco, ast.Call) else deco
                    chain = _dotted_chain(target)
                    if not chain:
                        continue
                    last = chain.rsplit(".", 1)[-1]
                    if last in _HANDLER_DECORATOR_NAMES:
                        shape = "low_level_dispatcher" if last == "call_tool" else "fastmcp_decorator"
                        key = (path, node.name)
                        entrypoints[key] = McpEntrypoint(
                            path, node.name, node.lineno, _params_of(node), shape, "high"
                        )
                    elif last == "append":
                        list_name = chain.rsplit(".", 1)[0]
                        appended_to_list.setdefault((path.stem, list_name), []).append((path, node))

            # --- Shape B: a registration call passing a function object ---
            if isinstance(node, ast.Call):
                chain = _dotted_chain(node.func)
                if not chain or not node.args:
                    continue
                last = chain.rsplit(".", 1)[-1]
                if last not in _REGISTRATION_CALL_NAMES:
                    continue
                arg = node.args[0]
                if isinstance(arg, ast.Name):
                    shape = {"add_tool": "add_tool_call", "from_function": "tool_from_function"}.get(
                        last, "tool_call"
                    )
                    # Resolve against a def in the SAME file only -- a
                    # cross-file direct call is a call-graph fact this module
                    # deliberately does not chase (see module docstring).
                    for candidate in ast.walk(tree):
                        if (
                            isinstance(candidate, ast.FunctionDef | ast.AsyncFunctionDef)
                            and candidate.name == arg.id
                        ):
                            key = (path, candidate.name)
                            entrypoints[key] = McpEntrypoint(
                                path, candidate.name, candidate.lineno, _params_of(candidate), shape, "high"
                            )
                    # Shape C's "loop" half: `for t in mod.some_list: mcp.tool(t)`.
                    for maybe_for in ast.walk(tree):
                        if (
                            isinstance(maybe_for, ast.For)
                            and isinstance(maybe_for.target, ast.Name)
                            and maybe_for.target.id == arg.id
                        ):
                            it_chain = _dotted_chain(maybe_for.iter)
                            if "." in it_chain:
                                mod_ref, list_attr = it_chain.rsplit(".", 1)
                                looped_lists.add((mod_ref.rsplit(".", 1)[-1], list_attr))

    # Resolve shape C: a list only counts once BOTH halves are confirmed --
    # appended-to in its defining file AND looped-over somewhere else.
    for (mod_stem, list_attr), fns in appended_to_list.items():
        if (mod_stem, list_attr) not in looped_lists:
            continue
        for fn_path, fn_node in fns:
            key = (fn_path, fn_node.name)
            entrypoints[key] = McpEntrypoint(
                fn_path,
                fn_node.name,
                fn_node.lineno,
                _params_of(fn_node),
                "list_loop_registration",
                # Medium, not high: this shape depends on matching a bare
                # module-stem/attribute-name pair across two files rather
                # than resolving a name against a def in the same file --
                # more room for a coincidental name collision to over-match.
                "medium",
            )

    # Tool-name anchoring (shapes F/G, additive -- see module docstring).
    # Runs after A-C so it can see what they already found and never
    # downgrade a "high"-confidence entry recovered from a real SDK call.
    for path, tree in trees.items():
        _recover_tool_name_anchored(path, tree, entrypoints)

    # Dict-key registry assignment (shape H, additive -- see module
    # docstring). Runs after A-G for the same never-downgrade reason.
    for path, tree in trees.items():
        _recover_registry_subscript_anchored(path, tree, trees, entrypoints)

    return sorted(entrypoints.values(), key=lambda e: (str(e.file), e.line))


def _recover_tool_name_anchored(
    path: Path, tree: ast.Module, entrypoints: dict[tuple[Path, str], McpEntrypoint]
) -> None:
    """Shapes F and G (see module docstring): walk `tree` tracking the
    nearest enclosing `ClassDef` (plain `ast.walk` has no parent links, so a
    manual recursive descent is used here instead), trying shape G on every
    class body and shape F on every call expression."""
    class_stack: list[ast.ClassDef] = []

    def visit(node: ast.AST) -> None:
        pushed = False
        if isinstance(node, ast.ClassDef):
            _try_class_attribute_registration(node, path, entrypoints)
            class_stack.append(node)
            pushed = True
        elif isinstance(node, ast.Call):
            _try_keyword_registration(node, class_stack[-1] if class_stack else None, path, tree, entrypoints)
        for child in ast.iter_child_nodes(node):
            visit(child)
        if pushed:
            class_stack.pop()

    visit(tree)


def _record_if_not_downgrading(
    entrypoints: dict[tuple[Path, str], McpEntrypoint], key: tuple[Path, str], ep: McpEntrypoint
) -> None:
    existing = entrypoints.get(key)
    if existing is not None and existing.confidence == "high":
        return  # already recovered by a stronger, SDK-call-based shape
    entrypoints[key] = ep


def _try_keyword_registration(
    call: ast.Call,
    enclosing_class: ast.ClassDef | None,
    path: Path,
    tree: ast.Module,
    entrypoints: dict[tuple[Path, str], McpEntrypoint],
) -> None:
    """Shape F: a `name="..."` keyword and a `method=`/`handler=`/... sibling
    keyword in the SAME call (see module docstring's CrowdStrike example)."""
    name_val: str | None = None
    handler_val: ast.expr | None = None
    for kw in call.keywords:
        if kw.arg is None:  # a **kwargs spread -- not a literal keyword
            continue
        if kw.arg in _KEYWORD_NAME_ARGS and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
            name_val = kw.value.value
        elif kw.arg in _KEYWORD_HANDLER_ARGS:
            handler_val = kw.value
    if name_val is None or handler_val is None:
        return

    fn_node: ast.FunctionDef | ast.AsyncFunctionDef | None = None
    if (
        isinstance(handler_val, ast.Attribute)
        and isinstance(handler_val.value, ast.Name)
        and handler_val.value.id in ("self", "cls")
        and enclosing_class is not None
    ):
        for stmt in enclosing_class.body:
            if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef) and stmt.name == handler_val.attr:
                fn_node = stmt
                break
    elif isinstance(handler_val, ast.Name):
        for candidate in ast.walk(tree):
            if isinstance(candidate, ast.FunctionDef | ast.AsyncFunctionDef) and candidate.name == handler_val.id:
                fn_node = candidate
                break
    if fn_node is None:
        return  # unresolved -- silence, not a guess (same rule as shapes A-C)

    key = (path, fn_node.name)
    _record_if_not_downgrading(
        entrypoints,
        key,
        McpEntrypoint(path, fn_node.name, fn_node.lineno, _params_of(fn_node), "keyword_registration", "medium"),
    )


def _try_class_attribute_registration(
    cls: ast.ClassDef, path: Path, entrypoints: dict[tuple[Path, str], McpEntrypoint]
) -> None:
    """Shape G: a class-body `name = "..."` (or `tool_name`/`TOOL_NAME`)
    assignment, paired with an `execute`/`run`/`call`/`handle`/`invoke`
    method defined directly in that SAME class (see module docstring's
    mongodb-mcp-server-style example)."""
    has_name_attr = False
    for stmt in cls.body:
        targets: list[str]
        value: ast.expr | None
        if isinstance(stmt, ast.Assign):
            targets = [t.id for t in stmt.targets if isinstance(t, ast.Name)]
            value = stmt.value
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            targets = [stmt.target.id]
            value = stmt.value
        else:
            continue
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            continue
        if any(t in _CLASS_NAME_ATTRS for t in targets):
            has_name_attr = True
            break
    if not has_name_attr:
        return

    for stmt in cls.body:
        if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef) and stmt.name in _CLASS_HANDLER_METHODS:
            key = (path, stmt.name)
            _record_if_not_downgrading(
                entrypoints,
                key,
                McpEntrypoint(
                    path, stmt.name, stmt.lineno, _params_of(stmt), "class_attribute_registration", "medium"
                ),
            )


def _recover_registry_subscript_anchored(
    path: Path,
    tree: ast.Module,
    all_trees: dict[Path, ast.Module],
    entrypoints: dict[tuple[Path, str], McpEntrypoint],
) -> None:
    """Shape H (see module docstring): walk `tree` tracking the nearest
    enclosing function (plain `ast.walk` has no parent links, so a manual
    recursive descent is used here, mirroring `_recover_tool_name_anchored`'s
    own class-stack approach for shapes F/G, just tracking a function stack
    instead of a class stack). `all_trees` (every parsed file in the repo,
    not just this one) is threaded through to resolution step 2 only -- see
    `_resolve_local_constructor_handler`'s own docstring for why that one
    step needs it."""
    fn_stack: list[ast.FunctionDef | ast.AsyncFunctionDef] = []

    def visit(node: ast.AST) -> None:
        pushed = False
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            fn_stack.append(node)
            pushed = True
        elif isinstance(node, ast.Assign):
            _try_registry_subscript_assignment(
                node, fn_stack[-1] if fn_stack else None, path, tree, all_trees, entrypoints
            )
        for child in ast.iter_child_nodes(node):
            visit(child)
        if pushed:
            fn_stack.pop()

    visit(tree)


def _try_registry_subscript_assignment(
    assign: ast.Assign,
    enclosing_fn: ast.FunctionDef | ast.AsyncFunctionDef | None,
    path: Path,
    tree: ast.Module,
    all_trees: dict[Path, ast.Module],
    entrypoints: dict[tuple[Path, str], McpEntrypoint],
) -> None:
    """Shape H: `self.<attr>[...] = <value>` where `<attr>` is in
    `_REGISTRY_DICT_ATTRS` (see module docstring's real python-sdk/fastmcp
    examples)."""
    if len(assign.targets) != 1:
        return
    target = assign.targets[0]
    if not isinstance(target, ast.Subscript):
        return
    obj = target.value
    if not (
        isinstance(obj, ast.Attribute)
        and isinstance(obj.value, ast.Name)
        and obj.value.id in ("self", "cls")
        and obj.attr in _REGISTRY_DICT_ATTRS
    ):
        return

    value = assign.value
    fn_node: ast.FunctionDef | ast.AsyncFunctionDef | None = None
    fn_path = path
    if isinstance(value, ast.Name):
        # (1) A bare same-file function/closure reference -- exactly shape
        # B's own resolution, nested closures included (covers python-sdk's
        # `self._request_handlers[X] = _default_get_task` shape).
        for candidate in ast.walk(tree):
            if isinstance(candidate, ast.FunctionDef | ast.AsyncFunctionDef) and candidate.name == value.id:
                fn_node = candidate
                break
        # (2) Only if (1) found nothing: ONE hop through a local variable's
        # own same-enclosing-function assignment to a class-constructor Call
        # (covers fastmcp-openapi-ssrf's `tool = OpenAPITool(...)` /
        # `self._tools[tool.name] = tool` two-statement shape). The resolved
        # method can live in a DIFFERENT file than `path` (see
        # `_resolve_local_constructor_handler`'s own docstring) -- its own
        # `fn_path` is used for recording below, never the registration
        # call's `path`, the same "a cross-file match's path must be read
        # from ITS OWN file" discipline `entrypoints_go.py`'s
        # `_find_toplevel_func_in_package` already documents.
        if fn_node is None and enclosing_fn is not None:
            found = _resolve_local_constructor_handler(value.id, enclosing_fn, all_trees)
            if found is not None:
                fn_node, fn_path = found
    if fn_node is None:
        return  # unresolved -- silence, not a guess (same rule as shapes A-G)

    key = (fn_path, fn_node.name)
    _record_if_not_downgrading(
        entrypoints,
        key,
        McpEntrypoint(
            fn_path, fn_node.name, fn_node.lineno, _params_of(fn_node), "registry_subscript_assignment", "medium"
        ),
    )


def _resolve_local_constructor_handler(
    var_name: str, enclosing_fn: ast.FunctionDef | ast.AsyncFunctionDef, all_trees: dict[Path, ast.Module]
) -> tuple[ast.FunctionDef | ast.AsyncFunctionDef, Path] | None:
    """ONE hop (see module docstring's shape H resolution step 2): find
    `var_name = SomeClass(...)` anywhere in `enclosing_fn`'s own body (this
    half stays same-function, no wider search), then resolve `SomeClass` to
    its own `ClassDef` -- searched across `all_trees` (every parsed file in
    the repo), a deliberate, narrow exception to this module's own same
    -file-only discipline: confirmed directly against the real
    fastmcp-openapi-ssrf target, `OpenAPITool` (the constructed class) is
    defined in `components.py` while `tool = OpenAPITool(...)` /
    `self._tools[tool.name] = tool` are both in the sibling `provider.py`
    (an ordinary `from .components import OpenAPITool` one file apart) --
    requiring same-file resolution here would make this shape miss the
    exact real target it exists to catch, the identical reasoning
    `entrypoints_js.py`'s own shape F already documents for its analogous
    Aiven cross-file enum case. Still bounded to a plain by-NAME class
    lookup (no import-graph resolution, no handling of a class re-exported
    or aliased under a different name) -- not a general cross-file call
    graph. Returns `(method, the file it was found in)` for the first
    `execute`/`run`/`call`/`handle`/`invoke` method (`_CLASS_HANDLER_METHODS`,
    the same vocabulary shape G already uses) defined DIRECTLY in that
    class -- the file must be returned alongside it since a cross-file
    match's own path (never the registration call's `path`) is what the
    caller has to record it under, mirroring `entrypoints_go.py`'s
    `_find_toplevel_func_in_package`'s identical return shape and rationale.
    `None` (unresolved -- silence, not a guess) if no such local
    constructor assignment, class, or handler method is found anywhere."""
    for stmt in ast.walk(enclosing_fn):
        if not (isinstance(stmt, ast.Assign) and len(stmt.targets) == 1):
            continue
        t = stmt.targets[0]
        if not (isinstance(t, ast.Name) and t.id == var_name):
            continue
        if not isinstance(stmt.value, ast.Call):
            continue
        class_name = _dotted_chain(stmt.value.func).rsplit(".", 1)[-1]
        if not class_name:
            continue
        for other_path, other_tree in all_trees.items():
            for candidate in ast.walk(other_tree):
                if isinstance(candidate, ast.ClassDef) and candidate.name == class_name:
                    for member in candidate.body:
                        if (
                            isinstance(member, ast.FunctionDef | ast.AsyncFunctionDef)
                            and member.name in _CLASS_HANDLER_METHODS
                        ):
                            return member, other_path
        break  # first matching local assignment only -- see module docstring
    return None


if __name__ == "__main__":
    import sys

    for ep in recover_entrypoints(sys.argv[1] if len(sys.argv) > 1 else "."):
        print(
            f"{ep.file}:{ep.line}  {ep.function_name}({', '.join(ep.parameter_names)})  "
            f"via={ep.sdk_shape} confidence={ep.confidence}"
        )
