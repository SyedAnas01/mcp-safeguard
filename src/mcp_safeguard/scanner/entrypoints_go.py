"""Stage 1: MCP entrypoint recovery (Go).

The Go sibling of `entrypoints.py` (Python) and `entrypoints_js.py` (JS/TS) --
same job ("which functions in this repository actually run when an MCP
client calls a tool?"), same output shape (`McpEntrypoint`, imported from
`entrypoints.py` rather than redefined), a different language and a
different parser. Go has no stdlib AST module usable from Python, so this
module uses `tree-sitter` with the real `tree-sitter-go` grammar, mirroring
`entrypoints_js.py`'s own tree-sitter approach rather than entrypoints.py's
`ast` walk.

Built to close a confirmed gap: Go had ZERO language support anywhere in
this pipeline before this module, even though real, campaign-audited Go MCP
servers exist and are already in this project's own ledger (see
`bench/ledger/entries/digitalocean-genai-evaluation-arbitrary-file-read.json`
and `bench/ledger/entries/datadog-code-security-mcp-sbom-path-traversal.json`)
-- both confirmed vulnerabilities live in functions this module recovers as
real entrypoints (see `GO_ENTRYPOINTS_STATUS.md` for the exact before/after
counts against both real targets).

Recognized registration shapes -- both found by reading the real source of
the two proof targets, not assumed from documentation:

  A. `add_tool_call` -- any call whose final selector component is
     `AddTool`, covering THREE real call shapes that all share this exact
     name across two different Go MCP SDKs:
       - `github.com/mark3labs/mcp-go`'s `(*server.MCPServer).AddTool(mcp.Tool{...}, handler)`
         (the real datadog-labs/datadog-code-security-mcp shape, e.g.
         `s.AddTool(mcp.Tool{Name: "datadog_generate_sbom", ...}, handleGenerateSBOM)`).
       - the official `github.com/modelcontextprotocol/go-sdk`'s method form,
         `(*mcp.Server).AddTool(&mcp.Tool{...}, handler)` (confirmed against
         real usage in docker/mcp-gateway's own example servers, e.g.
         `server.AddTool(&mcp.Tool{Name: "list_collections", ...}, vs.handleListCollections)`).
       - the same SDK's generic free-function form,
         `mcp.AddTool(server, &mcp.Tool{...}, handler)`.
     All three are recognized by ONE rule rather than three separate shapes:
     a call named `AddTool` where ANY positional argument is a `Tool{...}`
     composite literal (or `&Tool{...}`, unwrapped through the leading `&`)
     whose own field literally named `Name` holds a string constant, and
     the LAST positional argument is the handler. Requiring the literal
     type's last dotted component to be exactly `Tool` (not just "some
     struct with a Name field") is what keeps this call-name-based shape at
     "high" confidence, the same reasoning `entrypoints.py`'s own shape B
     uses for its recognized call names.
  B. `server_tool_struct` -- `github.com/mark3labs/mcp-go`'s OTHER real
     registration idiom, returning a slice of its own `server.ServerTool`
     struct from a `Tools()` method (the real digitalocean-labs/
     mcp-digitalocean shape):
       ```go
       func (et *EvaluationTool) Tools() []server.ServerTool {
           return []server.ServerTool{
               {Handler: et.createEvaluationDataset,
                Tool: mcp.NewTool("genai-create-evaluation-dataset", ...)},
               ...
           }
       }
       ```
     Recognized by a composite literal whose type's last dotted component
     is exactly `ServerTool`, carrying both a `Handler` field (the handler)
     and a `Tool` field (structurally always the tool descriptor, and in
     every real target seen a call to something ending in `NewTool` --
     though, mirroring `entrypoints_js.py`'s own explicit precedent for its
     analogous Aiven shape F ("resolution failing does NOT block
     recovery"), the `Tool` field's own literal name is NOT required to
     resolve for this shape to fire; `Handler`+`Tool` co-occurring on a
     literal actually typed `ServerTool` is treated as sufficient on its
     own). Tagged "high", not "medium" -- unlike a bare name/handler
     naming-convention collision (shape C below), this requires the
     literal's own TYPE to be the SDK's real, specific `ServerTool` name.
  C. `tool_name_anchored` -- a SECOND, ADDITIVE, generic fallback,
     symmetric with `entrypoints.py`'s shapes F/G and `entrypoints_js.py`'s
     shapes F/G/H: shapes A/B above both require a *specific* call name or
     struct type. A project that wraps registration in its own helper type
     (`Registration{Name: "x", Handler: fn}`) would use neither. This shape
     anchors on the same "a tool name string literal and a handler
     reference co-occur in the SAME lexical unit" signal those Python/JS
     shapes already use, applied to Go's composite literals: ANY composite
     literal (no type-name requirement at all) with a field named
     `Name`/`ToolName`/`Tool_Name` holding a string constant, paired with a
     sibling field named `Handler`/`Fn`/`Func`/`Callback`/`Run`/`Call`/
     `Execute`/`Invoke`. Tagged "medium", never downgrading an entry shapes
     A/B already recovered at the same (file, line) -- identical discipline
     to every other tool-name-anchoring fallback in this project.
  D. `type_anchored_signature` / E. `type_anchored_registrar_call` --
     evidence-structural-fixes milestone, Fix 3: two further ADDITIVE
     shapes anchored on the SDK's own request/result TYPE NAMES
     (`CallToolRequest`/`CallToolResult`) or a repo-local generic handler
     -type alias (`ToolHandlerFunc[T, R]`/`ToolHandlerFor[In, Out]`) rather
     than any call shape at all -- see this file's own section comment
     directly above `_try_type_anchored_signature` for the full real-target
     detail (github-mcp-server's generic `NewTool[In, Out any](...)`
     wrapper and grafana/mcp-grafana's generic `MustTool[T, R any](...)`,
     neither recognized by shapes A/B/C).
  F. `interface_method_override` -- SDK-vocab-and-truncation-fix milestone,
     Fix 1a: a further ADDITIVE shape anchored on a fixed stdlib/SDK
     INTERFACE method name+signature (`ServeHTTP(http.ResponseWriter,
     *http.Request)`, Go's `http.Handler` interface) rather than any call,
     composite-literal, or handler-signature shape at all -- recovers a
     transport/protocol type's own interface-method override (e.g.
     modelcontextprotocol/go-sdk's `StreamableHTTPHandler.ServeHTTP`,
     CVE-2026-33252) that shapes A-E have no vocabulary for, since it is the
     TRANSPORT layer invoking tool handlers, not a tool handler itself. See
     this file's own section comment directly above
     `_try_interface_method_override` for the full detail.

Handler resolution (shared by all three shapes above) is scoped to the
SAME PACKAGE, not the same file -- a deliberate departure from
`entrypoints.py`/`entrypoints_js.py`'s own same-file-only discipline,
forced by a real difference between the languages rather than a laxer
standard: Python and JS/TS scope names to the file (a name must be
`import`ed to cross a file boundary), but Go's compilation unit is the
PACKAGE -- every `.go` file in one directory shares one top-level scope
automatically, with no import needed, and a directory is provably a single
package (Go forbids two packages in one directory). "Same directory" is
therefore the exact Go analog of "same file" elsewhere in this project: the
narrowest scope that still requires zero import-graph resolution. This was
not a stylistic choice -- an earlier, same-file-only version of this module
recovered 0 entrypoints from the real datadog-labs/datadog-code-security-mcp
target, because that target registers every tool in `start.go` but defines
every handler in a SEPARATE sibling file, `handlers.go`, of the same
`cmd/datadog-code-security-mcp` package (confirmed by reading both files).
Resolution itself:
  - an inline `func_literal` is the handler itself;
  - a bare `identifier` is resolved against a top-level `func` declaration
    (no receiver) of that name anywhere in the SAME PACKAGE (the real
    datadog shape above);
  - a `recv.Method` selector is resolved via the ONE real binding Go
    actually gives it: `recv` must be the RECEIVER VARIABLE of the
    enclosing method the registration call itself lives inside (e.g.
    `vs.handleListCollections` inside `func (vs *VectorServer)
    registerTools(...)`, or `et.createEvaluationDataset` inside `func (et
    *EvaluationTool) Tools()`) -- confirmed the real binding mechanism in
    BOTH proof targets, not a guess. The method is then looked up by name
    against every `method_declaration` in the SAME PACKAGE whose OWN
    receiver has the same TYPE (stripping a leading `*`), not by
    variable-name convention alone. A selector whose base identifier does
    NOT match the enclosing method's own receiver (a package-level var, an
    unrelated local, a receiver of a DIFFERENT method) is deliberately left
    unresolved -- silence, not a guess, the same rule stated in
    `entrypoints.py`'s own module docstring.

Deliberately NOT attempted, matching every other module in this package:
a general call graph, type inference beyond one receiver-name hop, CROSS
-package import resolution, or chasing a handler through a factory/wrapper
function. `_test.go` files are skipped outright (never part of a real
server binary), on top of the shared `_SKIP_DIR_PARTS` skip-dir discipline
`entrypoints.py` already applies (extended here with Go-specific
`testdata`/`third_party`/`third-party`/`bin`, the same real-target-driven
additions `entrypoints_js.py` made for its own language's build-output
conventions).
"""

from __future__ import annotations

from pathlib import Path

from tree_sitter import Language, Node, Parser

from .entrypoints import _SKIP_DIR_PARTS as _PY_SKIP_DIR_PARTS
from .entrypoints import McpEntrypoint, _is_skip_dir_part

# Go-specific additions on top of the shared skip list (node_modules, dist,
# vendor, .git, test(s), venv/.venv, benchmarks/examples/docs/.github are
# already covered there). "third_party"/"third-party" matter for Go
# specifically: a real vendored copy of an SDK under that directory name
# (seen in real Go MCP servers) is SDK source, not a target's own
# registration code, and would otherwise flood recovery with the SDK's own
# internal call sites.
_SKIP_DIR_PARTS = _PY_SKIP_DIR_PARTS | frozenset({"testdata", "third_party", "third-party", "bin"})

_ADD_TOOL_CALL_NAME = "AddTool"

# Tool-name anchoring (shape C, see module docstring).
_NAME_FIELD_KEYS = frozenset({"Name", "ToolName", "Tool_Name"})
_HANDLER_FIELD_KEYS = frozenset({"Handler", "Fn", "Func", "Callback", "Run", "Call", "Execute", "Invoke"})

_langs: dict[str, Language] = {}
_parsers: dict[str, Parser] = {}


def _language() -> Language:
    if "go" not in _langs:
        import tree_sitter_go as tsgo

        _langs["go"] = Language(tsgo.language())
    return _langs["go"]


def _parser() -> Parser:
    if "go" not in _parsers:
        _parsers["go"] = Parser(_language())
    return _parsers["go"]


def parse_file(path: Path) -> tuple[Node, bytes] | None:
    """Parse one `.go` file. Returns (root_node, source-bytes), or None for
    an unreadable file or a parse failure."""
    if path.suffix != ".go":
        return None
    try:
        src = path.read_bytes()
    except OSError:
        return None
    try:
        tree = _parser().parse(src)
    except Exception:
        return None
    return tree.root_node, src


def iter_go_files(root: Path):
    for p in root.rglob("*.go"):
        if not p.is_file() or p.name.endswith("_test.go"):
            continue
        try:
            rel_parts = p.relative_to(root).parts[:-1]
        except ValueError:
            rel_parts = p.parts[:-1]
        if any(_is_skip_dir_part(part, _SKIP_DIR_PARTS) for part in rel_parts):
            continue
        yield p


def walk(node: Node):
    """All descendants of `node`, including itself. Mirrors
    `entrypoints_js.py`'s own stack-based `walk`."""
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(n.children)


def node_text(node: Node, src: bytes) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", errors="ignore")


def _string_literal_text(node: Node, src: bytes) -> str | None:
    """The literal text of an `interpreted_string_literal`/`raw_string_literal`
    node with its quotes/backticks stripped, or None if `node` isn't a
    string literal at all. A plain quote-strip, not full escape processing
    -- mirrors `entrypoints_js.py`'s own `_string_literal_text`, which makes
    the identical simplification for the same reason (a real tool name is a
    plain identifier-like string, never one that needs escape decoding)."""
    if node.type not in ("interpreted_string_literal", "raw_string_literal"):
        return None
    text = node_text(node, src)
    if len(text) >= 2 and text[0] in "\"`" and text[-1] == text[0]:
        return text[1:-1]
    return text


def _bare_type_name(type_text: str | None) -> str | None:
    """A composite literal's own type, reduced to its bare final component:
    `server.ServerTool` and `*server.ServerTool` both yield `ServerTool`.
    None passes through as None."""
    if type_text is None:
        return None
    return type_text.lstrip("*").rsplit(".", 1)[-1]


def _iter_field_literals(root_node: Node, src: bytes):
    """Yield `(effective_type_name_or_None, body_node)` for every Go
    literal body with keyed fields in the file: an explicit composite
    literal (`mcp.Tool{...}`, optionally `&`-wrapped -- the type comes from
    its own `type` field) AND an ELIDED-type element inside an aggregate
    literal (`[]server.ServerTool{ {Handler: ..., Tool: ...}, ... }`'s own
    `{...}` entries). Go allows omitting the repeated type on an aggregate's
    own elements, and tree-sitter-go represents an elided element as a bare
    `literal_value` with NO `composite_literal` wrapper at all -- confirmed
    directly against the real digitalocean-labs/mcp-digitalocean source,
    which uses exactly this elided form for every `server.ServerTool{...}`
    entry in its `Tools()` methods. Missing this case entirely, not a
    lower-confidence miss, is what an earlier version of this module did
    before being corrected against that real target. The effective type of
    an elided element is read off the ENCLOSING aggregate literal's own
    type: `element` field of a `slice_type`/`array_type`, `value` field of
    a `map_type`, or the type's own text otherwise."""
    for node in walk(root_node):
        if node.type != "literal_value":
            continue
        parent = node.parent
        if parent is not None and parent.type == "composite_literal":
            type_node = parent.child_by_field_name("type")
            yield (node_text(type_node, src) if type_node is not None else None), node
            continue
        if parent is not None and parent.type == "literal_element":
            outer_body = parent.parent
            outer_composite = outer_body.parent if outer_body is not None and outer_body.type == "literal_value" else None
            type_text: str | None = None
            if outer_composite is not None and outer_composite.type == "composite_literal":
                outer_type = outer_composite.child_by_field_name("type")
                if outer_type is not None:
                    if outer_type.type in ("slice_type", "array_type"):
                        elem = outer_type.child_by_field_name("element")
                        type_text = node_text(elem, src) if elem is not None else None
                    elif outer_type.type == "map_type":
                        val = outer_type.child_by_field_name("value")
                        type_text = node_text(val, src) if val is not None else None
                    else:
                        type_text = node_text(outer_type, src)
            yield type_text, node
            continue
        yield None, node


def _call_name(fn_node: Node, src: bytes) -> str:
    """The final component of a call's own callee expression: the field
    name of a `recv.Method(...)`/`pkg.Func(...)` selector, or a bare
    identifier's own text."""
    if fn_node.type == "selector_expression":
        field = fn_node.child_by_field_name("field")
        return node_text(field, src) if field is not None else ""
    if fn_node.type == "identifier":
        return node_text(fn_node, src)
    return ""


def _keyed_fields(body: Node, src: bytes) -> dict[str, Node]:
    """A literal body's (a `literal_value` node -- either an explicit
    composite literal's own `body` field, or an elided-type aggregate
    element, see `_iter_field_literals`) OWN top-level `key: value` fields
    (never descending into a nested literal) as `{field_name: value_node}`.
    Go's grammar wraps both the key and the value of a `keyed_element` in a
    `literal_element` node, unwrapped here so callers see the real
    identifier/expression underneath directly."""
    fields: dict[str, Node] = {}
    for el in body.named_children:
        if el.type != "keyed_element":
            continue
        key_node = el.child_by_field_name("key")
        value_node = el.child_by_field_name("value")
        if key_node is None or value_node is None:
            continue
        if key_node.type == "literal_element" and key_node.named_children:
            key_node = key_node.named_children[0]
        if value_node.type == "literal_element" and value_node.named_children:
            value_node = value_node.named_children[0]
        if key_node.type != "identifier":
            continue
        fields[node_text(key_node, src)] = value_node
    return fields


def _type_name(type_node: Node | None, src: bytes) -> str | None:
    """A method receiver's declared type, stripped of a leading `*` --
    `(vs *VectorServer)` and `(vs VectorServer)` both yield `VectorServer`.
    None for anything this module doesn't recognize (a generic receiver, a
    qualified cross-package type -- Go method receivers must be local
    types, so this is not expected in real code)."""
    if type_node is None:
        return None
    if type_node.type == "pointer_type":
        inner = type_node.named_children[0] if type_node.named_children else None
        return _type_name(inner, src)
    if type_node.type == "type_identifier":
        return node_text(type_node, src)
    return None


def _params_of_go(fn_node: Node, src: bytes) -> list[str]:
    """Every parameter NAME (never a type) of a `function_declaration`,
    `method_declaration`, or `func_literal`'s own `parameters` field. Go's
    grammar distinguishes variable-name `identifier` nodes from type-name
    `type_identifier`/`qualified_type`/... nodes, so filtering a parameter
    group's named children down to `identifier` alone correctly recovers a
    grouped declaration's every name (`a, b string` -> `["a", "b"]`) without
    also picking up the shared type."""
    params_node = fn_node.child_by_field_name("parameters")
    if params_node is None:
        return []
    names: list[str] = []
    for pd in params_node.named_children:
        for child in pd.named_children:
            if child.type == "identifier":
                names.append(node_text(child, src))
    return names


def _find_toplevel_func_in_package(
    package_files: list[tuple[Path, Node, bytes]], name: str
) -> tuple[Node, Path, bytes] | None:
    """A receiver-less `func name(...) {...}`, searched across every file of
    the SAME PACKAGE (shape A/C's plain-identifier handler case, e.g.
    Datadog's `handleGenerateSBOM` -- defined in a sibling file to its own
    registration call, see module docstring). Returns `(fn_node, the file it
    was found in, that file's own src bytes)` since a cross-file match's
    path and source text must be read from ITS file, not the registration
    call's."""
    for path, root_node, src in package_files:
        for node in walk(root_node):
            if node.type == "function_declaration":
                name_field = node.child_by_field_name("name")
                if name_field is not None and node_text(name_field, src) == name:
                    return node, path, src
    return None


def _find_method_by_receiver_type_in_package(
    package_files: list[tuple[Path, Node, bytes]], recv_type: str, method_name: str
) -> tuple[Node, Path, bytes] | None:
    for path, root_node, src in package_files:
        for node in walk(root_node):
            if node.type != "method_declaration":
                continue
            name_field = node.child_by_field_name("name")
            if name_field is None or node_text(name_field, src) != method_name:
                continue
            recv = node.child_by_field_name("receiver")
            if recv is None or not recv.named_children:
                continue
            recv_decl = recv.named_children[0]
            if _type_name(recv_decl.child_by_field_name("type"), src) == recv_type:
                return node, path, src
    return None


def _enclosing_func_or_method(node: Node) -> Node | None:
    cur = node.parent
    while cur is not None:
        if cur.type in ("method_declaration", "function_declaration"):
            return cur
        cur = cur.parent
    return None


def find_enclosing_function(root_node: Node, line: int) -> Node | None:
    """Innermost `function_declaration`/`method_declaration` (by largest
    start row) whose span contains `line` (1-indexed) -- the Go analog of
    `entrypoints_js.py`'s own `find_enclosing_function`/
    `entrypoints_kotlin.py`'s own `find_enclosing_function`. Used by
    `taint_scanner.reconstruct_path_go` (Stage 3), not by this module's own
    Stage 1 recovery (which resolves a registration call's handler directly,
    via `_resolve_handler_go`/`_enclosing_func_or_method` above, not by
    scanning for a line-containing function)."""
    best: Node | None = None
    for node in walk(root_node):
        if node.type in ("function_declaration", "method_declaration"):
            start = node.start_point[0] + 1
            end = node.end_point[0] + 1
            if start <= line <= end and (best is None or start >= best.start_point[0] + 1):
                best = node
    return best


def function_params(fn_node: Node, src: bytes) -> list[str]:
    """Public wrapper around `_params_of_go`, for reuse by
    `taint_scanner.reconstruct_path_go` -- mirrors `entrypoints_js.py`'s own
    public `function_params`."""
    return _params_of_go(fn_node, src)


def _record_entrypoint(
    fn_node: Node,
    fn_path: Path,
    fn_src: bytes,
    shape: str,
    entrypoints: dict[tuple[Path, int], McpEntrypoint],
    confidence: str,
) -> None:
    """Record `fn_node` (a `function_declaration`/`method_declaration`/
    `func_literal` -- anything `_params_of_go` accepts) as a real recovered
    entrypoint at its own (file, line), unless that key is already recovered
    at "high" confidence by a stronger shape (never downgraded). Factored
    out of `_resolve_handler_go`'s own tail so a shape that already HAS the
    real function node in hand (type-anchored signature matching, shape D --
    see module docstring) doesn't need to round-trip through a fake
    "resolve a reference" step just to reach this same recording logic."""
    line = fn_node.start_point[0] + 1
    name_field = fn_node.child_by_field_name("name")
    function_name = node_text(name_field, fn_src) if name_field is not None else f"<handler@{fn_path.name}:{line}>"
    key = (fn_path, line)
    existing = entrypoints.get(key)
    if existing is not None and existing.confidence == "high" and confidence != "high":
        return  # already recovered by a stronger shape -- don't downgrade
    entrypoints[key] = McpEntrypoint(fn_path, function_name, line, _params_of_go(fn_node, fn_src), shape, confidence)


def _resolve_handler_go(
    value_node: Node,
    cur_path: Path,
    cur_src: bytes,
    package_files: list[tuple[Path, Node, bytes]],
    shape: str,
    entrypoints: dict[tuple[Path, int], McpEntrypoint],
    confidence: str,
) -> None:
    """Resolve a handler reference to the real function it names and
    record it, unless it's already recovered at "high" confidence by a
    stronger shape -- see module docstring's "Handler resolution" section
    for exactly what's resolved (same-PACKAGE, not same-file -- see there
    for why) and what's deliberately left silent."""
    fn_node: Node | None
    fn_path: Path
    fn_src: bytes
    if value_node.type == "func_literal":
        fn_node, fn_path, fn_src = value_node, cur_path, cur_src
    elif value_node.type == "identifier":
        found = _find_toplevel_func_in_package(package_files, node_text(value_node, cur_src))
        if found is None:
            return  # unresolved -- silence, not a guess
        fn_node, fn_path, fn_src = found
    elif value_node.type == "selector_expression":
        operand = value_node.child_by_field_name("operand")
        field = value_node.child_by_field_name("field")
        if operand is None or field is None or operand.type != "identifier":
            return  # unresolved -- silence, not a guess
        enclosing = _enclosing_func_or_method(value_node)
        if enclosing is None or enclosing.type != "method_declaration":
            return
        recv = enclosing.child_by_field_name("receiver")
        if recv is None or not recv.named_children:
            return
        recv_decl = recv.named_children[0]
        recv_name_field = recv_decl.child_by_field_name("name")
        if recv_name_field is None or node_text(recv_name_field, cur_src) != node_text(operand, cur_src):
            return  # the selector's base isn't the enclosing method's own receiver
        recv_type = _type_name(recv_decl.child_by_field_name("type"), cur_src)
        if recv_type is None:
            return
        found = _find_method_by_receiver_type_in_package(package_files, recv_type, node_text(field, cur_src))
        if found is None:
            return
        fn_node, fn_path, fn_src = found
    else:
        return

    _record_entrypoint(fn_node, fn_path, fn_src, shape, entrypoints, confidence)


def _try_add_tool_call(
    call_node: Node,
    cur_path: Path,
    cur_src: bytes,
    package_files: list[tuple[Path, Node, bytes]],
    entrypoints: dict[tuple[Path, int], McpEntrypoint],
) -> None:
    """Shape A -- see module docstring."""
    fn = call_node.child_by_field_name("function")
    args_node = call_node.child_by_field_name("arguments")
    if fn is None or args_node is None or _call_name(fn, cur_src) != _ADD_TOOL_CALL_NAME:
        return
    arg_nodes = args_node.named_children
    if len(arg_nodes) < 2:
        return

    found_tool_literal = False
    for arg in arg_nodes:
        lit = arg
        if lit.type == "unary_expression":
            operand = lit.child_by_field_name("operand")
            if operand is not None:
                lit = operand
        if lit.type != "composite_literal":
            continue
        type_node = lit.child_by_field_name("type")
        body = lit.child_by_field_name("body")
        if type_node is None or body is None or _bare_type_name(node_text(type_node, cur_src)) != "Tool":
            continue
        name_val = _keyed_fields(body, cur_src).get("Name")
        if name_val is not None and _string_literal_text(name_val, cur_src) is not None:
            found_tool_literal = True
            break
    if not found_tool_literal:
        return

    _resolve_handler_go(arg_nodes[-1], cur_path, cur_src, package_files, "add_tool_call", entrypoints, confidence="high")


def _try_server_tool_struct(
    type_name: str | None,
    body: Node,
    cur_path: Path,
    cur_src: bytes,
    package_files: list[tuple[Path, Node, bytes]],
    entrypoints: dict[tuple[Path, int], McpEntrypoint],
) -> None:
    """Shape B -- see module docstring. `type_name`/`body` come from
    `_iter_field_literals`, which already resolves an elided-type aggregate
    element's effective type (the real digitalocean-labs shape -- every
    `server.ServerTool{...}` entry there is written with the type elided)."""
    if _bare_type_name(type_name) != "ServerTool":
        return
    fields = _keyed_fields(body, cur_src)
    handler_val = fields.get("Handler")
    if handler_val is None or "Tool" not in fields:
        return
    _resolve_handler_go(handler_val, cur_path, cur_src, package_files, "server_tool_struct", entrypoints, confidence="high")


def _try_tool_name_anchored(
    body: Node,
    cur_path: Path,
    cur_src: bytes,
    package_files: list[tuple[Path, Node, bytes]],
    entrypoints: dict[tuple[Path, int], McpEntrypoint],
) -> None:
    """Shape C -- see module docstring."""
    fields = _keyed_fields(body, cur_src)
    name_val: Node | None = None
    handler_val: Node | None = None
    for key, val in fields.items():
        if key in _NAME_FIELD_KEYS and _string_literal_text(val, cur_src) is not None:
            name_val = val
        elif key in _HANDLER_FIELD_KEYS:
            handler_val = val
    if name_val is None or handler_val is None:
        return
    _resolve_handler_go(
        handler_val, cur_path, cur_src, package_files, "tool_name_anchored", entrypoints, confidence="medium"
    )


# --------------------------------------------------------------------------
# Evidence-structural-fixes milestone, Fix 3: type-anchored seed discovery.
#
# Shapes A/B/C above all anchor on a CALL SHAPE -- a specific call name
# (`AddTool`), a specific literal type name (`ServerTool`), or a field-name
# pairing (`Name`+`Handler`). Real, confirmed gap (see
# `bench/EVIDENCE_STRUCTURAL_FIXES_STATUS.md`): github-mcp-server registers
# its ~90 real tool handlers through a locally-defined GENERIC wrapper,
# `NewTool[In, Out any](toolset, tool mcp.Tool, scopeAccess, handler func(ctx
# context.Context, deps ToolDependencies, req *mcp.CallToolRequest, args In)
# (*mcp.CallToolResult, Out, error)) inventory.ServerTool` -- none of shapes
# A/B/C recognize this (the call is named `NewTool`, not `AddTool`; there is
# no `Tool{...}`/`ServerTool{...}` composite literal carrying both the name
# AND the handler as sibling fields). These two shapes are ADDITIVE, never a
# replacement for A/B/C -- both run on top of, not instead of, the existing
# call-shape detectors, and neither ever downgrades an entry a stronger
# shape already recovered (`_record_entrypoint`'s own "never downgrade"
# rule).
#
# Shape D -- `type_anchored_signature`: ANY function/method declaration or
# inline func literal whose OWN parameter or return type list references
# the real MCP SDK's own request/result type by name (`CallToolRequest`/
# `CallToolResult` -- confirmed the literal type both the official
# `github.com/modelcontextprotocol/go-sdk` (`ToolHandler`/`ToolHandlerFor`)
# AND `github.com/mark3labs/mcp-go` (`ToolHandlerFunc`) use for this exact
# purpose) is recorded as a handler candidate directly -- REGARDLESS of how
# (or whether) it can be traced back to a registration call at all. This is
# what recovers github-mcp-server's real inline handlers (each one literally
# typed `func(ctx context.Context, deps ToolDependencies, req
# *mcp.CallToolRequest, args map[string]any) (*mcp.CallToolResult, any,
# error)`), without needing to recognize `NewTool` as a registrar by name at
# all. Tagged "medium", not "high": unlike shapes A/B (an exact SDK call
# name PLUS a real tool-name literal), this shape alone does not confirm the
# function is actually REGISTERED as a tool -- a logging/tracing wrapper
# with the same signature shape would also match. That is an accepted,
# documented tradeoff for an additive, best-effort discovery strategy (see
# status doc), not silently swept under "high confidence".
#
# Shape E -- `type_anchored_registrar_call`: covers the OTHER real gap this
# milestone's own diagnostic found (grafana/mcp-grafana): its real handlers
# (e.g. `func getDashboardByUID(ctx context.Context, args
# GetDashboardByUIDParams) (*DashboardResponse, error)`) carry NEITHER
# shape A/B/C's call-shape signal NOR shape D's own literal SDK type names
# in their OWN signature -- the handler's request/response types are
# entirely domain-specific (`GetDashboardByUIDParams`/`*DashboardResponse`),
# because they are registered through a locally-defined GENERIC alias,
# `type ToolHandlerFunc[T any, R any] = func(ctx context.Context, request T)
# (R, error)`, itself installed via `mcpgrafana.MustTool[T, R](name,
# description string, toolHandler ToolHandlerFunc[T, R], options
# ...mcp.ToolOption) Tool`. Shape D cannot see this (the handler's own
# signature has no anchor at all); shapes A/B/C cannot either (no
# `AddTool`-named call, no `Tool{...}`/`ServerTool{...}` literal). This
# shape instead anchors on the REGISTRAR's own declared parameter type
# (`ToolHandlerFunc[T, R]`/`ToolHandlerFor[In, Out]` -- the two real generic
# handler-type names this task named): find every function/method IN THIS
# REPO (any file, not just the same package -- a registrar can live in a
# different directory than its own callers, exactly the real mcpgrafana
# root-package-vs-tools-subpackage split) whose own parameter list has a
# type bare-naming to one of `_HANDLER_GENERIC_REGISTRAR_NAMES`, then for
# every call to a function of that SAME NAME anywhere in the repo, resolves
# the argument at that same positional index as the handler -- reusing
# `_resolve_handler_go`'s own same-PACKAGE-as-the-CALL-SITE resolution
# (correct: `getDashboardByUID` and its own `mcpgrafana.MustTool(...)` call
# site are always in the same package as each other in every real target
# seen -- it is only the REGISTRAR's OWN declaration that can live
# elsewhere). Tagged "medium" for the same reason shape C is: a heuristic
# name-based match (a same-named, unrelated `MustTool` in some other
# package would also match; not resolved further -- see status doc for this
# accepted limitation).
# --------------------------------------------------------------------------

_HANDLER_SIGNATURE_BARE_NAMES = frozenset({"CallToolRequest", "CallToolResult"})
_HANDLER_GENERIC_REGISTRAR_NAMES = frozenset({"ToolHandlerFunc", "ToolHandlerFor"})

# --------------------------------------------------------------------------
# SDK-vocab-and-truncation-fix milestone, Fix 1a: interface-method-override
# seed discovery -- a FURTHER additive shape, in the same spirit as shape D
# above (anchor on a fixed SDK signature rather than any call/registration
# shape) but for the SDK's own TRANSPORT/protocol-interface layer instead of
# its tool-handler layer. Real, confirmed gap (see
# `bench/remaining_misses_diagnosis/REMAINING_MISSES_DIAGNOSIS.md` target 3,
# modelcontextprotocol/go-sdk, CVE-2026-33252): `mcp/streamable.go:229`,
# `func (h *StreamableHTTPHandler) ServeHTTP(w http.ResponseWriter, req
# *http.Request)`, is a raw `http.Handler` INTERFACE-METHOD OVERRIDE --
# `StreamableHTTPHandler` never itself calls `AddTool`/builds a
# `Tool{...}`/`ServerTool{...}` literal (shapes A/B/C), its own signature
# never references `CallToolRequest`/`CallToolResult` (shape D), and it is
# not registered through a locally-defined generic registrar (shape E) --
# it is the TRANSPORT layer that eventually INVOKES tool handlers via
# session/transport plumbing, not a tool handler itself, so shapes A-E have
# no vocabulary for it at all. `ServeHTTP(http.ResponseWriter, *http.Request)`
# is the one fixed, unambiguous method name+signature Go's stdlib
# `http.Handler` interface requires -- confirmed directly against the real
# bug (module docstring's own "Recognized registration shapes" list has no
# entry for "a type that itself implements a stdlib/SDK request-handling
# interface" until this shape).
#
# Deliberately keyed on METHOD NAME + first-parameter TYPE together (not
# signature membership the way shape D is) -- `_INTERFACE_METHOD_SIGNATURES`
# is a small, real, confirmed vocabulary (one entry, today), the same
# "recognize a small vocabulary, not any signature at all" discipline shape
# C's own `_NAME_FIELD_KEYS`/`_HANDLER_FIELD_KEYS` already use. Tagged
# "medium", never "high" -- same reasoning as shape D: this alone does not
# confirm the method is actually WIRED into a running MCP server (an
# unrelated `http.Handler` implementation in the same repo would also
# match), an accepted tradeoff for an additive, best-effort discovery
# strategy, not silently swept under "high confidence".
# --------------------------------------------------------------------------

_INTERFACE_METHOD_SIGNATURES: dict[str, str] = {
    "ServeHTTP": "ResponseWriter",
}


def _try_interface_method_override(
    fn_node: Node,
    fn_path: Path,
    fn_src: bytes,
    entrypoints: dict[tuple[Path, int], McpEntrypoint],
) -> None:
    """Shape F -- see this section's own module comment above. Only a
    `method_declaration` can implement an interface (a receiver-less
    function or an inline `func_literal` cannot), so this shape, unlike
    shape D, does not consider those two node types at all."""
    if fn_node.type != "method_declaration":
        return
    name_field = fn_node.child_by_field_name("name")
    if name_field is None:
        return
    required_param_type = _INTERFACE_METHOD_SIGNATURES.get(node_text(name_field, fn_src))
    if required_param_type is None:
        return
    param_types = _flatten_param_types(fn_node.child_by_field_name("parameters"))
    if not any(_type_bare_name(t, fn_src) == required_param_type for t in param_types):
        return
    _record_entrypoint(fn_node, fn_path, fn_src, "interface_method_override", entrypoints, confidence="medium")


def _type_bare_name(node: Node | None, src: bytes) -> str | None:
    """The bare final identifier of a Go type node, unwrapping the layers
    that matter for shape D/E's own matching: `*mcp.CallToolRequest` ->
    `"CallToolRequest"`, `ToolHandlerFunc[T, R]` -> `"ToolHandlerFunc"`,
    `mcp.Tool` -> `"Tool"`, a bare `type_identifier` -> its own text. `None`
    for any other type-node shape (an inline `func(...)` type, a slice/
    array/map/interface type, ...) -- deliberately not resolved further,
    same "silence, not a guess" discipline as `_resolve_handler_go`."""
    if node is None:
        return None
    if node.type == "pointer_type":
        inner = node.named_children[0] if node.named_children else None
        return _type_bare_name(inner, src)
    if node.type == "qualified_type":
        name_field = node.child_by_field_name("name")
        return node_text(name_field, src) if name_field is not None else None
    if node.type == "generic_type":
        type_field = node.child_by_field_name("type")
        return _type_bare_name(type_field, src)
    if node.type == "type_identifier":
        return node_text(node, src)
    return None


def _flatten_param_types(param_list: Node | None) -> list[Node | None]:
    """Every parameter's own type node, in the SAME positional order a real
    call site's arguments would occupy -- expands a grouped declaration
    (`name, description string` -> two positions, both typed `string`) the
    same way Go's own calling convention does, and a `variadic_parameter_
    declaration` (`options ...T`) contributes exactly one position (its own
    declared type), matching how a plain, non-spread call passes it as a
    single argument. Used for BOTH a function's own `parameters` field
    (shape D/E) and its `result` field (shape D only, see
    `_result_type_nodes`) -- Go's grammar shapes a multi-value return
    exactly like a parameter list (see module docstring: `child_by_field_
    name("result")` returns a `parameter_list` for a multi-return, or the
    single type node directly otherwise, handled separately by
    `_result_type_nodes`)."""
    if param_list is None:
        return []
    types: list[Node | None] = []
    for pd in param_list.named_children:
        if pd.type not in ("parameter_declaration", "variadic_parameter_declaration"):
            continue
        idents = [c for c in pd.children if c.type == "identifier"]
        type_node: Node | None = None
        for c in reversed(pd.children):
            if c.type not in ("identifier", ","):
                type_node = c
                break
        count = len(idents) if idents else 1
        types.extend([type_node] * count)
    return types


def _result_type_nodes(fn_node: Node) -> list[Node]:
    """Every type node in `fn_node`'s own return signature -- `None` (no
    return value), a single bare type node (one return value), or a
    `parameter_list` (2+ return values, flattened the same way
    `_flatten_param_types` flattens a parameter list) all handled."""
    result = fn_node.child_by_field_name("result")
    if result is None:
        return []
    if result.type == "parameter_list":
        return [t for t in _flatten_param_types(result) if t is not None]
    return [result]


def _try_type_anchored_signature(
    fn_node: Node,
    fn_path: Path,
    fn_src: bytes,
    entrypoints: dict[tuple[Path, int], McpEntrypoint],
) -> None:
    """Shape D -- see this section's own module comment above. `fn_node` is
    a `function_declaration`, `method_declaration`, or `func_literal`."""
    param_types = _flatten_param_types(fn_node.child_by_field_name("parameters"))
    signature_types = [*param_types, *_result_type_nodes(fn_node)]
    if not any(_type_bare_name(t, fn_src) in _HANDLER_SIGNATURE_BARE_NAMES for t in signature_types):
        return
    _record_entrypoint(fn_node, fn_path, fn_src, "type_anchored_signature", entrypoints, confidence="medium")


def _find_type_anchored_registrars(parsed_files: dict[Path, tuple[Node, bytes]]) -> dict[str, int]:
    """Shape E's own pass 1 -- see this section's own module comment above.
    Scanned across the WHOLE repo (every parsed file, not scoped to one
    package/directory the way shape A/B/C's own handler RESOLUTION is):
    `function_name -> 0-based positional index of the FIRST parameter whose
    own type bare-names to `_HANDLER_GENERIC_REGISTRAR_NAMES`. First match
    wins for a given name -- a second, differently-shaped function of the
    same name elsewhere is not expected in real code and is deliberately
    not disambiguated further (see this section's own module comment)."""
    registrars: dict[str, int] = {}
    for root_node, src in parsed_files.values():
        for node in walk(root_node):
            if node.type not in ("function_declaration", "method_declaration"):
                continue
            name_field = node.child_by_field_name("name")
            if name_field is None:
                continue
            fn_name = node_text(name_field, src)
            if fn_name in registrars:
                continue
            param_types = _flatten_param_types(node.child_by_field_name("parameters"))
            for idx, t in enumerate(param_types):
                if _type_bare_name(t, src) in _HANDLER_GENERIC_REGISTRAR_NAMES:
                    registrars[fn_name] = idx
                    break
    return registrars


def _try_type_anchored_registrar_call(
    call_node: Node,
    registrars: dict[str, int],
    cur_path: Path,
    cur_src: bytes,
    package_files: list[tuple[Path, Node, bytes]],
    entrypoints: dict[tuple[Path, int], McpEntrypoint],
) -> None:
    """Shape E's own pass 2 -- see this section's own module comment above."""
    fn = call_node.child_by_field_name("function")
    args_node = call_node.child_by_field_name("arguments")
    if fn is None or args_node is None:
        return
    idx = registrars.get(_call_name(fn, cur_src))
    if idx is None:
        return
    arg_nodes = args_node.named_children
    if idx >= len(arg_nodes):
        return
    _resolve_handler_go(
        arg_nodes[idx], cur_path, cur_src, package_files, "type_anchored_registrar_call", entrypoints,
        confidence="medium",
    )


def recover_go_entrypoints(root: str | Path) -> list[McpEntrypoint]:
    """Walk a Go source tree and recover the set of functions that are real
    MCP tool handlers, via the shapes documented in this module's
    docstring. Registration-shape DETECTION is per-file; handler
    RESOLUTION is per-PACKAGE (every file in the same directory) -- see the
    module docstring's "Handler resolution" section for why Go needs that
    wider scope where Python/JS/TS don't. Shape E's own registrar-signature
    DISCOVERY (evidence-structural-fixes milestone, Fix 3) is the one
    exception -- REPO-wide, not per-package; see `_find_type_anchored_
    registrars`'s own docstring for why."""
    root = Path(root)
    parsed_files: dict[Path, tuple[Node, bytes]] = {}
    for path in iter_go_files(root):
        parsed = parse_file(path)
        if parsed is not None:
            parsed_files[path] = parsed

    files_by_dir: dict[Path, list[tuple[Path, Node, bytes]]] = {}
    for path, (root_node, src) in parsed_files.items():
        files_by_dir.setdefault(path.parent, []).append((path, root_node, src))

    entrypoints: dict[tuple[Path, int], McpEntrypoint] = {}
    type_anchored_registrars = _find_type_anchored_registrars(parsed_files)

    for path, (root_node, src) in parsed_files.items():
        package_files = files_by_dir[path.parent]

        for node in walk(root_node):
            if node.type == "call_expression":
                _try_add_tool_call(node, path, src, package_files, entrypoints)
                _try_type_anchored_registrar_call(node, type_anchored_registrars, path, src, package_files, entrypoints)
            elif node.type in ("function_declaration", "method_declaration", "func_literal"):
                _try_type_anchored_signature(node, path, src, entrypoints)
                _try_interface_method_override(node, path, src, entrypoints)

        for type_name, body in _iter_field_literals(root_node, src):
            _try_server_tool_struct(type_name, body, path, src, package_files, entrypoints)
            _try_tool_name_anchored(body, path, src, package_files, entrypoints)

    return sorted(entrypoints.values(), key=lambda e: (str(e.file), e.line))


if __name__ == "__main__":
    import sys

    for ep in recover_go_entrypoints(sys.argv[1] if len(sys.argv) > 1 else "."):
        print(
            f"{ep.file}:{ep.line}  {ep.function_name}({', '.join(ep.parameter_names)})  "
            f"via={ep.sdk_shape} confidence={ep.confidence}"
        )
