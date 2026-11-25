"""SRC-042 (EXPERIMENTAL): server-minted handle used as a tool argument with
no binding to the caller.

Anchor: MCP 2026-07-28 stateless model (sessions removed; servers mint opaque
handles that clients pass back as tool args). A handle that keys server state
without a `<caller>:<handle>` ownership binding lets any caller who learns or
guesses a handle read or mutate another user's state.

Python only (ast): a tool-decorated function takes a handle-like parameter,
uses it as a subscript/`.get()`/`.pop()` key on a store, and never references a
caller identity (user_id / ctx / principal / owner ...) in its body.
Experimental: novelty of the class is being validated separately (WS10).
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from .prompt_injection import Severity
from .source_scanner import SourceFinding, _iter_source

RULE_IDS: list[tuple[str, str]] = [
    ("SRC-042", "[experimental] Server-minted handle keys state with no caller ownership binding"),
]
EXPERIMENTAL: frozenset[str] = frozenset({"SRC-042"})

_HANDLE_PARAM = re.compile(r"(?:^|_)(?:handle|cursor_id|state_id|upload_id|job_id|task_id|resource_id)$", re.IGNORECASE)
_CALLER = re.compile(
    r"user_?id|userid|\bctx\b|context|principal|owner|caller|client_id|subject|\bsub\b|"
    r"current_user|auth_info|access_token|identity|tenant",
    re.IGNORECASE,
)
_TOOL_DECORATOR = re.compile(r"\btool\b|call_tool", re.IGNORECASE)
_STORE_METHODS = {"get", "pop", "setdefault", "__getitem__", "__delitem__"}


def _is_tool(fn: ast.AST) -> bool:
    return any(_TOOL_DECORATOR.search(ast.unparse(d)) for d in fn.decorator_list)  # type: ignore[attr-defined]


def _handle_used_as_key(fn: ast.AST, handle: str) -> ast.AST | None:
    for node in ast.walk(fn):
        if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Name) and node.slice.id == handle:
            return node
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr in _STORE_METHODS
                and node.args and isinstance(node.args[0], ast.Name) and node.args[0].id == handle):
            return node
    return None


def scan_text(rel: str, text: str) -> list[SourceFinding]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    out: list[SourceFinding] = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) or not _is_tool(fn):
            continue
        params = [a.arg for a in fn.args.args + fn.args.kwonlyargs]
        # A caller-identity parameter itself counts as a binding source.
        if any(_CALLER.search(p) for p in params):
            continue
        body_src = "\n".join(ast.unparse(s) for s in fn.body)
        if _CALLER.search(body_src):
            continue
        for p in params:
            if _HANDLE_PARAM.search(p):
                use = _handle_used_as_key(fn, p)
                if use is not None:
                    out.append(SourceFinding(
                        "SRC-042", Severity.MEDIUM,
                        "[experimental] Handle argument keys state with no caller binding",
                        f"Tool `{fn.name}` takes `{p}` and uses it directly as a state key, "
                        "with no caller identity (user/ctx/principal/owner) referenced. Any "
                        "caller who learns or guesses the handle can read or mutate another "
                        "user's state.",
                        f"{rel}:{use.lineno}",
                        ast.unparse(use)[:120],
                        "Key state by `<caller_id>:<handle>` (or store owner and compare to the "
                        "authenticated principal) and sign/random-ize handles.",
                        5.5,
                        confidence="low",
                    ))
                    break
    return out


def scan_tree(root: str | Path) -> list[SourceFinding]:
    root = Path(root)
    out: list[SourceFinding] = []
    for path, text, _raw in _iter_source(root):
        if path.suffix != ".py":
            continue
        rel = str(path.relative_to(root)) if path.is_relative_to(root) else str(path)
        out.extend(scan_text(rel, text))
    return out
