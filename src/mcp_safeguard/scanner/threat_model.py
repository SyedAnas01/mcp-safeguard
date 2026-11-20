"""S2 (fleet-scaffold): Threat Model Document (TMD) generation.

A TMD is the cached, per-commit "briefing packet" a future live hunter-fleet
run would load ONCE per repo before spawning any LLM-calling agent (see the
design doc this implements, `mcp-safeguard-agent-fleet-design-2026-09-05`,
stage S2). Nothing in this module calls an LLM or makes a network request --
it is pure static analysis over files already on disk, reusing Stage 1's own
entrypoint recovery verbatim rather than re-implementing it.

A TMD answers three questions about one repo at one commit:

1. **Which functions actually run when an MCP client calls a tool?**
   Reused verbatim from `entrypoints.py` (Python), `entrypoints_js.py`
   (JS/TS), `entrypoints_go.py` (Go), and `entrypoints_kotlin.py` (Kotlin;
   wired in by the v10 consolidation merge -- see
   bench/FINAL_COMPLETE_V10_STATUS.md's "Kotlin entrypoints not reaching
   the LLM hunter angles" section) -- this module recovers nothing new
   here, it only wraps their existing output into `EntrypointProfile`. Go
   and Kotlin entrypoints both get no `credential_access` inference (see
   `_go_profile_for`/`_kotlin_profile_for`) and no `delegates_to`
   (`cross_file.py` has no Go or Kotlin support) -- both stay at their
   honest defaults (`[]`/`None`), not a claim that no Go/Kotlin entrypoint
   touches a credential.
2. **For each entrypoint, what credential-shaped state can it reach without
   an explicit permission check first?** Best-effort static inference (see
   `_python_credential_accesses`/`_js_credential_accesses` below) -- NOT a
   real taint analysis or a call-graph walk. It answers a narrower question
   than taint_scanner.py's own sink-reachability rules: not "does a
   parameter reach a dangerous sink", but "does this handler's own scope
   already hold a credential-shaped variable it could use, and is there any
   recognized authorization-check call earlier in the same function". A
   negative result here is exactly as inconclusive as everywhere else in
   this project -- see the module-level discipline note at the bottom of
   this docstring.
3. **What has this repo's own documentation/code explicitly claimed about
   safety or scope?** Simple keyword+context extraction (task-specified
   keyword list) over README.md, SECURITY.md, and every source file's full
   text (docstrings and inline schema `description="..."` text are both
   just text inside those files, so one extraction pass covers both without
   needing a separate AST-docstring-only code path).

**Caching.** `build_threat_model()` keys its cache by commit hash
(`git rev-parse HEAD` when the repo is a git checkout; a deterministic
content hash of every scanned source file otherwise -- see `_resolve_commit`)
so a second call against the same commit reuses the cached JSON instead of
re-walking the repo and re-parsing every file. The cache lives OUTSIDE the
target entirely, under `~/.cache/mcp_safeguard/tmd/` (same convention as
`sandbox.py`'s `~/.cache/mcp_safeguard/sandbox_scratch/` and `rescan.py`'s
`~/.cache/mcp_safeguard/fleet_scan/`), never inside the scanned repo's own
directory tree -- see the security note below.

**Security: never trust a cache file found inside the target.** An earlier
version of this module cached at `<repo>/.mcp_safeguard_cache/tmd/...`,
INSIDE the repo being scanned. That is a real cache-poisoning
vulnerability, not a theoretical one: for any non-git target (a PyPI
sdist, an npm tarball, a "Download ZIP" extraction, or a plain directory),
the cache key is a `nogit-sha256` hash computed entirely from source files
the attacker themselves controls, so the attacker can compute their own
cache key offline and ship a pre-poisoned cache file (fabricated
`entrypoints: []`, fabricated "already audited" safety claims) at the
exact path this module would read back -- with no integrity check,
`build_threat_model()` happily loads the attacker's fabricated data
instead of ever running real entrypoint recovery. This was proven live
against the pre-fix code (see `bench/bug1_tmd_cache_poisoning_repro.py`
and `bench/SELF_ATTACK_FIX_STATUS.md`). The fix is the global, user-owned
cache directory above: `build_threat_model()` must NEVER read a cache file
from inside the target's own directory tree, under any circumstances, even
if one exists there.

**What this module is NOT**: it does not decide whether an entrypoint is
actually vulnerable, it does not call any model, and its credential/
permission-check inference is real-but-narrow static pattern matching (name
-based, same-scope-only) -- exactly the same "silence, not a guess" and
"an absence is not proof of safety" discipline `entrypoints.py`'s and
`source_scanner.py`'s own module docstrings already state for this project.
An entrypoint with no detected credential access may still hold one through
a shape this module doesn't recognize (e.g. a credential threaded through a
dependency-injection framework); an entrypoint with a detected, unchecked
credential access is a LEAD for a hunter agent to investigate, not itself a
finding.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .. import __version__ as _MCP_SAFEGUARD_VERSION
from .entrypoints import McpEntrypoint, _dotted_chain, _is_skip_dir_part, recover_entrypoints

# Global, user-owned cache directory -- OUTSIDE any scanned target, same
# `~/.cache/mcp_safeguard/<subdir>/` convention sandbox.py and rescan.py
# already use. NEVER inside the repo being scanned: see the module
# docstring's "Security" note for exactly why an in-target cache is a real
# cache-poisoning vulnerability, not a style preference.
_DEFAULT_CACHE_DIR = Path.home() / ".cache" / "mcp_safeguard" / "tmd"

# Exactly the keyword list the task spec names -- deliberately not expanded.
# Each is matched as a whole phrase (word-boundary-delimited, case
# -insensitive) against every "sentence" (see `_iter_sentences_with_lines`)
# in README.md, SECURITY.md, and every scanned source file's full text.
_CLAIM_KEYWORDS: tuple[str, ...] = (
    "read-only",
    "requires",
    "only if",
    "scoped to",
    "must not",
    "validates",
    "sanitizes",
    "authorized",
)
_CLAIM_KEYWORD_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (kw, re.compile(r"\b" + re.escape(kw).replace(r"\ ", r"\s+") + r"\b", re.IGNORECASE)) for kw in _CLAIM_KEYWORDS
)

# Name-based credential-shape vocabulary: a variable/attribute whose name
# contains one of these (case-insensitive) is treated as "holds a secret".
# Deliberately narrow (task's own phrasing: "an API key, token, client with
# stored auth") -- a bare "client"/"session" name alone is NOT enough (see
# `_CREDENTIAL_CTOR_KWARG_RE` for how a generically-named client is still
# caught when its OWN constructor call passes a credential-shaped keyword
# argument).
_CREDENTIAL_NAME_RE = re.compile(
    r"(api[_-]?key|token|secret|"
    r"passwd|password|bearer|credential|private[_-]?key|"
    r"service[_-]?account)",
    re.IGNORECASE,
)
# Matches a keyword-argument NAME passed to a constructor call, e.g.
# `Client(api_key=..., token=...)` or (JS object literal) `{ apiKey: ... }`
# -- lets a generically-named attribute ("self.client", "this.session") be
# recognized as credential-shaped by what it was BUILT with, not just its
# own name.
_CREDENTIAL_KWARG_NAME_RE = _CREDENTIAL_NAME_RE

# Name-based permission/authorization-check vocabulary. A call to a function
# whose name (last dotted/member component) matches this is treated as "an
# explicit permission check happened here" -- same name-based, no-call-graph
# discipline as the credential vocabulary above.
_PERMISSION_CHECK_NAME_RE = re.compile(
    r"(authoriz|permission|require_scope|require_role|requirerole|requirescope|"
    r"is_allowed|isallowed|has_permission|haspermission|check_access|checkaccess|"
    r"verify_auth|verifyauth|require_auth|requireauth|validate_token|validatetoken|"
    r"verify_token|verifytoken|enforce_policy|enforcepolicy|check_auth|checkauth|"
    r"ensure_authorized|ensureauthorized)",
    re.IGNORECASE,
)

_SOURCE_SUFFIXES = (".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".kt")
_DOC_FILENAMES = ("README.md", "SECURITY.md")


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------


@dataclass
class SafetyClaim:
    """One explicit safety/scope claim extracted from repo text -- a
    sentence containing one of `_CLAIM_KEYWORDS`, with the exact source
    location it was found at. `text` is captured verbatim (stripped of
    leading/trailing whitespace only) -- never paraphrased or summarized, so
    a human/hunter agent reading a Claim Card's `violated_claim` field can
    go look at the real line and see the real claim.
    """

    text: str
    source_file: str
    source_line: int
    keyword: str

    @property
    def location(self) -> str:
        return f"{self.source_file}:{self.source_line}"


@dataclass
class CredentialAccess:
    """One credential-shaped variable/attribute reachable from inside a
    specific entrypoint's own function body, and whether a recognized
    permission-check call appears earlier in that same function."""

    name: str
    kind: str  # "module_global" | "self_attribute" | "this_attribute"
    line: int  # line, inside the entrypoint's function, where it is read
    permission_check_before: bool
    guarding_call: str | None = None  # the nearest preceding check's own call text, if any


@dataclass
class DelegationTarget:
    """Where `cross_file.py`'s own tested single-hop resolver
    (`find_python_cross_file_hops`/`find_js_cross_file_hops`) found this
    entrypoint's body forwarding its own parameter(s) straight into a real
    function in another file -- the common "thin registration, real logic
    elsewhere" idiom. Bounded to ONE hop, same as `cross_file.py` itself: if
    the callee here ALSO just delegates further, that deeper hop is not
    resolved."""

    file: str
    function_name: str
    line: int


@dataclass
class EntrypointProfile:
    """One recovered MCP entrypoint plus this module's own best-effort
    authority analysis: what it's declared to do (`declared_authority`,
    the nearest safety claim in the same file, if any) vs. what
    credential-shaped state it can actually reach (`credential_access`)."""

    file: str
    function_name: str
    line: int
    parameter_names: list[str]
    sdk_shape: str
    confidence: str
    declared_authority: SafetyClaim | None = None
    credential_access: list[CredentialAccess] = field(default_factory=list)
    delegates_to: DelegationTarget | None = None

    @property
    def has_unchecked_credential_access(self) -> bool:
        return any(not c.permission_check_before for c in self.credential_access)


@dataclass
class ThreatModelDocument:
    """The full TMD for one repo at one commit."""

    repo_path: str
    repo_name: str
    commit: str
    generated_at: str
    entrypoints: list[EntrypointProfile]
    claims: list[SafetyClaim]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ThreatModelDocument:
        entrypoints = [
            EntrypointProfile(
                file=ep["file"],
                function_name=ep["function_name"],
                line=ep["line"],
                parameter_names=list(ep["parameter_names"]),
                sdk_shape=ep["sdk_shape"],
                confidence=ep["confidence"],
                declared_authority=SafetyClaim(**ep["declared_authority"]) if ep.get("declared_authority") else None,
                credential_access=[CredentialAccess(**c) for c in ep.get("credential_access", [])],
                delegates_to=DelegationTarget(**ep["delegates_to"]) if ep.get("delegates_to") else None,
            )
            for ep in data["entrypoints"]
        ]
        claims = [SafetyClaim(**c) for c in data["claims"]]
        return cls(
            repo_path=data["repo_path"],
            repo_name=data["repo_name"],
            commit=data["commit"],
            generated_at=data["generated_at"],
            entrypoints=entrypoints,
            claims=claims,
        )


# --------------------------------------------------------------------------
# File discovery (shares entrypoints.py's skip-dir discipline)
# --------------------------------------------------------------------------


def _iter_source_files(root: Path):
    for p in root.rglob("*"):
        if not p.is_file() or p.suffix not in _SOURCE_SUFFIXES:
            continue
        try:
            rel_parts = p.relative_to(root).parts[:-1]
        except ValueError:
            rel_parts = p.parts[:-1]
        if any(_is_skip_dir_part(part) for part in rel_parts):
            continue
        yield p


# --------------------------------------------------------------------------
# Commit resolution / cache
# --------------------------------------------------------------------------


def _run_git(args: list[str], cwd: Path, *, timeout: int) -> subprocess.CompletedProcess:
    """Run `git -C <cwd> <args>`, capturing text output, with the given
    timeout. Raises on a genuine subprocess failure (`OSError`/
    `subprocess.SubprocessError`, including a timeout) -- it is the caller's
    job to decide whether that's fatal or should be caught and treated as
    "could not determine" (see `_resolve_commit`'s own try/except below, and
    `rescan.py`'s per-call try/except at each of its own call sites). Shared
    by `_resolve_commit` (this module) and every git operation in
    `rescan.py`, which previously each reimplemented this same
    `subprocess.run(...)` wrapper independently."""
    return subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, text=True, timeout=timeout)


def _resolve_commit(root: Path) -> str:
    """Real `git rev-parse HEAD` when `root` is a git checkout; otherwise a
    deterministic `nogit-<sha256>` content hash over every scanned source
    file's relative path + bytes (sorted by path) -- NOT a git commit, but
    changes exactly when the scanned content changes, which is all the
    cache key needs."""
    try:
        result = _run_git(["rev-parse", "HEAD"], root, timeout=10)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    digest = hashlib.sha256()
    for path in sorted(_iter_source_files(root)):
        try:
            digest.update(str(path.relative_to(root)).encode("utf-8"))
            digest.update(path.read_bytes())
        except OSError:
            continue
    return f"nogit-{digest.hexdigest()}"


def _repo_identity_key(root: Path) -> str:
    """A short, filesystem-safe fingerprint of `root`'s own absolute
    resolved path -- so two different repos that happen to share a
    basename (e.g. two different clones both named `server`) never collide
    in the shared, global cache directory. Resolves `root` itself
    (`.resolve()`) rather than trusting the caller to have already done
    so, so every caller (this module's own `build_threat_model`, and
    `rescan.py`'s cache lookups) computes the same key for the same real
    directory regardless of whether it was handed a relative path, an
    unresolved absolute path, or a symlink."""
    return hashlib.sha256(str(Path(root).resolve()).encode("utf-8")).hexdigest()[:16]


def _cache_path(root: Path, repo_name: str, commit: str, cache_dir: str | Path | None) -> Path:
    """Cache file path for `root` at `commit`. Defaults to the global,
    user-owned `_DEFAULT_CACHE_DIR` (NEVER a path inside `root` itself --
    see the module docstring's "Security" note). Keyed by repo identity
    (`root`'s own absolute path, not just its basename) + the real
    content-key (`commit`: a real git commit, or the `nogit-sha256` for a
    non-git target) + the installed `mcp-safeguard` package version, so a
    tool upgrade that changes what a TMD captures invalidates stale
    caches from an older version rather than silently reusing them."""
    base = Path(cache_dir) if cache_dir is not None else _DEFAULT_CACHE_DIR
    return base / f"{repo_name}-{_repo_identity_key(root)}-{_MCP_SAFEGUARD_VERSION}-{commit}.json"


# --------------------------------------------------------------------------
# Claim extraction (README.md / SECURITY.md / every source file's full text)
# --------------------------------------------------------------------------


def _iter_sentences_with_lines(text: str):
    """Yield (sentence, line_number) pairs, 1-indexed. Deliberately simple:
    a "sentence" here is a `.`/`!`/`?`-terminated (or end-of-line) run of
    non-newline characters -- it never crosses a newline, so a markdown
    bullet list or a multi-line docstring can never have two unrelated
    lines spliced into one garbled "sentence". Matches this task's own
    "simple keyword+context extraction is fine" instruction."""
    line_starts: list[int] = []
    pos = 0
    for line in text.split("\n"):
        line_starts.append(pos)
        pos += len(line) + 1
    for m in re.finditer(r"[^\n]+", text):
        fragment = m.group()
        start = m.start()
        line_no = 1
        for i, ls in enumerate(line_starts):
            if ls <= start:
                line_no = i + 1
            else:
                break
        for piece in re.split(r"(?<=[.!?])\s+", fragment):
            piece = piece.strip()
            if piece:
                yield piece, line_no


def _claims_from_text(text: str, source_file: str) -> list[SafetyClaim]:
    claims: list[SafetyClaim] = []
    seen: set[tuple[int, str]] = set()
    for sentence, line_no in _iter_sentences_with_lines(text):
        for keyword, pattern in _CLAIM_KEYWORD_PATTERNS:
            if pattern.search(sentence):
                key = (line_no, sentence)
                if key not in seen:
                    seen.add(key)
                    claims.append(SafetyClaim(text=sentence, source_file=source_file, source_line=line_no, keyword=keyword))
                break
    return claims


def _collect_claims(root: Path) -> list[SafetyClaim]:
    claims: list[SafetyClaim] = []
    for name in _DOC_FILENAMES:
        doc_path = root / name
        if doc_path.is_file():
            try:
                text = doc_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            claims.extend(_claims_from_text(text, str(doc_path)))
    for path in sorted(_iter_source_files(root)):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        claims.extend(_claims_from_text(text, str(path)))
    return claims


def _nearest_claim_for(entrypoint_file: str, entrypoint_line: int, claims: list[SafetyClaim], window: int = 25) -> SafetyClaim | None:
    """The claim, if any, in the SAME file as `entrypoint_file` whose line
    is within `window` lines of the entrypoint's own definition line -- in
    practice this is almost always that handler's own docstring or an
    immediately preceding/following comment, without needing a second,
    docstring-specific extraction path (see module docstring)."""
    best: SafetyClaim | None = None
    best_dist: int | None = None
    for claim in claims:
        if claim.source_file != entrypoint_file:
            continue
        dist = abs(claim.source_line - entrypoint_line)
        if dist <= window and (best_dist is None or dist < best_dist):
            best, best_dist = claim, dist
    return best


# --------------------------------------------------------------------------
# Python credential / permission-check inference
# --------------------------------------------------------------------------


def _module_level_credential_globals(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign) and node.target is not None:
            targets = [node.target]
        else:
            continue
        for t in targets:
            if isinstance(t, ast.Name) and _CREDENTIAL_NAME_RE.search(t.id):
                names.add(t.id)
    return names


def _class_credential_self_attrs(class_node: ast.ClassDef) -> set[str]:
    """`self.<attr>` assignment targets anywhere in the class body whose own
    name matches the credential vocabulary directly, OR whose assigned
    value is a call passing a credential-shaped keyword argument (covers a
    generically-named `self.client = SomeSDK(api_key=..., token=...)`)."""
    attrs: set[str] = set()
    for node in ast.walk(class_node):
        if not isinstance(node, ast.Assign):
            continue
        for t in node.targets:
            if not (isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) and t.value.id in ("self", "cls")):
                continue
            if _CREDENTIAL_NAME_RE.search(t.attr):
                attrs.add(t.attr)
                continue
            if isinstance(node.value, ast.Call):
                for kw in node.value.keywords:
                    if kw.arg and _CREDENTIAL_KWARG_NAME_RE.search(kw.arg):
                        attrs.add(t.attr)
                        break
    return attrs


def _enclosing_class(tree: ast.Module, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> ast.ClassDef | None:
    """The ClassDef `fn` is a DIRECT method of (one level only -- a method
    nested inside another method/class two levels down is not chased,
    matching this module's stated same-scope-only discipline)."""
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and fn in node.body:
            return node
    return None


def _permission_check_before(fn: ast.FunctionDef | ast.AsyncFunctionDef, line: int) -> tuple[int, str] | None:
    calls: list[tuple[int, str]] = []
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        chain = _dotted_chain(node.func)
        name = (chain.rsplit(".", 1)[-1] if chain else "") or (
            node.func.attr if isinstance(node.func, ast.Attribute) else ""
        )
        if name and _PERMISSION_CHECK_NAME_RE.search(name):
            calls.append((node.lineno, f"{chain or name}(...)"))
    before = [c for c in calls if c[0] <= line]
    if not before:
        return None
    return max(before, key=lambda c: c[0])


def _python_credential_accesses(
    tree: ast.Module, fn: ast.FunctionDef | ast.AsyncFunctionDef
) -> list[CredentialAccess]:
    module_globals = _module_level_credential_globals(tree)
    class_node = _enclosing_class(tree, fn)
    self_attrs = _class_credential_self_attrs(class_node) if class_node is not None else set()
    if not module_globals and not self_attrs:
        return []

    found: list[CredentialAccess] = []
    seen: set[tuple[str, str]] = set()
    for node in ast.walk(fn):
        if node is fn:
            continue
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in module_globals:
            key = ("module_global", node.id)
            if key in seen:
                continue
            seen.add(key)
            check = _permission_check_before(fn, node.lineno)
            found.append(
                CredentialAccess(
                    name=node.id,
                    kind="module_global",
                    line=node.lineno,
                    permission_check_before=check is not None,
                    guarding_call=check[1] if check else None,
                )
            )
        elif (
            isinstance(node, ast.Attribute)
            and isinstance(node.ctx, ast.Load)
            and isinstance(node.value, ast.Name)
            and node.value.id in ("self", "cls")
            and node.attr in self_attrs
        ):
            key = ("self_attribute", node.attr)
            if key in seen:
                continue
            seen.add(key)
            check = _permission_check_before(fn, node.lineno)
            found.append(
                CredentialAccess(
                    name=f"self.{node.attr}",
                    kind="self_attribute",
                    line=node.lineno,
                    permission_check_before=check is not None,
                    guarding_call=check[1] if check else None,
                )
            )
    return sorted(found, key=lambda c: c.line)


# --------------------------------------------------------------------------
# JS/TS credential / permission-check inference (tree-sitter based -- only
# imported lazily, mirrors taint_scanner.py's own ImportError-tolerant
# `from . import entrypoints_js` so this module never forces the
# `static-taint` extra onto a caller who only wants Python analysis).
# --------------------------------------------------------------------------


def _js_module_level_credential_globals(root_node, src: bytes) -> set[str]:
    from . import entrypoints_js as ejs

    names: set[str] = set()
    for child in root_node.named_children:
        if child.type not in ("lexical_declaration", "variable_declaration"):
            continue
        for decl in child.named_children:
            if decl.type != "variable_declarator":
                continue
            name_node = decl.child_by_field_name("name")
            if name_node is not None and name_node.type == "identifier":
                name = ejs.node_text(name_node, src)
                if _CREDENTIAL_NAME_RE.search(name):
                    names.add(name)
    return names


def _js_class_credential_this_attrs(class_node, src: bytes) -> set[str]:
    from . import entrypoints_js as ejs

    attrs: set[str] = set()
    for node in ejs.walk(class_node):
        if node.type != "assignment_expression":
            continue
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or ejs.dotted_chain(left, src).partition(".")[0] != "this":
            continue
        attr = left.child_by_field_name("property")
        if attr is None:
            continue
        attr_name = ejs.node_text(attr, src)
        if _CREDENTIAL_NAME_RE.search(attr_name):
            attrs.add(attr_name)
            continue
        if right is not None and right.type in ("call_expression", "new_expression"):
            # Look for an object-literal argument with a credential-shaped
            # property key, e.g. `new Client({ apiKey: ... })`.
            for arg_node in ejs.walk(right):
                if arg_node.type != "object":
                    continue
                for prop in arg_node.named_children:
                    # ES6 shorthand property (`{ secretKey, otherProp }`,
                    # tree-sitter node type `shorthand_property_identifier`)
                    # has no "key"/"value" fields at all -- `child_by_field_
                    # name("key")` always returns None for it, so the
                    # explicit-`pair` check below silently missed every
                    # shorthand credential property (confirmed real miss on
                    # Stripe's `new StripeMcpClient({ secretKey, ... })`).
                    # The node's own text IS the property name for this shape.
                    if prop.type == "shorthand_property_identifier":
                        if _CREDENTIAL_KWARG_NAME_RE.search(ejs.node_text(prop, src)):
                            attrs.add(attr_name)
                        continue
                    key_node = prop.child_by_field_name("key")
                    if key_node is not None and _CREDENTIAL_KWARG_NAME_RE.search(ejs.node_text(key_node, src)):
                        attrs.add(attr_name)
    return attrs


def _js_permission_check_before(fn_node, src: bytes, line: int) -> tuple[int, str] | None:
    from . import entrypoints_js as ejs

    calls: list[tuple[int, str]] = []
    for node in ejs.walk(fn_node):
        if node.type != "call_expression":
            continue
        callee = node.child_by_field_name("function")
        if callee is None:
            continue
        chain = ejs.dotted_chain(callee, src) or (ejs.node_text(callee, src) if callee.type == "identifier" else "")
        name = chain.rsplit(".", 1)[-1] if chain else ""
        if name and _PERMISSION_CHECK_NAME_RE.search(name):
            calls.append((node.start_point[0] + 1, f"{chain or name}(...)"))
    before = [c for c in calls if c[0] <= line]
    if not before:
        return None
    return max(before, key=lambda c: c[0])


def _js_credential_accesses(root_node, fn_node, src: bytes) -> list[CredentialAccess]:
    from . import entrypoints_js as ejs

    module_globals = _js_module_level_credential_globals(root_node, src)
    # Nearest enclosing class body, if any (best-effort: walks up via
    # `.parent`, which tree-sitter nodes always expose).
    class_node = None
    cur = fn_node.parent
    while cur is not None:
        if cur.type == "class_body":
            class_node = cur
            break
        cur = cur.parent
    this_attrs = _js_class_credential_this_attrs(class_node, src) if class_node is not None else set()
    if not module_globals and not this_attrs:
        return []

    found: list[CredentialAccess] = []
    seen: set[tuple[str, str]] = set()
    for node in ejs.walk(fn_node):
        if node is fn_node:
            continue
        if node.type == "identifier":
            name = ejs.node_text(node, src)
            if name in module_globals:
                key = ("module_global", name)
                if key in seen:
                    continue
                seen.add(key)
                line = node.start_point[0] + 1
                check = _js_permission_check_before(fn_node, src, line)
                found.append(
                    CredentialAccess(
                        name=name,
                        kind="module_global",
                        line=line,
                        permission_check_before=check is not None,
                        guarding_call=check[1] if check else None,
                    )
                )
        elif node.type == "member_expression":
            chain = ejs.dotted_chain(node, src)
            if not chain.startswith("this."):
                continue
            attr = chain.rsplit(".", 1)[-1]
            if attr not in this_attrs:
                continue
            key = ("this_attribute", attr)
            if key in seen:
                continue
            seen.add(key)
            line = node.start_point[0] + 1
            check = _js_permission_check_before(fn_node, src, line)
            found.append(
                CredentialAccess(
                    name=f"this.{attr}",
                    kind="this_attribute",
                    line=line,
                    permission_check_before=check is not None,
                    guarding_call=check[1] if check else None,
                )
            )
    return sorted(found, key=lambda c: c.line)


def _recover_js_entrypoints_safe(root: Path) -> list[McpEntrypoint]:
    """[] (not an error) if the `static-taint` extra (tree-sitter) isn't
    installed -- same ImportError-only-tolerance as taint_scanner.py's own
    `run_static_taint_scan`, so a genuine bug inside entrypoints_js.py still
    surfaces instead of being silently swallowed."""
    try:
        from . import entrypoints_js as ejs
    except ImportError:
        return []
    return ejs.recover_js_entrypoints(root)


def _recover_go_entrypoints_safe(root: Path) -> list[McpEntrypoint]:
    """[] (not an error) if the `static-taint` extra (tree-sitter-go) isn't
    installed -- same ImportError-only-tolerance as `_recover_js_entrypoints_safe`
    above."""
    try:
        from . import entrypoints_go as ego
    except ImportError:
        return []
    return ego.recover_go_entrypoints(root)


def _go_profile_for(root: Path, ep: McpEntrypoint, claims: list[SafetyClaim]) -> EntrypointProfile:
    """Go's own `_profile_for`. No `credential_access` inference is
    attempted here (unlike `_python_profile_for`/`_js_profile_for`) -- that
    would need its own Go-specific static pattern matcher, out of scope for
    entrypoint recovery, and an empty list here is exactly this project's
    own "absence is not proof of safety" default already documented at the
    top of this module, not a claim that no Go entrypoint ever touches a
    credential. `delegates_to` is likewise always None: `cross_file.py`'s
    one-hop resolver has no Go support either."""
    return EntrypointProfile(
        file=str(ep.file),
        function_name=ep.function_name,
        line=ep.line,
        parameter_names=ep.parameter_names,
        sdk_shape=ep.sdk_shape,
        confidence=ep.confidence,
        declared_authority=_nearest_claim_for(str(ep.file), ep.line, claims),
        credential_access=[],
        delegates_to=None,
    )


def _recover_kotlin_entrypoints_safe(root: Path) -> list[McpEntrypoint]:
    """[] (not an error) if the `static-taint` extra (tree-sitter-kotlin)
    isn't installed -- same ImportError-only-tolerance as
    `_recover_js_entrypoints_safe`/`_recover_go_entrypoints_safe` above.

    v10 consolidation-merge fix (bench/FINAL_COMPLETE_V10_STATUS.md's
    "Kotlin entrypoints not reaching the LLM hunter angles" section): the
    kotlin-support-work milestone wired `entrypoints_kotlin.py`'s output
    into `taint_scanner.py` (Stage 2/3) only -- this module (Stage 2's own
    Threat Model Document, the ONE artifact the 6 LLM-based hunter angles
    actually read) never called it at all, so a Kotlin target's real
    recovered entrypoints (e.g. JetBrains/teamcity-mcp's own 12, see
    bench/KOTLIN_SUPPORT_STATUS.md) were invisible to claims-vs-enforcement/
    credential-and-secrets/cross-file-authority/whole-handler-audit/
    scope-selector-override even after that milestone merged -- every one
    of those angles' own prompts would still say "(no MCP entrypoints were
    recovered)" for a Kotlin repo. This function plus `_kotlin_profile_for`
    below and their wiring
    into `build_threat_model()` closes that gap."""
    try:
        from . import entrypoints_kotlin as ekt
    except ImportError:
        return []
    return ekt.recover_kotlin_entrypoints(root)


def _kotlin_profile_for(root: Path, ep: McpEntrypoint, claims: list[SafetyClaim]) -> EntrypointProfile:
    """Kotlin's own `_profile_for` -- same shape as `_go_profile_for`
    (added at the same time, same reason): no `credential_access`
    inference (`entrypoints_kotlin.py` never built one -- see
    bench/KOTLIN_SUPPORT_STATUS.md's own "Real, stated scope limits"
    section) and no `delegates_to` (`cross_file.py` has no Kotlin support
    either). Both stay at their honest `[]`/`None` defaults -- absence is
    not proof of safety, not a claim that no Kotlin entrypoint touches a
    credential."""
    return EntrypointProfile(
        file=str(ep.file),
        function_name=ep.function_name,
        line=ep.line,
        parameter_names=ep.parameter_names,
        sdk_shape=ep.sdk_shape,
        confidence=ep.confidence,
        declared_authority=_nearest_claim_for(str(ep.file), ep.line, claims),
        credential_access=[],
        delegates_to=None,
    )


def _delegation_target_for(ep: McpEntrypoint, hop_by_origin: dict[tuple[Path, int], Any]) -> DelegationTarget | None:
    """Look up the one-hop `cross_file.py` resolution (if any) already
    computed for this exact entrypoint in `build_threat_model` -- see that
    function's own comment. Never re-derives; a miss is just "no hop found",
    not an error."""
    hop = hop_by_origin.get((ep.file, ep.line))
    if hop is None:
        return None
    return DelegationTarget(file=str(hop.target_file), function_name=hop.target_function_name, line=hop.target_line)


def _js_profile_for(
    root: Path,
    ep: McpEntrypoint,
    claims: list[SafetyClaim],
    hop_by_origin: dict[tuple[Path, int], Any] | None = None,
) -> EntrypointProfile:
    from . import entrypoints_js as ejs

    declared = _nearest_claim_for(str(ep.file), ep.line, claims)
    credential_access: list[CredentialAccess] = []
    parsed = ejs.parse_file(ep.file)
    if parsed is not None:
        root_node, src = parsed
        fn_node = ejs.find_enclosing_function(root_node, ep.line)
        if fn_node is not None:
            credential_access = _js_credential_accesses(root_node, fn_node, src)
    return EntrypointProfile(
        file=str(ep.file),
        function_name=ep.function_name,
        line=ep.line,
        parameter_names=ep.parameter_names,
        sdk_shape=ep.sdk_shape,
        confidence=ep.confidence,
        declared_authority=declared,
        credential_access=credential_access,
        delegates_to=_delegation_target_for(ep, hop_by_origin) if hop_by_origin else None,
    )


def _python_profile_for(
    root: Path,
    ep: McpEntrypoint,
    claims: list[SafetyClaim],
    hop_by_origin: dict[tuple[Path, int], Any] | None = None,
) -> EntrypointProfile:
    from .taint_scanner import _find_enclosing_function

    declared = _nearest_claim_for(str(ep.file), ep.line, claims)
    credential_access: list[CredentialAccess] = []
    try:
        source = ep.file.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(source, filename=str(ep.file))
    except (OSError, SyntaxError):
        tree = None
    if tree is not None:
        fn = _find_enclosing_function(tree, ep.line)
        if fn is not None:
            credential_access = _python_credential_accesses(tree, fn)
    return EntrypointProfile(
        file=str(ep.file),
        function_name=ep.function_name,
        line=ep.line,
        parameter_names=ep.parameter_names,
        sdk_shape=ep.sdk_shape,
        confidence=ep.confidence,
        declared_authority=declared,
        credential_access=credential_access,
        delegates_to=_delegation_target_for(ep, hop_by_origin) if hop_by_origin else None,
    )


# --------------------------------------------------------------------------
# Public entry point
# --------------------------------------------------------------------------


def build_threat_model(
    repo_path: str | Path,
    *,
    use_cache: bool = True,
    cache_dir: str | Path | None = None,
) -> ThreatModelDocument:
    """Build (or load from cache) the Threat Model Document for the repo at
    `repo_path`. Cached at `~/.cache/mcp_safeguard/tmd/<repo-name>-<repo-
    identity>-<version>-<commit>.json` by default (override with
    `cache_dir`) -- NEVER inside `repo_path` itself, see the module
    docstring's "Security" note -- a second call against the same commit
    is a cache read, not a re-scan."""
    root = Path(repo_path).resolve()
    repo_name = root.name
    commit = _resolve_commit(root)
    cache_path = _cache_path(root, repo_name, commit, cache_dir)

    if use_cache and cache_path.is_file():
        try:
            return ThreatModelDocument.from_dict(json.loads(cache_path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError, KeyError, TypeError):
            pass  # corrupt/stale cache entry -- fall through and recompute

    py_entrypoints = recover_entrypoints(root)
    js_entrypoints = _recover_js_entrypoints_safe(root)
    go_entrypoints = _recover_go_entrypoints_safe(root)
    kotlin_entrypoints = _recover_kotlin_entrypoints_safe(root)
    claims = _collect_claims(root)

    # One-hop delegation-following (S3's cross-file-authority angle): reuse
    # cross_file.py's own tested single-hop resolver -- already relied on by
    # taint_scanner.py for the same "thin registration, real logic
    # elsewhere" idiom -- rather than reimplementing import/call resolution
    # here. Computed once, indexed by the origin entrypoint's own
    # (file, line), so every `_profile_for` call below is a dict lookup, not
    # a re-scan. Best-effort: any failure here just means no delegation
    # info gets attached, never a build_threat_model crash.
    py_hop_by_origin: dict[tuple[Path, int], Any] = {}
    js_hop_by_origin: dict[tuple[Path, int], Any] = {}
    try:
        from . import cross_file

        py_hop_by_origin = {(h.origin_entrypoint.file, h.origin_entrypoint.line): h for h in cross_file.find_python_cross_file_hops(py_entrypoints, root)}
        if js_entrypoints:
            js_hop_by_origin = {(h.origin_entrypoint.file, h.origin_entrypoint.line): h for h in cross_file.find_js_cross_file_hops(js_entrypoints, root)}
    except Exception:
        pass

    profiles = [_python_profile_for(root, ep, claims, py_hop_by_origin) for ep in py_entrypoints]
    profiles.extend(_js_profile_for(root, ep, claims, js_hop_by_origin) for ep in js_entrypoints)
    profiles.extend(_go_profile_for(root, ep, claims) for ep in go_entrypoints)
    profiles.extend(_kotlin_profile_for(root, ep, claims) for ep in kotlin_entrypoints)
    profiles.sort(key=lambda p: (p.file, p.line))

    tmd = ThreatModelDocument(
        repo_path=str(root),
        repo_name=repo_name,
        commit=commit,
        generated_at=datetime.now(UTC).isoformat(),
        entrypoints=profiles,
        claims=claims,
    )

    if use_cache:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(tmd.to_dict(), indent=2), encoding="utf-8")
    return tmd


if __name__ == "__main__":
    import sys

    tmd = build_threat_model(sys.argv[1] if len(sys.argv) > 1 else ".")
    print(f"# Threat Model Document: {tmd.repo_name} @ {tmd.commit}")
    print(f"# {len(tmd.entrypoints)} entrypoints, {len(tmd.claims)} safety claims\n")
    for ep in tmd.entrypoints:
        flag = " [UNCHECKED CREDENTIAL ACCESS]" if ep.has_unchecked_credential_access else ""
        print(f"{ep.file}:{ep.line}  {ep.function_name}({', '.join(ep.parameter_names)}){flag}")
        if ep.declared_authority:
            print(f"    declared: {ep.declared_authority.text!r} ({ep.declared_authority.location})")
        for c in ep.credential_access:
            checked = f"checked by {c.guarding_call} " if c.guarding_call else "NO CHECK FOUND "
            print(f"    credential: {c.name} @ line {c.line} -- {checked}")
    print("\n# Safety claims:")
    for claim in tmd.claims[:40]:
        print(f"  [{claim.keyword}] {claim.location}: {claim.text}")
