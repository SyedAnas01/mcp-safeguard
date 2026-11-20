"""Stage 2/3: static-taint detection (Python), tier "S".

Stage 2 generates semgrep taint rules whose SOURCES are the real MCP handler
functions/parameters recovered by Stage 1 (`entrypoints.py`) -- not a generic
"any function parameter" pattern -- for five sink classes: command
injection, path traversal, SSRF, credential forwarding/confused deputy, and
missing object-level authorization (IDOR). semgrep CE (already a real
dataflow/taint engine, intra-procedural) does the actual source-to-sink
reachability and sanitizer-recognition work; this module does not
reimplement that.

The first three classes (CMDI/PATHTRAV/SSRF) are HARD-SINK classes: the sink
itself (a shell exec, a raw file open, an unvalidated HTTP fetch) is
inherently dangerous, so "semgrep found a path with no recognized sanitizer"
is a strong signal on its own. The two classes added after them are
structurally different:

  TAINT-CREDFWD (credential forwarding / confused deputy) is still a
  hard-sink class, but a two-CONDITION one: the sink only fires when BOTH a
  tool parameter reaches an outbound call's destination AND that same call
  attaches a credential the server holds (an Authorization/API-key header,
  or an `auth=` tuple). Real pattern confirmed against huggingface/
  hf-mcp-server (`gradio-caller.ts`'s `callGradioToolWithHeaders`, which
  attaches `X-HF-Authorization` to whatever `mcpUrl` it is given with no
  destination check) -- TypeScript in that real instance; the Python rule was
  validated against a constructed Python-equivalent (see
  MILESTONE_CLASSES_STATUS.md). A real JS/TS port (`_CREDFWD_JS`,
  `generate_credfwd_any_fn_rule_yaml_js()`) now exists and IS validated
  directly against hf-mcp-server's own real source at the exact commit this
  campaign's report cites -- see MILESTONE_CREDFWD_JS_STATUS.md.

  TAINT-IDOR (missing object-level authorization) is an ABSENCE-based class,
  the weakest-confidence class in this file by design, same honest framing
  SRC-024's own lexical rule already uses for the identical bug class: the
  sink (a data-access/mutation call keyed by a tainted ID) is NOT inherently
  dangerous, so semgrep is asked to fire on every reachable hit regardless
  of whether a check-shaped call exists on the path (semgrep OSS's own
  taint sanitizers empirically do NOT clear on a bare assert-style guard --
  see TAINT-SSRF's own documented limitation below, which is the same
  mechanism), and this module's OWN Python code then walks the
  Stage-3-reconstructed path and only emits a finding when NO call matching
  `IDOR_AUTH_CHECK_NAMES` (deliberately a plain, extensible module-level
  constant, not hardcoded inline) was found on it. Findings from this class
  carry `confidence="low"` on their `SourceFinding` and say so in their own
  description text. Real validation target: oraichain/ragflow-mcp's
  `upload_rag` (`main.py`), already in this project's own frozen holdout
  (bench/holdout_frozen.yaml) for a related finding on the same file.

Stage 3 takes each raw semgrep hit and reconstructs a human-auditable path:
walks the enclosing function's AST from its parameters to the flagged sink
line, recording the intermediate assignments and any sanitizer-shaped calls
it recognizes along the way as a `Step` list. This is deliberately a
best-effort, statement-order approximation (no real control-flow graph, no
branch/loop modeling) -- semgrep already did the hard, sound reachability
analysis in Stage 2; Stage 3 only re-narrates a plausible route for a human
reviewer, the same "leads to confirm, not proofs" discipline the rest of this
package already documents.

Every finding this module produces carries `tier="S"` on the existing
`SourceFinding` dataclass (see source_scanner.py) and a `taint_path` list of
`Step` dicts -- purely additive, nothing about the existing "L" tier rules
changes.

TypeScript/JavaScript (Milestone 2): `run_static_taint_scan()` also recovers
JS/TS entrypoints (`entrypoints_js.py`, tree-sitter-based) and runs a second,
separate semgrep pass over the same 3 vulnerability classes for JS/TS sinks
-- both languages are covered transparently by the same `--static-taint`
flag with no separate flag needed. The two passes are kept as two
independent `_run_semgrep()` invocations (one config each) rather than
merged into a single call, on purpose: it costs one extra semgrep walk of
the tree on a mixed-language repo, in exchange for zero changes to the
existing, already-tested Python rule-generation code path. `entrypoints_js`
is imported lazily inside `run_static_taint_scan()`, not at module level --
`tree-sitter`/`tree-sitter-javascript`/`tree-sitter-typescript` are real
dependencies (added to this project's `static-taint` extra), but a
Python-only install must not hard-fail a Python-only scan if they are
somehow missing; the JS/TS pass is skipped with a warning instead, the same
"optional, additive feature" discipline `_run_semgrep()` already applies to
a missing `semgrep` binary itself.

Kotlin (Kotlin-support milestone): a THIRD, independent semgrep pass, same
"one extra `_run_semgrep()` invocation, lazily-imported `entrypoints_kotlin`,
skip-with-a-warning if `tree-sitter-kotlin` is missing" discipline as the
JS/TS pass above -- but deliberately NARROWER in scope: only the 3 hard-sink
classes (CMDI/PATHTRAV/SSRF, see `_VULN_CLASSES_KOTLIN`), no cross-file hop
synthesis, and `reconstruct_path_kotlin`'s own evidence path is a minimal
source+sink pair rather than the full statement-order walk the other two
languages get (see that function's own docstring). Built to close a
confirmed real blocker (JetBrains/teamcity-mcp had zero Kotlin entrypoint
recovery before this) -- see entrypoints_kotlin.py's own module docstring
and bench/KOTLIN_SUPPORT_STATUS.md for the real validation record.

Bounded, single-hop cross-file resolution (cross-file milestone): two
independent gaps this file's own docs already named -- Milestone 2's own
"the dominant real-world limiting factor" (a source and sink split between
a handler file and a shared client/utility module) and a plausible root
cause for some of TAINT-IDOR's false positives (a real auth-check call
that exists, just in a helper imported from another file) -- come from the
SAME root cause: same-file-only resolution. `cross_file.py` does the actual
import resolution and call-argument-to-parameter mapping (kept there,
vuln-class-agnostic, to avoid a circular import); this file wires it in at
two points:

  1. `run_static_taint_scan()` calls `cross_file.find_python_cross_file_hops`/
     `find_js_cross_file_hops` on the REAL recovered entrypoints, and feeds
     each hop's synthetic entrypoint into the SAME per-file rule generation
     a real entrypoint would go through -- so a genuinely cross-file
     source-to-sink flow (the handler-forwards-to-a-shared-module shape) has
     a real chance at a semgrep hit in the callee's OWN file, not just an
     annotation on an already-found one. `_findings_from_raw` then prepends
     the origin entrypoint's own context and a `cross_file_call` Step ahead
     of that finding's normal (target-file) evidence path.
  2. `reconstruct_path`/`reconstruct_path_js`, when an assignment's RHS call
     or a bare guard call isn't a recognized same-file sanitizer/check,
     additionally try `_probe_python_call`/`_probe_js_call` -- resolve the
     call via `cross_file.py` and, if it points at a real local file, walk
     ONE hop into the resolved function (`_walk_python_callee`/
     `_walk_js_callee`, using this file's OWN sink/sanitizer vocabulary,
     never a second import resolution) to see whether the forwarded
     parameter reaches a dangerous sink or gets cleared by a recognized
     sanitizer/auth-check there. This is what lets a real cross-file
     TAINT-IDOR check get recognized instead of producing a false "no check
     found".

Both wiring points are bounded to EXACTLY one hop by construction (the
probe never calls back into `cross_file.py`'s own resolvers a second time
against a nested unresolved call -- it reports `unresolved_deeper_indirection`
and stops), and both fail closed: an import that doesn't resolve to a local
file (a third-party package, an unresolved re-export) is recorded as
`external_call_unresolved` and treated as inconclusive -- never assumed
either safe or dangerous. See `bench/MILESTONE_CROSSFILE_STATUS.md` for the
real validation numbers and honest limitations.
"""

from __future__ import annotations

import ast
import json
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path

from . import cross_file, lexical
from .entrypoints import McpEntrypoint, recover_entrypoints
from .prompt_injection import Severity
from .source_scanner import SourceFinding

# --------------------------------------------------------------------------
# Vulnerability-class catalog: everything Stage 2 (rule generation) and
# Stage 3 (path reconstruction) need to stay in sync, in one place, so the
# evidence Stage 3 narrates always matches what Stage 2 actually asked
# semgrep to look for.
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class _VulnClass:
    rule_id: str
    title: str
    severity: Severity
    cvss: float
    semgrep_sink_patterns: tuple[str, ...]
    semgrep_sanitizer_patterns: tuple[str, ...]
    # Dotted call-name prefixes this class's sink actually is -- used by
    # Stage 3 to recognize the sink call independently of semgrep (Stage 3
    # re-parses the file itself and doesn't have semgrep's own AST handles).
    sink_call_names: tuple[str, ...]
    # STRONG sanitizer call names -- matches semgrep_sanitizer_patterns.
    strong_sanitizer_names: tuple[str, ...]
    # WEAK/still-suspicious sanitizer-shaped calls: deliberately NOT in
    # semgrep_sanitizer_patterns (so semgrep keeps flagging them), but
    # recognized here so Stage 3 can annotate "an inadequate check was
    # attempted" rather than staying silent about it.
    weak_sanitizer_names: tuple[str, ...]
    remediation: str
    # Escape hatch for a sink shape _sink_block() cannot express as a flat
    # pattern-either + one shared focus-metavariable -- currently only
    # TAINT-CREDFWD, whose sink is a genuine two-condition construct
    # (tainted destination AND a credential attached in the SAME call, each
    # needing its own extra metavariable-regex on a DIFFERENT metavariable).
    # When set, used verbatim as the rule's `pattern-sinks:` block instead of
    # generating one from semgrep_sink_patterns.
    semgrep_sink_yaml: str | None = None
    # Extra (metavariable, regex) constraints appended into the SAME sink
    # `patterns:` list _sink_block() already builds -- e.g. TAINT-IDOR uses
    # this to restrict $METHOD to a data-access-shaped verb. Not needed by
    # the three original hard-sink classes (empty by default).
    semgrep_sink_metavariable_regex: tuple[tuple[str, str], ...] = ()
    # True only for an ABSENCE-based class (currently only TAINT-IDOR): the
    # sink is not inherently dangerous, so a finding is only emitted when
    # NONE of strong_sanitizer_names' names is found anywhere on the
    # reconstructed path (see _path_has_recognized_check), and the emitted
    # finding is stamped confidence="low" with an explicit caveat in its
    # description. False (default) preserves the original 3 classes'
    # unconditional "every semgrep hit is a finding" behavior.
    absence_based: bool = False
    # Overrides the confidence _findings_from_raw() would otherwise derive
    # from absence_based alone ("low" if absence_based else "high") --
    # currently only TAINT-CREDFWD-JS's wrapper-call variant
    # (_CREDFWD_JS_WRAPPER), which is NOT absence-based (every hit IS a
    # real structural match) but has a demonstrated, real false-positive
    # class of its own (see that class's own comment and
    # MILESTONE_CREDFWD_JS_STATUS.md's false-positive sweep) distinct from
    # IDOR's "the check might exist somewhere this pass can't see" caveat.
    # None (default) preserves every other class's existing behavior.
    confidence_override: str | None = None
    # Extra sentence(s) appended to every finding's description, independent
    # of absence_based's own IDOR-specific caveat text below -- currently
    # only TAINT-CREDFWD-JS's wrapper-call variant. "" (default) appends
    # nothing, same as every class before this one.
    extra_caveat: str = ""


_CMDI = _VulnClass(
    rule_id="TAINT-CMDI",
    title="MCP tool parameter reaches a command-injection sink",
    severity=Severity.CRITICAL,
    cvss=9.8,
    semgrep_sink_patterns=(
        "subprocess.run($CMD, ..., shell=True, ...)",
        "subprocess.call($CMD, ..., shell=True, ...)",
        "subprocess.Popen($CMD, ..., shell=True, ...)",
        "os.system($CMD)",
    ),
    semgrep_sanitizer_patterns=("shlex.quote(...)", "shlex.split(...)"),
    sink_call_names=("subprocess.run", "subprocess.call", "subprocess.Popen", "os.system"),
    strong_sanitizer_names=("shlex.quote", "shlex.split"),
    weak_sanitizer_names=(),
    remediation=(
        "Never build a shell string from tool input. Pass the command as an argv list with "
        "shell=False (the default), or if a shell string is unavoidable, quote every "
        "interpolated value with shlex.quote()."
    ),
)

_PATH_TRAVERSAL = _VulnClass(
    rule_id="TAINT-PATHTRAV",
    title="MCP tool parameter reaches a filesystem sink with no real containment check",
    severity=Severity.HIGH,
    cvss=7.5,
    semgrep_sink_patterns=(
        "open($CMD, ...)",
        "open($CMD)",
        "os.remove($CMD)",
        "$CMD.read_text(...)",
        "$CMD.write_text(...)",
    ),
    # Deliberately NOT including a bare str.startswith(base) check here --
    # per this milestone's own scope, that is a real bug pattern this
    # project's disclosure campaign already found (SRC-018/024's module
    # comments), not adequate sanitization, so it must not suppress a match.
    semgrep_sanitizer_patterns=(
        "os.path.realpath(...)",
        "$V.resolve()",
        "$V.is_relative_to(...)",
        "os.path.commonpath(...)",
    ),
    sink_call_names=("open", "os.remove", ".read_text", ".write_text"),
    strong_sanitizer_names=("os.path.realpath", ".resolve", ".is_relative_to", "os.path.commonpath"),
    weak_sanitizer_names=(".startswith",),
    remediation=(
        "Resolve the joined path with os.path.realpath()/Path.resolve() and verify containment "
        "with os.path.commonpath() or Path.is_relative_to() against the intended base directory "
        "before using it. A bare str.startswith(base) check is not real containment -- "
        "'/base-evil' starts with '/base' as a string but is a sibling directory, not a child."
    ),
)

_SSRF = _VulnClass(
    rule_id="TAINT-SSRF",
    title="MCP tool parameter reaches an outbound HTTP sink with no host-allowlist check",
    severity=Severity.HIGH,
    cvss=8.6,
    semgrep_sink_patterns=(
        "requests.get($CMD, ...)",
        "requests.post($CMD, ...)",
        "httpx.get($CMD, ...)",
        "httpx.post($CMD, ...)",
        "urllib.request.urlopen($CMD, ...)",
        "urllib.request.urlopen($CMD)",
    ),
    # Same guard vocabulary source_scanner.py's SRC-011/SRC-023 already use,
    # for consistency between the lexical (L) and static-taint (S) tiers.
    semgrep_sanitizer_patterns=(
        "validate_url(...)",
        "check_ssrf(...)",
        "is_safe_url(...)",
        "is_ssrf_safe(...)",
        "validate_host(...)",
        "validate_target(...)",
        "ssrf_guard(...)",
    ),
    sink_call_names=("requests.get", "requests.post", "httpx.get", "httpx.post", "urllib.request.urlopen", "urlopen"),
    strong_sanitizer_names=(
        "validate_url",
        "check_ssrf",
        "is_safe_url",
        "is_ssrf_safe",
        "validate_host",
        "validate_target",
        "ssrf_guard",
    ),
    weak_sanitizer_names=(),
    remediation=(
        "Resolve the target host and check it against an explicit allowlist AFTER resolution "
        "(and after following any redirect), not just on the original URL string before it is "
        "fetched -- a pre-redirect-only check does not stop DNS rebinding or a redirect to an "
        "internal host."
    ),
)

# --------------------------------------------------------------------------
# TAINT-CREDFWD: credential forwarding / confused deputy (CWE-441).
#
# Real pattern this generalizes: huggingface/hf-mcp-server's
# `callGradioToolWithHeaders` (`gradio-caller.ts:190-199`) attaches the
# user's live HF bearer token (`X-HF-Authorization`) to whatever `mcpUrl` it
# is given, with the destination-privacy check (`metadata.private`)
# computed one call earlier and never threaded through -- a caller-supplied
# `space_name` tool argument builds the destination host, and the SAME call
# attaches the server-held credential. See round44-official-orgs-findings/
# 01-huggingface-hf-mcp-server-gradio-space-token-forwarding.md for the full
# trace (GHSA-6w92-f47f-5xx8). That real instance is TypeScript; this
# pipeline is Python-only (see entrypoints.py's own module docstring), so
# this rule is validated here against a constructed Python-equivalent of
# the identical shape (see MILESTONE_CLASSES_STATUS.md) -- an honest
# limitation, not a claim this rule was proven against the real hf-mcp-server
# source.
#
# Two-condition sink (see semgrep_sink_yaml below, the escape hatch
# _sink_block() can't express): the outbound call's DESTINATION must be
# reachable from the tool parameter (taint, same as SSRF), AND the SAME call
# must attach a credential -- either a `headers=` dict/variable whose
# CONTENTS mention credential vocabulary (Authorization/bearer/api-key/
# token/secret), matched via a two-statement `$VAR = {...}; ...; call(...,
# headers=$VAR, ...)` sequential pattern so a headers dict built one
# statement earlier (the common real-world idiom, including hf-mcp-server's
# own two-line shape) is still caught -- metavariable-regex only sees the
# text actually bound to its metavariable, so `headers=$VAR` alone binds
# just the identifier "headers", never the dict literal that defines it
# (empirically confirmed while building this rule; see
# MILESTONE_CLASSES_STATUS.md) -- or the `requests` library's own `auth=`
# kwarg, which is inherently credential-bearing by that library's own
# semantics regardless of its value's shape.
#
# Sanitizer vocabulary is deliberately the SAME as TAINT-SSRF's: the actual
# fix for this class (per the hf-mcp-server report's own "Suggested fix") is
# exactly a destination-trust gate before attaching the credential, the same
# host-allowlist idea SSRF already models.
_CREDFWD_SINK_YAML = """\
  pattern-sinks:
    - patterns:
        - pattern-either:
            - pattern: |
                $HVAR = $HDICT
                ...
                requests.get($CMD, ..., headers=$HVAR, ...)
            - pattern: |
                $HVAR = $HDICT
                ...
                requests.post($CMD, ..., headers=$HVAR, ...)
            - pattern: |
                $HVAR = $HDICT
                ...
                httpx.get($CMD, ..., headers=$HVAR, ...)
            - pattern: |
                $HVAR = $HDICT
                ...
                httpx.post($CMD, ..., headers=$HVAR, ...)
            - pattern: requests.get($CMD, ..., headers=$HDICT, ...)
            - pattern: requests.post($CMD, ..., headers=$HDICT, ...)
            - pattern: httpx.get($CMD, ..., headers=$HDICT, ...)
            - pattern: httpx.post($CMD, ..., headers=$HDICT, ...)
        - metavariable-regex:
            metavariable: $HDICT
            regex: (?is).*(authorization|bearer|api[_-]?key|apikey|x-api-key|access[_-]?token|secret).*
        - focus-metavariable: $CMD
    - patterns:
        - pattern-either:
            - pattern: requests.get($CMD, ..., auth=$AUTHTUP, ...)
            - pattern: requests.post($CMD, ..., auth=$AUTHTUP, ...)
        - focus-metavariable: $CMD
"""

_CREDFWD = _VulnClass(
    rule_id="TAINT-CREDFWD",
    title="MCP tool parameter reaches an outbound destination that also carries a server-held credential",
    severity=Severity.CRITICAL,
    cvss=9.1,
    semgrep_sink_patterns=(),  # unused -- semgrep_sink_yaml below is this class's sink
    semgrep_sanitizer_patterns=(
        "validate_url(...)",
        "check_ssrf(...)",
        "is_safe_url(...)",
        "is_ssrf_safe(...)",
        "validate_host(...)",
        "validate_target(...)",
        "ssrf_guard(...)",
    ),
    sink_call_names=("requests.get", "requests.post", "httpx.get", "httpx.post"),
    strong_sanitizer_names=(
        "validate_url",
        "check_ssrf",
        "is_safe_url",
        "is_ssrf_safe",
        "validate_host",
        "validate_target",
        "ssrf_guard",
    ),
    weak_sanitizer_names=(),
    remediation=(
        "Never let presence of a credential alone decide whether to attach it -- require the "
        "caller to explicitly confirm the destination is trusted (e.g. thread the already-computed "
        "'is this destination private/mine?' boolean into the call that attaches the credential, "
        "the same gate hf-mcp-server's own schema-fetch path already used correctly one call away "
        "from where the invocation path forgot it), or validate the destination host against an "
        "explicit allowlist before attaching any Authorization/API-key/token."
    ),
    semgrep_sink_yaml=_CREDFWD_SINK_YAML,
)

# --------------------------------------------------------------------------
# TAINT-IDOR: missing object-level authorization (BOLA/IDOR, CWE-639/862/863).
#
# ABSENCE-based, the weakest-confidence class in this file -- see this
# module's own docstring above and MILESTONE_CLASSES_STATUS.md. The sink is
# an ordinary data-access/mutation call (get_x/fetch_x/query/approve_x/...)
# keyed by a tainted, resource-ID-shaped tool parameter -- not inherently
# dangerous the way CMDI/PATHTRAV/SSRF/CREDFWD's sinks are, so semgrep is
# asked to fire on every reachable hit (semgrep_sanitizer_patterns is
# deliberately EMPTY: semgrep OSS's own taint sanitizers empirically do not
# clear on a bare assert-style guard call anyway -- see TAINT-SSRF's
# documented limitation, the same underlying mechanism -- so relying on
# semgrep to suppress the checked case would silently under-fire), and
# run_static_taint_scan() below does the actual "was a check found?"
# determination in Python, by reusing Stage 3's EXISTING path-reconstruction
# code with IDOR_AUTH_CHECK_NAMES loaded into strong_sanitizer_names (Stage
# 3's own "bare guard call referencing a tainted argument" second pass
# already records exactly this shape as a Step -- no changes to
# reconstruct_path were needed).
#
# Real validation target: oraichain/ragflow-mcp's `upload_rag` (main.py:137,
# sink at line 150: `ragflow.get_dataset(name=dataset_name)`), already in
# this project's own frozen holdout (bench/holdout_frozen.yaml) for a
# related finding on the same file/repo -- see MILESTONE_CLASSES_STATUS.md.
IDOR_AUTH_CHECK_NAMES: tuple[str, ...] = (
    # Bare/module-level calls: check_access(resource_id, user), authorize(...).
    "check_access",
    "verify_owner",
    "verify_ownership",
    "check_ownership",
    "check_permission",
    "has_permission",
    "authorize",
    "is_authorized",
    "require_scope",
    "verify_access",
    "can_access",
    "is_owner",
    "require_ownership",
    "get_project",
    "getProject",
    # --- IDOR-fix milestone additions below: real object/permission-scoped
    # patterns from actual frameworks, not just this project's own original
    # example list. Deliberately EXCLUDES pure-authentication names
    # (login_required, requires_auth, ...) -- those go in
    # IDOR_AUTHN_ONLY_NAMES below instead, because "the caller is logged in"
    # is not the same claim as "the caller owns THIS object", and folding
    # them in here would silently turn every authenticated-but-still-IDOR
    # bug into a false negative (see that constant's own docstring).
    "permission_required",  # Django/DRF decorator, also used as a bare call in some codebases
    "require_permission",
    "requires_permission",
    "object_permission_required",
    "has_object_permission",  # DRF's per-object permission hook name
    "check_object_permission",
    "owner_required",
    "assert_owner",
    "ensure_owner",
    "verify_tenant",
    "check_tenant",
    "require_tenant_match",
    "ensure_tenant_match",
    "scoped_to_user",
    "get_owned_or_404",
    "require_ownership_or_404",
    # The same names called as a method on some object (self.authorize(...),
    # access_control.check_access(...)) -- a leading "." matches ANY
    # receiver, the same convention _matches_sanitizer_name already uses for
    # TAINT-PATHTRAV's ".resolve"/".is_relative_to".
    ".check_access",
    ".verify_owner",
    ".verify_ownership",
    ".check_ownership",
    ".check_permission",
    ".has_permission",
    ".authorize",
    ".is_authorized",
    ".require_scope",
    ".verify_access",
    ".can_access",
    ".is_owner",
    ".require_ownership",
    ".permission_required",
    ".require_permission",
    ".requires_permission",
    ".has_object_permission",
    ".check_object_permission",
    ".owner_required",
    ".assert_owner",
    ".ensure_owner",
    ".verify_tenant",
    ".check_tenant",
)
# Deliberately a plain, public module-level tuple -- not hardcoded inline in
# the detection logic -- so a real codebase's own check-function names can
# be added (or a caller can build a differently-configured IDOR vuln class
# via `dataclasses.replace(_IDOR, strong_sanitizer_names=(...))`) without
# touching run_static_taint_scan() itself.

# Authentication-only names: real, common (Flask's flask_login.login_required,
# Django's login_required, FastAPI-community requires_auth/auth_required
# helpers, flask-jwt-extended's jwt_required, ...) but deliberately NOT
# folded into IDOR_AUTH_CHECK_NAMES above. These decorators/calls establish
# "there is a valid, authenticated session" -- they say nothing about
# whether THIS caller owns the SPECIFIC resource the tainted parameter
# names, which is the entire claim an IDOR/BOLA check has to make (CWE-639's
# own definition: authentication != authorization). Recognizing a bare
# @login_required as if it were equivalent to @permission_required would
# convert a real class of bug (an authenticated user reading ANOTHER
# authenticated user's resource) into a silent false negative -- exactly the
# failure mode this milestone was asked not to introduce while fixing false
# positives elsewhere. So a match against this tuple is recorded as an
# annotation on the reconstructed path (a human should still see it) but
# does NOT, by itself, suppress a TAINT-IDOR finding (see
# reconstruct_path's decorator pass and _path_has_recognized_check below).
# It DOES count as one of the tenancy-evidence signals for the confidence
# gate (see _scan_repo_for_tenancy_evidence) -- a codebase that bothers
# gating handlers behind authentication at all is more likely to be a real
# multi-user service than a local single-user tool, even though
# authentication alone doesn't prove per-object scoping.
IDOR_AUTHN_ONLY_NAMES: tuple[str, ...] = (
    "login_required",
    "require_auth",
    "requires_auth",
    "auth_required",
    "authenticated",
    "jwt_required",
    "token_required",
    ".login_required",
    ".require_auth",
    ".requires_auth",
    ".auth_required",
    ".jwt_required",
    ".token_required",
)

# Data-access-shaped verbs the sink's $METHOD must match -- deliberately
# excludes a bare, unsuffixed "get"/"find"/"list" (the single largest real
# false-positive source: dict.get(), os.environ.get(), request.args.get()
# are all extremely common and none of them are an object-level-authz-
# relevant data fetch) in favor of requiring an underscore-suffixed,
# resource-naming form (get_dataset, fetch_record, find_user, ...), the
# same shape as the real ragflow-mcp bug this class validates against.
# "query"/"fetch"/"approve"/"reject" are kept bare since they collide with
# far fewer common builtins.
#
# Deliberately CASE-SENSITIVE (no `(?i)`) -- found empirically while
# validating against the clean corpus: semgrep's own Python "from $MOD
# import $NAME; $NAME(...)" equivalence (see MILESTONE_CLASSES_STATUS.md,
# the same mechanic that lets this sink catch a bare imported function call)
# also matched a case-INSENSITIVE bare "query" against `Query(base_query)` --
# a class CONSTRUCTOR (redis/mcp-redis's redis_query_engine.py, imported
# from redis.commands.search.query), not a method call -- on
# redis/mcp-redis, a real target in this project's own clean-corpus
# precision check. Python convention is snake_case for functions/methods
# and PascalCase for classes, so requiring lowercase costs no realistic
# recall and removes this exact false-positive class.
_IDOR_SINK_METHOD_REGEX = (
    r"^(get_\w+|fetch(_\w+)?|find(_\w+)?|read_\w+|list_\w+|approve(_\w+)?|"
    r"reject(_\w+)?|delete(_\w+)?|update(_\w+)?|remove(_\w+)?|lookup(_\w+)?|query)$"
)

_IDOR = _VulnClass(
    rule_id="TAINT-IDOR",
    title="MCP tool parameter reaches a data-access call with no recognized authorization check",
    severity=Severity.HIGH,
    cvss=8.1,
    semgrep_sink_patterns=(
        "$OBJ.$METHOD($CMD, ...)",
        "$OBJ.$METHOD(..., $KW=$CMD, ...)",
    ),
    semgrep_sanitizer_patterns=(),  # see module comment above: intentionally empty
    sink_call_names=(),  # sink is a dynamic $OBJ.$METHOD pair, not a fixed name list
    strong_sanitizer_names=IDOR_AUTH_CHECK_NAMES,
    weak_sanitizer_names=(),
    remediation=(
        "Before returning or acting on the resource, verify server-side that the authenticated "
        "caller owns it or is scoped to it (a membership/tenant lookup keyed by the caller's own "
        "identity, not the client-supplied ID) -- the same access check this file's other handlers "
        "may already apply to sibling operations."
    ),
    semgrep_sink_metavariable_regex=(("$METHOD", _IDOR_SINK_METHOD_REGEX),),
    absence_based=True,
)

_VULN_CLASSES: tuple[_VulnClass, ...] = (_CMDI, _PATH_TRAVERSAL, _SSRF, _CREDFWD, _IDOR)


# --------------------------------------------------------------------------
# JS/TS vulnerability-class catalog (Milestone 2). Same 3 classes, same
# `rule_id`/title/severity/cvss/remediation as their Python counterparts
# above (this is the same conceptual vulnerability regardless of language),
# but with JS/TS-shaped semgrep patterns and sink/sanitizer call-name
# vocabulary for Stage 3's tree-sitter-based path reconstruction.
# --------------------------------------------------------------------------

_CMDI_JS = _VulnClass(
    rule_id="TAINT-CMDI",
    title=_CMDI.title,
    severity=_CMDI.severity,
    cvss=_CMDI.cvss,
    semgrep_sink_patterns=(
        "child_process.exec($CMD)",
        "child_process.exec($CMD, ...)",
        "exec($CMD)",
        "exec($CMD, ...)",
        "child_process.execSync($CMD)",
        "child_process.execSync($CMD, ...)",
        "execSync($CMD)",
        "execSync($CMD, ...)",
        "child_process.spawn($CMD, ..., {shell: true, ...})",
        "spawn($CMD, ..., {shell: true, ...})",
    ),
    # No sanitizer patterns: unlike Python's shlex.quote(), there's no
    # standard JS "make this shell-safe" call worth trusting blindly. The
    # task's own stated sanitizer for this class -- argv-array-form
    # spawn()/execFile() with no shell option -- isn't a sanitizer that
    # CLEARS a match; it is simply not one of the sink patterns above at
    # all (no `shell: true`), so it never fires in the first place.
    semgrep_sanitizer_patterns=(),
    sink_call_names=("child_process.exec", "exec", "child_process.execSync", "execSync",
                      "child_process.spawn", "spawn"),
    strong_sanitizer_names=(),
    weak_sanitizer_names=(),
    remediation=(
        "Never build a shell string from tool input. Use execFile()/spawn() with an argv "
        "array and no shell option (shell: false, the default) instead of exec()/execSync() "
        "or spawn(..., {shell: true})."
    ),
)

_PATH_TRAVERSAL_JS = _VulnClass(
    rule_id="TAINT-PATHTRAV",
    title=_PATH_TRAVERSAL.title,
    severity=_PATH_TRAVERSAL.severity,
    cvss=_PATH_TRAVERSAL.cvss,
    semgrep_sink_patterns=(
        "fs.readFile($CMD, ...)",
        "fs.readFileSync($CMD, ...)",
        "fs.readFileSync($CMD)",
        "fs.writeFile($CMD, ...)",
        "fs.writeFileSync($CMD, ...)",
        "fs.unlink($CMD, ...)",
        "fs.unlinkSync($CMD)",
        "fs.createReadStream($CMD, ...)",
        "fs.createReadStream($CMD)",
        # Bare forms for `import { readFileSync } from "fs"`-style named
        # imports, which this module (deliberately, like entrypoints.py)
        # never resolves -- matching the bare call name directly is the
        # only way to still catch this common real import style.
        "readFile($CMD, ...)",
        "readFileSync($CMD, ...)",
        "readFileSync($CMD)",
        "writeFile($CMD, ...)",
        "writeFileSync($CMD, ...)",
        "createReadStream($CMD, ...)",
        "createReadStream($CMD)",
    ),
    # Deliberately NOT including a bare str.startsWith(base) check here --
    # per this milestone's own scope (and this project's own campaign
    # findings, e.g. oncorporation-filesystem-server's is_allowed_path()),
    # that is a real bug pattern, not adequate sanitization, so it must
    # not suppress a match.
    semgrep_sanitizer_patterns=("path.resolve(...)", "fs.realpathSync(...)", "path.relative(...)"),
    sink_call_names=("fs.readFile", "fs.readFileSync", "fs.writeFile", "fs.writeFileSync",
                      "fs.unlink", "fs.unlinkSync", "fs.createReadStream",
                      "readFile", "readFileSync", "writeFile", "writeFileSync",
                      "unlink", "unlinkSync", "createReadStream"),
    strong_sanitizer_names=("path.resolve", "fs.realpathSync", "path.relative",
                             ".resolve", ".realpathSync", ".relative"),
    weak_sanitizer_names=(".startsWith",),
    remediation=(
        "Resolve the joined path with path.resolve()/fs.realpathSync() and verify containment "
        "(e.g. via path.relative() not starting with '..' and not itself absolute) against the "
        "intended base directory before using it. A bare .startsWith(base) check is not real "
        "containment -- '/base-evil' starts with '/base' as a string but is a sibling "
        "directory, not a child."
    ),
)

_SSRF_JS = _VulnClass(
    rule_id="TAINT-SSRF",
    title=_SSRF.title,
    severity=_SSRF.severity,
    cvss=_SSRF.cvss,
    semgrep_sink_patterns=(
        "fetch($CMD)",
        "fetch($CMD, ...)",
        "axios.get($CMD)",
        "axios.get($CMD, ...)",
        "axios.post($CMD, ...)",
        "http.request($CMD, ...)",
        "https.request($CMD, ...)",
        "http.get($CMD, ...)",
        "https.get($CMD, ...)",
    ),
    # Same guard vocabulary as the Python SSRF class's own comment
    # (SRC-011/SRC-023), spelled camelCase since that's the JS/TS norm --
    # kept alongside the snake_case forms too, since real repos vary.
    semgrep_sanitizer_patterns=(
        "validateUrl(...)", "checkSsrf(...)", "isSafeUrl(...)", "isSsrfSafe(...)",
        "validateHost(...)", "validateTarget(...)", "ssrfGuard(...)",
        "validate_url(...)", "check_ssrf(...)", "is_safe_url(...)", "is_ssrf_safe(...)",
        "validate_host(...)", "validate_target(...)", "ssrf_guard(...)",
    ),
    sink_call_names=("fetch", "axios.get", "axios.post", "http.request", "https.request",
                      "http.get", "https.get"),
    strong_sanitizer_names=("validateUrl", "checkSsrf", "isSafeUrl", "isSsrfSafe", "validateHost",
                             "validateTarget", "ssrfGuard", "validate_url", "check_ssrf",
                             "is_safe_url", "is_ssrf_safe", "validate_host", "validate_target",
                             "ssrf_guard"),
    weak_sanitizer_names=(),
    remediation=_SSRF.remediation,
)

# --------------------------------------------------------------------------
# TAINT-CREDFWD (JS/TS port). Same two-condition sink concept as the Python
# _CREDFWD above (destination-tainted outbound call THAT ALSO attaches a
# server-held credential on the SAME call), ported to JS/TS's actual HTTP
# -call shapes -- validated for real against the confirmed instance this
# whole class generalizes from: huggingface/hf-mcp-server, GHSA-6w92-f47f
# -5xx8 (see round44-official-orgs-findings/01-huggingface-hf-mcp-server
# -gradio-space-token-forwarding.md and bench/MILESTONE_CREDFWD_JS_STATUS.md
# for the full validation record).
#
# Real shape this rule generalizes from, and WHY a plain port of the Python
# rule's two literal-call forms (direct-literal / two-statement headers
# dict) is not enough on its own: hf-mcp-server's actual bug does not go
# through a literal fetch()/axios call at either of its two real call
# sites at all.
#
#   1. `invoke.ts:91`: `callGradioToolWithHeaders(mcpUrl, tool.name,
#      finalParameters, hfToken, {...})` -- `mcpUrl` (destination, tainted
#      from the tool's own `space_name` argument several statements
#      earlier in the SAME function) and `hfToken` (the server's held
#      credential) are both passed as ordinary POSITIONAL ARGUMENTS to a
#      project-specific WRAPPER function, not to `fetch`/`axios` directly,
#      and not inside a `headers=` dict at this call site at all -- the
#      header dict is built one function further in, invisible to this
#      exact call. The task's own framing names this precisely: "a wrapper
#      function is called with both a URL-shaped param and a
#      credential-shaped param, not just literal fetch/axios calls."
#   2. `gradio-caller.ts:190-206` (inside that same wrapper,
#      `callGradioToolWithHeaders`): the credential dict IS built here
#      (`customHeaders = {'X-HF-Authorization': ...}`), but it is attached
#      to a `transportOptions` object via a SEPARATE property assignment
#      (`transportOptions.requestInit = {headers: customHeaders}`) inside an
#      `if (hfToken)` block, and the destination is only actually dispatched
#      three statements later, OUTSIDE that block, via `new
#      StreamableHTTPClientTransport(validatedMcpUrl, transportOptions)` --
#      a constructor call, not a bare function call.
#
# Three sink alternatives below, each empirically validated (semgrep run
# directly, not guessed) against the REAL cloned hf-mcp-server source at the
# exact commit this campaign's report cites
# (0511479ee95230c6f9181c3e7f3b8f77751b6390):
#
#   (a) The Python rule's own literal-call idioms (inline headers object,
#       and the two-statement "$HVAR = $HDICT; ...; call(..., headers:
#       $HVAR, ...)" form for when the dict is built one statement earlier),
#       ported to fetch/axios.get/axios.post/http.request/https.request,
#       with `{..., headers: $HDICT, ...}` (not a bare `{headers: $HDICT}`)
#       so an options object with other real-world keys (`method`, `body`,
#       ...) around `headers` still matches -- confirmed necessary
#       empirically, a bare-object pattern only matches an object with
#       EXACTLY that one key. This alternative catches the "common case"
#       this project's other JS/TS classes already target: the bug is
#       fully contained inside one recognized MCP tool handler's own
#       function. It does NOT catch hf-mcp-server's real bug (neither of
#       hf-mcp-server's two real call sites is a literal fetch/axios call)
#       -- included for the case where a DIFFERENT real target puts this
#       exact bug directly in a handler, the same way TAINT-SSRF's own
#       literal sink patterns are still useful even though this milestone's
#       one named target needs more.
#   (b) The generic "wrapper function" sink this task explicitly asks for:
#       `$FUNC($CMD, ..., $CRED, ...)` -- ANY function name, not a fixed
#       list, with $CMD required by a SEPARATE metavariable-regex to be an
#       identifier/member-expression whose own TEXT looks
#       destination-shaped (url/uri/endpoint/address/host/target/dest) and
#       $CRED required to look credential-shaped (token/auth/bearer/secret/
#       api[-_]?key/credential) by name, in addition to $CMD's usual taint
#       -sourced requirement (focus-metavariable). This exact shape is what
#       catches `invoke.ts:91` -- confirmed directly.
#
#       The $CMD name-regex was added AFTER finding, empirically, that
#       without it this pattern also fired on `fetchSpaceMetadata(spaceName,
#       hfToken)` and `fetchGradioSchema(metadata.subdomain, metadata.private,
#       hfToken)` one and two lines above the real bug in the same
#       function -- both structurally identical two-argument-plus-token
#       calls, but NEITHER is the vulnerable call (their own token handling
#       is correctly gated inside `space-http.ts`, per the campaign report's
#       own "Attribution" section). Requiring $CMD's own name to look
#       destination-shaped (matches "mcpUrl", not "spaceName" or
#       "metadata.subdomain") removed both false hits with no loss on the
#       real target. This is a real, structural precision cost worth
#       stating plainly: this alternative fires on CALL-SITE SHAPE alone
#       (a taint-sourced destination-named argument plus a
#       credential-named argument passed to the same call), not on proof
#       the callee actually forwards the credential unconditionally --
#       see MILESTONE_CREDFWD_JS_STATUS.md's own "known limitations"
#       section for what a real generalization of this alternative would
#       need (some notion of "and the callee doesn't gate on a
#       privacy/trust flag first", which is interprocedural and out of
#       scope for semgrep OSS's intra-procedural taint mode).
#   (c) A narrower, purpose-built chain for hf-mcp-server's OTHER real call
#       site, `gradio-caller.ts`'s own `new StreamableHTTPClientTransport(...)`
#       construction: `if ($COND) { ...; $HVAR = $HDICT; ...; $OPTS.$FIELD =
#       {..., headers: $HVAR, ...}; ... } ...; new $CLASS($CMD, $OPTS)`.
#       Needed because semgrep's sequential `...` operator does not cross an
#       `if` block boundary on its own -- confirmed empirically: a flat
#       3-statement `$HVAR = $HDICT; ...; $OPTS.$FIELD = {...}; ...; new
#       $CLASS(...)` pattern (no explicit `if` wrapper) matched a synthetic
#       fixture with the same three statements at the SAME nesting level,
#       but produced zero matches against the real file, where the first two
#       statements sit one level deeper inside `if (hfToken) { ... }`.
#       Explicitly modeling that `if` wrapper in the pattern itself (still
#       with $COND unconstrained -- any condition) fixed it, confirmed
#       directly against the real file (fires exactly on
#       `gradio-caller.ts:190-206`, the exact block the campaign report
#       cites as "not gated at all"). This alternative is the most
#       tailored to this one real target's own literal code shape of the
#       three -- see MILESTONE_CREDFWD_JS_STATUS.md for an honest
#       assessment of how far it generalizes.
#
# Sanitizer vocabulary is the SAME as TAINT-SSRF-JS's, for the same reason
# the Python CREDFWD's is the same as TAINT-SSRF's: the actual fix is a
# destination-trust gate before attaching the credential.
#
# Split into TWO sink constants, not one, after the false-positive sweep
# (see MILESTONE_CREDFWD_JS_STATUS.md) found the wrapper-call alternative
# (b) has a real, demonstrated false-positive class the other two
# alternatives do not share: a shared, legitimate "make an authenticated
# API request" helper (`makeXRequest(url, token, options)`) is a common,
# GOOD real-world pattern, and this alternative cannot tell "the URL's
# HOST is tool-controlled" (hf-mcp-server's real bug) apart from "only a
# PATH SUFFIX on an otherwise-fixed, safe base URL is tool-controlled" (the
# demonstrated false-positive shape) -- semgrep taint mode proves
# reachability, not WHERE in the string a tainted value lands. Confirmed
# directly against doit-mcp-server (part of this milestone's own
# false-positive sweep): every one of its 25+ `makeDoitRequest(url, token,
# ...)` call sites fires this alternative, and every one is the SAME safe
# shape -- `url` built as `${FIXED_BASE_CONSTANT}/${taintedResourceId}`,
# never a tool-controlled host. Alternatives (a) and (c) do not share this
# problem: both require an ACTUAL credential-bearing header object
# (`headers: {...}` matching real Authorization/token vocabulary) rather
# than just an argument NAME that sounds credential-shaped, which is a
# much rarer, more specific real-world shape than "this wrapper takes a
# token parameter" -- see this class's own module comment above for the
# empirical basis of that split. Kept as two separate sink constants (and
# two separate `_VulnClass` entries below, `_CREDFWD_JS` and
# `_CREDFWD_JS_WRAPPER`, sharing the same rule_id/title/severity) so the
# wrapper-call alternative's findings can be stamped with a lower
# `confidence` and an explicit caveat, without touching alternatives (a)/(c)
# at all.
_CREDFWD_JS_SINK_YAML = """\
  pattern-sinks:
    - patterns:
        - pattern-either:
            - pattern: |
                $HVAR = $HDICT
                ...
                fetch($CMD, {..., headers: $HVAR, ...})
            - pattern: |
                fetch($CMD, {..., headers: $HDICT, ...})
            - pattern: |
                $HVAR = $HDICT
                ...
                axios.get($CMD, {..., headers: $HVAR, ...})
            - pattern: |
                axios.get($CMD, {..., headers: $HDICT, ...})
            - pattern: |
                $HVAR = $HDICT
                ...
                axios.post($CMD, {..., headers: $HVAR, ...})
            - pattern: |
                axios.post($CMD, {..., headers: $HDICT, ...})
            - pattern: |
                $HVAR = $HDICT
                ...
                http.request($CMD, {..., headers: $HVAR, ...})
            - pattern: |
                http.request($CMD, {..., headers: $HDICT, ...})
            - pattern: |
                $HVAR = $HDICT
                ...
                https.request($CMD, {..., headers: $HVAR, ...})
            - pattern: |
                https.request($CMD, {..., headers: $HDICT, ...})
        - metavariable-regex:
            metavariable: $HDICT
            regex: (?is).*(authorization|bearer|api[_-]?key|apikey|x-api-key|access[_-]?token|secret).*
        - focus-metavariable: $CMD
    - patterns:
        - pattern: |
            if ($COND) {
              ...
              $HVAR = $HDICT
              ...
              $OPTS.$FIELD = {..., headers: $HVAR, ...}
              ...
            }
            ...
            new $CLASS($CMD, $OPTS)
        - metavariable-regex:
            metavariable: $HDICT
            regex: (?is).*(authorization|bearer|api[_-]?key|apikey|x-api-key|access[_-]?token|secret).*
        - focus-metavariable: $CMD
"""

# Alternative (b) alone, kept separate for the confidence/caveat split
# explained above. Only ever combined with the "any function parameter"
# source (see `_CREDFWD_JS_WRAPPER` below) -- not added to the standard
# per-entrypoint rule at all, since a wrapper call inside an already
# -recognized MCP handler's own function is exactly as likely to hit the
# same fixed-base-URL false-positive shape as the any-fn variant is.
_CREDFWD_JS_WRAPPER_SINK_YAML = """\
  pattern-sinks:
    - patterns:
        - pattern: |
            $FUNC($CMD, ..., $CRED, ...)
        - metavariable-regex:
            metavariable: $CRED
            regex: (?i).*(token|auth|bearer|secret|api[_-]?key|credential).*
        - metavariable-regex:
            metavariable: $CMD
            regex: (?i).*(url|uri|endpoint|address|host|target|dest).*
        - focus-metavariable: $CMD
"""

_CREDFWD_JS = _VulnClass(
    rule_id="TAINT-CREDFWD",
    title=_CREDFWD.title,
    severity=_CREDFWD.severity,
    cvss=_CREDFWD.cvss,
    semgrep_sink_patterns=(),  # unused -- semgrep_sink_yaml above is this class's sink
    semgrep_sanitizer_patterns=_SSRF_JS.semgrep_sanitizer_patterns,
    sink_call_names=("fetch", "axios.get", "axios.post", "http.request", "https.request"),
    strong_sanitizer_names=_SSRF_JS.strong_sanitizer_names,
    weak_sanitizer_names=(),
    remediation=_CREDFWD.remediation,
    semgrep_sink_yaml=_CREDFWD_JS_SINK_YAML,
)

_CREDFWD_JS_WRAPPER = _VulnClass(
    rule_id="TAINT-CREDFWD",
    title=_CREDFWD.title,
    severity=_CREDFWD.severity,
    cvss=_CREDFWD.cvss,
    semgrep_sink_patterns=(),
    semgrep_sanitizer_patterns=_SSRF_JS.semgrep_sanitizer_patterns,
    sink_call_names=(),  # sink is a dynamic $FUNC(...) call, not a fixed name list
    strong_sanitizer_names=_SSRF_JS.strong_sanitizer_names,
    weak_sanitizer_names=(),
    remediation=_CREDFWD.remediation,
    semgrep_sink_yaml=_CREDFWD_JS_WRAPPER_SINK_YAML,
    confidence_override="medium",
    extra_caveat=(
        "This finding matched the GENERIC 'a wrapper function is called with both a "
        "destination-shaped and a credential-shaped argument' shape, not a literal "
        "Authorization/token header -- it cannot distinguish a genuinely tool-controlled "
        "DESTINATION HOST (the real, confirmed hf-mcp-server bug this shape generalizes "
        "from) from a tool-controlled PATH SUFFIX appended to an otherwise-fixed, safe base "
        "URL (a common, legitimate 'shared authenticated API-request helper' pattern -- "
        "confirmed as this exact false-positive shape against a real target during this "
        "class's own validation; see MILESTONE_CREDFWD_JS_STATUS.md). Read the destination "
        "argument's own construction before treating this as a confirmed issue."
    ),
)

_VULN_CLASSES_JS: tuple[_VulnClass, ...] = (_CMDI_JS, _PATH_TRAVERSAL_JS, _SSRF_JS, _CREDFWD_JS)


# --------------------------------------------------------------------------
# Kotlin vulnerability-class catalog (Kotlin-support milestone). Same 3 hard
# -sink classes as Python's/JS's own (rule_id/title/severity/cvss/
# remediation unchanged -- this is the same conceptual vulnerability
# regardless of language), with Kotlin-shaped semgrep patterns. Real
# per-pattern validation: each sink/sanitizer pattern below was run directly
# (semgrep, taint mode, against a real or hand-written Kotlin fixture -- not
# guessed from Java/Kotlin API docs alone) before being kept -- see
# bench/KOTLIN_SUPPORT_STATUS.md for the individual pattern-by-pattern
# record, including two patterns that were TRIED and DROPPED after testing
# empirically produced zero matches: `ProcessBuilder($CMD, ...)` alone
# (misses the common `ProcessBuilder("sh", "-c", $CMD)` vararg shape, where
# the tainted value is the LAST argument, not the first -- unlike Python's
# `subprocess.run($CMD, ...)`, so `ProcessBuilder(..., $CMD)` is ALSO listed
# below, not a replacement) and a leading-dot `.uri(URI.create($CMD))`
# chained-builder pattern (semgrep's generic "any receiver" leading-dot
# pattern, used without incident by the Python/JS classes' own
# `.resolve`/`.is_relative_to`/`.startsWith` sanitizers, produced zero
# matches for a KOTLIN call pattern in this semgrep version -- worked around
# by sinking on the un-chained `URI.create($CMD)` construction itself
# instead, which is reached by taint identically regardless of which
# builder-chain method it is later passed into).
#
# No Stage 3 path-reconstruction port exists for Kotlin (see
# `reconstruct_path_kotlin` below) -- this milestone's own stated scope is
# "basic" taint/sink rules, not the full statement-order, sanitizer-
# annotating walk `reconstruct_path`/`reconstruct_path_js` do. No
# TAINT-CREDFWD or TAINT-IDOR port either -- neither was in this
# milestone's scope and neither has a real, validated Kotlin target the way
# CMDI/PATHTRAV/SSRF now do (JetBrains/teamcity-mcp).
# --------------------------------------------------------------------------

_CMDI_KOTLIN = _VulnClass(
    rule_id="TAINT-CMDI",
    title=_CMDI.title,
    severity=_CMDI.severity,
    cvss=_CMDI.cvss,
    semgrep_sink_patterns=(
        "ProcessBuilder($CMD)",
        "ProcessBuilder($CMD, ...)",
        "ProcessBuilder(..., $CMD)",
        "Runtime.getRuntime().exec($CMD)",
        "Runtime.getRuntime().exec($CMD, ...)",
    ),
    # No sanitizer patterns: same reasoning as _CMDI_JS's own comment --
    # there is no standard Kotlin/Java "make this shell-safe" call worth
    # trusting blindly. The real fix (an argv-list ProcessBuilder with no
    # shell wrapper at all) isn't a sanitizer that clears a match; it's
    # simply not one of the sink patterns above.
    semgrep_sanitizer_patterns=(),
    sink_call_names=("ProcessBuilder", "Runtime.getRuntime().exec", "exec"),
    strong_sanitizer_names=(),
    weak_sanitizer_names=(),
    remediation=(
        "Never build a shell string from tool input. Pass each argument as its own "
        "ProcessBuilder element (never a single interpolated 'sh -c ...' string), and never "
        "route through Runtime.exec(String) with a concatenated command line."
    ),
)

_PATH_TRAVERSAL_KOTLIN = _VulnClass(
    rule_id="TAINT-PATHTRAV",
    title=_PATH_TRAVERSAL.title,
    severity=_PATH_TRAVERSAL.severity,
    cvss=_PATH_TRAVERSAL.cvss,
    semgrep_sink_patterns=(
        "File($CMD)",
        "File($CMD, ...)",
        "Files.readAllBytes($CMD)",
        "Files.newInputStream($CMD)",
        "Files.newInputStream($CMD, ...)",
    ),
    # Deliberately NOT including a bare $V.startsWith(base) check here --
    # same reasoning as the Python/JS classes' own module comments: that is
    # a real bug pattern (a string-prefix check, not real containment), not
    # adequate sanitization, so it must not suppress a match.
    semgrep_sanitizer_patterns=("$V.normalize()", "$V.toRealPath()"),
    sink_call_names=("File", "Files.readAllBytes", "Files.newInputStream"),
    strong_sanitizer_names=(".normalize", ".toRealPath"),
    weak_sanitizer_names=(".startsWith",),
    remediation=(
        "Resolve the joined path with Path.normalize()/toRealPath() and verify containment "
        "against the intended base directory before using it. A bare $path.startsWith(base) "
        "check is not real containment -- '/base-evil' starts with '/base' as a string but is "
        "a sibling directory, not a child."
    ),
)

_SSRF_KOTLIN = _VulnClass(
    rule_id="TAINT-SSRF",
    title=_SSRF.title,
    severity=_SSRF.severity,
    cvss=_SSRF.cvss,
    semgrep_sink_patterns=(
        "URL($CMD).openConnection()",
        "URL($CMD).openStream()",
        # Sinks on the URI CONSTRUCTION itself, not the later builder chain
        # it's passed into (HttpRequest.newBuilder(...)/.uri(...)) -- see
        # this section's own module comment above for why the chained form
        # was tried and dropped. Taint reaches this identically regardless
        # of which java.net.http.HttpClient builder call the URI is later
        # passed into.
        "URI.create($CMD)",
    ),
    semgrep_sanitizer_patterns=(
        "validateUrl(...)", "checkSsrf(...)", "isSafeUrl(...)", "isSsrfSafe(...)",
        "validateHost(...)", "validateTarget(...)", "ssrfGuard(...)",
        "validate_url(...)", "check_ssrf(...)", "is_safe_url(...)", "is_ssrf_safe(...)",
        "validate_host(...)", "validate_target(...)", "ssrf_guard(...)",
    ),
    sink_call_names=("URL", "URI.create"),
    strong_sanitizer_names=("validateUrl", "checkSsrf", "isSafeUrl", "isSsrfSafe", "validateHost",
                             "validateTarget", "ssrfGuard", "validate_url", "check_ssrf",
                             "is_safe_url", "is_ssrf_safe", "validate_host", "validate_target",
                             "ssrf_guard"),
    weak_sanitizer_names=(),
    remediation=_SSRF.remediation,
)

_VULN_CLASSES_KOTLIN: tuple[_VulnClass, ...] = (_CMDI_KOTLIN, _PATH_TRAVERSAL_KOTLIN, _SSRF_KOTLIN)


# --------------------------------------------------------------------------
# TAINT-CREDFWD-JS's second, additive source variant: "any function's own
# parameter", not just a recovered MCP entrypoint's. Needed because
# `_VULN_CLASSES_JS`'s standard per-entrypoint rule (via `_source_block_js`,
# scoped with `paths: include:` to exactly the file a real entrypoint was
# recovered in) cannot reach hf-mcp-server's real bug at all: neither
# `invoke.ts`'s `invokeSpace()` nor `gradio-caller.ts`'s
# `callGradioToolWithHeaders()` is itself a recognized MCP entrypoint (no
# `registerTool`/`tool`/`setRequestHandler` call exists in either file --
# both are internal helpers, one and two calls away from the actual
# `dynamic_space` tool handler in `dynamic-space-tool.ts`). This is the
# SAME real-world "handler file vs. shared client/utility module" split
# `MILESTONE_2_STATUS.md` already documents as this pipeline's dominant
# real-world limiting factor for the three original hard-sink classes --
# but for THIS class specifically, both real sink functions still have
# their own relevant parameter (`mcpUrl`/`spaceName`-derived in
# `invokeSpace`, `mcpUrl`/`hfToken` directly in `callGradioToolWithHeaders`)
# in scope, so the fix here does not require chasing a call graph across
# files at all -- it only requires NOT limiting the taint SOURCE to a
# recovered top-level entrypoint's parameter, and instead treating ANY
# function's own formal parameters (named or anonymous-assigned-to-a-const,
# sync or async, exported or not) as a source, for this class only.
#
# Why only this class, not CMDI/PATHTRAV/SSRF too: those three classes'
# sinks are common enough on their own (any raw exec/file-open/HTTP-fetch
# call) that sourcing from "any function parameter, anywhere in the repo"
# would flood real, unrelated code with findings -- entrypoint-scoping
# exists specifically to make those three classes usable at all (see
# `generate_taint_rule_yaml`'s own docstring, ahujasid/blender-mcp). This
# class's sink is structurally different: EVERY alternative in
# `_CREDFWD_JS_SINK_YAML` already requires a two-condition combination
# (destination reachable from a parameter, AND a credential-shaped value
# attached in the SAME call/statement chain) that is inherently much rarer
# in ordinary code than a bare HTTP call alone -- the same reasoning that
# already justifies the Python `_CREDFWD` class's own narrow sink design.
# Broadening only the SOURCE side for this one class, while keeping every
# other class's source scoped to real recovered entrypoints, is the
# deliberate tradeoff being made here; see
# `bench/MILESTONE_CREDFWD_JS_STATUS.md` for the false-positive sweep this
# tradeoff was actually checked against, not just asserted.
#
# Deliberately covers only the handful of common named-function shapes
# real code actually uses for this kind of internal helper (plain/async
# function declarations, each with or without a leading `export`) -- not
# every possible JS/TS function-definition syntax (arrow-const, class
# methods, generators). Both of hf-mcp-server's real sink functions
# (`invokeSpace`, `callGradioToolWithHeaders`) are `export async
# function`s, matched by the fourth alternative below; the other three are
# kept for the same shapes' non-exported/non-async variants, which are
# common enough elsewhere to be worth the negligible extra cost of one more
# `pattern-inside` alternative. A real target using an arrow function or a
# class method for this kind of helper is a known, stated gap -- adding
# those shapes is a small, mechanical follow-up, not attempted here to keep
# this rule's own footprint minimal (this project's own "minimum code that
# solves the validated problem" discipline).
_CREDFWD_JS_ANY_FUNCTION_SOURCE_YAML = """\
  pattern-sources:
    - patterns:
        - pattern-either:
            - pattern-inside: |
                function $FN(..., $P, ...) { ... }
            - pattern-inside: |
                async function $FN(..., $P, ...) { ... }
            - pattern-inside: |
                export function $FN(..., $P, ...) { ... }
            - pattern-inside: |
                export async function $FN(..., $P, ...) { ... }
        - pattern: $P
"""


def generate_credfwd_any_fn_rule_yaml_js() -> str:
    """The JS/TS `TAINT-CREDFWD` class's second and third rules: the SAME
    two sinks (`_CREDFWD_JS_SINK_YAML`, `_CREDFWD_JS_WRAPPER_SINK_YAML`) the
    standard per-entrypoint rule and the wrapper-only rule already use, but
    BOTH sourced from ANY function's own parameters (see this module's own
    comment above `_CREDFWD_JS_ANY_FUNCTION_SOURCE_YAML` for why only this
    one class gets this broader source) rather than a recovered MCP
    entrypoint's. Kept as two separate rule ids (not merged into one
    `pattern-sinks:` list) specifically so `run_static_taint_scan()` can
    map each back to its own `_VulnClass` (`_CREDFWD_JS` vs.
    `_CREDFWD_JS_WRAPPER`) and stamp the wrapper-call hits with their own
    lower confidence and caveat -- see `_CREDFWD_JS_WRAPPER`'s own comment
    for why that split exists. Unlike every other rule generator in this
    file, this one takes no `entrypoints`/`root` argument and always
    returns two rules -- it does not depend on Stage 1 having recovered
    anything at all, and neither rule is scoped to any one file via
    `paths: include:` (semgrep's own `languages: [javascript, typescript]`
    filter already restricts both to JS/TS files across the whole scanned
    tree). Always run in ADDITION to, never instead of, the standard
    entrypoint-sourced rule -- see `run_static_taint_scan()`, which merges
    these rules' raw semgrep hits with the standard JS/TS pass's own before
    deduplicating, so a location more than one rule agrees on is still
    reported once, not twice.
    """
    high_confidence_rule = (
        "- id: taint-credfwd-js-anyfn-0\n"
        "  mode: taint\n"
        "  languages: [javascript, typescript]\n"
        "  severity: ERROR\n"
        f'  message: "MCP handler parameter reaches a {_CREDFWD_JS.title.split(" ")[-1]}"\n'
        f"{_CREDFWD_JS_ANY_FUNCTION_SOURCE_YAML}"
        f"{_CREDFWD_JS.semgrep_sink_yaml}"
        f"{_sanitizer_block(_CREDFWD_JS)}"
    )
    wrapper_rule = (
        "- id: taint-credfwd-js-anyfn-wrapper-0\n"
        "  mode: taint\n"
        "  languages: [javascript, typescript]\n"
        "  severity: ERROR\n"
        f'  message: "MCP handler parameter reaches a {_CREDFWD_JS_WRAPPER.title.split(" ")[-1]}"\n'
        f"{_CREDFWD_JS_ANY_FUNCTION_SOURCE_YAML}"
        f"{_CREDFWD_JS_WRAPPER.semgrep_sink_yaml}"
        f"{_sanitizer_block(_CREDFWD_JS_WRAPPER)}"
    )
    return "rules:\n" + high_confidence_rule + "\n" + wrapper_rule


# --------------------------------------------------------------------------
# Go vulnerability-class catalog (Milestone: go-taint-work). Same 3
# hard-sink classes as the Python/JS catalogs above (CMDI/PATHTRAV/SSRF; no
# Go port of CREDFWD/IDOR yet -- out of this milestone's scope), same
# rule_id/title/severity/cvss/remediation shape as their Python/JS
# counterparts (this is the same conceptual vulnerability regardless of
# language), Go-shaped semgrep sink patterns and sanitizer vocabulary.
# --------------------------------------------------------------------------

_CMDI_GO = _VulnClass(
    rule_id="TAINT-CMDI",
    title=_CMDI.title,
    severity=_CMDI.severity,
    cvss=_CMDI.cvss,
    # Deliberately NOT `exec.Command($CMD, ...)`/`exec.CommandContext($CTX,
    # $CMD, ...)` (a tainted-anywhere-in-the-argv-list form) -- tried first,
    # then dropped after an empirical finding while validating this rule
    # against the real DataDog/datadog-agent source (see
    # bench/GO_TAINT_RULES_STATUS.md): semgrep's `focus-metavariable` only
    # changes WHICH part of a match is reported, not WHICH part must
    # actually carry the taint -- confirmed directly against a minimal
    # reproduction (`func runIt(fixedBin string, args []string) {
    # exec.Command(fixedBin, args...) }`, where only `args` is a tainted
    # parameter and `fixedBin` is not): `exec.Command($CMD, ...)` with
    # `focus-metavariable: $CMD` still fired, reported AT `fixedBin`'s
    # location, purely because SOME tainted value (`args`, absorbed by the
    # trailing `...`) appeared somewhere in the overall matched call. Since
    # Go's `exec.Command` does NOT invoke a shell unless the program itself
    # IS a shell (see the `"sh", "-c"` forms below), a tainted trailing argv
    # ELEMENT reaching a fixed, untainted program name is the SAFE,
    # recommended Go idiom (this project's own Python CMDI class has an
    # explicit test for the identical concept:
    # `test_argv_list_form_without_shell_true_is_not_flagged`) -- and the
    # dropped pattern produced exactly this false-positive shape for real,
    # unmodified code (`datadog-agent/cmd/agent/subcommands/integrations/
    # command.go:324`: `exec.Command(pythonPath, args...)`, where
    # `pythonPath` is NOT tainted and `args` is, a safe call incorrectly
    # flagged). The two forms kept below instead -- an explicit "sh"/"bash"
    # -c shell-invocation (no "..." at all: $CMD is the exact, only
    # shell-command-string argument, so there is no other position for
    # unrelated taint to leak in through) and a bare SINGLE-argument
    # `exec.Command($CMD)`/`exec.CommandContext($CTX, $CMD)` (also no
    # "...": the entire program name IS the one argument, a real, bounded,
    # narrower "tool parameter picks the whole binary" shape, confirmed
    # against a real match in DataDog/datadog-agent's own
    # `selftestExec` -- see the status doc) -- both avoid this ambiguity
    # entirely, at the cost of not catching a tainted program name that
    # ALSO has additional fixed or tainted trailing arguments (e.g.
    # `exec.Command(params.path, someArg)`) -- a real, honestly-stated scope
    # limit, not hidden.
    semgrep_sink_patterns=(
        'exec.Command("sh", "-c", $CMD)',
        'exec.Command("bash", "-c", $CMD)',
        'exec.CommandContext($CTX, "sh", "-c", $CMD)',
        'exec.CommandContext($CTX, "bash", "-c", $CMD)',
        "exec.Command($CMD)",
        "exec.CommandContext($CTX, $CMD)",
    ),
    # No sanitizer patterns: same reasoning `_CMDI_JS`'s own comment already
    # states -- there is no standard Go "make this shell-safe" call worth
    # trusting blindly (no Go stdlib equivalent of Python's shlex.quote()).
    # The task's own stated fix for this class -- passing arguments as
    # separate exec.Command(name, args...) elements with no shell in
    # between -- isn't a sanitizer that CLEARS a match; it simply never
    # matches either sink pattern above at all (no "sh"/"bash" -c, and more
    # than one argument), the same "not one of the sink patterns to begin
    # with" reasoning `_CMDI_JS` already documents for its own argv-form
    # case.
    semgrep_sanitizer_patterns=(),
    sink_call_names=("exec.Command", "exec.CommandContext"),
    strong_sanitizer_names=(),
    weak_sanitizer_names=(),
    remediation=(
        'Never build a shell command string from tool input and pass it to "sh"/"bash" -c. '
        "Pass the program name and each argument as separate exec.Command(name, args...) "
        "elements with no shell in between, and never let a tool parameter choose the "
        "program name itself."
    ),
)

# v10 small-fixes milestone (bug 3): TAINT-PATHTRAV-GO's sink catalog was
# too narrow -- only a value flowing DIRECTLY into os.Open/os.ReadFile/
# ioutil.ReadFile as the sole argument matched, missing the real confirmed
# datadog-labs/datadog-code-security-mcp bug (`internal/sbom/generator.go`'s
# `ensurePath()`): `fullPath := filepath.Join(args.WorkingDir, args.Path)`
# then `os.Stat(fullPath)`, with NO containment check anywhere in the
# function. `os.Stat` itself was simply missing from the sink list --
# confirmed empirically (not assumed) that semgrep's default taint-mode
# propagation already carries taint through a `filepath.Join(...)`
# assignment with no special-casing needed, so no dedicated "Join-then-sink"
# pattern shape is needed once `os.Stat` is a recognized sink; a plain
# `os.Stat($CMD)` addition to the flat sink-pattern list, run directly
# against the real `generator.go` source, fires on the real vulnerable line
# (`ensurePath`'s `os.Stat(fullPath)`).
#
# The real false-positive risk widening the sink list this way creates:
# this SAME repo's sibling function, `internal/scan/scan.go`'s
# `validateFilePaths` -- the disclosure report's own cited "correctly-
# guarded" contrast to `ensurePath` -- also calls `os.Stat` on a
# `filepath.Join`-derived path, and neither Go PATHTRAV sanitizer tuple
# below can suppress it: empirically confirmed (not assumed) that a bare
# `pattern-sanitizers` entry for `filepath.Rel(...)`/`strings.HasPrefix(...)`
# does NOT clear taint here, even in a synthetic reproduction where the
# check runs BEFORE the sink -- Go's real containment idiom checks a
# DIFFERENT, newly-computed variable (`rel`) than the one that reaches the
# sink (`fullPath`/`target` itself, unchanged), so semgrep's standard
# "sanitizer wraps/transforms the tainted value" model (the same model that
# already makes `os.path.realpath(...)`/`.resolve()` work for Python/JS)
# cannot express it -- exactly the gap `strong_sanitizer_names`' own comment
# below already documented BEFORE this fix ("a multi-statement idiom, not a
# single trusted call this module could list here"). Since this is a
# sink-shape `_sink_block()`'s flat pattern-either + one shared
# focus-metavariable cannot express -- the same "needs the semgrep_sink_yaml
# escape hatch" situation TAINT-CREDFWD/TAINT-SSRF-GO's own comments already
# document -- this class uses that SAME existing escape hatch (reusing the
# established structure, not inventing a new `_VulnClass` field) to add a
# `pattern-not-inside` guard: a match is suppressed only when the SAME
# enclosing function ALSO contains, anywhere in its body (order-independent
# -- Go's idiom doesn't reliably run the check immediately before the sink,
# confirmed against `scan.go`'s own ordering, check-after-Stat), a call to
# `filepath.Rel`/`strings.HasPrefix`/`strings.Contains` -- the exact
# vocabulary this class's own `remediation` text below already recommends.
# Validated directly (see bench/V10_SMALLFIXES_STATUS.md for the full
# before/after): fires on `generator.go`'s real `ensurePath` (which has NO
# such call anywhere in its body), does NOT fire on `scan.go`'s real
# `validateFilePaths` (which does, just positioned after the sink), and a
# same-function-scoped spot-check against fresh clones of digitalocean/doctl
# and DataDog/datadog-agent (the same two real codebases and commits used to
# validate the original Go taint rules) found zero regressions against the
# pre-widening sink list and zero spurious matches among the newly-surfaced
# `os.Stat` hits -- all real tainted-CLI-value-reaches-os.Stat flows, same
# "real flow, not an actual MCP vulnerability in a non-MCP-server codebase"
# caveat the original milestone's own 39 matches already carried.
#
# Two variants of this guard were tried and rejected before the one below,
# both for real, measured reasons rather than by inspection alone:
#   1. As 6 separate top-level `pattern-not-inside` entries (one per check
#      name x function form) instead of one nested `pattern-not-inside:
#      {pattern-either: [...]}` -- functionally identical, but measured to
#      roughly double this rule's own semgrep runtime and reintroduce this
#      project's already-documented per-rule-timeout non-determinism on a
#      large real file (`doctl/commands/kubernetes.go`, 1500+ lines) under a
#      multi-directory scan, silently dropping a real finding on some runs
#      and not others. The nested form below is functionally identical but
#      was empirically stable (3/3 identical runs on both spot-check repos)
#      and close to this rule's own pre-fix runtime.
#   2. Widening `strings.HasPrefix(...)`/`strings.Contains(...)` to also
#      match when embedded in an `if` CONDITION (Go's semgrep parser's `...`
#      ellipsis only matches a statement SEQUENCE, so a bare `func { ...
#      strings.HasPrefix(...) ... }` pattern does NOT match `if
#      strings.HasPrefix(x, "..") { ... }` at all -- confirmed empirically;
#      a deep-expression `<... X ...>` wrapped in an `if <...X...> { ... }`
#      statement pattern does reach it). Tried, and then reverted: run
#      against the real datadog-agent/cmd corpus, this over-matched on
#      `strings.HasPrefix`/`strings.Contains` calls that have NOTHING to do
#      with path containment -- real, confirmed false negatives introduced
#      by the widening, e.g. `cmd/agent/common/misconfig/mounts.go:74`'s
#      `os.Open(path)` finding was suppressed by an unrelated
#      `strings.HasPrefix(opt, "gid=")` mount-option check elsewhere in the
#      SAME function, and `cmd/system-probe/.../sysinfo_linux.go:319`'s
#      `os.ReadFile(environPath)` finding was suppressed by an unrelated
#      `strings.HasPrefix(env, "DD_SERVICE=")` environment-variable check --
#      both real, unmodified functions with zero actual path-containment
#      logic. It also reintroduced the SAME per-rule-timeout non-determinism
#      as variant 1 above, on a different large file
#      (`cmd/agent/common/import.go`, ~190-line function). Net effect: worse
#      precision AND worse reliability for a shape (`if
#      strings.HasPrefix(...)`/`if strings.Contains(...)`) that is common
#      for unrelated string checks and not reliably distinguishable from a
#      real containment check by call name alone.
#
# Net, STATED scope limit kept by the version below: `filepath.Rel(...)` is
# recognized regardless of how its result is subsequently used (it always
# appears as a bare assignment statement, `rel, err := filepath.Rel(...)`,
# structurally -- it returns two values, so it can never itself be written
# inline inside a boolean condition), but `strings.HasPrefix(...)`/
# `strings.Contains(...)` are only recognized in that SAME bare-assignment
# shape (`ok := strings.HasPrefix(...)`), not the arguably more common
# `if strings.HasPrefix(...) { ... }` inline-condition idiom -- an honest,
# deliberate gap given the measured precision/reliability cost above, not a
# silently-dropped case.
_PATH_TRAVERSAL_GO_SINK_YAML = """\
  pattern-sinks:
    - patterns:
        - pattern-either:
            - pattern: |
                os.Stat($CMD)
            - pattern: |
                os.Open($CMD)
            - pattern: |
                os.ReadFile($CMD)
            - pattern: |
                ioutil.ReadFile($CMD)
        - focus-metavariable: $CMD
        - pattern-not-inside:
            pattern-either:
              - pattern: |
                  func $ANYFN(...) {
                    ...
                    filepath.Rel(...)
                    ...
                  }
              - pattern: |
                  func $ANYFN(...) {
                    ...
                    strings.HasPrefix(...)
                    ...
                  }
              - pattern: |
                  func $ANYFN(...) {
                    ...
                    strings.Contains(...)
                    ...
                  }
              - pattern: |
                  func ($ARECV $ARTYPE) $ANYFN(...) {
                    ...
                    filepath.Rel(...)
                    ...
                  }
              - pattern: |
                  func ($ARECV $ARTYPE) $ANYFN(...) {
                    ...
                    strings.HasPrefix(...)
                    ...
                  }
              - pattern: |
                  func ($ARECV $ARTYPE) $ANYFN(...) {
                    ...
                    strings.Contains(...)
                    ...
                  }
"""

_PATH_TRAVERSAL_GO = _VulnClass(
    rule_id="TAINT-PATHTRAV",
    title=_PATH_TRAVERSAL.title,
    severity=_PATH_TRAVERSAL.severity,
    cvss=_PATH_TRAVERSAL.cvss,
    semgrep_sink_patterns=(),  # unused -- semgrep_sink_yaml below is this class's sink (see comment above)
    # Deliberately empty -- see weak_sanitizer_names below for why
    # filepath.Clean() is recognized but kept OUT of this tuple, the same
    # "recognized but does not clear" split the Python/JS PATHTRAV classes'
    # own weak_sanitizer_names (a bare .startswith()/.startsWith()) already
    # use for an inadequate-but-common real check.
    semgrep_sanitizer_patterns=(),
    sink_call_names=("os.Stat", "os.Open", "os.ReadFile", "ioutil.ReadFile"),
    # Deliberately empty, not just "not yet found" -- Go's stdlib has no
    # single-call containment check equivalent to Python's
    # os.path.commonpath()/JS's path.relative(): the real fix (see
    # remediation below) needs an explicit comparison AFTER resolving the
    # path (filepath.Rel() + checking the result doesn't start with "..",
    # or strings.HasPrefix() against a cleaned absolute base), which is a
    # multi-statement idiom, not a single trusted call this module could
    # list here. Still true after the v10 small-fixes milestone's own
    # semgrep-level `pattern-not-inside` guard (see
    # _PATH_TRAVERSAL_GO_SINK_YAML's own comment above) -- that guard
    # suppresses a semgrep MATCH directly; it is not expressed through this
    # tuple, and populating this tuple would not help Stage 3's own
    # narration either: reconstruct_path_go's strong_sanitizer_names
    # handling only recognizes a value-transforming ASSIGNMENT (`x :=
    # sanitizer(y)`) and clears the ASSIGNED name (`x`) -- but Go's real
    # containment idiom assigns the check's own boolean/derived result
    # (`rel`) to a DIFFERENT variable than the one that actually reaches the
    # sink (`fullPath`/`target`, unchanged), so marking filepath.Rel/
    # strings.HasPrefix/strings.Contains as a "strong sanitizer" here would
    # make Stage 3 narrate the wrong variable as cleared. Left empty and
    # explicitly re-confirmed, rather than populated for a superficial
    # parity with Python/JS that would actively mislead the evidence
    # narration.
    strong_sanitizer_names=(),
    # WEAK, not strong -- confirmed against the real documented behavior of
    # filepath.Clean(), not assumed: Go's own godoc for it says it
    # eliminates an inner ".." together with the non-".." element before
    # it, and eliminates a LEADING ".." only when it begins a ROOTED
    # (absolute) path. A still-relative path with a leading ".." is left
    # UNCHANGED by Clean() alone (filepath.Clean("../etc/passwd") ==
    # "../etc/passwd"), and even after joining against an absolute base,
    # enough leading ".." segments still walk past that base into its
    # parent directories -- Clean() only removes the ".." tokens lexically,
    # it does not verify the result stays inside any particular directory.
    # filepath.Clean() is nonetheless a very common REAL Go mistake
    # (reached for as if it were a containment check on its own), so it is
    # recognized here -- a future Go Stage 3 path-reconstruction can
    # annotate "an inadequate check was attempted" on it, the same way this
    # module's existing Stage 3 already does for Python's/JS's own weak
    # .startswith()/.startsWith() -- but, per this class's own
    # semgrep_sanitizer_patterns comment above, it must NOT suppress a
    # match.
    weak_sanitizer_names=("filepath.Clean",),
    remediation=(
        "Resolve the joined path and verify containment against the intended base directory "
        "AFTER resolving it -- e.g. filepath.Rel(base, target) and checking the result does not "
        'start with ".." and is not itself absolute, or strings.HasPrefix() against a '
        "filepath.Clean()'d absolute base -- before using it. filepath.Clean() alone is not a "
        'containment check: it only removes redundant "."/".." elements lexically and does not '
        "verify the result stays inside any particular directory."
    ),
    semgrep_sink_yaml=_PATH_TRAVERSAL_GO_SINK_YAML,
)

# SSRF's sink needs the semgrep_sink_yaml escape hatch (the same one
# TAINT-CREDFWD/TAINT-CREDFWD-JS above use): Go's own `http.Client.Do()`
# takes a `*http.Request`, not a URL string, so the real-world
# `http.NewRequest(method, url, body)` + `client.Do(req)` idiom needs a
# two-statement sequential pattern (`$REQ, $ERR = http.NewRequest(...); ...;
# $CLIENT.Do($REQ)`) that `_sink_block()`'s flat one-pattern-per-line join
# can't express, the same reason TAINT-CREDFWD's two-statement headers-dict
# form needed it. `http.Post()`'s three positional arguments (url,
# contentType, body -- confirmed against the real stdlib signature, it is
# NOT variadic) are all named as separate metavariables rather than a
# trailing "..." specifically to avoid the exact ambiguity documented on
# `_CMDI_GO` above (a "..." here could let an unrelated tainted `body`
# argument cause a report at $CMD's position even if the URL itself were
# fixed) -- confirmed unnecessary for `http.Get()`/`http.Head()` (both take
# exactly one argument in the real stdlib, so there is no "..." to begin
# with).
_SSRF_GO_SINK_YAML = """\
  pattern-sinks:
    - patterns:
        - pattern-either:
            - pattern: http.Get($CMD)
            - pattern: http.Head($CMD)
            - pattern: http.Post($CMD, $CONTENTTYPE, $BODY)
            - pattern: |
                $REQ, $ERR = http.NewRequest($METHOD, $CMD, $BODY)
                ...
                $CLIENT.Do($REQ)
            - pattern: |
                $REQ, $ERR = http.NewRequestWithContext($CTX, $METHOD, $CMD, $BODY)
                ...
                $CLIENT.Do($REQ)
        - focus-metavariable: $CMD
"""

_SSRF_GO = _VulnClass(
    rule_id="TAINT-SSRF",
    title=_SSRF.title,
    severity=_SSRF.severity,
    cvss=_SSRF.cvss,
    semgrep_sink_patterns=(),  # unused -- semgrep_sink_yaml above is this class's sink
    # Same guard vocabulary as the Python/JS SSRF classes' own comment
    # (SRC-011/SRC-023), spelled in the exported-PascalCase and
    # unexported-camelCase forms real Go code actually uses for either a
    # package-level function or a receiver method of either casing.
    semgrep_sanitizer_patterns=(
        "ValidateURL(...)", "validateURL(...)", "validateUrl(...)",
        "CheckSSRF(...)", "checkSSRF(...)", "checkSsrf(...)",
        "IsSafeURL(...)", "isSafeURL(...)", "isSafeUrl(...)",
        "IsSSRFSafe(...)", "isSSRFSafe(...)", "isSsrfSafe(...)",
        "ValidateHost(...)", "validateHost(...)",
        "ValidateTarget(...)", "validateTarget(...)",
        "SSRFGuard(...)", "ssrfGuard(...)",
    ),
    sink_call_names=("http.Get", "http.Head", "http.Post", "http.NewRequest", "http.NewRequestWithContext"),
    strong_sanitizer_names=(
        "ValidateURL", "validateURL", "validateUrl",
        "CheckSSRF", "checkSSRF", "checkSsrf",
        "IsSafeURL", "isSafeURL", "isSafeUrl",
        "IsSSRFSafe", "isSSRFSafe", "isSsrfSafe",
        "ValidateHost", "validateHost",
        "ValidateTarget", "validateTarget",
        "SSRFGuard", "ssrfGuard",
    ),
    weak_sanitizer_names=(),
    remediation=_SSRF.remediation,
    semgrep_sink_yaml=_SSRF_GO_SINK_YAML,
)

_VULN_CLASSES_GO: tuple[_VulnClass, ...] = (_CMDI_GO, _PATH_TRAVERSAL_GO, _SSRF_GO)


# --------------------------------------------------------------------------
# Go source, historical fallback: "any function's own parameter", not a
# recovered MCP entrypoint's. Written by the go-taint-work milestone BEFORE
# it could see the go-entrypoints-work milestone's own output (confirmed at
# the time: no `entrypoints_go.py` existed anywhere in this package yet) --
# kept here, UNCHANGED and still unwired into `run_static_taint_scan()`, as
# the real regression-tested proof that the generated semgrep RULE SYNTAX
# (sinks/sanitizers/focus-metavariable) correctly parses and fires on real,
# unmodified, non-synthetic Go source (digitalocean/doctl,
# DataDog/datadog-agent -- see bench/GO_TAINT_RULES_STATUS.md), independent
# of entrypoint sourcing. `generate_taint_rule_yaml_go()` below (the
# consolidation-merge fix, see bench/FINAL_COMPLETE_V10_STATUS.md) is the
# real, entrypoint-scoped generator now actually wired into
# `run_static_taint_scan()` -- this any-function version is superseded for
# that purpose, not deleted, since `tests/test_taint_scanner_go.py`'s own
# 18 regression tests (renamed to call it as
# `generate_taint_rule_yaml_go_anyfn()`) still validate the underlying sink/
# sanitizer rule mechanics directly, the same role `_CREDFWD_JS_ANY_
# FUNCTION_SOURCE_YAML` already plays for one JS/TS class.
#
# Real, concrete consequence, stated plainly: this any-function form is
# broader than the Python/JS rules' own entrypoint-scoped sourcing and WILL
# flag genuine, intentional local-tool behavior (e.g. a CLI's own
# flag-supplied file path or URL, not a remote MCP client argument) as if
# it were an MCP-reachable taint source -- confirmed directly while
# validating this rule against digitalocean/doctl and DataDog/datadog-agent
# (see bench/GO_TAINT_RULES_STATUS.md): neither publishes an official Go
# MCP server, so every real match found there is a CLI-flag-to-sink flow,
# not an actual MCP vulnerability. This is exactly the false-positive class
# `generate_taint_rule_yaml_go()`'s real entrypoint scoping below removes.
#
# Two source shapes covered (`pattern-either`, one shared `pattern: $P`
# metavariable) -- a plain function declaration and a method declaration
# (either receiver form; a bare metavariable for the receiver's type
# matches both `func (s *Server) F(...)` and `func (s Server) F(...)`,
# confirmed empirically) -- not every possible Go function-definition
# syntax (an anonymous function literal assigned to a variable/field, e.g.
# `var f = func(url string) { ... }` -- a REAL shape found in
# digitalocean/doctl's own `commands/gradientai_simulations.go`, though not
# one this milestone's fixtures/validation exercise -- is NOT covered). A
# real target using that idiom for an HTTP-fetch/file-read/exec helper is a
# known, stated gap, the same kind of deliberately-not-chased shape the
# JS/TS `_CREDFWD_JS_ANY_FUNCTION_SOURCE_YAML` comment above already
# documents for arrow functions and class methods -- kept minimal on
# purpose (this project's "minimum code that solves the validated problem"
# discipline), not attempted here.
#
# `..., $P $T, ...` (a type metavariable on BOTH sides open) is REQUIRED,
# not `..., $P, ...` (no type, Python's own shape) -- confirmed
# empirically: Go's parameter-list grammar requires a type on every
# parameter (unlike Python's untyped `def f(x): ...`), and a bare `$P` with
# no type metavariable matched ZERO real parameters in testing, even though
# the identical shape (parameter present, sink reachable) fires correctly
# the moment `$T` is added. Also confirmed to correctly match Go's
# "shared-type" parameter-list shorthand (`func download(URL, targetFile
# string) error { ... }`, a REAL shape found in digitalocean/doctl's own
# `do/serverless.go`) -- semgrep's Go parser desugars this into
# individually-typed parameters before matching, so no separate pattern is
# needed for it.
_GO_ANY_FUNCTION_SOURCE_YAML = """\
  pattern-sources:
    - patterns:
        - pattern-either:
            - pattern-inside: |
                func $FN(..., $P $T, ...) { ... }
            - pattern-inside: |
                func ($RECV $RTYPE) $FN(..., $P $T, ...) { ... }
        - pattern: $P
"""


def generate_taint_rule_yaml_go_anyfn() -> str:
    """The historical "any Go function's own parameter" rule generator --
    see the module comment directly above for why it is kept (regression
    coverage for the underlying semgrep rule mechanics) and why it is no
    longer the version wired into `run_static_taint_scan()`
    (`generate_taint_rule_yaml_go()` below is). Renamed from this
    milestone's original, argument-less `generate_taint_rule_yaml_go()`
    during the v10 consolidation merge -- see
    `bench/FINAL_COMPLETE_V10_STATUS.md`. Behavior is completely unchanged
    from the go-taint-work milestone: still takes no `entrypoints`/`root`
    argument, still not scoped with `paths: include:` to any one file
    (semgrep's own `languages: [go]` filter already restricts it to `.go`
    files across the whole scanned tree, the same "whole tree, no
    entrypoint dependency" shape `generate_credfwd_any_fn_rule_yaml_js()`
    above already uses), still validated directly via `_run_semgrep()` in
    `tests/test_taint_scanner_go.py`, never through
    `run_static_taint_scan()`.
    """
    rules = []
    for idx, vc in enumerate(_VULN_CLASSES_GO):
        rule = (
            f"- id: {vc.rule_id.lower()}-go-anyfn-{idx}\n"
            f"  mode: taint\n"
            f"  languages: [go]\n"
            f"  severity: ERROR\n"
            f'  message: "MCP handler parameter reaches a {vc.title.split(" ")[-1]}"\n'
            f"{_GO_ANY_FUNCTION_SOURCE_YAML}"
            f"{vc.semgrep_sink_yaml if vc.semgrep_sink_yaml is not None else _sink_block(vc)}"
            f"{_sanitizer_block(vc)}"
        )
        rules.append(rule)
    return "rules:\n" + "\n".join(rules)


# --------------------------------------------------------------------------
# Go source, entrypoint-scoped (v10 consolidation-merge fix -- see
# bench/FINAL_COMPLETE_V10_STATUS.md's "Go entrypoints vs Go taint mismatch"
# section). `entrypoints_go.py` (merged in alongside this fix) now exists
# and recovers real MCP tool handlers by (file, function/method name,
# parameter names) -- the same `McpEntrypoint` shape Python/JS/Kotlin
# already source from. This mirrors `_source_block()` (Python)'s own
# "anchor on the real recovered function NAME, scoped per-file via `paths:
# include:`" design exactly, not `_source_block_js()`'s per-entrypoint
# literal-signature anchor -- Go entrypoints, like Python's, always have a
# real name (`entrypoints_go.py` never recovers an anonymous handler), so
# the simpler, Python-style name-regex anchor applies unchanged. Both
# receiver forms are covered by the SAME two `pattern-inside` alternatives
# `_GO_ANY_FUNCTION_SOURCE_YAML` above already validated -- only the added
# `metavariable-regex` on `$FN` is new, restricting the match to this
# file's own real recovered entrypoint names instead of every function in
# the repo.
#
# Real, empirically-confirmed correctness point (this is the actual fix,
# not just a narrower regex): the source anchor is the entrypoint's own
# BARE parameter (`$P`, e.g. `req mcp.CallToolRequest` or `request
# *mcp.CallToolRequest`), not a specific accessor method call on it. This
# was checked directly against the real MCP Go SDK shape before assuming it
# would work -- neither mark3labs/mcp-go's `CallToolRequest` (whose real
# argument-reading API is `req.GetArguments()` / `req.GetString(key,
# default)` / `req.Params.Arguments.(map[string]any)`, confirmed directly
# against the vendored `mark3labs/mcp-go@v0.43.2` module source) nor the
# official `modelcontextprotocol/go-sdk`'s generic `ToolHandlerFor[In,
# Out]` (whose real per-tool argument is a THIRD, typed parameter, `input
# In`, confirmed directly against the vendored `go-sdk@v1.6.1` module
# source) hands a tool's real argument to the handler as a directly
# -sink-usable scalar the way Python's/JS's own MCP SDKs do. Rather than
# hand-writing a source pattern for every one of these accessor shapes
# (`GetString`/`GetInt`/`GetBool`/`.Params.Arguments`/a typed `input`
# struct's own fields/...), this rule leans on semgrep OSS taint mode's own
# default propagation behavior -- a method call or field/index access on an
# already-tainted receiver produces a tainted result, unless the call is a
# recognized sanitizer -- and taints the WHOLE request-shaped parameter at
# the source, exactly as Python's/JS's own rules taint a whole named
# parameter. Confirmed empirically against a real, verbatim-reproduced
# fixture of digitalocean-labs/mcp-digitalocean's own
# `createEvaluationDataset` (the exact function the go-entrypoints
# milestone's own ledger-cited vulnerability lives in --
# `pkg/registry/genai/evaluation_tools.go:271`,
# `bench/ledger/entries/digitalocean-genai-evaluation-arbitrary-file-read.json`):
# `req mcp.CallToolRequest` tainted at the source correctly propagates
# through `args := req.GetArguments()`, `filePath, ok :=
# args["file_path"].(string)` (a map index + type assertion), all the way
# to `os.ReadFile(filePath)` -- a real, verified regression test
# (`test_reconstruct_path_go_...`/`test_generate_taint_rule_yaml_go_...`
# below) locks this fixture in. See "Known limitations" in
# bench/FINAL_COMPLETE_V10_STATUS.md for the honest, real gap this does NOT
# close: the OTHER ledger-cited real Go finding (Datadog's
# `handleGenerateSBOM`) routes the tainted map through a locally-defined
# helper function (`parseSBOMArgs`) into a DIFFERENT file/package
# (`internal/sbom/generator.go`) before reaching its own path-traversal
# sink -- a genuinely cross-file, multi-hop flow `cross_file.py` has no Go
# support for (same stated scope limit `generate_taint_rule_yaml`/`_js`'s
# own single-hop cross-file support already carries for a SECOND hop), so
# it is not expected to be caught by this same-function-only rule, and
# isn't, without that being a new regression -- it was equally uncaught
# before this fix (the any-function fallback never fired there either,
# since Datadog's own `handleGenerateSBOM` had already-tainted arguments
# from a request parameter matched by BOTH the old and new source shapes,
# but semgrep's own intraprocedural taint engine stops at the
# `parseSBOMArgs(argsMap)` call boundary either way -- confirmed directly,
# not assumed).
# --------------------------------------------------------------------------


def _call_name_go(node, src: bytes) -> str:
    """Full dotted name of a Go call's own function-selector expression --
    `filepath.Clean` for `filepath.Clean(...)`, `a.b.Clean` for a
    multi-level `a.b.Clean(...)`, or a bare identifier's own text for a
    receiver-less call. Mirrors `_call_name` (Python)/
    `entrypoints_js.dotted_chain` (JS/TS) exactly -- see either's own
    docstring for why the fallback is a single leading-dot component (never
    reached in practice for the sanitizer names this module currently
    checks, all of which are either fully-qualified like `filepath.Clean`
    or bare like `ValidateURL`, but kept for the same non-Name-root case
    Python's/JS's own version handle). `node` is a tree-sitter `Node`,
    deliberately untyped -- same convention `_probe_js_call`'s own `call`
    parameter already uses in this module, so this file never requires a
    module-level `from tree_sitter import Node` (and therefore the
    `static-taint` extra) just to type-check, matching this module's own
    "importable with no extras installed" discipline."""
    from . import entrypoints_go

    if node.type == "selector_expression":
        parts: list[str] = []
        cur = node
        while cur is not None and cur.type == "selector_expression":
            field = cur.child_by_field_name("field")
            if field is not None:
                parts.append(entrypoints_go.node_text(field, src))
            cur = cur.child_by_field_name("operand")
        if cur is not None and cur.type == "identifier":
            parts.append(entrypoints_go.node_text(cur, src))
            return ".".join(reversed(parts))
        return "." + parts[0] if parts else ""
    if node.type == "identifier":
        return entrypoints_go.node_text(node, src)
    return ""


def _source_block_go(entrypoints_for_file: list[McpEntrypoint]) -> str:
    """The Go sibling of `_source_block()` (Python) -- see its own
    docstring for the general design. Go entrypoints, like Python's, always
    carry a real function/method NAME (`entrypoints_go.py` never recovers
    an anonymous handler the way `entrypoints_js.py` sometimes must), so
    the same name-anchored `metavariable-regex` approach applies directly,
    covering both receiver forms with the same two `pattern-either`
    alternatives `_GO_ANY_FUNCTION_SOURCE_YAML` above already validates.
    There is no Go cross-file-hop entrypoint shape (`cross_file.py` has no
    Go support -- see GO_ENTRYPOINTS_STATUS.md's own stated scope), so
    unlike `_source_block()` there is only ever this one block, never a
    second per-hop one."""
    names = sorted({e.function_name for e in entrypoints_for_file})
    name_alt = "|".join(names)
    return f"""\
  pattern-sources:
    - patterns:
        - pattern-either:
            - pattern-inside: |
                func $FN(..., $P $T, ...) {{ ... }}
            - pattern-inside: |
                func ($RECV $RTYPE) $FN(..., $P $T, ...) {{ ... }}
        - metavariable-regex:
            metavariable: $FN
            regex: ^({name_alt})$
        - pattern: $P
"""


def generate_taint_rule_yaml_go(entrypoints: list[McpEntrypoint], root: str | Path) -> str | None:
    """The Go sibling of `generate_taint_rule_yaml()` (Python) --
    consolidation-merge fix, replacing the go-taint-work milestone's
    original argument-less `generate_taint_rule_yaml_go()` (kept, renamed,
    as `generate_taint_rule_yaml_go_anyfn()` above) now that
    `entrypoints_go.py` exists. Same per-file scoping discipline as
    `generate_taint_rule_yaml`/`generate_taint_rule_yaml_js`: one rule per
    (source file, vulnerability class), sources restricted to that file's
    own real recovered entrypoint names via `_source_block_go()`, and a
    `paths: include:` restricting the rule to that same file -- the same
    same-name-different-file collision fix `generate_taint_rule_yaml`'s own
    docstring documents for Python applies identically here (a Go package's
    two different files could in principle name a function identically;
    per-file scoping means a rule anchored on file A's own `$FN` regex is
    never even evaluated against file B). Returns None if there are no
    recovered entrypoints at all, same "nothing to source from" convention
    as every other language's generator.
    """
    if not entrypoints:
        return None

    root = Path(root)
    by_file: dict[str, list[McpEntrypoint]] = {}
    for e in entrypoints:
        try:
            rel = str(e.file.relative_to(root))
        except ValueError:
            rel = str(e.file)
        by_file.setdefault(rel, []).append(e)

    rules = []
    for idx, (rel_path, eps) in enumerate(sorted(by_file.items())):
        for vc in _VULN_CLASSES_GO:
            rule = (
                f"- id: {vc.rule_id.lower()}-go-{idx}\n"
                f"  mode: taint\n"
                f"  languages: [go]\n"
                f"  severity: ERROR\n"
                f'  message: "MCP handler parameter reaches a {vc.title.split(" ")[-1]}"\n'
                f"  paths:\n"
                f"    include:\n"
                f'      - "{rel_path}"\n'
                f"{_source_block_go(eps)}"
                f"{vc.semgrep_sink_yaml if vc.semgrep_sink_yaml is not None else _sink_block(vc)}"
                f"{_sanitizer_block(vc)}"
            )
            rules.append(rule)

    return "rules:\n" + "\n".join(rules)


@dataclass
class Step:
    """One point in a reconstructed taint path.

    `kind` is one of "source" | "assign" | "call" | "sink" (the original
    four, same-file only) or, added by the cross-file milestone:
    "cross_file_call" (a resolved single-hop jump into a locally-imported
    function -- see cross_file.py), "unresolved_deeper_indirection" (the
    resolved callee itself needed a SECOND hop, which this project
    deliberately never chases), or "external_call_unresolved" (the call is
    an import, but doesn't resolve to a local file in this repo -- a
    third-party package or an unresolved re-export; treated as
    inconclusive, never assumed safe or dangerous).
    """

    kind: str
    line: int
    code: str
    note: str = ""
    # Relative (to the scan root) path of the file this step's `line`
    # belongs to. Optional/blank for every step predating the cross-file
    # milestone (all of them were implicitly the finding's own file); a
    # cross-file evidence path spans two files, so this field disambiguates
    # which one each step's line number refers to. Purely additive -- see
    # SourceFinding.taint_path's own docstring in source_scanner.py.
    file: str = ""
    # Adversary-fullcontext milestone: a real, bounded block of surrounding
    # source (typically the step's own enclosing function/method body, or,
    # for a doc-file citation, its enclosing Markdown header section --
    # doc-context-fix milestone), re-read from disk -- blank for every step
    # that predates these milestones and for any step nothing more could
    # honestly be shown for (an unsupported language, module-level code
    # with no enclosing function, or a `.md` line with no heading before
    # it). Only ever populated by
    # `hunter._evidence_path_from_citations` today (the one place that
    # already has both a real repo root and real cited lines); every other
    # `Step(...)` call site in this codebase leaves it at its default.
    # Purely additive -- `critic.py`'s own evidence_path rendering
    # (`build_critic_prompt`) does not read this field, so it is unaffected.
    context: str = ""


# --------------------------------------------------------------------------
# Stage 2a: rule generation
# --------------------------------------------------------------------------


def _source_block(entrypoints_for_file: list[McpEntrypoint]) -> str:
    """Build the `pattern-sources:` block for one file's worth of
    entrypoints. A REAL Stage-1 entrypoint (every `sdk_shape` except
    `"cross_file_hop"`) is grouped by function name into the original,
    unchanged "any parameter of this function" pattern -- a genuine MCP
    tool handler's entire signature is user-controlled, so tainting every
    parameter is correct there. A cross-file-hop synthetic entrypoint (see
    cross_file.py) gets its OWN, narrower block per mapped parameter name
    instead: only the specific argument(s) a real entrypoint's own
    parameter was actually mapped into are confirmed tainted -- treating
    every OTHER parameter of a shared helper function as tainted too would
    be exactly the over-eager cross-file following this milestone's own
    task spec warned against ("following into a huge shared utils file
    could create noise")."""
    real_names = sorted({e.function_name for e in entrypoints_for_file if e.sdk_shape != "cross_file_hop"})
    hop_entries = [e for e in entrypoints_for_file if e.sdk_shape == "cross_file_hop"]

    blocks: list[str] = []
    if real_names:
        name_alt = "|".join(real_names)
        blocks.append(
            f"""\
    - patterns:
        - pattern-inside: |
            def $F(..., $P, ...):
              ...
        - metavariable-regex:
            metavariable: $F
            regex: ^({name_alt})$
        - pattern: $P
    - patterns:
        - pattern-inside: |
            async def $F(..., $P, ...):
              ...
        - metavariable-regex:
            metavariable: $F
            regex: ^({name_alt})$
        - pattern: $P
"""
        )
    for e in hop_entries:
        for pname in e.parameter_names:
            blocks.append(
                f"""\
    - patterns:
        - pattern-inside: |
            def {e.function_name}(..., {pname}, ...):
              ...
        - pattern: {pname}
    - patterns:
        - pattern-inside: |
            async def {e.function_name}(..., {pname}, ...):
              ...
        - pattern: {pname}
"""
            )
    return "  pattern-sources:\n" + "".join(blocks)


def _sink_block(vc: _VulnClass) -> str:
    # Each pattern is emitted as a `|` block-literal scalar, not a plain
    # flow scalar -- required for the JS/TS spawn(..., {shell: true, ...})
    # sink pattern, whose `{...}` object-shape argument contains a `:`
    # that a plain scalar can't hold without ambiguity (verified directly
    # against the YAML parser: a flow scalar there raises "mapping values
    # are not allowed here"). Block-literal form parses identically for
    # every existing Python pattern too (none of which need it), so this
    # is a safe, uniform choice rather than a per-pattern special case.
    alts = "\n".join(f"            - pattern: |\n                {p}" for p in vc.semgrep_sink_patterns)
    extra_constraints = "".join(
        f"        - metavariable-regex:\n            metavariable: {mv}\n            regex: {regex}\n"
        for mv, regex in vc.semgrep_sink_metavariable_regex
    )
    return f"""\
  pattern-sinks:
    - patterns:
        - pattern-either:
{alts}
{extra_constraints}        - focus-metavariable: $CMD
"""


def _sanitizer_block(vc: _VulnClass) -> str:
    if not vc.semgrep_sanitizer_patterns:
        return ""
    lines = "\n".join(f"    - pattern: |\n        {p}" for p in vc.semgrep_sanitizer_patterns)
    return f"  pattern-sanitizers:\n{lines}\n"


def generate_taint_rule_yaml(entrypoints: list[McpEntrypoint], root: str | Path) -> str | None:
    """Build one semgrep taint-mode rule per (source file, vulnerability
    class), with sources scoped to the MCP handler function names actually
    recovered IN THAT FILE and a `paths: include:` restricting the rule to
    that same file. Returns None if there are no recovered entrypoints at
    all -- nothing for a taint rule to source from, so there is nothing
    useful to generate.

    Scoping is per-file, not repo-wide, on purpose: a single repo-wide rule
    matching by function name alone was tried first and produced a real
    false-positive class, confirmed against ahujasid/blender-mcp -- its
    Blender-addon side (`addon.py`, a socket-command handler that runs
    INSIDE Blender, not reachable by an MCP client argument at all) defines
    methods with the SAME NAMES as the actual `@mcp.tool()` handlers in
    `server.py` (both sides name a command `get_polyhaven_categories`, by
    the nature of a client/addon protocol mirroring tool names on both
    ends). A name-only source pattern can't tell those apart and flagged 17
    addon.py call sites as tainted MCP-handler sinks. Since semgrep taint
    mode is already intra-procedural -- true positives always have their
    source and sink in the SAME function, hence the same file -- scoping
    each rule to the exact file its entrypoints were recovered from removes
    this collision with no loss of recall on any of this milestone's
    validated real bugs.
    """
    if not entrypoints:
        return None

    root = Path(root)
    by_file: dict[str, list[McpEntrypoint]] = {}
    for e in entrypoints:
        try:
            rel = str(e.file.relative_to(root))
        except ValueError:
            rel = str(e.file)
        by_file.setdefault(rel, []).append(e)

    rules = []
    for idx, (rel_path, eps) in enumerate(sorted(by_file.items())):
        for vc in _VULN_CLASSES:
            # Cross-file milestone: an absence-based class (currently only
            # TAINT-IDOR) deliberately does NOT source from a
            # cross-file-hop entrypoint here -- measured directly against
            # the Round 40 corpus (see bench/MILESTONE_CROSSFILE_STATUS.md),
            # widening this already-lowest-confidence "no check found"
            # class's reach into more helper functions amplifies its
            # existing single-tenant/no-real-authorization-boundary
            # false-positive class (FINAL_STATUS.md Section 4) rather than
            # adding genuine recall -- unlike the hard-sink classes, where
            # the same widened reach is exactly this milestone's intended
            # recall gain. Mechanism B (reconstruct_path's own in-place
            # cross-file check resolution, wired in separately) is
            # UNAFFECTED by this and still applies to TAINT-IDOR: it only
            # ever clears an existing same-file finding by recognizing a
            # real check one hop away, never creates a new one, so it
            # carries none of this risk.
            vc_eps = [e for e in eps if not (vc.absence_based and e.sdk_shape == "cross_file_hop")]
            if not vc_eps:
                continue
            rule = (
                f"- id: {vc.rule_id.lower()}-{idx}\n"
                f"  mode: taint\n"
                f"  languages: [python]\n"
                f"  severity: ERROR\n"
                f'  message: "MCP handler parameter reaches a {vc.title.split(" ")[-1]}"\n'
                f"  paths:\n"
                f"    include:\n"
                f'      - "{rel_path}"\n'
                f"{_source_block(vc_eps)}"
                f"{vc.semgrep_sink_yaml if vc.semgrep_sink_yaml is not None else _sink_block(vc)}"
                f"{_sanitizer_block(vc)}"
            )
            rules.append(rule)

    return "rules:\n" + "\n".join(rules)


# --------------------------------------------------------------------------
# Stage 2a (JS/TS): rule generation. Unlike Python's `_source_block()`,
# which anchors on a function NAME (a metavariable-regex over recovered
# names against `pattern-inside: def $F(...): ...`), most real JS/TS
# handlers are anonymous inline arrow/function expressions with no name to
# regex against at all -- so each JS/TS entrypoint gets its own
# `pattern-inside` anchored on that handler's own literal parameter-list
# text instead (`entrypoints_js.function_signature_pattern()`). See that
# function's docstring for why this is at least as precise per-entrypoint,
# and why combining it with the same per-file `paths: include:` scoping
# Python's own rule generation uses (below) re-applies the exact
# same-name-different-file collision fix that project's own Python
# milestone had to make (see generate_taint_rule_yaml's docstring).
# --------------------------------------------------------------------------


def _yaml_literal_block(text: str, indent: int) -> str:
    pad = " " * indent
    return "\n".join(pad + line for line in text.splitlines()) + "\n"


def _source_block_js(entrypoints: list[McpEntrypoint]) -> str | None:
    from . import entrypoints_js

    blocks: list[str] = []
    trees: dict[Path, tuple] = {}
    for ep in entrypoints:
        if ep.file not in trees:
            trees[ep.file] = entrypoints_js.parse_file(ep.file)
        parsed = trees[ep.file]
        if parsed is None:
            continue
        root_node, src = parsed
        fn_node = entrypoints_js.find_enclosing_function(root_node, ep.line)
        if fn_node is None:
            continue
        sig = entrypoints_js.function_signature_pattern(fn_node, src)
        if sig is None:
            continue
        for param in ep.parameter_names:
            blocks.append(
                "    - patterns:\n"
                "        - pattern-inside: |\n"
                + _yaml_literal_block(sig, 12)
                + f"        - pattern: {param}\n"
            )
    if not blocks:
        return None
    return "  pattern-sources:\n" + "".join(blocks)


def generate_taint_rule_yaml_js(entrypoints: list[McpEntrypoint], root: str | Path) -> str | None:
    """The JS/TS sibling of `generate_taint_rule_yaml()` -- same per-file
    scoping discipline (one rule per file x vulnerability class, restricted
    to that file via `paths: include:`), same reuse of `_sink_block()`/
    `_sanitizer_block()` (both already language-agnostic: they only emit
    the vulnerability class's own pattern strings, which are just JS/TS
    -shaped for `_VULN_CLASSES_JS`). Returns None if there are no recovered
    JS/TS entrypoints, or if none of them could be re-anchored to a real
    function node (see `_source_block_js`) -- nothing for a taint rule to
    source from.
    """
    if not entrypoints:
        return None

    root = Path(root)
    by_file: dict[str, list[McpEntrypoint]] = {}
    for e in entrypoints:
        try:
            rel = str(e.file.relative_to(root))
        except ValueError:
            rel = str(e.file)
        by_file.setdefault(rel, []).append(e)

    rules = []
    for idx, (rel_path, eps) in enumerate(sorted(by_file.items())):
        source_block = _source_block_js(eps)
        if source_block is None:
            continue
        for vc in _VULN_CLASSES_JS:
            rule = (
                f"- id: {vc.rule_id.lower()}-js-{idx}\n"
                f"  mode: taint\n"
                f"  languages: [javascript, typescript]\n"
                f"  severity: ERROR\n"
                f'  message: "MCP handler parameter reaches a {vc.title.split(" ")[-1]}"\n'
                f"  paths:\n"
                f"    include:\n"
                f'      - "{rel_path}"\n'
                f"{source_block}"
                # A real, pre-existing gap fixed while building TAINT-CREDFWD-JS:
                # unlike generate_taint_rule_yaml (Python)'s own equivalent line,
                # this JS/TS generator never checked vc.semgrep_sink_yaml at all --
                # harmless for CMDI/PATHTRAV/SSRF-JS (none of which ever set it),
                # but meant TAINT-CREDFWD-JS's standard per-entrypoint rule
                # silently fell back to _sink_block(vc)'s EMPTY pattern-either
                # (semgrep_sink_patterns=() for this class, same as the Python
                # side) and could never fire at all, on ANY target -- found via
                # this class's own "bug directly inside a registered handler"
                # unit test failing.
                f"{vc.semgrep_sink_yaml if vc.semgrep_sink_yaml is not None else _sink_block(vc)}"
                f"{_sanitizer_block(vc)}"
            )
            rules.append(rule)

    if not rules:
        return None
    return "rules:\n" + "\n".join(rules)


# --------------------------------------------------------------------------
# Stage 2a (Kotlin): rule generation. Same per-entrypoint `pattern-inside`
# -anchored-on-the-handler's-own-signature-text approach as
# `_source_block_js`/`generate_taint_rule_yaml_js`, for the identical reason
# (a real Kotlin MCP tool handler recovered by entrypoints_kotlin.py's own
# shape B is a named `execute`/`run`/... method, so a name-based
# `pattern-inside: fun $F(...): ... { ... }` + metavariable-regex WOULD work
# here, unlike JS's mostly-anonymous handlers -- but reusing the same
# signature-text-anchor approach means one shared per-file `paths: include:`
# scoping discipline and one shared `_yaml_literal_block` helper, not two
# subtly different rule generators for what is the same underlying need).
#
# Deliberately does NOT give a source anchor to `add_tool_call` (shape A)
# entrypoints at all -- see entrypoints_kotlin.py's own module docstring:
# the one real target that has one (teamcity-mcp's McpServerConfigurator.kt)
# uses it as a generic per-tool dispatch wrapper whose own lambda parameter
# just forwards into each concrete tool's OWN `execute()` (a separate,
# shape-B entrypoint already covered) -- anchoring a taint source on that
# wrapper's own enclosing function would scope taint far too broadly (the
# whole `configureServer()` method, not just the one lambda). A real target
# that puts actual tool logic directly inside an `addTool { }` trailing
# lambda is not something this milestone's one validation target exhibits,
# so this is left an honest, documented gap rather than a guess.
# --------------------------------------------------------------------------


def _source_block_kotlin(entrypoints: list[McpEntrypoint]) -> str | None:
    from . import entrypoints_kotlin

    blocks: list[str] = []
    trees: dict[Path, tuple] = {}
    for ep in entrypoints:
        if ep.sdk_shape == "add_tool_call":
            continue  # see this section's own module comment above
        if ep.file not in trees:
            trees[ep.file] = entrypoints_kotlin.parse_file(ep.file)
        parsed = trees[ep.file]
        if parsed is None:
            continue
        root_node, src = parsed
        fn_node = entrypoints_kotlin.find_enclosing_function(root_node, ep.line)
        if fn_node is None:
            continue
        sig = entrypoints_kotlin.function_signature_pattern(fn_node, src)
        if sig is None:
            continue
        for param in ep.parameter_names:
            blocks.append(
                "    - patterns:\n"
                "        - pattern-inside: |\n"
                + _yaml_literal_block(sig, 12)
                + f"        - pattern: {param}\n"
            )
    if not blocks:
        return None
    return "  pattern-sources:\n" + "".join(blocks)


def generate_taint_rule_yaml_kotlin(entrypoints: list[McpEntrypoint], root: str | Path) -> str | None:
    """The Kotlin sibling of `generate_taint_rule_yaml()`/
    `generate_taint_rule_yaml_js()` -- same per-file scoping discipline (one
    rule per file x vulnerability class, restricted to that file via `paths:
    include:`), same reuse of `_sink_block()`/`_sanitizer_block()` (already
    language-agnostic). Returns None if there are no recovered Kotlin
    entrypoints, or if none of them re-anchor to a real function node (see
    `_source_block_kotlin` -- this always excludes shape-A `add_tool_call`
    entrypoints by design) -- nothing for a taint rule to source from.
    """
    if not entrypoints:
        return None

    root = Path(root)
    by_file: dict[str, list[McpEntrypoint]] = {}
    for e in entrypoints:
        try:
            rel = str(e.file.relative_to(root))
        except ValueError:
            rel = str(e.file)
        by_file.setdefault(rel, []).append(e)

    rules = []
    for idx, (rel_path, eps) in enumerate(sorted(by_file.items())):
        source_block = _source_block_kotlin(eps)
        if source_block is None:
            continue
        for vc in _VULN_CLASSES_KOTLIN:
            rule = (
                f"- id: {vc.rule_id.lower()}-kotlin-{idx}\n"
                f"  mode: taint\n"
                f"  languages: [kotlin]\n"
                f"  severity: ERROR\n"
                f'  message: "MCP handler parameter reaches a {vc.title.split(" ")[-1]}"\n'
                f"  paths:\n"
                f"    include:\n"
                f'      - "{rel_path}"\n'
                f"{source_block}"
                f"{vc.semgrep_sink_yaml if vc.semgrep_sink_yaml is not None else _sink_block(vc)}"
                f"{_sanitizer_block(vc)}"
            )
            rules.append(rule)

    if not rules:
        return None
    return "rules:\n" + "\n".join(rules)


# --------------------------------------------------------------------------
# Stage 2b: run semgrep
# --------------------------------------------------------------------------


def _run_semgrep(root: Path, rule_yaml: str) -> list[dict]:
    """Write the generated rule to a temp file and run semgrep against
    `root`. Returns the raw `results` list from semgrep's own JSON output.
    Returns [] (with a stderr warning, not an exception) if semgrep isn't
    installed -- this is an optional, additive feature, not a hard
    dependency of the rest of the scanner.
    """
    if shutil.which("semgrep") is None:
        print(
            "Warning: semgrep not found on PATH -- skipping static-taint (tier S) scan. "
            "Install it with `pip install semgrep` or `pip install mcp-safeguard[static-taint]`.",
            file=sys.stderr,
        )
        return []

    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
        f.write(rule_yaml)
        rule_path = f.name

    try:
        proc = subprocess.run(
            # --no-git-ignore: semgrep's default (--use-git-ignore) excludes any
            # file that is BOTH untracked-by-git AND gitignored. `root` is not
            # necessarily its own git repo -- it can be an extracted archive, a
            # fresh un-committed checkout, or a subtree that is itself listed in
            # an ancestor repo's .gitignore (e.g. this project's own
            # bench/.cache/) -- any of which silently scans 0 files under the
            # default and reports a clean "success" with no findings. Found via
            # the Milestone-0 holdout harness, where every target's static-taint
            # pass was silently a no-op until this flag was added.
            #
            # NOTE (FINAL-v2 merge): tried adding --timeout=0 --timeout-threshold=0
            # here, on the theory (from bench/MILESTONE_CROSSFILE_STATUS.md's own
            # non-determinism finding) that semgrep's default 5s per-rule-per-file
            # timeout was the cause of this project's measured run-to-run variance
            # on large repos. Tested directly against this merged code:
            # taylorwilsdon/google-workspace-mcp's TAINT-IDOR count was [26, 28, 29]
            # across 3 runs WITHOUT the flags, and [28, 24, 30] WITH them -- no
            # reduction in variance, so the flags were reverted rather than kept
            # for an unproven benefit. Root cause is deeper than the per-rule
            # timeout; see bench/FINAL_V2_STATUS.md for the honest writeup.
            ["semgrep", "--config", rule_path, "--json", "--quiet", "--metrics=off",
             "--no-git-ignore", str(root)],
            capture_output=True,
            text=True,
            timeout=300,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        print(f"Warning: semgrep invocation failed ({exc}) -- skipping static-taint scan.", file=sys.stderr)
        return []
    finally:
        Path(rule_path).unlink(missing_ok=True)

    if not proc.stdout.strip():
        return []
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []
    return data.get("results", [])


# --------------------------------------------------------------------------
# Stage 3: path reconstruction
# --------------------------------------------------------------------------


def _call_name(node: ast.expr) -> str:
    """Full dotted name of a Call's func, walking the WHOLE Attribute chain
    (e.g. `os.path.realpath`, not just its last component `.realpath`) when
    the chain's root is a plain Name. Falls back to just `.attr` (leading
    dot) when the receiver itself isn't a plain Name (e.g. a chained call's
    result) -- see _matches_sanitizer_name below for how that leading-dot
    form is matched against a receiver-agnostic method name."""
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    if not parts and isinstance(node, ast.Name):
        return node.id
    if parts:
        return "." + parts[0]
    return ""


def _decorator_name(node: ast.expr) -> str:
    """Same dotted-name resolution as _call_name, but for a DECORATOR
    expression -- which is syntactically just an ast.expr sitting in
    `FunctionDef.decorator_list`, either a bare Name/Attribute
    (`@login_required`) or a Call wrapping one (`@permission_required("view")`,
    `@app.route("/x")`). Added for the IDOR-fix milestone's decorator-level
    check: reconstruct_path's own statement-order walk only ever looked at
    the function BODY, so a check expressed as a decorator on the handler
    itself (`@login_required` / `@permission_required(...)` sitting on the
    `def`, not a call inside it) was invisible to it -- extremely common in
    real Flask/Django/DRF-style code, per this milestone's own task."""
    target = node.func if isinstance(node, ast.Call) else node
    if isinstance(target, ast.Name | ast.Attribute):
        return _call_name(target)
    return ""


def _matches_sanitizer_name(call_name: str, names: tuple[str, ...]) -> bool:
    """True if `call_name` (from _call_name) matches one of `names`.
    A name starting with "." is receiver-agnostic (matches ANY receiver's
    method of that name, e.g. ".startswith" matches both "candidate.startswith"
    and "x.y.startswith"); a fully-qualified name (e.g. "os.path.realpath",
    "shlex.quote") must match the full dotted chain exactly, so a same-named
    method on an unrelated object doesn't false-match a module-level function."""
    for name in names:
        if name.startswith("."):
            if call_name == name or call_name.endswith(name):
                return True
        elif call_name == name:
            return True
    return False


def _names_in(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _find_enclosing_function(tree: ast.Module, line: int) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    best = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            end = getattr(node, "end_lineno", None) or node.lineno
            if node.lineno <= line <= end:
                if best is None or node.lineno >= best.lineno:
                    best = node
    return best


# --------------------------------------------------------------------------
# Bounded, single-hop cross-file resolution (Python side). Resolution
# primitives (import maps, module-to-file lookup, call-arg-to-parameter
# mapping) live in cross_file.py, vuln-class-agnostic; this module keeps
# ownership of "does this call match a sink/sanitizer name" (`_call_name`,
# `_matches_sanitizer_name`) so the same vocabulary a normal same-file walk
# uses is reused, unchanged, one hop into a resolved callee. See this
# module's own docstring and cross_file.py's for the full design and scope.
# --------------------------------------------------------------------------


@dataclass
class _CrossFileProbe:
    """The outcome of resolving and walking ONE hop into a cross-file call.
    `status` is one of "checked" (a recognized sanitizer/auth-check was
    found, applied to the forwarded parameter), "reaches_sink" (the
    forwarded parameter reaches one of `vc`'s own dangerous-sink call
    names), "no_signal" (walked the whole callee, found neither),
    "deeper_indirection" (the callee itself calls out to another
    cross-file/unresolvable function along the tainted path -- a second
    hop this module deliberately does not chase), or
    "external_call_unresolved" (the call is an import, but doesn't resolve
    to a local file in this repo)."""

    status: str
    line: int
    code: str
    matched_name: str = ""
    target_function_name: str = ""
    target_rel: str = ""


def _relpath(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _bound_name_python(call: ast.Call) -> str | None:
    """The single identifier a call's callee is rooted in -- `func` for
    `func(...)`, `module` for `module.func(...)` -- or None for any other
    callee shape (a chained call's result, a subscript, ...). Used only to
    check membership against an import map before attempting resolution;
    NOT a general call-name renderer (see `_call_name` for that)."""
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return func.value.id
    return None


def _walk_python_callee(
    fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
    tree: ast.Module,
    lines: list[str],
    tainted: set[str],
    vc: _VulnClass,
    root: Path,
    callee_file: Path,
) -> _CrossFileProbe:
    """Walk `fn_node`'s WHOLE body once, in source order, mirroring
    `reconstruct_path`'s own statement-order approximation -- but seeded
    with the caller-mapped parameter(s) instead of every real parameter,
    and with no fixed sink line (this probe is itself looking for one,
    bounded to exactly this one function). Stops at the first sink,
    recognized check, or further-indirection signal found; a same-file
    call that matches none of those simply propagates taint through an
    assignment target, exactly like `reconstruct_path`."""
    callee_import_map = cross_file.build_python_import_map(tree)
    assign_nodes = sorted(
        (n for n in ast.walk(fn_node) if isinstance(n, ast.Assign | ast.AnnAssign)),
        key=lambda n: n.lineno,
    )
    assign_lines = {n.lineno for n in assign_nodes}
    bare_calls = [n for n in ast.walk(fn_node) if isinstance(n, ast.Call) and n.lineno not in assign_lines]
    ordered: list[ast.Assign | ast.AnnAssign | ast.Call] = sorted([*assign_nodes, *bare_calls], key=lambda n: n.lineno)

    def line_text(lineno: int) -> str:
        return lines[lineno - 1].strip() if 0 < lineno <= len(lines) else ""

    for node in ordered:
        if isinstance(node, ast.Assign | ast.AnnAssign):
            value = node.value
            if value is None:
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            target_names = {t.id for t in targets if isinstance(t, ast.Name)}
            rhs_names = _names_in(value)
            calls_here = [n for n in ast.walk(value) if isinstance(n, ast.Call)]
        else:
            target_names = set()
            rhs_names = _names_in(node)
            calls_here = [node]

        touching = bool(rhs_names & tainted)

        for call in calls_here:
            call_name = _call_name(call.func)
            call_arg_names = _names_in(call)
            if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name):
                call_arg_names.add(call.func.value.id)
            if not (call_arg_names & tainted):
                continue
            if _matches_sanitizer_name(call_name, vc.sink_call_names):
                return _CrossFileProbe(status="reaches_sink", line=call.lineno, code=line_text(call.lineno), matched_name=call_name)
            if _matches_sanitizer_name(call_name, vc.strong_sanitizer_names):
                return _CrossFileProbe(status="checked", line=call.lineno, code=line_text(call.lineno), matched_name=call_name)
            nested_bound = _bound_name_python(call)
            if nested_bound is not None and nested_bound in callee_import_map:
                nested_target = cross_file.resolve_python_call_target(call, callee_import_map, root, callee_file)
                status = "deeper_indirection" if nested_target is not None else "external_call_unresolved"
                return _CrossFileProbe(status=status, line=call.lineno, code=line_text(call.lineno), matched_name=call_name)

        if target_names and touching:
            tainted |= target_names

    return _CrossFileProbe(status="no_signal", line=fn_node.lineno, code="")


def _probe_python_call(
    call: ast.Call,
    tainted: set[str],
    vc: _VulnClass,
    root: Path,
    current_file: Path,
    import_map: dict[str, cross_file.PyImportRef],
) -> _CrossFileProbe | None:
    """Bounded, single-hop resolution for ONE call encountered while
    reconstructing a Python taint path. Returns None if `call` isn't
    shaped like a locally-imported cross-file call at all (a builtin, a
    same-file function, a bare non-imported name, a method call on a
    non-imported receiver, or an import that doesn't map ANY tainted
    argument to a specific callee parameter) -- in every such case, the
    existing same-file-only behavior is completely unchanged."""
    bound = _bound_name_python(call)
    if bound is None or bound not in import_map:
        return None

    line = call.lineno

    def origin_line_text() -> str:
        try:
            src_lines = current_file.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            return ""
        return src_lines[line - 1].strip() if 0 < line <= len(src_lines) else ""

    target = cross_file.resolve_python_call_target(call, import_map, root, current_file)
    if target is None:
        return _CrossFileProbe(status="external_call_unresolved", line=line, code=origin_line_text(), matched_name=bound)

    target_file, function_name = target
    found = cross_file.find_python_function(target_file, function_name)
    if found is None:
        return _CrossFileProbe(
            status="external_call_unresolved",
            line=line,
            code=origin_line_text(),
            matched_name=function_name,
            target_rel=_relpath(target_file, root),
        )

    fn_node, callee_tree, callee_lines = found
    callee_params = [a.arg for a in fn_node.args.args if a.arg not in ("self", "cls")]
    mapped = cross_file.map_python_call_args(call, tainted, callee_params)
    if not mapped:
        return None

    result = _walk_python_callee(fn_node, callee_tree, callee_lines, set(mapped), vc, root, target_file)
    result.target_function_name = function_name
    result.target_rel = _relpath(target_file, root)
    return result


_CROSS_FILE_STEP_KIND = {
    "deeper_indirection": "unresolved_deeper_indirection",
    "external_call_unresolved": "external_call_unresolved",
}


def reconstruct_path(file: Path, sink_line: int, vc: _VulnClass, root: Path) -> list[Step] | None:
    """Walk the function enclosing `sink_line` from its parameters to that
    line, recording assignments and sanitizer-shaped calls encountered along
    the way. Returns None if the file can't be parsed or no enclosing
    function is found (the finding is still reported, just without a
    reconstructed path).

    `root` (the scan root) is used only for the bounded cross-file
    resolution added by the cross-file milestone (see this module's own
    docstring and cross_file.py) -- every pre-existing same-file code path
    below is unchanged.

    Lexical-wiring milestone: every `Step.code` built below is sliced from
    `stripped_lines`, a comment/docstring-blanked copy of `lines` (see
    `lexical.strip_comments_and_docstrings` -- same-length, same-line-count,
    so every existing line-index computation here is unaffected), not `lines`
    itself. This is the taint-shaped hunter angle's own evidence path
    (`ClaimCard.evidence_path`, reused unchanged by `adversary.py`/
    `critic.py`'s prompt-building) -- before this, it was the one hunter
    angle whose per-line evidence could carry a trailing comment or an
    adjacent commented-out statement into an LLM prompt unfiltered (see
    `bench/LEXICAL_WIRING_STATUS.md`). Parsing (`ast.parse` above) and
    `source_segment` below (used only to widen `_ownership_comparison_regex_for`'s
    identity vocabulary, never shown to an LLM) both still use the RAW
    `source`/`lines` -- this only changes what TEXT is displayed for an
    already-located line, never what lines get walked or matched.
    """
    try:
        source = file.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(source, filename=str(file))
    except (OSError, SyntaxError):
        return None

    fn = _find_enclosing_function(tree, sink_line)
    if fn is None:
        return None

    import_map = cross_file.build_python_import_map(tree)
    lines = source.splitlines()
    stripped_lines = lexical.strip_comments_and_docstrings(source, file.suffix).splitlines()
    params = [a.arg for a in fn.args.args if a.arg not in ("self", "cls")]
    tainted: set[str] = set(params)
    weak_flagged: set[str] = set()

    steps: list[Step] = [
        Step(
            kind="source",
            line=fn.lineno,
            code=f"{fn.name}({', '.join(params)})",
            note="MCP tool handler parameter(s), recovered in Stage 1",
        )
    ]

    # IDOR-fix milestone addition: a check expressed as a DECORATOR on the
    # enclosing handler function itself (`@login_required`, a bare Name/
    # Attribute/Call sitting in fn.decorator_list) applies to every line in
    # the function body, including the sink -- but nothing below this point
    # ever looked at fn.decorator_list at all, only the body. Two tiers,
    # matching IDOR_AUTH_CHECK_NAMES vs IDOR_AUTHN_ONLY_NAMES's own split
    # (see those constants' docstrings for why authentication and
    # object-level authorization are deliberately NOT treated as
    # equivalent): a strong-sanitizer-name decorator is recognized the same
    # way a strong-sanitizer-name bare guard call already is (see
    # _path_has_recognized_check); an authentication-only decorator is
    # recorded as a visible annotation for a human reviewer but does NOT
    # suppress the finding on its own. The authn-only branch only applies to
    # absence-based classes (currently only TAINT-IDOR) -- the
    # authenticated-vs-authorized distinction is specific to that class's
    # own "was an object-level check found?" question, not to CMDI/
    # PATHTRAV/SSRF/CREDFWD, none of which have anything in
    # IDOR_AUTHN_ONLY_NAMES in their own strong/weak_sanitizer_names anyway.
    for dec in fn.decorator_list:
        dec_name = _decorator_name(dec)
        if not dec_name:
            continue
        dec_line = getattr(dec, "lineno", fn.lineno)
        dec_text = stripped_lines[dec_line - 1].strip() if 0 < dec_line <= len(lines) else f"@{dec_name}"
        if _matches_sanitizer_name(dec_name, vc.strong_sanitizer_names):
            steps.append(
                Step(
                    kind="call",
                    line=dec_line,
                    code=dec_text,
                    note=f"recognized authorization decorator on the enclosing function: "
                    f"@{dec_name}(...) -- applies to every line in this function, including "
                    f"the sink below",
                )
            )
        elif vc.absence_based and _matches_sanitizer_name(dec_name, IDOR_AUTHN_ONLY_NAMES):
            steps.append(
                Step(
                    kind="call",
                    line=dec_line,
                    code=dec_text,
                    note=f"authentication-only decorator on the enclosing function: @{dec_name}(...) "
                    f"-- confirms the caller has a valid session, NOT that they own this specific "
                    f"resource; does not by itself clear this finding",
                )
            )

    # Statement-order approximation: every Assign/AnnAssign in the function,
    # in source order, up to the sink line. No branch/loop control-flow
    # modeling -- semgrep's own dataflow already established real
    # reachability in Stage 2; this is a best-effort audit trail, not a
    # second independent proof.
    assigns = [
        n
        for n in ast.walk(fn)
        if isinstance(n, ast.Assign | ast.AnnAssign) and n.lineno < sink_line
    ]
    assigns.sort(key=lambda n: n.lineno)

    for node in assigns:
        value = node.value
        if value is None:
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        target_names = {t.id for t in targets if isinstance(t, ast.Name)}
        if not target_names:
            continue

        rhs_names = _names_in(value)
        rhs_calls = [n for n in ast.walk(value) if isinstance(n, ast.Call)]
        rhs_call_names = {_call_name(c.func) for c in rhs_calls}

        if not (rhs_names & (tainted | weak_flagged)):
            continue

        strong_hit = next((n for n in rhs_call_names if _matches_sanitizer_name(n, vc.strong_sanitizer_names)), None)
        weak_hit = next((n for n in rhs_call_names if _matches_sanitizer_name(n, vc.weak_sanitizer_names)), None)

        line_text = stripped_lines[node.lineno - 1].strip() if 0 < node.lineno <= len(lines) else ""

        if strong_hit:
            tainted -= target_names
            weak_flagged -= target_names
            steps.append(
                Step(
                    kind="call",
                    line=node.lineno,
                    code=line_text,
                    note=f"recognized strong sanitizer: {strong_hit}(...) -- semgrep's own dataflow "
                    f"treats this as cleared unless the finding below still fired",
                )
            )
        elif weak_hit:
            tainted |= target_names
            weak_flagged |= target_names
            steps.append(
                Step(
                    kind="call",
                    line=node.lineno,
                    code=line_text,
                    note=f"weak sanitizer seen: {weak_hit}(...) is a string prefix check, not real "
                    f"path containment (a sibling directory can share the prefix) -- still suspicious",
                )
            )
        else:
            cross_probe = None
            for c in rhs_calls:
                cross_probe = _probe_python_call(c, tainted | weak_flagged, vc, root, file, import_map)
                if cross_probe is not None:
                    break

            if cross_probe is None:
                tainted |= target_names
                steps.append(
                    Step(kind="assign", line=node.lineno, code=line_text, note="value stays tainted")
                )
            elif cross_probe.status == "checked":
                tainted -= target_names
                weak_flagged -= target_names
                steps.append(
                    Step(
                        kind="cross_file_call",
                        line=node.lineno,
                        code=line_text,
                        note=f"single-hop cross-file resolution: jumps into {cross_probe.target_function_name}(...) "
                        f"in {cross_probe.target_rel} -- recognized strong sanitizer found there: "
                        f"{cross_probe.matched_name}(...) applied to the forwarded parameter, treated as "
                        f"cleared, same as a same-file recognized strong sanitizer match",
                    )
                )
            elif cross_probe.status == "reaches_sink":
                tainted |= target_names
                steps.append(
                    Step(
                        kind="cross_file_call",
                        line=node.lineno,
                        code=line_text,
                        note=f"single-hop cross-file resolution: jumps into {cross_probe.target_function_name}(...) "
                        f"in {cross_probe.target_rel} -- the forwarded parameter ALSO reaches a {vc.rule_id} "
                        f"sink there ({cross_probe.matched_name}(...)) -- still tainted",
                    )
                )
            else:
                tainted |= target_names
                kind = _CROSS_FILE_STEP_KIND.get(cross_probe.status, "cross_file_call")
                if cross_probe.status == "deeper_indirection":
                    note = (
                        f"cross-file resolution stopped: {cross_probe.target_function_name}(...) in "
                        f"{cross_probe.target_rel} itself calls another cross-file/unresolved function "
                        f"({cross_probe.matched_name}(...)) -- this pass follows exactly ONE hop by "
                        f"design (see cross_file.py); treated as inconclusive beyond this point"
                    )
                else:
                    note = (
                        f"{cross_probe.matched_name}(...) is imported but does not resolve to a local "
                        f"file in this repo (a third-party package, or an unresolved re-export) -- "
                        f"treated as inconclusive, neither safe nor dangerous"
                    )
                steps.append(Step(kind=kind, line=node.lineno, code=line_text, note=note))

    # A second pass for sanitizer-shaped calls that are NOT an assignment's
    # RHS -- most commonly a bare guard used for its side effect/return value
    # inside an `if`, e.g. `if not candidate.startswith(base): raise ...`.
    # These never touch `tainted`/`weak_flagged` above (nothing is assigned),
    # but are still worth surfacing: empirically (see this milestone's own
    # status doc), semgrep OSS's taint sanitizers do NOT clear a variable for
    # a bare assert-style guard call either -- a real, verified limitation,
    # not just a gap in this narration step. Reported here as an annotation
    # regardless, on the same "surface it, don't force a rule to hide it"
    # discipline as the rest of this project.
    assign_lines = {n.lineno for n in assigns}
    guard_calls = sorted(
        (n for n in ast.walk(fn) if isinstance(n, ast.Call) and n.lineno < sink_line and n.lineno not in assign_lines),
        key=lambda n: n.lineno,
    )
    for call in guard_calls:
        call_name = _call_name(call.func)
        # IDOR-fix milestone fix: also collect names referenced in KEYWORD
        # arguments, not just positional ones. Real ORM/framework ownership
        # guards are almost always keyword-only -- `.filter_by(id=record_id,
        # owner=current_user)`, `get_object_or_404(Model, pk=record_id,
        # owner=request.user)` -- and the original code below only ever
        # looked at `call.args`, so a guard call referencing the tainted
        # parameter SOLELY through a keyword argument was silently invisible
        # to this whole pass (never even reached the sanitizer-name check).
        arg_names: set[str] = set()
        for a in call.args:
            arg_names |= _names_in(a)
        for kw in call.keywords:
            if kw.value is not None:
                arg_names |= _names_in(kw.value)
        if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name):
            arg_names.add(call.func.value.id)
        if not (arg_names & (tainted | weak_flagged)):
            continue
        line_text = stripped_lines[call.lineno - 1].strip() if 0 < call.lineno <= len(lines) else ""
        if _matches_sanitizer_name(call_name, vc.weak_sanitizer_names):
            weak_flagged |= tainted & arg_names
            steps.append(
                Step(
                    kind="call",
                    line=call.lineno,
                    code=line_text,
                    note=f"weak guard seen: {call_name}(...) is a string prefix check, not real "
                    f"path containment -- still suspicious",
                )
            )
        elif _matches_sanitizer_name(call_name, vc.strong_sanitizer_names):
            steps.append(
                Step(
                    kind="call",
                    line=call.lineno,
                    code=line_text,
                    note=f"recognized sanitizer name seen as a bare guard call: {call_name}(...) -- "
                    f"empirically, semgrep OSS taint mode does NOT treat an assert-style guard "
                    f"(as opposed to a value reassignment/wrap) as clearing taint, so this finding "
                    f"still fired; a human should confirm whether the guard actually raises before "
                    f"the sink below runs",
                )
            )
        elif vc.absence_based and _INLINE_OWNERSHIP_FILTER.search(line_text):
            # IDOR-fix milestone addition: an ORM filter/where guard
            # (.filter_by(owner=...), .where(user_id=...)) or a Django
            # get_object_or_404(...)/get_list_or_404(...) call WITH an
            # owner-ish kwarg -- neither has a fixed name in
            # IDOR_AUTH_CHECK_NAMES (get_object_or_404 alone, with no owner
            # filter, is NOT a check -- see the regex's own comment), so the
            # two branches above never match it; recognized here by the same
            # regex _path_has_recognized_check itself uses.
            steps.append(
                Step(
                    kind="call",
                    line=call.lineno,
                    code=line_text,
                    note="recognized inline ownership/tenant comparison (e.g. an ORM "
                    ".filter_by(owner=...)/.where(user_id=...) guard, or a Django "
                    "get_object_or_404(...)/get_list_or_404(...) call with an owner-ish "
                    "kwarg) -- treated as a recognized authorization check",
                )
            )
        else:
            # Not a recognized same-file sanitizer/check (nor, for an
            # absence-based class, a recognized inline ownership filter just
            # above) -- try bounded single-hop cross-file resolution before
            # giving up on this guard call entirely. This is the main path
            # that lets a real cross-file TAINT-IDOR auth-check get
            # recognized (see this module's own docstring and cross_file.py).
            cross_probe = _probe_python_call(call, tainted | weak_flagged, vc, root, file, import_map)
            if cross_probe is None:
                continue
            if cross_probe.status == "checked":
                steps.append(
                    Step(
                        kind="cross_file_call",
                        line=call.lineno,
                        code=line_text,
                        note=f"single-hop cross-file resolution: jumps into {cross_probe.target_function_name}(...) "
                        f"in {cross_probe.target_rel} -- recognized strong sanitizer found there: "
                        f"{cross_probe.matched_name}(...) applied to the forwarded parameter, same as a "
                        f"same-file recognized strong sanitizer match seen as a bare guard call",
                    )
                )
            elif cross_probe.status == "reaches_sink":
                steps.append(
                    Step(
                        kind="cross_file_call",
                        line=call.lineno,
                        code=line_text,
                        note=f"single-hop cross-file resolution: jumps into {cross_probe.target_function_name}(...) "
                        f"in {cross_probe.target_rel} -- the forwarded parameter ALSO reaches a {vc.rule_id} "
                        f"sink there ({cross_probe.matched_name}(...)) -- still tainted",
                    )
                )
            elif cross_probe.status == "deeper_indirection":
                steps.append(
                    Step(
                        kind="unresolved_deeper_indirection",
                        line=call.lineno,
                        code=line_text,
                        note=f"cross-file resolution stopped: {cross_probe.target_function_name}(...) in "
                        f"{cross_probe.target_rel} itself calls another cross-file/unresolved function "
                        f"({cross_probe.matched_name}(...)) -- this pass follows exactly ONE hop by "
                        f"design (see cross_file.py); treated as inconclusive beyond this point",
                    )
                )
            elif cross_probe.status == "external_call_unresolved":
                steps.append(
                    Step(
                        kind="external_call_unresolved",
                        line=call.lineno,
                        code=line_text,
                        note=f"{cross_probe.matched_name}(...) is imported but does not resolve to a local "
                        f"file in this repo (a third-party package, or an unresolved re-export) -- "
                        f"treated as inconclusive, neither safe nor dangerous",
                    )
                )
            # status == "no_signal": walked the whole callee, found neither a
            # sink nor a recognized check -- not worth a Step of its own,
            # same as any other same-file call that matches nothing today.

    # IDOR-fix milestone addition -- a third pass, absence-based classes
    # only: a bare ownership/tenant COMPARISON that is neither an
    # assignment's RHS nor a Call at all, e.g.
    #   if resource.owner_id != current_user.id:
    #       raise HTTPException(403)
    # This is exactly the FastAPI dependency-injection shape the task asked
    # about (`current_user: User = Depends(get_current_user)` establishing
    # an identity, then a SUBSEQUENT comparison against it) and is also the
    # natural shape of a hand-written ownership check that isn't wrapped in
    # a named helper function at all. ast.Compare nodes are invisible to
    # BOTH passes above (the assigns loop only visits Assign/AnnAssign; the
    # guard-call pass only visits Call nodes) -- without this pass, a
    # same-line regex checking `s.code` for this shape would never fire,
    # because reconstruct_path would never have created a Step out of this
    # line in the first place. `_ownership_comparison_regex_for` widens the
    # fixed current-identity vocabulary with any parameter this function
    # itself binds via `Depends(...)` (see that function's own docstring for
    # why -- this stays same-file/same-function, no cross-file resolution of
    # what get_current_user actually does).
    #
    # Deliberately scans the WHOLE enclosing function, not just strictly
    # BEFORE sink_line like the two passes above -- a very common real
    # ownership-check shape is fetch-then-check-the-RESULT
    # (`record = store.fetch_record(record_id)` -- the sink -- immediately
    # followed by `if record.owner_id != current_user.id: raise ...`), where
    # the check necessarily comes AFTER the data-access call it is guarding,
    # since it inspects that call's own return value. The other two passes
    # correctly stay before-sink-only because THEIR job is taint-CLEARING
    # (a sanitizer must run before a value reaches a dangerous sink to matter
    # at all) -- but an ownership check has no such ordering requirement:
    # what matters is whether the fetched resource is ever exposed to the
    # caller without one, not literally whether the check textually precedes
    # the fetch. The same real-world risk this widening could introduce (a
    # check further down the function that is actually guarding a DIFFERENT
    # resource) already exists for the before-sink case too -- same honest,
    # already-documented tradeoff as the rest of this absence-based class.
    if vc.absence_based:
        source_segment = "\n".join(lines[fn.lineno - 1 : getattr(fn, "end_lineno", sink_line)])
        ownership_re = _ownership_comparison_regex_for(source_segment)
        compare_lines_seen: set[int] = set()
        for node in ast.walk(fn):
            if not isinstance(node, ast.Compare):
                continue
            if node.lineno == sink_line or node.lineno in compare_lines_seen or node.lineno in assign_lines:
                continue
            line_text = stripped_lines[node.lineno - 1].strip() if 0 < node.lineno <= len(lines) else ""
            if ownership_re.search(line_text):
                compare_lines_seen.add(node.lineno)
                steps.append(
                    Step(
                        kind="call",
                        line=node.lineno,
                        code=line_text,
                        note="recognized inline ownership/tenant comparison (e.g. a FastAPI "
                        "Depends(get_current_user)-style identity compared against a resource's "
                        "owner/tenant field) -- treated as a recognized authorization check",
                    )
                )

    sink_text = stripped_lines[sink_line - 1].strip() if 0 < sink_line <= len(lines) else ""
    note = "weak sanitizer seen earlier in this function but not real containment" if weak_flagged else ""
    steps.append(Step(kind="sink", line=sink_line, code=sink_text, note=note))
    return steps


# --------------------------------------------------------------------------
# IDOR-fix milestone: a broader, more accurate same-line ownership-check
# vocabulary. Originally just an inline Django `.filter(id=x, owner=y)`
# detector; widened here to also recognize (all still same-line/same-
# function, purely lexical, no cross-file resolution):
#   - more owner-ish field names actually seen in real ORMs/frameworks
#     (owner_id, user, user_id, tenant, workspace_id, created_by -- not just
#     "owner"/"tenant_id"/"account_id"),
#   - more ORM call shapes (.filter_by(...), .where(...) -- SQLAlchemy's and
#     Django's own alternate spellings of the same idea, not just .filter()),
#   - Django's get_object_or_404()/get_list_or_404() WITH an owner-ish
#     kwarg (bare get_object_or_404(Model, pk=id) alone is NOT a check --
#     only the owner-filtered form is; the previous version of this project
#     didn't recognize this shortcut at all),
#   - a direct COMPARISON between an owner-ish field and a current-identity
#     expression in EITHER order (resource.owner_id != current_user.id, or
#     current_user.id == resource.owner_id) -- the shape a hand-written or
#     FastAPI-DI-based check actually takes when it isn't wrapped in a named
#     helper function.
# Still a same-line lexical check, still applied to already-recorded Step
# text -- this is the SAME honest tradeoff IDOR_AUTH_CHECK_NAMES's own
# docstring already states (a differently-worded real check is a false
# negative here, not a bug), just with a wider, more realistic vocabulary.
_IDOR_OWNER_FIELD = r"(?:owner_id|owner|tenant_id|tenant|account_id|user_id|workspace_id|created_by)"
# The bare alternation (no enclosing "(?:...)") -- kept separate from
# _IDOR_CURRENT_IDENTITY below so _ownership_comparison_regex_for can splice
# extra Depends(...)-bound names into the SAME alternation via simple string
# concatenation, instead of slicing apart an already-wrapped group (fragile
# and easy to get off-by-one on the "(?:" prefix length).
_IDOR_CURRENT_IDENTITY_ALTS = (
    r"current_user|current_account|self\.user|self\.current_user|ctx\.user|req\.user|"
    r"request\.user|g\.user"
)
_IDOR_CURRENT_IDENTITY = rf"(?:{_IDOR_CURRENT_IDENTITY_ALTS})"
_INLINE_OWNERSHIP_FILTER = re.compile(
    rf"{_IDOR_OWNER_FIELD}\s*=\s*{_IDOR_CURRENT_IDENTITY}"
    rf"|\.(?:filter|filter_by|where)\([^)]*\b{_IDOR_OWNER_FIELD}\b"
    rf"|get_(?:object|list)_or_404\([^)]*\b{_IDOR_OWNER_FIELD}\b\s*="
    rf"|(?:\w+\.)?{_IDOR_OWNER_FIELD}\b\s*(?:==|!=)\s*{_IDOR_CURRENT_IDENTITY}(?:\.\w+)?"
    rf"|{_IDOR_CURRENT_IDENTITY}(?:\.\w+)?\s*(?:==|!=)\s*(?:\w+\.)?{_IDOR_OWNER_FIELD}\b",
    re.IGNORECASE,
)

# FastAPI's dependency-injection idiom: `name: Type = Depends(provider)` (as
# a function parameter default). Recognized purely by shape -- ANY
# `Depends(...)`-bound parameter name is added to the current-identity
# vocabulary for THIS function's own ownership-comparison check, without
# resolving what the inner provider callable (`get_current_user`, etc.)
# actually does (that would be cross-file/import-resolution work, out of
# this milestone's scope). Applied to the function's own source text
# (signature through the sink line), not a full parameter-default AST walk
# -- simplet and sufficient for the real shape this task named
# (`current_user: User = Depends(get_current_user)`), at the cost of also
# matching a `Depends(...)`-bound parameter that ISN'T actually an identity
# (a real but rare false-negative-avoidance/false-positive-risk tradeoff,
# same style as this file's other name-based vocabulary matches).
_FASTAPI_DEPENDS_PARAM_RE = re.compile(r"(\w+)\s*(?::[^=,\n]*)?=\s*Depends\(")


def _ownership_comparison_regex_for(source_segment: str) -> re.Pattern[str]:
    """Return `_INLINE_OWNERSHIP_FILTER`, widened with any `Depends(...)`
    -bound parameter name found in `source_segment` (typically the enclosing
    function's own source, signature through the sink line) as an
    additional current-identity alternative. Falls back to the plain
    `_INLINE_OWNERSHIP_FILTER` (no per-function recompilation) when no
    `Depends(...)` parameter is present -- the common case."""
    extra = _FASTAPI_DEPENDS_PARAM_RE.findall(source_segment)
    if not extra:
        return _INLINE_OWNERSHIP_FILTER
    extra_alt = "|".join(re.escape(name) for name in dict.fromkeys(extra))
    identity = rf"(?:{_IDOR_CURRENT_IDENTITY_ALTS}|{extra_alt})"
    return re.compile(
        rf"{_IDOR_OWNER_FIELD}\s*=\s*{identity}"
        rf"|\.(?:filter|filter_by|where)\([^)]*\b{_IDOR_OWNER_FIELD}\b"
        rf"|get_(?:object|list)_or_404\([^)]*\b{_IDOR_OWNER_FIELD}\b\s*="
        rf"|(?:\w+\.)?{_IDOR_OWNER_FIELD}\b\s*(?:==|!=)\s*{identity}(?:\.\w+)?"
        rf"|{identity}(?:\.\w+)?\s*(?:==|!=)\s*(?:\w+\.)?{_IDOR_OWNER_FIELD}\b",
        re.IGNORECASE,
    )


def _path_has_recognized_check(steps: list[Step] | None) -> bool:
    """True if an absence-based vuln class's reconstructed path already
    shows a recognized authorization/ownership check. Signals, all produced
    by reconstruct_path (the IDOR-fix milestone added the decorator pass and
    the bare-comparison third pass; the cross-file milestone added signal 3;
    the rest predate both):

    1. reconstruct_path's note templates for a recognized strong-sanitizer-
       name match: the guard-call second pass's bare-call annotation, the
       assign loop's reassignment annotation, the decorator pass's
       authorization-decorator annotation, and the third pass's inline
       ownership-comparison annotation -- exact substring match against the
       fixed note text those branches emit (this is deliberately
       note-text-based, not regex-based, for the decorator/comparison cases,
       so a per-function DYNAMIC regex match -- e.g. one widened with a
       Depends(...) parameter name -- is still recognized here without this
       function needing to reconstruct that same per-function regex itself).
    2. The supplementary same-line check below, against every step's own
       code text (including the final "sink" step, whose line is otherwise
       never walked by reconstruct_path for sanitizer purposes) -- covers a
       check embedded directly in the SINK call's own arguments, which is
       never a Step in its own right, so has no note to match on.
    3. (Cross-file milestone) A `cross_file_call` step whose note reports
       `status == "checked"` -- the SAME "recognized strong sanitizer"
       phrase, deliberately reused verbatim in `_probe_python_call`'s own
       note text (see `reconstruct_path`), just found one hop into a
       locally-imported function instead of the same file. This is what
       lets a real cross-file TAINT-IDOR auth-check clear the absence-based
       finding, instead of a same-file-only pass wrongly reporting "no
       check found".

    An authentication-only decorator (IDOR_AUTHN_ONLY_NAMES) is deliberately
    NOT one of these signals -- see that constant's own docstring for why
    "the caller is logged in" must not be treated as equivalent to "the
    caller owns this object".

    Callers must have already reconstructed `steps` using a _VulnClass whose
    strong_sanitizer_names holds the relevant check-name vocabulary (e.g.
    IDOR_AUTH_CHECK_NAMES) -- this function does no name matching of its
    own, only inspects what reconstruct_path already recorded.
    """
    if not steps:
        return False
    if any(
        s.kind in ("call", "cross_file_call")
        and (
            "recognized sanitizer name seen as a bare guard call" in s.note
            or "recognized strong sanitizer" in s.note
            or "recognized authorization decorator" in s.note
            or "recognized inline ownership/tenant comparison" in s.note
        )
        for s in steps
    ):
        return True
    return any(_INLINE_OWNERSHIP_FILTER.search(s.code) for s in steps)


# --------------------------------------------------------------------------
# Stage 3 (JS/TS): path reconstruction. Same algorithm as `reconstruct_path`
# above (statement-order approximation, no real control-flow graph -- see
# that function's docstring for why), walked over a tree-sitter tree
# instead of Python's `ast` module. `entrypoints_js.pattern_names()` is
# reused here to name destructuring assignment TARGETS too, not just a
# handler's own formal parameters -- e.g. `const { a } = tainted_obj;`
# propagates taint to `a` the same way a plain `x = tainted_obj.a` would.
# --------------------------------------------------------------------------


# --------------------------------------------------------------------------
# Bounded, single-hop cross-file resolution (JS/TS side). Same structure and
# scope as the Python probe above -- see this module's own docstring and
# cross_file.py's for the full design.
# --------------------------------------------------------------------------


def _bound_name_js(callee_node, src: bytes) -> str | None:
    from . import entrypoints_js

    if callee_node.type == "identifier":
        return entrypoints_js.node_text(callee_node, src)
    if callee_node.type == "member_expression":
        obj = callee_node.child_by_field_name("object")
        if obj is not None and obj.type == "identifier":
            return entrypoints_js.node_text(obj, src)
    return None


def _walk_js_callee(fn_node, root_node, src: bytes, tainted: set[str], vc: _VulnClass, root: Path, callee_file: Path) -> _CrossFileProbe:
    """The JS/TS sibling of `_walk_python_callee` -- see its docstring."""
    from . import entrypoints_js

    callee_import_map = cross_file.build_js_import_map(root_node, src)
    lines = src.decode("utf-8", errors="ignore").splitlines()

    assigns = [n for n in entrypoints_js.walk(fn_node) if n.type in ("variable_declarator", "assignment_expression")]
    assign_lines = {n.start_point[0] + 1 for n in assigns}
    bare_calls = [
        n for n in entrypoints_js.walk(fn_node) if n.type == "call_expression" and n.start_point[0] + 1 not in assign_lines
    ]
    ordered = sorted([*assigns, *bare_calls], key=lambda n: n.start_byte)

    def line_text(lineno: int) -> str:
        return lines[lineno - 1].strip() if 0 < lineno <= len(lines) else ""

    for node in ordered:
        if node.type in ("variable_declarator", "assignment_expression"):
            if node.type == "variable_declarator":
                target_node = node.child_by_field_name("name")
                value_node = node.child_by_field_name("value")
            else:
                target_node = node.child_by_field_name("left")
                value_node = node.child_by_field_name("right")
            if target_node is None or value_node is None:
                continue
            target_names = set(entrypoints_js.pattern_names(target_node, src))
            rhs_names = {entrypoints_js.node_text(n, src) for n in entrypoints_js.walk(value_node) if n.type == "identifier"}
            calls_here = [n for n in entrypoints_js.walk(value_node) if n.type == "call_expression"]
        else:
            target_names = set()
            rhs_names = {entrypoints_js.node_text(n, src) for n in entrypoints_js.walk(node) if n.type == "identifier"}
            calls_here = [node]

        touching = bool(rhs_names & tainted)

        for call in calls_here:
            callee = call.child_by_field_name("function")
            args_node = call.child_by_field_name("arguments")
            if callee is None:
                continue
            call_name = entrypoints_js.dotted_chain(callee, src)
            call_arg_names: set[str] = set()
            if args_node is not None:
                for a in args_node.named_children:
                    call_arg_names |= {entrypoints_js.node_text(n, src) for n in entrypoints_js.walk(a) if n.type == "identifier"}
            if callee.type == "member_expression":
                obj = callee.child_by_field_name("object")
                if obj is not None and obj.type == "identifier":
                    call_arg_names.add(entrypoints_js.node_text(obj, src))
            if not (call_arg_names & tainted):
                continue
            cl = call.start_point[0] + 1
            if _matches_sanitizer_name(call_name, vc.sink_call_names):
                return _CrossFileProbe(status="reaches_sink", line=cl, code=line_text(cl), matched_name=call_name)
            if _matches_sanitizer_name(call_name, vc.strong_sanitizer_names):
                return _CrossFileProbe(status="checked", line=cl, code=line_text(cl), matched_name=call_name)
            bound = _bound_name_js(callee, src)
            if bound is not None and bound in callee_import_map:
                nested_target = cross_file.resolve_js_call_target(callee, callee_import_map, callee_file, src)
                status = "deeper_indirection" if nested_target is not None else "external_call_unresolved"
                return _CrossFileProbe(status=status, line=cl, code=line_text(cl), matched_name=call_name)

        if target_names and touching:
            tainted |= target_names

    return _CrossFileProbe(status="no_signal", line=fn_node.start_point[0] + 1, code="")


def _probe_js_call(
    call, tainted: set[str], vc: _VulnClass, root: Path, current_file: Path, import_map: dict[str, cross_file.JsImportRef], src: bytes
) -> _CrossFileProbe | None:
    """The JS/TS sibling of `_probe_python_call` -- see its docstring."""
    from . import entrypoints_js

    callee = call.child_by_field_name("function")
    args_node = call.child_by_field_name("arguments")
    if callee is None:
        return None
    bound = _bound_name_js(callee, src)
    if bound is None or bound not in import_map:
        return None

    line = call.start_point[0] + 1

    def origin_line_text() -> str:
        parsed = entrypoints_js.parse_file(current_file)
        if parsed is None:
            return ""
        _, cur_src = parsed
        ls = cur_src.decode("utf-8", errors="ignore").splitlines()
        return ls[line - 1].strip() if 0 < line <= len(ls) else ""

    target = cross_file.resolve_js_call_target(callee, import_map, current_file, src)
    if target is None:
        return _CrossFileProbe(status="external_call_unresolved", line=line, code=origin_line_text(), matched_name=bound)

    target_file, function_name = target
    parsed = entrypoints_js.parse_file(target_file)
    if parsed is None:
        return _CrossFileProbe(
            status="external_call_unresolved", line=line, code=origin_line_text(),
            matched_name=function_name, target_rel=_relpath(target_file, root),
        )
    target_root, target_src = parsed
    callee_fn = entrypoints_js.find_function_by_name(target_root, function_name, target_src)
    if callee_fn is None:
        return _CrossFileProbe(
            status="external_call_unresolved", line=line, code=origin_line_text(),
            matched_name=function_name, target_rel=_relpath(target_file, root),
        )

    mapped = cross_file.map_js_call_args(args_node, tainted, src, callee_fn, target_src)
    if not mapped:
        return None

    result = _walk_js_callee(callee_fn, target_root, target_src, set(mapped), vc, root, target_file)
    result.target_function_name = function_name
    result.target_rel = _relpath(target_file, root)
    return result


def reconstruct_path_js(file: Path, sink_line: int, vc: _VulnClass, root: Path) -> list[Step] | None:
    """The JS/TS sibling of `reconstruct_path` -- see its docstring for the
    `root` parameter's purpose (bounded cross-file resolution only; every
    pre-existing same-file code path below is unchanged) and for why
    `Step.code` below is sliced from `stripped_lines`, not `lines`
    (lexical-wiring milestone)."""
    from . import entrypoints_js

    parsed = entrypoints_js.parse_file(file)
    if parsed is None:
        return None
    root_node, src = parsed

    fn = entrypoints_js.find_enclosing_function(root_node, sink_line)
    if fn is None:
        return None

    import_map = cross_file.build_js_import_map(root_node, src)
    src_text = src.decode("utf-8", errors="ignore")
    lines = src_text.splitlines()
    stripped_lines = lexical.strip_comments_and_docstrings(src_text, file.suffix).splitlines()
    params = entrypoints_js.function_params(fn, src)
    tainted: set[str] = set(params)
    weak_flagged: set[str] = set()

    steps: list[Step] = [
        Step(
            kind="source",
            line=fn.start_point[0] + 1,
            code=f"({', '.join(params)}) => ...",
            note="MCP tool handler parameter(s), recovered in Stage 1",
        )
    ]

    # Statement-order approximation: every variable_declarator/
    # assignment_expression in the function, in source order, up to the
    # sink line. No branch/loop control-flow modeling -- same discipline
    # as the Python version above.
    assigns = [
        n
        for n in entrypoints_js.walk(fn)
        if n.type in ("variable_declarator", "assignment_expression") and n.start_point[0] + 1 < sink_line
    ]
    assigns.sort(key=lambda n: n.start_byte)

    for node in assigns:
        if node.type == "variable_declarator":
            target_node = node.child_by_field_name("name")
            value_node = node.child_by_field_name("value")
        else:
            target_node = node.child_by_field_name("left")
            value_node = node.child_by_field_name("right")
        if target_node is None or value_node is None:
            continue
        target_names = set(entrypoints_js.pattern_names(target_node, src))
        if not target_names:
            continue

        rhs_names = {
            entrypoints_js.node_text(n, src) for n in entrypoints_js.walk(value_node) if n.type == "identifier"
        }
        rhs_call_names = {
            entrypoints_js.dotted_chain(n.child_by_field_name("function"), src)
            for n in entrypoints_js.walk(value_node)
            if n.type == "call_expression" and n.child_by_field_name("function") is not None
        }

        if not (rhs_names & (tainted | weak_flagged)):
            continue

        strong_hit = next((n for n in rhs_call_names if _matches_sanitizer_name(n, vc.strong_sanitizer_names)), None)
        weak_hit = next((n for n in rhs_call_names if _matches_sanitizer_name(n, vc.weak_sanitizer_names)), None)

        line_no = node.start_point[0] + 1
        line_text = stripped_lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ""

        if strong_hit:
            tainted -= target_names
            weak_flagged -= target_names
            steps.append(
                Step(
                    kind="call",
                    line=line_no,
                    code=line_text,
                    note=f"recognized strong sanitizer: {strong_hit}(...) -- semgrep's own dataflow "
                    f"treats this as cleared unless the finding below still fired",
                )
            )
        elif weak_hit:
            tainted |= target_names
            weak_flagged |= target_names
            steps.append(
                Step(
                    kind="call",
                    line=line_no,
                    code=line_text,
                    note=f"weak sanitizer seen: {weak_hit}(...) is a string prefix check, not real "
                    f"path containment (a sibling directory can share the prefix) -- still suspicious",
                )
            )
        else:
            cross_probe = None
            for c in [n for n in entrypoints_js.walk(value_node) if n.type == "call_expression"]:
                cross_probe = _probe_js_call(c, tainted | weak_flagged, vc, root, file, import_map, src)
                if cross_probe is not None:
                    break

            if cross_probe is None:
                tainted |= target_names
                steps.append(Step(kind="assign", line=line_no, code=line_text, note="value stays tainted"))
            elif cross_probe.status == "checked":
                tainted -= target_names
                weak_flagged -= target_names
                steps.append(
                    Step(
                        kind="cross_file_call",
                        line=line_no,
                        code=line_text,
                        note=f"single-hop cross-file resolution: jumps into {cross_probe.target_function_name}(...) "
                        f"in {cross_probe.target_rel} -- recognized strong sanitizer found there: "
                        f"{cross_probe.matched_name}(...) applied to the forwarded parameter, treated as "
                        f"cleared, same as a same-file recognized strong sanitizer match",
                    )
                )
            elif cross_probe.status == "reaches_sink":
                tainted |= target_names
                steps.append(
                    Step(
                        kind="cross_file_call",
                        line=line_no,
                        code=line_text,
                        note=f"single-hop cross-file resolution: jumps into {cross_probe.target_function_name}(...) "
                        f"in {cross_probe.target_rel} -- the forwarded parameter ALSO reaches a {vc.rule_id} "
                        f"sink there ({cross_probe.matched_name}(...)) -- still tainted",
                    )
                )
            else:
                tainted |= target_names
                kind = _CROSS_FILE_STEP_KIND.get(cross_probe.status, "cross_file_call")
                if cross_probe.status == "deeper_indirection":
                    note = (
                        f"cross-file resolution stopped: {cross_probe.target_function_name}(...) in "
                        f"{cross_probe.target_rel} itself calls another cross-file/unresolved function "
                        f"({cross_probe.matched_name}(...)) -- this pass follows exactly ONE hop by "
                        f"design (see cross_file.py); treated as inconclusive beyond this point"
                    )
                else:
                    note = (
                        f"{cross_probe.matched_name}(...) is imported but does not resolve to a local "
                        f"file in this repo (a third-party package, or an unresolved re-export) -- "
                        f"treated as inconclusive, neither safe nor dangerous"
                    )
                steps.append(Step(kind=kind, line=line_no, code=line_text, note=note))

    # A second pass for sanitizer-shaped calls that are NOT an assignment's
    # RHS -- a bare guard used for its side effect/return value inside an
    # `if`, e.g. `if (!candidate.startsWith(base)) throw ...`. Same
    # empirically-verified semgrep OSS limitation as the Python version:
    # a bare assert-style guard does NOT clear taint either, so it is
    # reported as an annotation only, never as clearing the finding.
    assign_lines = {n.start_point[0] + 1 for n in assigns}
    guard_calls = sorted(
        (
            n
            for n in entrypoints_js.walk(fn)
            if n.type == "call_expression"
            and n.start_point[0] + 1 < sink_line
            and n.start_point[0] + 1 not in assign_lines
        ),
        key=lambda n: n.start_byte,
    )
    for call in guard_calls:
        callee = call.child_by_field_name("function")
        args_node = call.child_by_field_name("arguments")
        if callee is None:
            continue
        call_name = entrypoints_js.dotted_chain(callee, src)
        arg_names: set[str] = set()
        if args_node is not None:
            for a in args_node.named_children:
                arg_names |= {entrypoints_js.node_text(n, src) for n in entrypoints_js.walk(a) if n.type == "identifier"}
        if callee.type == "member_expression":
            obj = callee.child_by_field_name("object")
            if obj is not None and obj.type == "identifier":
                arg_names.add(entrypoints_js.node_text(obj, src))
        if not (arg_names & (tainted | weak_flagged)):
            continue
        line_no = call.start_point[0] + 1
        line_text = stripped_lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ""
        if _matches_sanitizer_name(call_name, vc.weak_sanitizer_names):
            weak_flagged |= tainted & arg_names
            steps.append(
                Step(
                    kind="call",
                    line=line_no,
                    code=line_text,
                    note=f"weak guard seen: {call_name}(...) is a string prefix check, not real "
                    f"path containment -- still suspicious",
                )
            )
        elif _matches_sanitizer_name(call_name, vc.strong_sanitizer_names):
            steps.append(
                Step(
                    kind="call",
                    line=line_no,
                    code=line_text,
                    note=f"recognized sanitizer name seen as a bare guard call: {call_name}(...) -- "
                    f"empirically, semgrep OSS taint mode does NOT treat an assert-style guard "
                    f"(as opposed to a value reassignment/wrap) as clearing taint, so this finding "
                    f"still fired; a human should confirm whether the guard actually raises before "
                    f"the sink below runs",
                )
            )
        else:
            cross_probe = _probe_js_call(call, tainted | weak_flagged, vc, root, file, import_map, src)
            if cross_probe is None:
                continue
            if cross_probe.status == "checked":
                steps.append(
                    Step(
                        kind="cross_file_call",
                        line=line_no,
                        code=line_text,
                        note=f"single-hop cross-file resolution: jumps into {cross_probe.target_function_name}(...) "
                        f"in {cross_probe.target_rel} -- recognized strong sanitizer found there: "
                        f"{cross_probe.matched_name}(...) applied to the forwarded parameter, same as a "
                        f"same-file recognized strong sanitizer match seen as a bare guard call",
                    )
                )
            elif cross_probe.status == "reaches_sink":
                steps.append(
                    Step(
                        kind="cross_file_call",
                        line=line_no,
                        code=line_text,
                        note=f"single-hop cross-file resolution: jumps into {cross_probe.target_function_name}(...) "
                        f"in {cross_probe.target_rel} -- the forwarded parameter ALSO reaches a {vc.rule_id} "
                        f"sink there ({cross_probe.matched_name}(...)) -- still tainted",
                    )
                )
            elif cross_probe.status == "deeper_indirection":
                steps.append(
                    Step(
                        kind="unresolved_deeper_indirection",
                        line=line_no,
                        code=line_text,
                        note=f"cross-file resolution stopped: {cross_probe.target_function_name}(...) in "
                        f"{cross_probe.target_rel} itself calls another cross-file/unresolved function "
                        f"({cross_probe.matched_name}(...)) -- this pass follows exactly ONE hop by "
                        f"design (see cross_file.py); treated as inconclusive beyond this point",
                    )
                )
            elif cross_probe.status == "external_call_unresolved":
                steps.append(
                    Step(
                        kind="external_call_unresolved",
                        line=line_no,
                        code=line_text,
                        note=f"{cross_probe.matched_name}(...) is imported but does not resolve to a local "
                        f"file in this repo (a third-party package, or an unresolved re-export) -- "
                        f"treated as inconclusive, neither safe nor dangerous",
                    )
                )

    sink_text = stripped_lines[sink_line - 1].strip() if 0 < sink_line <= len(lines) else ""
    note = "weak sanitizer seen earlier in this function but not real containment" if weak_flagged else ""
    steps.append(Step(kind="sink", line=sink_line, code=sink_text, note=note))
    return steps


# --------------------------------------------------------------------------
# Stage 3 (Go): the Go equivalent of reconstruct_path/reconstruct_path_js
# named by go-taint-work's own "Known limitations / merge-blocking
# dependency" section as not yet existing -- built as part of the v10
# consolidation merge (see bench/FINAL_COMPLETE_V10_STATUS.md). Mirrors
# reconstruct_path's own statement-order assignment-tracing walk (source ->
# short_var_declaration/assignment_statement chain -> sink, annotating
# recognized strong/weak sanitizer calls along the way) rather than
# reconstruct_path_kotlin's deliberately-minimal 2-step shape -- Go's real
# recovered entrypoints (unlike Kotlin's) taint a whole request-shaped
# parameter that then flows through several real intermediate statements
# before reaching a sink (see _source_block_go's own module comment above
# for the real digitalocean-labs/mcp-digitalocean example this narrates),
# so the intermediate steps are genuinely informative evidence here, not
# narration for its own sake. No cross-file hop resolution -- cross_file.py
# has no Go support (same stated scope as generate_taint_rule_yaml_go's own
# module comment above), so unlike reconstruct_path/reconstruct_path_js
# there is no _probe_*_call step; a call this walk can't resolve into a
# recognized sanitizer is simply treated as "value stays tainted", the same
# conservative default reconstruct_path uses for its own unresolved-call
# case.
# --------------------------------------------------------------------------


def reconstruct_path_go(file: Path, sink_line: int, vc: _VulnClass, root: Path) -> list[Step] | None:
    """Returns None (not a guess) if `file` can't be parsed or no enclosing
    `function_declaration`/`method_declaration` contains `sink_line`. `root`
    is part of this function's shared signature with `reconstruct_path`/
    `reconstruct_path_js`/`reconstruct_path_kotlin` (see
    `_findings_from_raw`'s `reconstruct` param) but unused here -- there is
    no cross-file hop resolution for Go (see this section's own module
    comment above). Every `Step.code` below is sliced from a comment
    /docstring-blanked copy of the source (`lexical.strip_comments_and_
    docstrings`, same same-length/same-line-count guarantee `reconstruct_
    path`/`reconstruct_path_js` already rely on) -- the lexical-wiring
    milestone's own hardening, extended to this new Go path so a Go
    finding's evidence gets the identical comment-stripping treatment as
    every other language's, not a narrower one just because this function
    was written later.
    """
    from . import entrypoints_go

    parsed = entrypoints_go.parse_file(file)
    if parsed is None:
        return None
    root_node, src = parsed

    fn = entrypoints_go.find_enclosing_function(root_node, sink_line)
    if fn is None:
        return None

    src_text = src.decode("utf-8", errors="ignore")
    lines = src_text.splitlines()
    stripped_lines = lexical.strip_comments_and_docstrings(src_text, file.suffix).splitlines()
    params = entrypoints_go.function_params(fn, src)
    tainted: set[str] = set(params)
    weak_flagged: set[str] = set()

    name_field = fn.child_by_field_name("name")
    fn_name = entrypoints_go.node_text(name_field, src) if name_field is not None else "?"
    source_line = fn.start_point[0] + 1
    steps: list[Step] = [
        Step(
            kind="source",
            line=source_line,
            code=f"func {fn_name}({', '.join(params)}) ...",
            note="MCP tool handler parameter(s), recovered in Stage 1",
        )
    ]

    # Statement-order approximation: every short_var_declaration (`:=`) or
    # assignment_statement (`=`) in the function, in source order, up to the
    # sink line -- same "no branch/loop control-flow modeling" discipline as
    # reconstruct_path/reconstruct_path_js.
    assigns = [
        n
        for n in entrypoints_go.walk(fn)
        if n.type in ("short_var_declaration", "assignment_statement") and n.start_point[0] + 1 < sink_line
    ]
    assigns.sort(key=lambda n: n.start_byte)

    for node in assigns:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None:
            continue

        target_names = {
            entrypoints_go.node_text(c, src) for c in entrypoints_go.walk(left) if c.type == "identifier"
        } - {"_"}
        if not target_names:
            continue

        rhs_names = {
            entrypoints_go.node_text(c, src) for c in entrypoints_go.walk(right) if c.type == "identifier"
        }
        rhs_call_names = {
            _call_name_go(c.child_by_field_name("function"), src)
            for c in entrypoints_go.walk(right)
            if c.type == "call_expression" and c.child_by_field_name("function") is not None
        }

        if not (rhs_names & (tainted | weak_flagged)):
            continue

        strong_hit = next((n for n in rhs_call_names if _matches_sanitizer_name(n, vc.strong_sanitizer_names)), None)
        weak_hit = next((n for n in rhs_call_names if _matches_sanitizer_name(n, vc.weak_sanitizer_names)), None)

        line_no = node.start_point[0] + 1
        line_text = stripped_lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ""

        if strong_hit:
            tainted -= target_names
            weak_flagged -= target_names
            steps.append(
                Step(
                    kind="call",
                    line=line_no,
                    code=line_text,
                    note=f"recognized strong sanitizer: {strong_hit}(...) -- semgrep's own dataflow "
                    f"treats this as cleared unless the finding below still fired",
                )
            )
        elif weak_hit:
            tainted |= target_names
            weak_flagged |= target_names
            steps.append(
                Step(
                    kind="call",
                    line=line_no,
                    code=line_text,
                    note=f"weak sanitizer seen: {weak_hit}(...) is a lexical cleanup, not a real "
                    f"containment check (see this class's own remediation note) -- still suspicious",
                )
            )
        else:
            tainted |= target_names
            steps.append(Step(kind="assign", line=line_no, code=line_text, note="value stays tainted"))

    sink_text = stripped_lines[sink_line - 1].strip() if 0 < sink_line <= len(lines) else ""
    note = "weak sanitizer seen earlier in this function but not real containment" if weak_flagged else ""
    steps.append(Step(kind="sink", line=sink_line, code=sink_text, note=note))
    return steps


# --------------------------------------------------------------------------
# Stage 3 (Kotlin): a deliberately MINIMAL path reconstruction, not a port of
# reconstruct_path/reconstruct_path_js's full statement-order,
# sanitizer-annotating walk. This milestone's own stated scope is "basic"
# Kotlin taint/sink rules -- so rather than build (and only partially test) a
# third copy of the assignment-tracing/cross-file-probing machinery above,
# this returns just the two endpoints semgrep's own taint-mode hit ALREADY
# proves are connected: the enclosing function's own signature line as a
# "source" step, and the flagged sink line's own real source text as a
# "sink" step. Both lines are read from the real file, not fabricated. This
# is an honest, stated limitation (see bench/KOTLIN_SUPPORT_STATUS.md), not
# a silent gap: a Kotlin finding's evidence path will show WHERE the source
# and sink are, not the intermediate assignments/sanitizer-shaped calls a
# Python/JS finding's own path would narrate.
# --------------------------------------------------------------------------


def reconstruct_path_kotlin(file: Path, sink_line: int, vc: _VulnClass, root: Path) -> list[Step] | None:
    """Returns None (not a guess) if `file` can't be parsed or no enclosing
    `function_declaration` contains `sink_line` -- same "silence, not a
    guess" rule the rest of this project follows. `vc` and `root` are part
    of this function's shared signature with `reconstruct_path`/
    `reconstruct_path_js` (see `_findings_from_raw`'s `reconstruct` param)
    but unused here -- there is no sanitizer/check annotation pass to run.

    v10 consolidation-merge fix: `source_text`/`sink_text` are now sliced
    from `stripped_lines` (comment-blanked, see `lexical.strip_comments_and_
    docstrings` -- `.kt` added to `_C_STYLE_SUFFIXES` at the same time),
    not the raw `lines` this function used when it was first built (before
    the lexical-wiring milestone existed) -- extending the exact same
    `strip=True` treatment `reconstruct_path`/`reconstruct_path_js`/
    `reconstruct_path_go` already give their own source/sink text, so a
    Kotlin finding's evidence gets the identical comment/injection-stripping
    hardening as every other language's, not a narrower one just because
    this function predates that milestone.
    """
    from . import entrypoints_kotlin

    parsed = entrypoints_kotlin.parse_file(file)
    if parsed is None:
        return None
    root_node, src = parsed
    fn = entrypoints_kotlin.find_enclosing_function(root_node, sink_line)
    if fn is None:
        return None

    src_text = src.decode("utf-8", errors="ignore")
    lines = src_text.splitlines()
    stripped_lines = lexical.strip_comments_and_docstrings(src_text, file.suffix).splitlines()
    source_line = fn.start_point[0] + 1
    source_text = stripped_lines[source_line - 1].strip() if 0 < source_line <= len(lines) else ""
    sink_text = stripped_lines[sink_line - 1].strip() if 0 < sink_line <= len(lines) else ""
    return [
        Step(kind="source", line=source_line, code=source_text),
        Step(kind="sink", line=sink_line, code=sink_text),
    ]


# --------------------------------------------------------------------------
# IDOR-fix milestone, Fix 1: a tenancy-evidence confidence gate.
#
# The problem, measured on a real 36-repo corpus (bench/FINAL_STATUS.md
# section 4): TAINT-IDOR fired 295 times, ~281 (95%) of them false positives
# on genuinely single-tenant/local-only tools (an IDA Pro plugin scoring
# memory addresses, an RSS-search relevance-ranking loop, a home-automation
# add-on manager, a raw Redis key-value proxy) where "no ownership check on
# a data-access call" is meaningless -- there is no second tenant/owner for
# an object-level check to protect against in the first place. No amount of
# widening IDOR_AUTH_CHECK_NAMES (Fix 2, above) fixes this class of noise,
# because the bug isn't "a check exists but isn't recognized" -- it's "there
# is nothing here that needs a check".
#
# This gate asks, once per PROJECT (see _nearest_project_root below for why
# not once per repo): is there ANY real evidence this codebase distinguishes
# between different callers/tenants at all? If none of the signals below are
# found anywhere in the project, every TAINT-IDOR finding in it is
# downgraded to confidence="very-low" and, by default, dropped from the
# returned findings entirely -- recoverable with `include_low_confidence=True`
# (threaded from the CLI's `--include-low-confidence` flag) for a reviewer
# who wants to see them anyway.
#
# The four signals (deliberately conjunctive per-signal, disjunctive across
# signals -- ANY one found is enough to treat the project as evidenced):
#
#   1. A multi-tenant identifier (user_id/org_id/tenant_id/account_id/
#      workspace_id/customer_id) used as a function PARAMETER (so its value
#      varies per call) AND separately used in a comparison (==/!=) or an
#      ORM filter/where kwarg ANYWHERE in the project. Requiring BOTH halves
#      is the fix for the single-global-config-value trap found during this
#      milestone's own validation: redis/mcp-redis's entraid_auth.py has
#      `tenant_id` all over it, but only ever as a SINGLE Azure-AD tenant
#      the whole server authenticates AS (`ENTRAID_CFG["tenant_id"]`, set
#      once from an env var) -- never compared against a caller-supplied
#      value. The id-as-parameter half is what a single fixed config value
#      never satisfies; the comparison half is what tells apart "used to
#      pick a caller's own record" from "just threaded through unchanged".
#   2. A conventionally-named user/session/auth/tenant/permission/model
#      file (exact basename stem, e.g. `auth.py`, `models.py`, `session.py`
#      -- see _TENANCY_MODEL_FILE_STEMS's own comment for why this is an
#      EXACT-stem, not substring, match).
#   3. An import of a real multi-tenant/identity-provider framework or
#      library (Django's auth app, django-tenants, FastAPI Users, Auth0,
#      Keycloak, Clerk, Supabase auth, Casbin, ...).
#   4. A multi-credential / credential-per-caller pattern (a plural
#      "API_KEYS"-shaped config, an explicit "per-user/per-tenant API key"
#      comment) -- weaker and rarer in practice than the other three, kept
#      mainly for the config-driven multi-tenant proxy shape (each caller
#      gets its own key) that doesn't necessarily also have an ORM or a
#      framework import. Deliberately does NOT match a bare
#      `credentials.get(...)` call -- tried during this milestone's own
#      validation and found to false-match homeassistant-ai/ha-mcp's OAuth
#      AUTHORIZATION-SERVER code (`self.ha_credentials.get(client_id)`,
#      looking up ONE registered OAuth client's credentials by client_id).
#      That is genuinely "more than one credential exists", but for WHICH
#      THIRD-PARTY APP may call the add-on's API, not for whose DATA a
#      resource belongs to -- the underlying Home Assistant installation's
#      data is still single-tenant regardless of how many OAuth clients
#      (Claude, ChatGPT, ...) are registered to reach it. A bare
#      `.get(`-shaped lookup is too generic to tell those two things apart,
#      so this signal is restricted to shapes that are hard to produce by
#      accident (a literal plural constant name, or an explicit
#      per-user/per-tenant comment).
#
# Every one of these is itself a heuristic with its own honest false-negative
# risk, stated plainly rather than buried: a genuinely multi-tenant service
# that names its identifiers something else entirely (`acct`, `cid`, a
# custom `Principal` type with no file named after it, an in-house
# authorization library this list has never heard of) produces NONE of these
# four signals and would have its real TAINT-IDOR findings silently
# downgraded and hidden by default -- exactly the tradeoff
# MILESTONE_IDOR_FIX_STATUS.md documents and the task asked to be honest
# about. `--include-low-confidence` exists specifically so that tradeoff is
# recoverable, not permanent data loss.
_PROJECT_MARKER_FILES = ("pyproject.toml", "setup.py", "setup.cfg", "Pipfile", "package.json", "go.mod", "Cargo.toml")

# Directories that are noise for this purpose (vendored/third-party code,
# build output, dependency installs) -- a vendored copy of an unrelated
# library's own auth.py (confirmed real case during validation:
# homeassistant-ai/ha-mcp bundles a vendored `websockets` package whose OWN
# generic basic-auth helper lives at `_vendor/websockets/auth.py`, nothing
# to do with ha-mcp's own single-installation threat model) must not count
# as evidence of the SCANNED project's own tenancy model.
_TENANCY_EXCLUDE_DIR_NAMES = frozenset({
    ".git", ".venv", "venv", "env", "node_modules", "site-packages", "dist", "build",
    "_vendor", "vendor", "third_party", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache",
    ".ruff_cache",
})

_TENANCY_ID_NAMES = ("user_id", "org_id", "tenant_id", "account_id", "workspace_id", "customer_id")
_TENANCY_ID_ALT = "|".join(_TENANCY_ID_NAMES)
# Half 1: the id appears as a function PARAMETER -- i.e. a value that varies
# per call, not a single value threaded in from one place (a module-level
# constant, an env-var read into a config dict, ...).
_TENANCY_ID_PARAM_RE = re.compile(rf"def\s+\w+\s*\([^)]*\b(?:{_TENANCY_ID_ALT})\b")
# Half 2: the id is actually USED to distinguish one caller/record from
# another -- a comparison, or an ORM filter/where keyed by it. A bare
# pass-through (`fields["user_id"] = user_id`, `kwargs.get("tenant_id")`)
# does NOT match this half, which is deliberate: passing a value through
# unchanged is not evidence it is ever checked against anything.
_TENANCY_ID_COMPARISON_RE = re.compile(
    rf"\b(?:{_TENANCY_ID_ALT})\b\s*(?:==|!=)"
    rf"|\.(?:filter|filter_by|where)\([^)]*\b(?:{_TENANCY_ID_ALT})\b\s*="
)

# Exact basename stems (case-insensitive, extension stripped) -- NOT a
# substring match. Deliberately excludes near-misses confirmed during
# validation to be poor evidence of THIS project's own multi-tenancy:
# `auth_native.py` (homeassistant-ai/ha-mcp's own OAuth RESOURCE-SERVER
# helper for its single HA instance -- authentication, not multi-tenant
# object scoping) and `auth_context.py`/`session_registry.py`-style
# compound names, which a substring match on "auth"/"session" would have
# wrongly swept in.
_TENANCY_MODEL_FILE_STEMS = frozenset({
    "auth", "authentication", "authn", "authz", "session", "sessions",
    "user", "users", "account", "accounts", "tenant", "tenants",
    "permission", "permissions",
})
# "models.py"/"models" is handled SEPARATELY, by content not just filename --
# confirmed during round-40 corpus validation to be far too generic a
# basename on its own: mukul975/cve-mcp-server's models.py is a set of
# Pydantic schemas for PUBLIC CVE records (CVSSData, CVERecord) with no
# tenant/owner concept whatsoever, and "models.py" is an extremely common
# filename in Django/FastAPI/Pydantic projects regardless of whether the
# app is multi-tenant at all. So a bare "models.py" only counts as evidence
# when it ALSO defines a class that looks like an identity/tenancy model.
_TENANCY_MODEL_CLASS_RE = re.compile(
    r"class\s+\w*(?:User|Account|Tenant|Organization|Org|Workspace|Member|Customer|Session)\w*\s*[(:]"
)

_TENANCY_IMPORT_RE = re.compile(
    r"^\s*(?:from|import)\s+("
    r"django\.contrib\.auth|django_tenants|django_multitenant|django_organizations|"
    r"flask_login|flask_multipass|fastapi_users|authlib|oauthlib|python_keycloak|keycloak|"
    r"auth0|okta|clerk_backend_api|firebase_admin\.auth|supabase|casbin|permit|oso|cerbos"
    r")\b",
    re.MULTILINE,
)

_TENANCY_MULTI_CREDENTIAL_RE = re.compile(
    r"\bAPI_KEYS\b|\bapi_keys\s*[:=]\s*[\{\[]|for\s+\w+\s+in\s+\w*api_keys|"
    r"per[-_]?(?:user|tenant|caller)\s+api\s+key",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class TenancyEvidence:
    """One project's tenancy-signal scan result. `any_signal` is what the
    gate actually acts on; the four booleans are kept individually so
    MILESTONE_IDOR_FIX_STATUS.md's own before/after numbers can be broken
    down by which signal fired, and so a caller debugging a surprising
    suppression can see exactly why."""

    id_param_and_comparison: bool
    model_file: bool
    framework_import: bool
    multi_credential: bool

    @property
    def any_signal(self) -> bool:
        return self.id_param_and_comparison or self.model_file or self.framework_import or self.multi_credential


def _nearest_project_root(file: Path, scan_root: Path) -> Path:
    """Walk UP from `file`'s own directory to `scan_root`, returning the
    first directory carrying a recognized project marker (pyproject.toml,
    setup.py, package.json, ...); falls back to `scan_root` itself if none
    is found by the time the walk reaches it.

    This is NOT the same thing as scoping a taint RULE to one file (see
    generate_taint_rule_yaml's own docstring for that, unrelated, fix) --
    it is scoping a TENANCY-EVIDENCE scan to the right subtree, which matters
    for exactly the same underlying reason: a single git clone can hold more
    than one independent piece of software. Confirmed real case found while
    building this gate: IBM/mcp-context-forge is one repo containing BOTH a
    genuinely multi-tenant gateway product (`mcpgateway/`, its own
    `pyproject.toml` at the repo root) AND a bundled, single-tenant demo tool
    (`mcp-servers/python/mcp-rss-search/`, its OWN separate `pyproject.toml`)
    that is one of this milestone's three confirmed false positives. Scanning
    the whole repo root for tenancy evidence would see the real gateway's
    auth model and never downgrade the unrelated rss-search false positive
    living in the same clone. Walking up only to the NEAREST project marker
    keeps the two correctly separated -- verified directly against this real
    repo layout before writing this function, not assumed.
    """
    try:
        file = file.resolve()
        scan_root = scan_root.resolve()
    except OSError:
        return scan_root
    cur = file.parent
    while True:
        if any((cur / marker).is_file() for marker in _PROJECT_MARKER_FILES):
            return cur
        if cur == scan_root or scan_root not in cur.parents:
            break
        cur = cur.parent
    return scan_root


def _scan_project_for_tenancy_evidence(project_root: Path) -> TenancyEvidence:
    """Lexical, repo-wide scan for the four signals described in this
    section's own module comment above. This is NOT taint-following and NOT
    cross-file import resolution (both stay out of this milestone's scope,
    same as everywhere else in this file) -- it is a plain text/regex sweep
    over every .py file under `project_root`, looking for VOCABULARY that
    indicates multiple tenants/callers exist at all, not tracing any
    specific value's flow.
    """
    id_param_seen = False
    id_comparison_seen = False
    model_file_seen = False
    framework_import_seen = False
    multi_credential_seen = False

    for py_file in project_root.rglob("*.py"):
        if any(part in _TENANCY_EXCLUDE_DIR_NAMES for part in py_file.parts):
            continue
        try:
            if py_file.stat().st_size > 2_000_000:  # skip pathological single files
                continue
            text = py_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        stem = py_file.stem.lower()
        if stem in _TENANCY_MODEL_FILE_STEMS:
            model_file_seen = True
        elif stem == "models" and _TENANCY_MODEL_CLASS_RE.search(text):
            model_file_seen = True
        if not id_param_seen and _TENANCY_ID_PARAM_RE.search(text):
            id_param_seen = True
        if not id_comparison_seen and _TENANCY_ID_COMPARISON_RE.search(text):
            id_comparison_seen = True
        if not framework_import_seen and _TENANCY_IMPORT_RE.search(text):
            framework_import_seen = True
        if not multi_credential_seen and _TENANCY_MULTI_CREDENTIAL_RE.search(text):
            multi_credential_seen = True

        if model_file_seen and id_param_seen and id_comparison_seen and framework_import_seen and multi_credential_seen:
            break  # every signal already found -- no need to keep reading files

    return TenancyEvidence(
        id_param_and_comparison=id_param_seen and id_comparison_seen,
        model_file=model_file_seen,
        framework_import=framework_import_seen,
        multi_credential=multi_credential_seen,
    )


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------


def _cross_file_origin_steps(hop: cross_file.CrossFileHop, root: Path) -> list[Step]:
    """The two Steps prepended ahead of a hop-derived finding's own
    (target-file) reconstructed path: the origin entrypoint's own "source"
    step (for full auditability -- this parameter really did start at a
    real, Stage-1-recovered MCP handler) and a `cross_file_call` step
    documenting exactly which call made the jump and which parameter(s)
    were mapped. See `find_python_cross_file_hops`/`find_js_cross_file_hops`
    in cross_file.py for how `hop` was built."""
    ep = hop.origin_entrypoint
    origin_rel = _relpath(ep.file, root)
    target_rel = _relpath(hop.target_file, root)
    return [
        Step(
            kind="source",
            line=ep.line,
            code=f"{ep.function_name}({', '.join(ep.parameter_names)})",
            note="MCP tool handler parameter(s), recovered in Stage 1 -- this is the ORIGIN entrypoint; "
            "the finding below was resolved one hop away, see the cross_file_call step immediately "
            "after this one",
            file=origin_rel,
        ),
        Step(
            kind="cross_file_call",
            line=hop.call_line,
            code=hop.call_code,
            note=f"single-hop cross-file resolution: jumps into {hop.target_function_name}(...) in "
            f"{target_rel}, mapped parameter(s): {', '.join(hop.mapped_params)} -- bounded to exactly "
            f"one hop by design, see cross_file.py's module docstring",
            file=origin_rel,
        ),
    ]


def _findings_from_raw(
    raw_results: list[dict],
    by_rule_id: dict[str, _VulnClass],
    reconstruct: Callable[[Path, int, _VulnClass, Path], list[Step] | None],
    root: Path,
    include_low_confidence: bool = False,
    hop_index: dict[tuple[Path, int], cross_file.CrossFileHop] | None = None,
) -> list[SourceFinding]:
    """Shared by both the Python and JS/TS passes below: turn semgrep's raw
    per-rule hits into `SourceFinding` objects, deduplicating and
    reconstructing an evidence path for each. `reconstruct` is
    `reconstruct_path` (Python/ast) or `reconstruct_path_js` (tree-sitter)
    -- the two differ only in which language they walk, not in how a hit
    becomes a finding.

    `include_low_confidence` controls the Fix-1 tenancy gate immediately
    below: it only ever matters for TAINT-IDOR (the only absence_based class
    today), so it is a silent no-op for every other rule and for the JS/TS
    pass (`_VULN_CLASSES_JS` has no absence_based class at all).

    `hop_index` (cross-file milestone) maps `(target_file, target_function_
    start_line)` to the `CrossFileHop` that caused `target_file`'s own
    per-file rule to source from a MAPPED parameter instead of a real
    Stage-1 entrypoint's own parameters (see `run_static_taint_scan`). When
    a raw hit's reconstructed path starts inside such a function (its own
    leading "source" Step's line -- always the enclosing function's start
    line -- matches a hop target), the origin entrypoint's own context is
    prepended ahead of it, purely for evidence/auditability; the
    absence-based "was a check found" decision above is still made on the
    UN-prepended, target-file-only `path_steps` (a real check would live on
    that same reconstructed path already; the prepended origin steps never
    contain one by construction).
    """
    hop_index = hop_index or {}
    findings: list[SourceFinding] = []
    seen: set[tuple[str, int, str]] = set()
    tenancy_cache: dict[Path, TenancyEvidence] = {}
    for result in raw_results:
        # Rule ids are generated as "<vuln-class>[-js]-<file-index>" (see
        # generate_taint_rule_yaml{,_js}'s per-file scoping) -- strip the
        # trailing "-<index>" to map back to the vulnerability class.
        raw_check_id = result.get("check_id", "").rsplit(".", 1)[-1]
        check_id = raw_check_id.rsplit("-", 1)[0]
        vc = by_rule_id.get(check_id)
        if vc is None:
            continue

        path = Path(result["path"])
        line = result["start"]["line"]
        key = (str(path), line, vc.rule_id)
        if key in seen:
            continue
        seen.add(key)

        try:
            rel = str(path.relative_to(root))
        except ValueError:
            rel = str(path)

        path_steps = reconstruct(path, line, vc, root)

        # TAINT-IDOR (currently the only absence_based class): semgrep was
        # deliberately asked to fire on every reachable hit regardless of
        # whether a check exists (see _IDOR's own module comment) -- the
        # actual "was a check found?" decision happens here, in Python, by
        # inspecting what the reconstruction pass already recorded. A
        # recognized check found anywhere on the path means: don't emit.
        # This is the ONLY vuln class in this file where a semgrep hit does
        # not automatically become a finding. `_VULN_CLASSES_JS` does not
        # include an absence_based class, so this is a no-op on the JS/TS
        # pass (reconstruct=reconstruct_path_js) -- kept here rather than
        # duplicated per-language since the check only inspects `path_steps`,
        # not which language produced them. Deliberately checked on the
        # UN-prepended path_steps (see this function's own docstring).
        if vc.absence_based and _path_has_recognized_check(path_steps):
            continue

        if path_steps:
            for s in path_steps:
                s.file = rel

        hop = hop_index.get((path, path_steps[0].line)) if path_steps else None
        if hop is not None:
            path_steps = _cross_file_origin_steps(hop, root) + path_steps

        weak_note = ""
        if path_steps and path_steps[-1].note:
            weak_note = " " + path_steps[-1].note

        evidence_line = path_steps[-1].code if path_steps else ""

        description = (
            f"An MCP tool handler parameter, recovered by this project's own entrypoint-"
            f"recovery pass (not a generic 'any function argument' source), flows into "
            f"this sink via semgrep's intra-procedural taint analysis with no recognized "
            f"strong sanitizer clearing it.{weak_note}"
        )
        confidence = "high"
        if hop is not None:
            description += (
                f" This finding is CROSS-FILE (bounded single-hop resolution, see "
                f"cross_file.py): the tainted parameter originates in "
                f"{hop.origin_entrypoint.function_name}(...) in {_relpath(hop.origin_entrypoint.file, root)}, "
                f"a real MCP tool handler, and reaches this sink after being forwarded, one hop, into "
                f"{hop.target_function_name}(...) here -- see the taint_path's own cross_file_call step "
                f"for the exact jump."
            )
        if vc.absence_based:
            confidence = "low"
            description += (
                " No authorization/ownership-check call was found anywhere on this "
                "reconstructed path -- this is a LOWER-CONFIDENCE, absence-based signal "
                "(the sink itself is an ordinary data-access call, not an inherently "
                "dangerous one): a real check this intra-procedural, same-file pass "
                "cannot see (a middleware, or a check inside a helper function in "
                "another file) would be a false negative here, not a bug in this "
                "finding, so treat this as a lead to confirm by reading the function and "
                "its call chain, not a proof -- may be a false negative if the check "
                "happens elsewhere."
            )

            # Fix 1 (IDOR-fix milestone): a tenancy-evidence confidence gate,
            # scoped to the finding's own nearest project (see
            # _nearest_project_root's docstring for why not the whole scan
            # root). No signal found anywhere in the project => there is no
            # measured evidence this codebase has more than one tenant/owner
            # at all, so "missing an ownership check" is a much weaker claim
            # here than IDOR_AUTH_CHECK_NAMES's own absence-based caveat
            # already states -- downgrade to "very-low" and, unless the
            # caller opted in via include_low_confidence, drop the finding
            # rather than report it as if it carried the same weight as an
            # absence-based finding in a codebase actually shown to be
            # multi-tenant.
            project_root = _nearest_project_root(path, root)
            evidence = tenancy_cache.get(project_root)
            if evidence is None:
                evidence = _scan_project_for_tenancy_evidence(project_root)
                tenancy_cache[project_root] = evidence
            if not evidence.any_signal:
                if not include_low_confidence:
                    continue
                confidence = "very-low"
                description += (
                    " Additionally: no evidence of multi-tenancy (a user_id/org_id/"
                    "tenant_id/account_id/workspace_id compared or filtered against a "
                    "caller identity, a user/session/auth model file, a multi-tenant "
                    "framework import, or a multi-credential pattern) was found anywhere "
                    "in this project -- this may well be a single-tenant/local-only tool "
                    "where 'no ownership check' is not a real bug (see "
                    "bench/MILESTONE_IDOR_FIX_STATUS.md). Shown only because "
                    "--include-low-confidence was requested; suppressed by default."
                )

        if vc.extra_caveat:
            description += " " + vc.extra_caveat

        findings.append(
            SourceFinding(
                rule_id=vc.rule_id,
                severity=vc.severity,
                title=vc.title,
                description=description,
                location=f"{rel}:{line}",
                evidence=evidence_line,
                remediation=vc.remediation,
                cvss_score=vc.cvss,
                tier="S",
                taint_path=[asdict(s) for s in path_steps] if path_steps else None,
                # `confidence` already encodes the absence_based/tenancy-gate
                # logic above (high / low / very-low); `confidence_override`
                # (currently only TAINT-CREDFWD-JS-WRAPPER, never absence_based)
                # takes precedence over that when set -- the two features are
                # mutually exclusive per vuln class today, but written this way
                # so that stays true by construction rather than by coincidence.
                confidence=vc.confidence_override or confidence,
            )
        )

    return findings


def run_static_taint_scan(root: str | Path, include_low_confidence: bool = False) -> list[SourceFinding]:
    """Run the full Stage 1-3 pipeline against a source tree and return
    tier="S" SourceFinding objects, covering Python, JS/TS, Go, AND Kotlin
    files in the same call (see this module's docstring). Returns [] (never
    raises) if no MCP entrypoints are recovered in any language or semgrep
    is unavailable -- this is an additive scan mode, not a replacement for
    scan_source_tree(). The Go pass (see entrypoints_go.py, wired in as
    part of the v10 consolidation merge -- bench/FINAL_COMPLETE_V10_STATUS.md)
    and the Kotlin pass (see entrypoints_kotlin.py) both cover only the 3
    hard-sink classes (CMDI/PATHTRAV/SSRF), with no cross-file hop synthesis
    and no TAINT-CREDFWD/TAINT-IDOR port -- see bench/GO_TAINT_RULES_STATUS.md/
    bench/KOTLIN_SUPPORT_STATUS.md for each language's own stated scope.

    `include_low_confidence` (default False, matching the CLI's own default):
    IDOR-fix milestone's Fix 1 tenancy gate (see the module comment above
    `_findings_from_raw`) suppresses a TAINT-IDOR finding by default when its
    own project has no measured evidence of multi-tenancy at all. Pass True
    to see those findings anyway, downgraded to confidence="very-low" rather
    than silently dropped. No effect on any other rule -- CMDI/PATHTRAV/SSRF/
    CREDFWD are not absence_based and are never gated.
    """
    root = Path(root)
    findings: list[SourceFinding] = []

    py_entrypoints = recover_entrypoints(root)
    # Cross-file milestone: for each REAL entrypoint, look for a call that
    # forwards its own parameter(s) into a function imported from another
    # file in this repo, and synthesize an additional entrypoint for that
    # callee -- fed into the SAME per-file rule generation below, so a
    # genuinely cross-file source-to-sink flow gets a real chance at a
    # semgrep hit in the callee's own file. `hop_index` lets
    # `_findings_from_raw` recognize which findings came from one of these
    # synthetic entrypoints (keyed by the callee's own file + start line)
    # and prepend the origin's context. See cross_file.py.
    py_hops = cross_file.find_python_cross_file_hops(py_entrypoints, root)
    py_hop_index = {(h.target_file, h.target_line): h for h in py_hops}
    py_rule_entrypoints = [*py_entrypoints, *(h.synthetic_entrypoint for h in py_hops)]
    py_rule_yaml = generate_taint_rule_yaml(py_rule_entrypoints, root)
    if py_rule_yaml is not None:
        py_by_rule_id = {vc.rule_id.lower(): vc for vc in _VULN_CLASSES}
        findings.extend(
            _findings_from_raw(
                _run_semgrep(root, py_rule_yaml),
                py_by_rule_id,
                reconstruct_path,
                root,
                include_low_confidence=include_low_confidence,
                hop_index=py_hop_index,
            )
        )

    try:
        from . import entrypoints_js
    except ImportError as exc:
        print(
            f"Warning: JS/TS static-taint support unavailable ({exc}) -- skipping tier S for "
            f"JS/TS files. Install tree-sitter/tree-sitter-javascript/tree-sitter-typescript "
            f"(bundled with `pip install mcp-safeguard[static-taint]`).",
            file=sys.stderr,
        )
        return findings

    js_entrypoints = entrypoints_js.recover_js_entrypoints(root)
    # Cross-file milestone: same hop-synthesis as the Python pass above, for
    # JS/TS entrypoints -- see cross_file.py.
    js_hops = cross_file.find_js_cross_file_hops(js_entrypoints, root)
    js_hop_index = {(h.target_file, h.target_line): h for h in js_hops}
    js_rule_entrypoints = [*js_entrypoints, *(h.synthetic_entrypoint for h in js_hops)]
    js_rule_yaml = generate_taint_rule_yaml_js(js_rule_entrypoints, root)
    js_raw_results = _run_semgrep(root, js_rule_yaml) if js_rule_yaml is not None else []

    # TAINT-CREDFWD's second, entrypoint-independent rule (see
    # generate_credfwd_any_fn_rule_yaml_js's own docstring) -- merged into
    # the SAME raw-results list, BEFORE _findings_from_raw's dedup, so a
    # location both this rule and the standard per-entrypoint rule above
    # agree on (possible if the vulnerable function happens to also be a
    # recovered entrypoint) is reported once, not twice. Guarded on "at
    # least one JS/TS file exists in this tree at all" -- unlike every other
    # rule in this module, this one does not depend on `js_entrypoints`
    # (its whole point is to work without a recovered entrypoint), so
    # without this cheap guard it would run a full extra semgrep invocation
    # on every single scan, including a pure-Python target with zero JS/TS
    # files -- found while running this milestone's own test suite (304
    # tests, one extra ~0.2s semgrep subprocess each, unconditionally,
    # before this guard was added).
    if next(entrypoints_js.iter_js_files(root), None) is not None:
        js_raw_results += _run_semgrep(root, generate_credfwd_any_fn_rule_yaml_js())

    if js_raw_results:
        js_by_rule_id = {vc.rule_id.lower() + "-js": vc for vc in _VULN_CLASSES_JS}
        js_by_rule_id["taint-credfwd-js-anyfn"] = _CREDFWD_JS
        js_by_rule_id["taint-credfwd-js-anyfn-wrapper"] = _CREDFWD_JS_WRAPPER
        findings.extend(
            _findings_from_raw(
                js_raw_results,
                js_by_rule_id,
                reconstruct_path_js,
                root,
                include_low_confidence=include_low_confidence,
                hop_index=js_hop_index,
            )
        )

    try:
        from . import entrypoints_go
    except ImportError as exc:
        print(
            f"Warning: Go static-taint support unavailable ({exc}) -- skipping tier S for "
            f"Go files. Install tree-sitter/tree-sitter-go "
            f"(bundled with `pip install mcp-safeguard[static-taint]`).",
            file=sys.stderr,
        )
        return findings

    # v10 consolidation-merge fix: sourced from real recovered Go MCP
    # entrypoints (entrypoints_go.py), NOT the go-taint-work milestone's own
    # "any function parameter" fallback (generate_taint_rule_yaml_go_anyfn,
    # kept above for its own regression coverage but never called from
    # here) -- see this module's own "Go source, entrypoint-scoped" comment
    # above generate_taint_rule_yaml_go's definition, and
    # bench/FINAL_COMPLETE_V10_STATUS.md's "Go entrypoints vs Go taint
    # mismatch" section for the full before/after.
    go_entrypoints = entrypoints_go.recover_go_entrypoints(root)
    go_rule_yaml = generate_taint_rule_yaml_go(go_entrypoints, root)
    if go_rule_yaml is not None:
        go_by_rule_id = {vc.rule_id.lower() + "-go": vc for vc in _VULN_CLASSES_GO}
        findings.extend(
            _findings_from_raw(
                _run_semgrep(root, go_rule_yaml),
                go_by_rule_id,
                reconstruct_path_go,
                root,
                include_low_confidence=include_low_confidence,
            )
        )

    try:
        from . import entrypoints_kotlin
    except ImportError as exc:
        print(
            f"Warning: Kotlin static-taint support unavailable ({exc}) -- skipping tier S for "
            f"Kotlin files. Install tree-sitter/tree-sitter-kotlin "
            f"(bundled with `pip install mcp-safeguard[static-taint]`).",
            file=sys.stderr,
        )
        return findings

    kotlin_entrypoints = entrypoints_kotlin.recover_kotlin_entrypoints(root)
    kotlin_rule_yaml = generate_taint_rule_yaml_kotlin(kotlin_entrypoints, root)
    if kotlin_rule_yaml is not None:
        kotlin_by_rule_id = {vc.rule_id.lower() + "-kotlin": vc for vc in _VULN_CLASSES_KOTLIN}
        findings.extend(
            _findings_from_raw(
                _run_semgrep(root, kotlin_rule_yaml),
                kotlin_by_rule_id,
                reconstruct_path_kotlin,
                root,
                include_low_confidence=include_low_confidence,
            )
        )

    return findings


if __name__ == "__main__":
    for f in run_static_taint_scan(sys.argv[1] if len(sys.argv) > 1 else "."):
        print(f"[{f.severity.value}] {f.rule_id} {f.title}\n    {f.location}\n    {f.evidence}\n")
        if f.taint_path:
            for step in f.taint_path:
                print(f"      {step['kind']:>7} L{step['line']}: {step['code']}  {step['note']}")
