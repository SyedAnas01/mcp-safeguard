"""Source-audit mode: scan an MCP server's SOURCE TREE for code-level security
footguns that a config/tool-definition scanner cannot see.

Unlike the other scanners (which read a config JSON of tool definitions), this one
walks a repository and flags patterns in the server's implementation. It is
heuristic (regex over source, not a full type-aware analysis), so findings are
LEADS to confirm by reading the cited file, not proofs. Every rule below was
derived from a real pattern found in an official big-company MCP server.

Rules:
  SRC-001  Auth header re-applied per-request in a Go transport with no CheckRedirect
           -> credential can survive a cross-host redirect (GitHub, Grafana).
  SRC-002  httpx client with follow_redirects=True AND a bearer/Authorization header
           -> Python equivalent of SRC-001 (AWS openapi-mcp).
  SRC-003  SQL "read-only" enforced by string/regex only, with no DB-level read-only
           transaction in the same connection path (AWS keyspaces).
  SRC-004  A server-held credential attached to a connection whose destination host
           is an interpolated, potentially caller-influenced variable.
  SRC-005  An --auth-token/AUTH_TOKEN flag is parsed and only warned about, never
           gated before a network listener starts serving (terminator-mcp-agent).
  SRC-006  A client-supplied resource ID (chat_id/session_id/...) keys shared
           server-side state with no ownership check on that ID (aperag).
  SRC-007  A "detect destructive"/"is_readonly" classifier that only recognizes
           statement-type syntax is trusted as a security gate, missing
           side-effecting calls wrapped in a safe-looking statement shape.
  SRC-008  A client-supplied owner/user_id/tenant field is trusted directly on a
           create/update mutation instead of being derived server-side (metatool-ai).
  SRC-009  Unescaped interpolation into a shell string passed to exec/system,
           while the same repo already has a safe argv/quoting alternative elsewhere.
  SRC-010  A credential/key file is written with no permission hardening, while the
           same repo hardens permissions on other file writes.
  SRC-011  An SSRF guard validates a resolved IP once, but the actual outbound call
           re-resolves the original URL string (DNS-rebinding TOCTOU).
  SRC-012  A manifest/lockfile parser silently drops sentinel-valued entries with
           only debug-level logging before the list reaches a security consumer.

SRC-005..SRC-012 are heuristic in the same sense as SRC-001..004: each is a
regex/text-proximity signal over source, not a type-aware or dataflow analysis.
They are LEADS to confirm by reading the cited file, not proofs. Several
(SRC-009, SRC-010) intentionally fire only when the SAME repository already
demonstrates it knows the safer pattern elsewhere, trading recall for a much
lower false-positive rate. SRC-007 intentionally requires evidence that the
classifier actually gates execution somewhere (not just that the function
exists) before flagging it, precisely to avoid conflating "there is a
type-classifier function" with "the type-classifier is used as a security
control" -- the exact overclaim shape a manual audit must otherwise catch by
hand.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .prompt_injection import Severity


@dataclass
class SourceFinding:
    rule_id: str
    severity: Severity
    title: str
    description: str
    location: str  # file:line
    evidence: str
    remediation: str
    cvss_score: float = 0.0


_GO_AUTH_SET = re.compile(
    r"""\.Header\.(Set|Add)\(\s*["']?[\w.]*[Aa]uthorization""",
)
_GO_ROUNDTRIP = re.compile(r"func\s*\([^)]*\)\s*RoundTrip\(")
_PY_HTTPX_CLIENT = re.compile(r"httpx\.(Async)?Client\(")
_PY_FOLLOW_REDIRECTS_TRUE = re.compile(r"follow_redirects\s*=\s*True")
_PY_AUTH_HEADER = re.compile(r"""["']?[Aa]uthorization["']?\s*[:=]\s*f?["']?Bearer|Bearer\s*\{""")
_SQL_STARTSWITH_SELECT = re.compile(r"""\.startswith\(\s*["']select""", re.IGNORECASE)
_SQL_DB_READONLY = re.compile(
    r"SET\s+TRANSACTION\s+READ\s+ONLY|BEGIN\s+(TRANSACTION\s+)?READ\s+ONLY|READ\s+ONLY\s+TRANSACTION",
    re.IGNORECASE,
)

# SRC-004: a server-held credential (token/secret/api key) is placed as the
# connection password / bearer while the destination host is an interpolated
# variable -> if that host is caller/model-controlled and unvalidated, the
# credential is exfiltrated to an attacker host (confused-deputy). Matches
# connection-string builders that interpolate the target host into one field
# and a bearer/access token into the password field: the C# pattern seen in
# the original finding, and the equivalent Python/JS f-string construction.
_CRED_TO_HOST = re.compile(
    r"(Host|Server|Data\s*Source|Endpoint)\s*=\s*[\{\$]\{?[^}\"'\n]+\}?"
    r".{0,200}?"
    r"(Password|Pwd)\s*=\s*[\{\$]\{?[^}\"'\n]*"
    r"(token|accesstoken|secret|apikey|api_key|credential|bearer)",
    re.IGNORECASE,
)

# SRC-005: an auth flag is parsed and referenced (e.g. printed in a warning) but
# never checked/gated before a network listener starts serving requests.
_AUTH_FLAG_REF = re.compile(r"auth[-_]?token", re.IGNORECASE)
_AUTH_WARN_ONLY = re.compile(
    r"(?:warn!|eprintln!|println!|log::warn|logger\.warning|console\.warn|print)\s*[!(][^\n]{0,120}"
    r"(?:auth|token)",
    re.IGNORECASE,
)
_NETWORK_SERVE_CALL = re.compile(
    r"\b(?:SseServer::serve|HttpServer::new|\.serve\(|\.listen\(|uvicorn\.run\(|app\.run\()"
)
# A "gate" requires an actual enforcement action (exit/return/panic) near the
# flag check -- merely testing .is_none()/.is_some() and then only warning
# (the exact SRC-005 bug shape) must NOT count as a gate.
_AUTH_GATE = re.compile(
    r"auth[-_]?token\b[\s\S]{0,150}?"
    r"(?:std::process::exit|process\.exit|sys\.exit|return\s+Err|panic!)",
    re.IGNORECASE,
)

# SRC-006: a client-supplied resource ID keys shared server-side state
# (a *History/*Store/*Session/*Cache/*Memory constructor) with the ID itself,
# and the file shows no ownership check tying that ID to the caller.
_ID_KEYED_STATE = re.compile(
    r"\b[A-Z]\w*(?:History|Store|Session|Cache|Memory)\(\s*"
    r"(?:session_id|chat_id|conversation_id|connection_id|room_id)\b"
)
_OWNERSHIP_CHECK = re.compile(
    r"\b(?:chat|session|conversation|connection|room)\.(?:owner|user_id|account_id)\b"
    r"|(?:owner_id|user_id|account_id)\s*==\s*(?:current_user|req\.user|ctx\.user|self\.user)",
    re.IGNORECASE,
)

# SRC-007: a "detect destructive"/"is_readonly" classifier trusted as a gate,
# but its body only recognizes statement-type syntax, not side-effecting calls.
_CLASSIFIER_DEF = re.compile(
    r"def\s+(is_read_?only\w*|is_safe\w*|is_destructive\w*|detect_destructive\w*|"
    r"classify_query\w*)\s*\(",
    re.IGNORECASE,
)
_TYPE_ONLY_CHECK = re.compile(
    r"""\.startswith\(\s*["']select|\.type\s*==\s*["']select|"""
    r"""isinstance\([^,]+,\s*(?:exp\.)?Select\)|node_type\s*==\s*["']SELECT["']""",
    re.IGNORECASE,
)
_CALL_NAME_CHECK = re.compile(
    r"setval|nextval|lastval|func(?:tion)?_name|call\.name|FuncCall|\.calls\b",
    re.IGNORECASE,
)
_CLASSIFIER_GATES_EXECUTION = re.compile(
    r"if\s+(?:not\s+)?\w*(?:is_read_?only|is_safe|is_destructive|classify_query)\w*\("
    r"[^)]*\)[\s\S]{0,100}?(?:raise|return|deny|block|reject)",
    re.IGNORECASE,
)

# SRC-008: a client-supplied owner/user_id/tenant field trusted directly on a
# create/update mutation instead of being derived from the authenticated session.
_CLIENT_OWNER_FIELD = re.compile(
    r"\b(?:input|body|req\.body|params)\.(?:user_id|owner_id|account_id|tenant_id)\b"
)
_MUTATION_CALL = re.compile(r"\.(?:create|update|upsert)\s*\(\s*\{")
_SERVER_DERIVED_IDENTITY = re.compile(
    r"\b(?:ctx\.session\.user\.id|ctx\.user\.id|req\.user\.id|ctx\.auth\.userId|"
    r"session\.user\.id)\b"
)

# SRC-009: unescaped interpolation into a shell string passed to exec/system,
# flagged only when the SAME repo also has a safer argv/quoting pattern elsewhere
# (showing the team already knows the risk).
_SHELL_STRING_CALL = re.compile(
    r"(?:child_process\.exec\(|(?<!\.)\bexec\(|subprocess\.run\([^)]*shell\s*=\s*True|"
    r"subprocess\.call\([^)]*shell\s*=\s*True|os\.system\()"
)
_SHELL_INTERP_MARK = re.compile(r"\$\{[^}]+\}|f[\"'][^\"']*\{[^}]+\}")
_SAFE_SHELL_HELPER = re.compile(
    r"\bshellQuote\b|\bescapeShellArg\b|shlex\.quote\(|execFile\(|\bspawn\("
)

# SRC-010: a credential/key file write with no permission hardening nearby,
# flagged only when the SAME repo hardens permissions on some other file write.
_SENSITIVE_FILE_WRITE = re.compile(
    r"""(?:WriteFile\(|writeFileSync\(|\.write\(to:)[^\n]{0,120}"""
    r"""(?:key|secret|token|credential|auth|\.p8|\.pem)""",
    re.IGNORECASE,
)
_PERM_HARDEN = re.compile(
    r"chmod|setAttributes\(\.posixPermissions|0o600|0o700|FileMode\(0o?600\)",
    re.IGNORECASE,
)

# SRC-011: an SSRF guard validates a resolved IP once, but the outbound call
# re-resolves the original URL string instead of connecting to a pinned IP.
_SSRF_VALIDATE_CALL = re.compile(
    r"\b(?:validate_url|check_ssrf|is_safe_url|validate_host|resolve_and_check)\w*\(",
    re.IGNORECASE,
)
_SSRF_RAW_FETCH_CALL = re.compile(
    r"\b(?:requests\.get|requests\.post|http\.Get|http\.Post|fetch)\s*\(\s*"
    r"(?:url|target_url|original_url)\b",
    re.IGNORECASE,
)
_SSRF_PINNED_FETCH = re.compile(
    r"resolved_ip|pinned_ip|validated_ip|DialContext|Transport\{|dialer\.Dial",
    re.IGNORECASE,
)

# SRC-012: a manifest/lockfile entry loop drops sentinel-valued entries
# (unresolved version, empty field) with only debug-level logging.
_SENTINEL_COND = re.compile(
    r"""if\s+[\w.]*(?:version|resolved|value)[\w.]*\s*(?:==\s*["'](?:unknown|0\.0\.0|)["']|"""
    r"""is\s+(?:None|null))""",
    re.IGNORECASE,
)
_SENTINEL_SKIP_BRANCH = re.compile(r"\b(?:continue|return\s+None|del\s+\w+\[)\b")
_DEBUG_ONLY_LOG = re.compile(r"\b(?:log\.debug|logger\.debug|logging\.debug|debug!|trace!)\s*\(", re.IGNORECASE)
_WARN_OR_ERROR_LOG = re.compile(
    r"\b(?:log\.warn|logger\.warning|logging\.warning|warn!|log\.error|logger\.error|error!)\s*\(",
    re.IGNORECASE,
)

_SRC_EXTS = {".go", ".py", ".ts", ".js", ".cs", ".rs", ".swift"}
# Matched against whole PATH COMPONENTS (via Path.parts), not a substring of
# the stringified path. Substring matching on e.g. "/test" also matches any
# directory that merely starts with "test" (a real "testUtils/" package, or
# pytest's own tmp_path dirs, named "test_<function name>...") and, for a
# relative root path, a top-level "tests/" dir has no leading slash to match
# against at all -- both silently skip real source. Component matching is
# exact and immune to both.
_SKIP_DIRS = {"node_modules", "dist", "vendor", ".git", "__pycache__", "test", "tests"}


def _iter_source(root: Path):
    for p in root.rglob("*"):
        if p.suffix not in _SRC_EXTS or not p.is_file():
            continue
        if any(part in _SKIP_DIRS for part in p.relative_to(root).parts[:-1]):
            continue
        if p.stem.endswith("_test"):
            continue
        try:
            yield p, p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue


def _line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def scan_source_tree(root: str | Path) -> list[SourceFinding]:
    """Walk a source tree and return heuristic code-level security findings."""
    root = Path(root)
    findings: list[SourceFinding] = []

    # Materialize once: SRC-009/SRC-010 need a repo-wide signal (does this repo
    # demonstrate the safer pattern *anywhere*?) before flagging a per-file match.
    files = list(_iter_source(root))
    repo_has_safe_shell_helper = any(_SAFE_SHELL_HELPER.search(text) for _, text in files)
    repo_hardens_perms_somewhere = any(_PERM_HARDEN.search(text) for _, text in files)

    for path, text in files:
        rel = str(path.relative_to(root)) if path.is_relative_to(root) else str(path)

        # SRC-001 (Go): a RoundTrip that sets Authorization, in a file whose
        # package sets no CheckRedirect -> auth may survive a cross-host redirect.
        if path.suffix == ".go" and _GO_ROUNDTRIP.search(text):
            m = _GO_AUTH_SET.search(text)
            if m and "CheckRedirect" not in text:
                findings.append(SourceFinding(
                    "SRC-001", Severity.MEDIUM,
                    "Auth header re-applied in transport without redirect guard",
                    "A custom http.RoundTripper sets the Authorization header on every "
                    "round-trip and no CheckRedirect drops it on host change. Go strips "
                    "auth on cross-host redirects only for headers set on the original "
                    "request; a transport that re-adds it defeats that, so a redirect can "
                    "forward the credential to a foreign host.",
                    f"{rel}:{_line_of(text, m.start())}",
                    text[max(0, m.start() - 40):m.start() + 60].strip(),
                    "Add a CheckRedirect to the wrapping http.Client that removes the "
                    "Authorization header when the redirect target host differs.",
                    6.5,
                ))

        # SRC-002 (Python): httpx client with follow_redirects=True and a bearer header.
        if path.suffix == ".py" and _PY_HTTPX_CLIENT.search(text):
            if _PY_FOLLOW_REDIRECTS_TRUE.search(text) and _PY_AUTH_HEADER.search(text):
                m = _PY_FOLLOW_REDIRECTS_TRUE.search(text)
                findings.append(SourceFinding(
                    "SRC-002", Severity.MEDIUM,
                    "httpx client follows redirects while carrying a bearer token",
                    "An httpx client is created with follow_redirects=True and an "
                    "Authorization/Bearer header. httpx keeps client headers across "
                    "redirects and does not strip auth on host change, so a redirect can "
                    "leak the token to a foreign host.",
                    f"{rel}:{_line_of(text, m.start())}",
                    text[max(0, m.start() - 40):m.start() + 40].strip(),
                    "Set follow_redirects=False, or add an event hook that strips the "
                    "Authorization header when the redirect host differs.",
                    6.5,
                ))

        # SRC-003 (SQL read-only by string check only, no DB-level read-only txn).
        if _SQL_STARTSWITH_SELECT.search(text) and not _SQL_DB_READONLY.search(text):
            m = _SQL_STARTSWITH_SELECT.search(text)
            findings.append(SourceFinding(
                "SRC-003", Severity.HIGH,
                "SQL read-only enforced by string prefix check only",
                "Read-only mode is gated on the query text starting with 'select' with "
                "no database-level read-only transaction (SET TRANSACTION READ ONLY / "
                "BEGIN READ ONLY) in this file. Prefix/keyword checks are defeated by "
                "leading comments, CTEs that write, and stacked statements.",
                f"{rel}:{_line_of(text, m.start())}",
                text[max(0, m.start() - 30):m.start() + 40].strip(),
                "Enforce read-only at the database layer (read-only transaction or a "
                "read-only role/login), not only by inspecting the query string.",
                7.5,
            ))

        # SRC-004: server-held credential sent to an interpolated (possibly
        # caller-controlled) destination host.
        for m in _CRED_TO_HOST.finditer(text):
            findings.append(SourceFinding(
                "SRC-004", Severity.HIGH,
                "Credential attached to a caller-influenced destination host",
                "A token/secret/API key is placed as the connection password (or "
                "bearer) while the destination host is an interpolated variable. If "
                "that host comes from a tool argument and is not validated against an "
                "allowlist, a caller (e.g. via prompt injection) can point it at an "
                "attacker host and receive the credential (confused-deputy). Confirm "
                "the host variable is pinned to a trusted allowlist before the "
                "credential is attached.",
                f"{rel}:{_line_of(text, m.start())}",
                text[m.start():m.start() + 90].strip(),
                "Never send a credential to a caller-influenced destination: resolve "
                "the host from trusted config/ARM or validate it against an allowlist, "
                "or withhold the credential when the host is not the trusted one.",
                7.5,
            ))

        # SRC-005: auth flag parsed and only warned about, never gated before serve.
        if (
            _AUTH_FLAG_REF.search(text)
            and _NETWORK_SERVE_CALL.search(text)
            and _AUTH_WARN_ONLY.search(text)
            and not _AUTH_GATE.search(text)
        ):
            m = _AUTH_WARN_ONLY.search(text)
            findings.append(SourceFinding(
                "SRC-005", Severity.HIGH,
                "Auth flag parsed and warned about, never enforced before serving",
                "An auth-token flag/env var is parsed and referenced (e.g. in a "
                "startup warning), but no comparison, unwrap, or exit on it gates "
                "the network listener in this file. Any client can connect and "
                "call tools -- the flag documents intent to require auth without "
                "actually requiring it.",
                f"{rel}:{_line_of(text, m.start())}",
                text[max(0, m.start() - 30):m.start() + 90].strip(),
                "Before calling serve()/listen(), check the token/flag and refuse "
                "to start (or reject unauthenticated requests) when it is unset or "
                "does not match an incoming request's credential.",
                7.5,
            ))

        # SRC-006: client-supplied resource ID keys shared state, no ownership check.
        m = _ID_KEYED_STATE.search(text)
        if m and not _OWNERSHIP_CHECK.search(text):
            findings.append(SourceFinding(
                "SRC-006", Severity.HIGH,
                "Client-supplied resource ID keys shared state with no ownership check",
                "A session/chat/connection ID taken from the request is used "
                "directly to construct or key shared server-side state (history, "
                "store, cache), with no check in this file that the caller owns "
                "that ID. A caller who guesses or reuses another user's ID can "
                "read or write that user's state.",
                f"{rel}:{_line_of(text, m.start())}",
                text[max(0, m.start() - 20):m.start() + 90].strip(),
                "Verify the authenticated caller owns the resource ID (look it up "
                "scoped to the caller's account) before using it to key shared "
                "state, the same way you would validate any other foreign ID.",
                7.5,
            ))

        # SRC-007: statement-type classifier trusted as a security gate, but it
        # only recognizes syntax shape, not side-effecting function calls.
        cm = _CLASSIFIER_DEF.search(text)
        if cm:
            body = text[cm.start():cm.start() + 1500]
            if (
                _TYPE_ONLY_CHECK.search(body)
                and not _CALL_NAME_CHECK.search(body)
                and _CLASSIFIER_GATES_EXECUTION.search(text)
            ):
                findings.append(SourceFinding(
                    "SRC-007", Severity.HIGH,
                    "Read-only/destructive classifier recognizes syntax, not calls",
                    "A function used to gate execution (confirmed: something in "
                    "this file checks its result before raising/blocking) decides "
                    "safety by statement-type/keyword or AST-node-type matching "
                    "only, with no check of function/procedure calls inside the "
                    "statement. A syntactically 'read' statement can still invoke "
                    "a side-effecting function (e.g. a SELECT wrapping setval()), "
                    "which this classifier will not catch.",
                    f"{rel}:{_line_of(text, cm.start())}",
                    text[cm.start():cm.start() + 90].strip(),
                    "Also check called function/procedure names against a "
                    "denylist (or better, an allowlist of known-safe calls) inside "
                    "the statement, not just its outermost statement type.",
                    7.5,
                ))

        # SRC-008: client-supplied owner/user_id trusted directly on a mutation.
        om = _CLIENT_OWNER_FIELD.search(text)
        if om and _MUTATION_CALL.search(text) and not _SERVER_DERIVED_IDENTITY.search(text):
            findings.append(SourceFinding(
                "SRC-008", Severity.HIGH,
                "Client-supplied ownership field trusted on create/update",
                "A create/update handler reads an ownership-designating field "
                "(user_id/owner_id/account_id/tenant_id) directly from client "
                "input, with no server-side derivation from the authenticated "
                "session anywhere in this file. A caller can set that field to "
                "another user's ID and write records attributed to them.",
                f"{rel}:{_line_of(text, om.start())}",
                text[max(0, om.start() - 20):om.start() + 80].strip(),
                "Derive the ownership field exclusively from the authenticated "
                "session/token server-side; ignore or reject a client-supplied "
                "value for it.",
                8.1,
            ))

        # SRC-009: unescaped shell interpolation, flagged only when this repo
        # already has a safer argv/quoting pattern elsewhere (known risk).
        if repo_has_safe_shell_helper:
            sm = _SHELL_STRING_CALL.search(text)
            if sm:
                window = text[sm.start():sm.start() + 200]
                if _SHELL_INTERP_MARK.search(window):
                    findings.append(SourceFinding(
                        "SRC-009", Severity.HIGH,
                        "Unescaped interpolation into a shell command",
                        "A variable is interpolated into a shell command string "
                        "passed to exec/system, rather than passed as a separate "
                        "argv element. This repository already uses a safer "
                        "quoting/argv-array pattern elsewhere, so the team knows "
                        "the risk -- this call site is the exception.",
                        f"{rel}:{_line_of(text, sm.start())}",
                        window[:90].strip(),
                        "Use an argv-array exec (execFile/spawn with an args "
                        "list, or subprocess.run([...], shell=False)) or quote "
                        "the value with the same helper used elsewhere in this "
                        "codebase before interpolating it into a shell string.",
                        8.1,
                    ))

        # SRC-010: credential/key file write with no nearby permission hardening,
        # flagged only when this repo hardens permissions on some other write.
        if repo_hardens_perms_somewhere:
            fm = _SENSITIVE_FILE_WRITE.search(text)
            if fm:
                window = text[max(0, fm.start() - 100):fm.start() + 250]
                if not _PERM_HARDEN.search(window):
                    findings.append(SourceFinding(
                        "SRC-010", Severity.MEDIUM,
                        "Credential file written without permission hardening",
                        "A file write whose path/filename looks like a "
                        "credential or private key has no chmod/setAttributes/"
                        "explicit-mode call near it, while this repository does "
                        "harden permissions on other file writes elsewhere -- "
                        "this write is the inconsistent case.",
                        f"{rel}:{_line_of(text, fm.start())}",
                        text[fm.start():fm.start() + 90].strip(),
                        "Set restrictive permissions (0600/0700) on the file "
                        "immediately after writing it, matching the pattern "
                        "already used elsewhere in this repo.",
                        5.5,
                    ))

        # SRC-011: SSRF guard validates once; the fetch call re-resolves the URL.
        vm = _SSRF_VALIDATE_CALL.search(text)
        if vm:
            tail = text[vm.end():vm.end() + 600]
            fm2 = _SSRF_RAW_FETCH_CALL.search(tail)
            if fm2 and not _SSRF_PINNED_FETCH.search(tail[:fm2.end()]):
                findings.append(SourceFinding(
                    "SRC-011", Severity.HIGH,
                    "SSRF guard validates once; fetch call re-resolves DNS separately",
                    "A hostname/IP is validated against a private/metadata "
                    "blocklist, but the actual outbound request is a separate "
                    "call that takes the original URL string and performs its "
                    "own independent DNS resolution rather than connecting to "
                    "the already-validated, pinned IP. A DNS record that changes "
                    "between validation and the request (DNS rebinding) bypasses "
                    "the guard entirely.",
                    f"{rel}:{_line_of(text, vm.start())}",
                    text[vm.start():vm.start() + 90].strip(),
                    "Pin the validated IP and connect to it directly (a custom "
                    "dialer/transport), or re-validate the resolved IP at "
                    "connection time instead of trusting the hostname string.",
                    7.5,
                ))

        # SRC-012: manifest/lockfile entry silently dropped on a sentinel value,
        # with only debug-level logging before it reaches a downstream consumer.
        sc = _SENTINEL_COND.search(text)
        if sc:
            tail = text[sc.end():sc.end() + 150]
            if _SENTINEL_SKIP_BRANCH.search(tail):
                window = text[sc.start():sc.end() + 150]
                if _DEBUG_ONLY_LOG.search(window) and not _WARN_OR_ERROR_LOG.search(window):
                    findings.append(SourceFinding(
                        "SRC-012", Severity.MEDIUM,
                        "Manifest entry silently dropped with only debug-level logging",
                        "An entry matching a sentinel condition (unresolved "
                        "version, empty/None field) is skipped/deleted before "
                        "the parsed list reaches a downstream consumer, and the "
                        "only logging of the drop is at debug level. A "
                        "vulnerable or malicious package hidden behind an "
                        "unresolved version can silently skip vuln/malware "
                        "analysis with no operator-visible warning.",
                        f"{rel}:{_line_of(text, sc.start())}",
                        text[sc.start():sc.start() + 90].strip(),
                        "Log dropped entries at warn/error level (not debug), or "
                        "surface a count of skipped entries to the operator, so "
                        "silently-excluded packages are not invisible to "
                        "downstream security analysis.",
                        5.5,
                    ))

    return findings


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "."
    for f in scan_source_tree(target):
        print(f"[{f.severity.name if hasattr(f.severity, 'name') else f.severity}] "
              f"{f.rule_id} {f.title}\n    {f.location}\n    {f.remediation}\n")
