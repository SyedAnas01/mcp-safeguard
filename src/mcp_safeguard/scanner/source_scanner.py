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
  SRC-013  TLS certificate verification explicitly disabled -- Python's verify
           parameter set to False, the ssl module's CERT_NONE, Node's
           rejectUnauthorized flag set to false, Go's InsecureSkipVerify, etc.
           (worded here to describe the patterns without literally reproducing
           them, so this doc comment doesn't trigger the rule it's describing).
  SRC-014  An OAuth redirect_uri is read from the request and used in a
           redirect response with no allowlist/registration comparison in
           between (authorization-code interception -- the single most common
           real bug class found across this project's own disclosure
           campaign: confirmed government and commercial MCP servers alike).
  SRC-015  The inbound Authorization header is captured and re-forwarded as an
           outbound request header (token passthrough) -- forbidden outright
           by the MCP spec's own Security Best Practices ("MUST NOT accept
           tokens not issued for it").
  SRC-016  A write/destructive-capability flag gates only the tool-list
           response, with no matching gate anywhere near the tool-call
           dispatcher in the same file -- a caller who already knows a tool's
           name executes it regardless of the flag (the flag hides discovery,
           not execution).
  SRC-017  An HTTP header value is used directly as an authorization/tenant-
           scoping identity, with no authentication-check call anywhere in
           the same file.
  SRC-018  A path is built by joining a base directory with a request/
           argument-derived value and used in a file operation, with no
           realpath+containment check in between (real path traversal, not
           the earlier "parameter is named 'path'" heuristic).
  SRC-019  Unescaped shell interpolation, same shape as SRC-009 but without
           requiring repo-wide corroboration -- broader recall for the
           single largest real-world MCP CVE class (shell/exec injection).
  SRC-020  A value is interpolated into a URL query string with no proper
           encoder -- the statically-detectable root cause behind HTTP
           Parameter Pollution and query-string injection.

SRC-005..SRC-020 are heuristic in the same sense as SRC-001..004: each is a
regex/text-proximity signal over source, not a type-aware or dataflow analysis.
They are LEADS to confirm by reading the cited file, not proofs. Several
(SRC-009, SRC-010) intentionally fire only when the SAME repository already
demonstrates it knows the safer pattern elsewhere, trading recall for a much
lower false-positive rate. SRC-007 intentionally requires evidence that the
classifier actually gates execution somewhere (not just that the function
exists) before flagging it, precisely to avoid conflating "there is a
type-classifier function" with "the type-classifier is used as a security
control" -- the exact overclaim shape a manual audit must otherwise catch by
hand. SRC-016 uses the same discipline in reverse: it only fires when a
write-gating flag is found INSIDE a list-tools function and confirmed ABSENT
everywhere else in the file, rather than merely noting the flag exists.

SRC-013..SRC-020 were added after this project's own coordinated-disclosure
campaign against real-world MCP servers turned up the same handful of bug
shapes repeatedly across unrelated codebases -- each rule below cites the
pattern it was derived from, not a hypothetical.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .prompt_injection import Severity

# Rule catalog for introspection (security://rules resource, docs generation).
# Kept as a plain list of (rule_id, title) rather than re-deriving it from the
# detection logic below, since several rules (e.g. SRC-007, SRC-016) fire from
# multi-step control flow, not a single flat pattern list the way the other
# scanner modules work -- this is the intentionally simple, honest source of
# truth for "how many source-audit rules exist" so README/doc counts can be
# generated from code instead of hand-maintained (and going stale, as the
# hand-maintained counts previously did).
RULE_IDS: list[tuple[str, str]] = [
    ("SRC-001", "Auth header re-applied in transport without redirect guard"),
    ("SRC-002", "httpx client follows redirects while carrying a bearer token"),
    ("SRC-003", "SQL read-only enforced by string prefix check only"),
    ("SRC-004", "Credential attached to a caller-influenced destination host"),
    ("SRC-005", "Auth flag parsed and warned about, never enforced before serving"),
    ("SRC-006", "Client-supplied resource ID keys shared state with no ownership check"),
    ("SRC-007", "Read-only/destructive classifier recognizes syntax, not calls"),
    ("SRC-008", "Client-supplied ownership field trusted on create/update"),
    ("SRC-009", "Unescaped interpolation into a shell command"),
    ("SRC-010", "Credential file written without permission hardening"),
    ("SRC-011", "SSRF guard validates once; fetch call re-resolves DNS separately"),
    ("SRC-012", "Manifest entry silently dropped with only debug-level logging"),
    ("SRC-013", "TLS certificate verification disabled"),
    ("SRC-014", "OAuth redirect_uri used in a redirect with no allowlist check"),
    ("SRC-015", "Inbound Authorization header re-forwarded to an outbound request"),
    ("SRC-016", "Write-capability flag gates tool listing, not tool execution"),
    ("SRC-017", "Header value used as authorization identity with no authentication check"),
    ("SRC-018", "Path traversal: joined path used with no containment check"),
    ("SRC-019", "Unescaped interpolation into a shell command (broad check)"),
    ("SRC-020", "Unencoded value interpolated into a URL query string"),
]


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

# SRC-013: TLS certificate verification explicitly disabled. Unlike most rules
# in this module, this one needs no repo-wide corroborating signal or nearby
# gate check -- the pattern itself is unambiguous, the same discipline Bandit
# (B501/B502/B503) and Ruff (S501) use for the identical check.
_TLS_VERIFY_DISABLED = re.compile(
    r"verify\s*=\s*False|ssl\.CERT_NONE|ssl\._create_unverified_context\(\)|"
    r"check_hostname\s*=\s*False|rejectUnauthorized\s*:\s*false|"
    r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0|InsecureSkipVerify\s*:\s*true",
)

# SRC-014: redirect_uri read from the request and used in a redirect response
# with no comparison against a stored/registered value anywhere in the file --
# authorization-code interception (RFC 9700 SS4.1.1). This exact bug class was
# the root cause of this project's two most severe confirmed government
# findings (a UK court-service MCP register and a Norwegian government MCP
# server) plus multiple commercial ones (Neon, Emporia Energy) -- it is the
# single most common real vulnerability this campaign has found.
#
# Matches BOTH a plain assignment (redirect_uri = req.query.redirect_uri) and
# a destructuring extraction (const { redirect_uri } = req.query), since real
# Express/Fastify-style handlers overwhelmingly use the latter -- an earlier
# version of this rule only matched the former and, verified against the
# actual confirmed-vulnerable Emporia Energy source, MISSED the real bug
# entirely. The redirect-call check and the validation check both search the
# WHOLE file, not just a window after the extraction, because the realistic
# shape stores redirect_uri (often in a map/session keyed by an OAuth
# `state`) in one handler and redirects using it in a SEPARATE handler --
# exactly Emporia's /oauth/authorize -> pendingOAuthRequests -> /oauth/callback
# flow. This trades a little precision (validation must be absent from the
# whole file, not provably "in between") for recall on the realistic
# multi-handler shape, which is the more common real-world pattern.
_OAUTH_REDIRECT_URI_FROM_REQUEST = re.compile(
    r"redirect_uri\s*=\s*(?:req(?:uest)?\.(?:query|body|params|args)\b|"
    r"query_params\.get\(\s*[\"']redirect_uri|params\.get\(\s*[\"']redirect_uri|"
    r"req\.query\.redirect_uri|request\.GET\.get\(\s*[\"']redirect_uri)|"
    r"\{[^}]{0,200}\bredirect_uri\b[^}]{0,200}\}\s*=\s*(?:req(?:uest)?|ctx)\."
    r"(?:query|body|params|args)\b",
    re.IGNORECASE,
)
_OAUTH_REDIRECT_CALL = re.compile(
    r"(?:res(?:ponse)?\.redirect\(|RedirectResponse\(|redirect\(\s*(?:url\s*=\s*)?)"
    r"[^)\n]{0,60}redirect_uri",
    re.IGNORECASE,
)
_OAUTH_REDIRECT_URI_VALIDATED = re.compile(
    r"allowlist|allow_list|registered_redirect|redirect_uris\s*\.\s*(?:includes|has|contains)|"
    r"validate_redirect|check_redirect_uri|redirect_uri\s*(?:==|!=|in\s|not\s+in\s)",
    re.IGNORECASE,
)

# SRC-015: the inbound Authorization header is captured into a variable that
# is later re-forwarded as an outbound request's own Authorization header
# (token passthrough) -- explicitly forbidden by the MCP spec's Security Best
# Practices ("MCP servers MUST NOT accept any tokens that were not explicitly
# issued for the MCP server"). Matched the way this project found it in the
# wild (Dify): a caller-configurable upstream URL receives the caller's own
# live session credential.
_INBOUND_AUTH_CAPTURE = re.compile(
    r"\b(\w+)\s*=\s*(?:req(?:uest)?\.headers(?:\.get)?\(?\s*\[?\s*[\"']authorization[\"']\]?\)?)",
    re.IGNORECASE,
)

# SRC-016: a write/destructive-capability flag that gates a tool-LIST function
# but that this file never references again near a tool-CALL/dispatch
# function -- the flag hides a tool from discovery without disabling it, the
# exact "ENABLE_WRITE_OPERATIONS gates tools/list, never tools/call" bug this
# campaign found in a production crypto-custody MCP server (any caller who
# already knows the tool name executes it regardless of the flag).
_WRITE_FLAG_NAME = re.compile(
    r"\b(ENABLE_WRITE\w*|WRITE_ENABLED|ALLOW_WRITE\w*|ENABLE_DESTRUCTIVE\w*|"
    r"enable_write_operations|write_operations_enabled|writes_enabled)\b"
)
_LIST_TOOLS_FUNC = re.compile(
    r"(?:def|function|async function|func)\s+\w*(?:list_tools|listTools|get_tools|"
    r"getTools|available_tools|availableTools)\w*\s*\(",
    re.IGNORECASE,
)
# Bounds the list-tools function body at the next top-level function
# definition (a fixed-size window would, on a short file, swallow the very
# next function -- e.g. the call_tool dispatcher -- and wrongly count its
# flag reference as "inside" the list function instead of "elsewhere").
_NEXT_FUNC_BOUNDARY = re.compile(r"^\s*(?:def|function|async function|func)\s+\w+", re.MULTILINE)

# SRC-017: an HTTP header value is assigned straight to an
# authorization/tenant-scoping identity variable, with no authentication-check
# call anywhere in the file -- the "x-rls-user-id decides which customers'
# data you see, and nothing upstream ever checks who you are" pattern this
# campaign found giving full-database access in a Microsoft sample MCP server.
#
# Matches two shapes: the direct read (identity_var = request.headers.get(...))
# and, since it's at least as common in real code, an indirection through a
# small wrapper helper (identity_var = get_header(ctx, "x-rls-user-id")) --
# verified against the actual confirmed-vulnerable Microsoft retail source,
# whose real code uses exactly this wrapper shape and which an earlier,
# direct-read-only version of this rule MISSED entirely.
_HEADER_AS_IDENTITY = re.compile(
    r"\b(\w*(?:user_id|tenant_id|org_id|account_id|rls_user\w*|scope_id)\w*)\s*=\s*"
    r"(?:(?:request|req)\.headers(?:\.get)?\(?\s*\[?\s*[\"'][\w-]+[\"']\]?\)?|"
    r"\w*[Hh]eader\w*\(\s*[^)\n]*[\"'][\w-]+[\"']\s*\))",
    re.IGNORECASE,
)
_AUTH_CHECK_PRESENT = re.compile(
    r"\b(?:verify_token|authenticate|require_auth|check_auth|Depends\(\s*get_current_user|"
    r"login_required|jwt\.decode|verify_jwt|validate_token|check_permission|"
    r"authorization_header|Bearer\s+token)\b",
    re.IGNORECASE,
)

# SRC-018: a filesystem path is built by joining a base directory with a
# request/tool-argument-derived value and fed into a file open/read/write
# call, with no containment check in between. This replaces the earlier,
# much weaker "a parameter happens to be named 'path'" heuristic -- per this
# project's own architecture research, lexical cleaning (os.path.normpath,
# path.Clean) does NOT count as sanitization, only realpath-resolution plus
# a prefix/containment check does, so that's specifically what's checked for.
# Two shapes are matched: the value inline in the join call itself
# (os.path.join(base, request.args.get("f"))), and the far more common
# "extract to a variable first, then join" shape (f = request.args.get("f");
# os.path.join(base, f)) -- tracked the same two-pass way as SRC-015/019.
_PATH_JOIN_WITH_ARG_INLINE = re.compile(
    r"(?:os\.path\.join\(|path\.join\(|Path\([^)\n]*\)\s*/\s*)"
    r"[^)\n]{0,80}\b(?:args|params|kwargs|request|req)\b",
    re.IGNORECASE,
)
_ARG_DERIVED_ASSIGN = re.compile(
    r"\b(\w+)\s*=\s*(?:(?:request|req)\.(?:args|params|query)|params|kwargs)\s*(?:\.get\(|\[)",
    re.IGNORECASE,
)
_PATH_JOIN_CALL = re.compile(r"os\.path\.join\(|path\.join\(|Path\([^)\n]*\)\s*/\s*", re.IGNORECASE)
_FILE_OPEN_CALL = re.compile(
    r"\bopen\(|\.read_text\(|\.write_text\(|readFile\(|writeFile\(|fs\.open\(",
)
_PATH_CONTAINMENT_CHECK = re.compile(
    r"realpath|resolve\(\)\.is_relative_to|is_relative_to\(|commonpath|"
    r"secure_filename|\.\.\s*(?:in|not\s+in)|startswith\(\s*(?:base|root|safe)",
    re.IGNORECASE,
)

# SRC-019: unescaped shell interpolation, WITHOUT requiring the repo-wide
# "already knows the risk" corroboration SRC-009 requires -- a deliberately
# broader-recall companion, since 43% of MCP CVEs filed in early 2026 were
# shell/exec injection (the single largest real-world MCP vulnerability
# class). Only excluded when the SAME call site also uses a known escaping
# helper on the interpolated value, so a properly-quoted call doesn't fire.
_SHELL_ESCAPED_INLINE = re.compile(r"shlex\.quote\(|shellQuote\(|escapeShellArg\(")

# SRC-020: unencoded user input concatenated/interpolated directly into a URL
# query string, instead of going through a proper encoder. This is the
# statically-detectable root cause behind HTTP Parameter Pollution and query-
# string injection -- true HPP is a differential/dynamic bug (two components
# parsing duplicate params differently) that can't be proven from source
# alone, but "a variable lands in a URL query string unescaped" is the
# concrete, checkable precondition for it, the same scope Datadog's own
# static HPP rule uses.
_URL_QUERY_STRING_BUILD = re.compile(
    r"""[\"']\?[\w=&{}$]*\{[^}]+\}|[\"']\?[\w=&]*[\"']\s*\+\s*\w+|"""
    r"""f[\"'][^\"']*\?[\w=&]*\{[^}]+\}""",
)
_URL_ENCODING_CALL = re.compile(
    r"urlencode\(|URLSearchParams\(|quote_plus\(|encodeURIComponent\(|querystring\.stringify\(",
    re.IGNORECASE,
)
# Database connection strings (postgresql://user:pass@host/db?application_name=...)
# use the same "?key=value" shape as an HTTP query string but aren't one --
# there's no downstream HTTP component to differentially parse it, so this
# isn't HPP-adjacent. Verified against a real false positive this rule
# produced on an actual scanned MCP server's DB config before adding the
# exclusion (a postgres_url property, not a network request).
_DB_CONNECTION_SCHEME = re.compile(
    r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|sqlite|mssql|oracle)://",
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


# Inline suppression: `# safeguard: ignore[SRC-013]` (or `// ...` for
# brace-language files), optionally with a trailing reason after the bracket
# and/or multiple comma-separated rule IDs. `ignore[*]` silences every rule
# flagged on that line. Adopting a scanner on an existing codebase without a
# way to mark accepted findings is the single fastest way a team abandons it.
_SUPPRESS_COMMENT = re.compile(
    r"(?:#|//)\s*safeguard:\s*ignore\[([A-Z0-9*,\s-]+)\]", re.IGNORECASE
)


def _is_suppressed(lines: list[str], line_no: int, rule_id: str) -> bool:
    """True if source line `line_no` (1-indexed) carries an inline
    suppression comment naming `rule_id` (or `*`)."""
    if line_no < 1 or line_no > len(lines):
        return False
    m = _SUPPRESS_COMMENT.search(lines[line_no - 1])
    if not m:
        return False
    ids = {i.strip().upper() for i in m.group(1).split(",")}
    return "*" in ids or rule_id.upper() in ids


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
        # Collected separately from `findings` and filtered against inline
        # suppression comments just before merging into the real result --
        # keeps every rule block below unchanged (still just "append a
        # finding"), with suppression handled once, in one place, per file.
        file_findings: list[SourceFinding] = []

        # SRC-001 (Go): a RoundTrip that sets Authorization, in a file whose
        # package sets no CheckRedirect -> auth may survive a cross-host redirect.
        if path.suffix == ".go" and _GO_ROUNDTRIP.search(text):
            m = _GO_AUTH_SET.search(text)
            if m and "CheckRedirect" not in text:
                file_findings.append(SourceFinding(
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
                file_findings.append(SourceFinding(
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
            file_findings.append(SourceFinding(
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
            file_findings.append(SourceFinding(
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
            file_findings.append(SourceFinding(
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
            file_findings.append(SourceFinding(
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
                file_findings.append(SourceFinding(
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
            file_findings.append(SourceFinding(
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
                    file_findings.append(SourceFinding(
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
                    file_findings.append(SourceFinding(
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
                file_findings.append(SourceFinding(
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
                    file_findings.append(SourceFinding(
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

        # SRC-013: TLS certificate verification explicitly disabled.
        for tm in _TLS_VERIFY_DISABLED.finditer(text):
            file_findings.append(SourceFinding(
                "SRC-013", Severity.HIGH,
                "TLS certificate verification disabled",
                "Certificate verification is explicitly turned off for an "
                "outbound connection, which defeats TLS's protection against "
                "man-in-the-middle attacks -- any network position between "
                "this server and its target can intercept or tamper with "
                "the traffic, including credentials sent over it.",
                f"{rel}:{_line_of(text, tm.start())}",
                text[max(0, tm.start() - 30):tm.start() + 60].strip(),
                "Never disable certificate verification outside a test "
                "fixture. If a self-signed/internal CA must be trusted, "
                "point the client at that CA's certificate bundle instead "
                "of disabling verification entirely.",
                7.4,
            ))

        # SRC-014: redirect_uri taken from the request, used in a redirect
        # response somewhere in the file, with no allowlist/comparison check
        # anywhere in the file (see the pattern comment above for why this
        # checks the whole file rather than a window after the extraction).
        rm = _OAUTH_REDIRECT_URI_FROM_REQUEST.search(text)
        cm2 = _OAUTH_REDIRECT_CALL.search(text) if rm else None
        if rm and cm2 and not _OAUTH_REDIRECT_URI_VALIDATED.search(text):
            file_findings.append(SourceFinding(
                "SRC-014", Severity.HIGH,
                "OAuth redirect_uri used in a redirect with no allowlist check",
                "A redirect_uri parameter is read directly from the "
                "incoming request and used to build a redirect response "
                "somewhere in this file, with no comparison against a "
                "registered/allowlisted value anywhere in the file "
                "(including across handlers, e.g. stored in a session/map "
                "in one handler and redirected to in another). An attacker "
                "can supply their own redirect_uri and receive a real "
                "authorization code intended for the victim "
                "(authorization-code interception, RFC 9700 SS4.1.1) -- "
                "the single most common real bug this project's own "
                "disclosure campaign has found.",
                f"{rel}:{_line_of(text, rm.start())}",
                text[rm.start():rm.start() + 90].strip(),
                "Validate redirect_uri against an exact-match allowlist "
                "of values registered for that client_id before using it "
                "in any redirect or token response. Never accept it "
                "unchecked, and never use prefix/substring matching for "
                "the comparison.",
                8.1,
            ))

        # SRC-015: inbound Authorization header captured, then re-forwarded
        # as an outbound request header (token passthrough).
        for im in _INBOUND_AUTH_CAPTURE.finditer(text):
            var = im.group(1)
            window = text[im.end():im.end() + 600]
            forward_re = re.compile(
                rf"[\"']?[Aa]uthorization[\"']?\s*[:=]\s*(?:f?[\"']?(?:Bearer\s+)?\{{?\s*)?{re.escape(var)}\b"
            )
            fm = forward_re.search(window)
            if fm:
                file_findings.append(SourceFinding(
                    "SRC-015", Severity.HIGH,
                    "Inbound Authorization header re-forwarded to an outbound request",
                    "The caller's own Authorization header is captured into "
                    "a variable and then set as the Authorization header on "
                    "an outbound request elsewhere in this file (token "
                    "passthrough). The MCP spec's Security Best Practices "
                    "explicitly forbid this: an MCP server MUST NOT accept "
                    "or forward a token that was not issued for it. If the "
                    "outbound destination is caller-influenced, this also "
                    "hands the caller's live credential to whatever host "
                    "they name.",
                    f"{rel}:{_line_of(text, im.start())}",
                    text[im.start():im.start() + 90].strip(),
                    "Never forward an inbound token as-is to an upstream "
                    "call. Issue and use the server's own credential for "
                    "outbound requests, or perform token exchange "
                    "(RFC 8693) to obtain a token scoped for that specific "
                    "downstream audience.",
                    7.5,
                ))

        # SRC-016: a write-capability flag gates only the tool-list function,
        # with no matching reference anywhere else in the file.
        lm = _LIST_TOOLS_FUNC.search(text)
        if lm:
            next_func_m = _NEXT_FUNC_BOUNDARY.search(text, lm.end())
            body_end = next_func_m.start() if next_func_m else min(len(text), lm.start() + 1200)
            list_body = text[lm.start():body_end]
            flag_m = _WRITE_FLAG_NAME.search(list_body)
            if flag_m:
                flag_name = flag_m.group(1)
                outside_text = text[:lm.start()] + text[body_end:]
                if not re.search(re.escape(flag_name), outside_text):
                    file_findings.append(SourceFinding(
                        "SRC-016", Severity.CRITICAL,
                        "Write-capability flag gates tool listing, not tool execution",
                        f"'{flag_name}' controls what appears in the "
                        "tool-list function here, but this file never "
                        "references it again anywhere near a tool-call/"
                        "dispatch function. A caller who already knows the "
                        "gated tool's name (from documentation, a prior "
                        "response, or guessing) can call it directly "
                        "regardless of the flag -- the flag hides discovery, "
                        "it does not disable execution. This is the exact "
                        "bug class this project's own campaign found in a "
                        "production crypto-custody MCP server, where it "
                        "gated visibility of a real fund-transfer tool but "
                        "not the ability to call it.",
                        f"{rel}:{_line_of(text, lm.start())}",
                        text[flag_m.start():flag_m.start() + 60].strip(),
                        "Check the same flag inside the tool-call/dispatch "
                        "path too (not only the list path), and reject the "
                        "call outright when the flag is unset -- a safety "
                        "control must gate execution, not just discovery.",
                        9.1,
                    ))

        # SRC-017: an HTTP header value is used as an authorization/tenant-
        # scoping identity, with no authentication check anywhere in the file.
        hm = _HEADER_AS_IDENTITY.search(text)
        if hm and not _AUTH_CHECK_PRESENT.search(text):
            file_findings.append(SourceFinding(
                "SRC-017", Severity.CRITICAL,
                "Header value used as authorization identity with no authentication check",
                "A value read directly from an HTTP header is used as an "
                "authorization or tenant-scoping identity (its name "
                "suggests user/tenant/org/account/RLS scoping), and this "
                "file contains no authentication-check call anywhere -- "
                "nothing verifies the caller actually owns the identity the "
                "header claims. Any caller can set this header to any "
                "value (including a documented 'admin'/'all access' "
                "default) and receive that identity's data. This is the "
                "exact pattern this project's campaign found giving full, "
                "unauthenticated database access in a production sample "
                "MCP server.",
                f"{rel}:{_line_of(text, hm.start())}",
                text[hm.start():hm.start() + 90].strip(),
                "Never let a caller-supplied header set its own "
                "authorization identity. Authenticate the caller first "
                "(verified token/session), then derive the "
                "tenant/user/org scope server-side from that authenticated "
                "identity -- never trust a header for it.",
                9.8,
            ))

        # SRC-018: path joined with a request/argument-derived value, fed
        # into a file operation, with no containment check in between.
        # Try the inline shape first, then the assign-then-join shape.
        pjm = _PATH_JOIN_WITH_ARG_INLINE.search(text)
        src018_window = text[pjm.start():pjm.start() + 400] if pjm else None
        if pjm is None:
            for am in _ARG_DERIVED_ASSIGN.finditer(text):
                var = am.group(1)
                lookahead = text[am.end():am.end() + 400]
                jm = _PATH_JOIN_CALL.search(lookahead)
                if jm and re.search(rf"\b{re.escape(var)}\b", lookahead[jm.start():jm.end() + 120]):
                    pjm = am  # anchor the reported location at the assignment
                    src018_window = lookahead[jm.start():jm.end() + 300]
                    break
        if pjm and src018_window is not None:
            if _FILE_OPEN_CALL.search(src018_window) and not _PATH_CONTAINMENT_CHECK.search(src018_window):
                file_findings.append(SourceFinding(
                    "SRC-018", Severity.HIGH,
                    "Path traversal: joined path used with no containment check",
                    "A filesystem path is built by joining a base directory "
                    "with a request/tool-argument-derived value, then used "
                    "in a file open/read/write call, with no containment "
                    "check (realpath + prefix check, is_relative_to, "
                    "secure_filename, or explicit '..' rejection) anywhere "
                    "in between. Lexical cleaning alone (os.path.normpath, "
                    "path.Clean) does not stop this -- only resolving the "
                    "real path and checking it stays under the base "
                    "directory does. A value like '../../etc/passwd' or an "
                    "absolute path can escape the intended directory.",
                    f"{rel}:{_line_of(text, pjm.start())}",
                    text[pjm.start():pjm.start() + 90].strip(),
                    "After joining, resolve the real path (os.path.realpath/"
                    "Path.resolve()) and verify it is still relative to the "
                    "base directory (Path.is_relative_to() or a commonpath "
                    "check) before opening it. Reject the request if not.",
                    8.6,
                ))

        # SRC-019: unescaped shell interpolation -- broader companion to
        # SRC-009, no repo-wide corroboration required (see module docstring).
        sm2 = _SHELL_STRING_CALL.search(text)
        if sm2:
            window2 = text[sm2.start():sm2.start() + 200]
            if _SHELL_INTERP_MARK.search(window2) and not _SHELL_ESCAPED_INLINE.search(window2):
                file_findings.append(SourceFinding(
                    "SRC-019", Severity.MEDIUM,
                    "Unescaped interpolation into a shell command (broad check)",
                    "A variable is interpolated into a shell command string "
                    "passed to exec/system, with no escaping helper "
                    "(shlex.quote/shellQuote/escapeShellArg) applied at this "
                    "call site. Unlike SRC-009, this fires without requiring "
                    "evidence the repo already knows the risk elsewhere -- "
                    "broader recall, so treat this one as a lead to confirm "
                    "even more than the other source-audit rules: check "
                    "whether the interpolated value can ever be influenced "
                    "by a tool caller (directly or via prompt injection).",
                    f"{rel}:{_line_of(text, sm2.start())}",
                    window2[:90].strip(),
                    "Use an argv-array exec (execFile/spawn with an args "
                    "list, or subprocess.run([...], shell=False)) or quote "
                    "the interpolated value with shlex.quote/shellQuote "
                    "before building the shell string.",
                    7.0,
                ))

        # SRC-020: unencoded value built directly into a URL query string --
        # the statically-checkable root cause behind HTTP Parameter Pollution
        # and query-string injection (true HPP itself needs dynamic testing;
        # this is the concrete precondition that's actually detectable here).
        uqm = _URL_QUERY_STRING_BUILD.search(text)
        if uqm:
            window3 = text[max(0, uqm.start() - 60):uqm.start() + 120]
            if not _URL_ENCODING_CALL.search(window3) and not _DB_CONNECTION_SCHEME.search(window3):
                file_findings.append(SourceFinding(
                    "SRC-020", Severity.MEDIUM,
                    "Unencoded value interpolated into a URL query string",
                    "A value is concatenated or interpolated directly into "
                    "a URL query string instead of being passed through a "
                    "proper query-string encoder. Beyond the obvious "
                    "injection risk if the value contains '&'/'=' or other "
                    "query metacharacters, this is the concrete, statically-"
                    "checkable precondition for HTTP Parameter Pollution -- "
                    "a downstream component that parses duplicate/malformed "
                    "parameters differently than this code expects can be "
                    "made to see a different value than what was intended.",
                    f"{rel}:{_line_of(text, uqm.start())}",
                    text[uqm.start():uqm.start() + 90].strip(),
                    "Build query strings with a proper encoder "
                    "(urllib.parse.urlencode, URLSearchParams, "
                    "querystring.stringify) instead of string "
                    "concatenation/interpolation.",
                    5.5,
                ))

        # Apply inline suppression once per file: a finding whose flagged
        # line carries `# safeguard: ignore[RULE-ID]` (or `// ...` for
        # brace-language files) is dropped before merging into the real
        # result. `ignore[*]` silences every rule on that line.
        source_lines = text.splitlines()
        for ff in file_findings:
            line_str = ff.location.rsplit(":", 1)[-1]
            line_no = int(line_str) if line_str.isdigit() else 0
            if not _is_suppressed(source_lines, line_no, ff.rule_id):
                findings.append(ff)

    return findings


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "."
    for f in scan_source_tree(target):
        print(f"[{f.severity.name if hasattr(f.severity, 'name') else f.severity}] "
              f"{f.rule_id} {f.title}\n    {f.location}\n    {f.remediation}\n")
