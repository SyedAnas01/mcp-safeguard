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
  SRC-021  A network listener (HTTP/SSE) starts serving with NO
           authentication-related vocabulary anywhere in the file -- the
           single most common real bug shape this project's disclosure
           campaign found, and the one gap none of SRC-001..020 covered.
  SRC-022  A SQL/SoQL/query-API fragment is built by hand-quoting an
           f-string- or concatenation-interpolated value directly into the
           query text instead of binding it as a parameter (CWE-89/943;
           apple-health-mcp-server's DuckDB tools, cdc-places-mcp-server's
           Socrata $where clause).
  SRC-023  A caller-derived URL/target flows into an outbound fetch (HTTP
           or git clone) with no SSRF-guard call anywhere in the file --
           the no-guard-at-all companion to SRC-011's guard-exists-but-
           bypassed case (ark-forge/mcp-eu-ai-act, datagouv-mcp, Bybit kaas).
  SRC-024  A tool/resource-handler reads or approves a resource by an
           ID-shaped parameter with no ownership/tenant-check vocabulary
           anywhere in the file -- broken object-level authorization
           (Agorai get_memory, DEFRA mural-mcp). The lowest-confidence rule
           in this file; see its own code comment for why.
  SRC-025  A request query/form parameter is interpolated, unescaped, into
           HTML response output (reflected XSS, CWE-79 --
           ibkr-portfolio-builder-mcp's OAuth login page).
  SRC-026  A server bound to loopback (127.0.0.1/localhost), or a WebSocket
           server constructed with no explicit public-interface bind, has no
           Origin-header check anywhere in the file -- DNS rebinding /
           cross-site WebSocket hijacking (unity-mcp, mcp-unity-cg); also
           flags an Origin check whose validation regex is unanchored, a
           substring-match bypass (fast-mcp).
  SRC-027  An OAuth scope parameter is taken directly from the request and
           embedded in an issued token, with no check against the caller's
           role anywhere in the file (mcp-construction: viewer-to-admin
           self-escalation, independently re-verified).
  SRC-028  A caught exception/error response is logged in full at error
           level with no redaction (GSA-TTS va-claims-mcp-server-DEMO,
           where VA's own validation errors echo back the veteran
           SSN/name/DOB that caused them).
  SRC-029  A runtime-obtained access token/secret (OAuth/API response, not
           a static env var) is written to disk in plaintext with no
           encryption of the value applied anywhere near the write (bank-mcp).
  SRC-030  CORS configured with no origin restriction, or a dev-server
           host-validation guard explicitly disabled (Alpic/Skybridge,
           1,990+ stars).

SRC-005..SRC-030 are heuristic in the same sense as SRC-001..004: each is a
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

SRC-013..SRC-030 were added after this project's own coordinated-disclosure
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
    ("SRC-021", "Network listener starts with no authentication mechanism anywhere in the file"),
    ("SRC-022", "SQL/query injection via unescaped string interpolation"),
    ("SRC-023", "Outbound fetch of a caller-derived URL with no SSRF validation call in the file"),
    ("SRC-024", "Resource ID used as a read/approval lookup key with no ownership check (BOLA)"),
    ("SRC-025", "Unescaped request parameter interpolated into HTML response (reflected XSS)"),
    ("SRC-026", "Loopback-bound server has no Origin-header check (DNS rebinding / cross-site WebSocket hijacking)"),
    ("SRC-027", "OAuth scope taken from request with no role check before token issuance"),
    ("SRC-028", "Full upstream response/exception body logged with no redaction"),
    ("SRC-029", "Live runtime-obtained access token/secret written to disk in plaintext"),
    ("SRC-030", "CORS wildcard or disabled dev-server host check exposes sensitive endpoints"),
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
# No leading \b: a private-helper naming convention (`self._validate_url(`,
# `_is_ssrf_safe(`) has no word-boundary transition right before the name
# (underscore is a \w character, so there's no boundary between it and the
# next letter) -- an anchored \b silently missed guard calls named that way.
# Verified via this project's own dogfooding: endpoint_scanner.py's real
# SSRF guards, `_is_ssrf_safe` and `_resolves_to_unsafe_ip`, weren't
# recognized by the original vocabulary (word order/prefix mismatch) or the
# original \b anchor (leading underscore) -- both fixed here.
_SSRF_VALIDATE_CALL = re.compile(
    r"(?:validate_url|check_ssrf|is_safe_url|is_ssrf_safe|validate_host|"
    r"resolve_and_check|resolves_to_unsafe_ip|is_private_ip|check_private_ip|"
    r"validate_target|ssrf_guard)\w*\(",
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

# SRC-021: a network listener starts serving with no INBOUND authentication
# check anywhere in the file -- not merely an unenforced flag (that's
# SRC-005), but no check of the CALLER's credentials at all. This was,
# empirically, the single most common real bug shape this project's
# disclosure campaign found, and it was the one real gap none of SRC-001..020
# covered.
#
# The naive version of this rule -- "any auth-adjacent word anywhere in the
# file suppresses it" -- was tried first and FAILED against the actual
# vulnerable code it was derived from (codespar/mcp-dev-latam): every real
# integration server mentions "Authorization"/"Bearer"/"API_KEY" for its own
# OUTBOUND call to the backend it wraps (e.g. `headers["Authorization"] =
# \`Bearer ${API_KEY}\`` when calling STP's payment API) -- that's normal and
# says nothing about whether the MCP transport itself checks its callers.
# This version instead requires the vocabulary to appear in an INBOUND shape:
# reading FROM the incoming request's headers, or a real named auth-check
# function/decorator/middleware -- not just being mentioned anywhere.
_INBOUND_AUTH_CHECK = re.compile(
    r"req(?:uest)?\.headers(?:\.get)?\(?\s*\[?\s*[\"']?(?:authorization|x-api-key|api-key)|"
    r"headers\.get\(\s*[\"'](?:authorization|x-api-key)|"
    r"\bmiddleware\b|Depends\(\s*get_current_user|login_required|"
    r"passport\.authenticate|verify[_-]?token\(|validate[_-]?token\(|"
    r"check[_-]?auth\(|require[_-]?auth\(|authenticate_request\(|"
    r"authenticate\(\s*req|jwt\.verify\(|"
    # A real auth provider wired into the app/framework construction itself
    # (FastMCP(auth=...), Starlette app built with an OAuthProvider, etc.) --
    # verified against a real, confirmed-auth-present MCP server whose
    # entrypoint file imports an OAuth provider class rather than reading a
    # header directly; an earlier version of this rule only recognized the
    # direct-header-read shape and missed this equally common one.
    r"\w*(?:OAuth|Auth)Provider\b|\bauth\s*=\s*\w",
    re.IGNORECASE,
)

# SRC-027: an OAuth `scope` parameter is read straight from the request and
# flows into an issued access token / authorization code, with no comparison
# against the authenticating user's ROLE anywhere in the file -- confirmed,
# independently re-verified viewer-to-admin privilege escalation (mcp-construction).
#
# An earlier version of this rule was a literal find/replace of SRC-014's
# redirect_uri regex (redirect_uri -> scope). Run against the actual
# vulnerable source (mcp-construction's src/auth/routes.ts) it MATCHED
# NOTHING: that code doesn't extract scope via a dotted `req.query`/`req.body`
# property the way SRC-014's redirect_uri shapes assume -- it uses a Hono
# context call (`c.req.query('scope')`) in the GET handler and bracket
# notation on a parsed body object (`body['scope']`) in the POST handler.
# This version adds both of those real shapes alongside the original
# SRC-014-style alternatives and its destructuring form, the same "verify
# against the real vulnerable code, fix what's missed" discipline SRC-014
# and SRC-017 document.
_OAUTH_SCOPE_FROM_REQUEST = re.compile(
    r"\bscope\s*=\s*(?:req(?:uest)?\.(?:query|body|params|args)\b|"
    r"c?\.?req\.query\(\s*[\"']scope[\"']|"
    r"query_params\.get\(\s*[\"']scope|params\.get\(\s*[\"']scope|"
    r"req\.query\.scope|request\.GET\.get\(\s*[\"']scope|"
    r"(?:req\.)?body\[\s*[\"']scope[\"']\s*\])|"
    r"\{[^}]{0,200}\bscope\b[^}]{0,200}\}\s*=\s*(?:req(?:uest)?|ctx)\."
    r"(?:query|body|params|args)\b",
    re.IGNORECASE,
)
# Deliberately loose, per the "don't over-engineer the dataflow tracing"
# guidance: rather than tracing the scope variable through named intermediate
# steps, this just confirms `scope` shows up near a token/authorization-code
# minting call SOMEWHERE in the file -- matched against both orderings
# (call-then-scope, as in createAuthorizationCode({..., scope, ...}), and
# scope-then-call) since real object-literal argument order varies.
_OAUTH_SCOPE_IN_TOKEN_CALL = re.compile(
    r"(?:create(?:Access)?Token\(|createAuthorizationCode\(|\bsign\(|jwt\.sign\()"
    r"[^)]{0,250}\bscope\b|"
    r"\bscope\b[^)]{0,150}(?:create(?:Access)?Token\(|createAuthorizationCode\(|jwt\.sign\()",
    re.IGNORECASE,
)
# Any real check of the requested scope against the caller's ROLE -- not
# against the OAuth client's registered scope, which is a different (and, in
# the real bug, equally absent) check this rule does not attempt to detect.
_ROLE_CHECK_PRESENT = re.compile(
    r"\brole\s*(?:===|!==|==|!=)|hasRole\(|checkRole\(|role\.includes\(|"
    r"requireRole\(|role\s*in\s*\[|ROLE_SCOPES\[",
    re.IGNORECASE,
)

# SRC-030: CORS configured with no origin restriction (wildcard), or a
# dev-server host-validation guard explicitly disabled -- either sub-pattern
# alone is a real finding. Derived from the real Alpic/Skybridge disclosure
# (1,990+ GitHub stars, Alpic's flagship MCP cloud framework): a bare
# CORS-middleware call with no options object set wildcard CORS on the dev
# router ahead of the /mcp endpoint and the devtools deploy-control router,
# while Vite's own host-allowlist override -- spread in after the
# developer's own server config, non-overridable -- forced off its
# DNS-rebinding protection. An earlier version of the CORS-wildcard regex
# required a trailing word-boundary after the quoted wildcard value, but a
# word-boundary cannot match between two non-word characters -- it silently
# failed to match the quoted-string form even though it correctly matched
# the bare-boolean form. Fixed by scoping the boundary to only the
# bare-boolean alternative. (Worded here, and in the finding text below, to
# avoid literally reproducing the trigger substrings, so this doc comment
# and the user-facing finding description don't self-match the rule they
# describe.)
_CORS_WILDCARD = re.compile(
    r"\bcors\(\s*\)|"
    r"origin\s*:\s*(?:[\"']\*[\"']|true\b)|"
    r"Access-Control-Allow-Origin[\"']?\s*[:,]\s*[\"']\*[\"']",
    re.IGNORECASE,
)
_DEV_HOST_CHECK_DISABLED = re.compile(
    r"\ballowedHosts\s*:\s*true\b|\bdisableHostCheck\s*:\s*true\b",
)

# SRC-023: outbound network fetch (HTTP, git clone, or similar) of a
# caller/request-derived URL or target with NO SSRF validation call
# anywhere in the file. This is deliberately the SIMPLER, more common
# companion to SRC-011: SRC-011 requires evidence a validate_url()-style
# guard EXISTS but is bypassed by a second, unpinned DNS resolution
# (TOCTOU); this rule instead requires evidence that NO such guard call
# (the same _SSRF_VALIDATE_CALL list SRC-011 uses) appears anywhere in the
# file at all -- the far more common real-world gap. Reusing SRC-011's own
# guard-name list is what keeps the two rules from double-flagging the same
# file: whenever a genuine guard is present, this rule stays silent and
# leaves that file to SRC-011 to judge.
#
# Derived from real, independently-confirmed findings across unrelated
# codebases: ark-forge/mcp-eu-ai-act (a caller-supplied repo_url passed
# straight into `git clone`, with only a scheme prefix check), the French
# government's datagouv-mcp (machine_documentation_url fetched via
# session.get(url) with no host/IP check at all), and Bybit's open-source
# kaas (URL-ingestion feature fetches via fetch_url(url) with zero
# validation).
_SSRF_FETCH_WITH_URLVAR_INLINE = re.compile(
    r"\b(?:requests\.(?:get|post)|httpx\.(?:get|post)|urlopen|axios\.(?:get|post)|"
    r"fetch|fetch_url|session\.(?:get|post)|client\.(?:get|post))\s*\("
    r"[^)\n]{0,120}?\b\w*url\w*\b"
    r"|subprocess\.(?:run|call|Popen)\(\s*\[?\s*[\"']git[\"'][\s\S]{0,120}?[\"']clone[\"']"
    r"[\s\S]{0,120}?\b\w*url\w*\b"
    r"|git\.clone\([^)\n]{0,120}?\b\w*url\w*\b",
    re.IGNORECASE,
)
_URL_ARG_DERIVED_ASSIGN = re.compile(
    r"\b(\w+)\s*=\s*(?:(?:request|req)\.(?:args|params|query|json|body)\s*(?:\.get\(|\[)|"
    r"\w+\.get\(\s*[\"'][\w.-]*url)",
    re.IGNORECASE,
)
_SSRF_OUTBOUND_CALL_BARE = re.compile(
    r"\b(?:requests\.(?:get|post)|httpx\.(?:get|post)|urlopen|axios\.(?:get|post)|"
    r"fetch|fetch_url|session\.(?:get|post)|client\.(?:get|post)|git\.clone)\s*\(",
    re.IGNORECASE,
)

# SRC-025: a value read from a request query/form parameter is interpolated,
# unescaped, into an HTML string built for a response (reflected XSS).
# Modeled on _ARG_DERIVED_ASSIGN (SRC-018) but broadened to also catch
# query_params/form/GET/POST reads. Derived from and verified against this
# project's own confirmed finding in adwiteeymauriya/ibkr-portfolio-builder-mcp:
# `_login_page()` splices a `next` query/form parameter into the OAuth login
# page's HTML with a raw f-string and zero escaping, landing inside the
# value attribute of a hidden input field, which a crafted payload breaks
# out of (CWE-79; worded here to avoid literally reproducing the trigger
# shape, so this doc comment doesn't self-match the rule it's describing).
# That real bug spans two functions in the same file, so -- like
# SRC-014 -- this rule searches the WHOLE file rather than a small window,
# linking the request-read and the interpolation by variable NAME.
_REQUEST_PARAM_ASSIGN = re.compile(
    r"\b(\w+)\s*=\s*(?:str\(\s*)?(?:(?:request|req)\.(?:args|params|query|query_params|GET|POST)|"
    r"form|params|kwargs)\s*(?:\.get\(|\[)",
    re.IGNORECASE,
)
_HTML_TAG_LITERAL = re.compile(
    r"<(?:html|body|div|input|form|span|button|label|p|a|title)\b", re.IGNORECASE
)
# Files that render through Jinja2 (or Flask's render_template, which is
# Jinja2 underneath) autoescape `{{ var }}` placeholders by default, a
# different code shape this regex-only rule cannot distinguish from a raw
# f-string's `{var}` -- excluded outright rather than risk false-positiving
# on a template engine that's already doing the right thing.
_JINJA_AUTOESCAPE_FILE = re.compile(
    r"\bimport\s+jinja2\b|from\s+jinja2\s+import|render_template\(|autoescape\s*=\s*True",
    re.IGNORECASE,
)

# SRC-028: an exception/upstream-response body is logged in full, with no
# redaction, inside an error-handling path -- the VA Claims MCP server shape
# (GSA-TTS va-claims-mcp-server-DEMO, src/va_claims/utils.py:88-97): every
# tool call in that server logs `e.response.text` -- the VA Benefits Claims
# API's raw error body -- at ERROR level on every failed call, and VA's own
# JSON:API validation errors routinely echo back the submitted SSN/name/DOB/
# address that triggered the failure. Deliberately narrow: it requires BOTH
# an error-level log call AND an argument shaped like a response/exception
# BODY (not just any exception reference), because ordinary
# `logger.error(f"Request failed: {e}")` is extremely common and is NOT this
# bug -- flagging it would make the rule unusably noisy.
_ERROR_LOG_CALL = re.compile(
    r"\b(?:logger\.error|console\.error|log\.error|logging\.error)\s*\(",
    re.IGNORECASE,
)
_RAW_BODY_LOGGED = re.compile(
    r"\.response\.(?:text|data|body|content)\b|"
    r"\berr(?:or)?\.body\b|"
    r"\bresp(?:onse)?\.text\b|"
    r"\bresponse\.data\b|"
    r"String\(\s*err(?:or)?\s*\)|"
    r"JSON\.stringify\(\s*err(?:or)?\.response\s*\)",
    re.IGNORECASE,
)
_REDACTION_APPLIED = re.compile(
    r"\bredact(?:ed)?\(|\bmask\(|\bsanitize\(|\bscrub\(|\bomit\(|\bstrip_pii\(",
    re.IGNORECASE,
)

# SRC-024: a tool/resource-handler function takes a resource-ID parameter
# (project_id/board_id/trust_id/patient_id/claim_id/request_id/...) and
# passes it straight into a read/lookup/approval call, with no
# ownership/tenant/scope-check vocabulary anywhere in the file tying that ID
# to the authenticated caller -- broken object-level authorization
# (BOLA/IDOR, OWASP API1:2023). Two real findings this generalizes: Agorai's
# `get_memory` tool (no getProject() access check in this handler, unlike
# its sibling handlers in the same file) and DEFRA mural-mcp's
# `approve_access_request` endpoint (no check anywhere that the reviewer is
# entitled to decide on that specific request_id).
#
# DELIBERATELY NARROW, and the weakest-precision rule in this file, by the
# design agent's own honest assessment: a vocabulary term generic enough to
# recognize legitimate per-object ownership checks (check_access(),
# authorize()) will also match a bare, non-object-scoped @login_required/
# [Authorize] decorator that only proves "this caller is logged in," not
# "this caller owns THIS resource" -- a regex cannot tell those apart. It
# structurally only recognizes Python and JS/TS handler shapes (confirmed:
# it does not fire on a real C# MCP resource with attribute-based routing).
# A non-firing result must never be read as "this file is BOLA-safe," only
# "no positive signal was found" -- the finding text below says so.
_ID_LOOKUP_CALL = re.compile(
    r"\b\w*(?:store|service|repo(?:sitory)?|db|client)\.\w*"
    r"(?:get|fetch|find|read|query|approve|reject)\w*\(\s*"
    r"(?:args\.|payload\.|params\.)?"
    r"(\w*(?:project|board|trust|patient|claim|memory|resource|request|record|case|document|account)_id)\b",
    re.IGNORECASE,
)
_TOOL_OR_ROUTE_HANDLER = re.compile(
    r"""server\.tool\(\s*["']|@mcp\.tool\b|@router\.(?:get|post)\(|"""
    r"""(?:async\s+)?def\s+(?:get|fetch|read|find|list|approve|reject)_\w*\s*\(""",
    re.IGNORECASE,
)
_SCOPE_OWNERSHIP_VOCAB = re.compile(
    r"\bowner_id\b|\btenant_id\b|"
    r"\b(?:project|board|trust|resource)_id\s*(?:==|!=)\s*\w|"
    r"\.filter\([^)]*==\s*(?:current_user|self\.user)|"
    r"WHERE[^\n]{0,40}owner|"
    r"check_access\(|verify_ownership\(|has_permission\(|authorize\(|"
    r"get_project\(|getProject\(|check_ownership\(|"
    r"current_user|req\.user\b|ctx\.user\b|self\.user\b",
    re.IGNORECASE,
)

# SRC-029: a live access token/secret obtained at RUNTIME (an OAuth token
# exchange, an API response) is written to disk in plaintext via a plain
# file-write call, with no encryption of the value anywhere near that write.
# Derived from the bank-mcp finding (elcukro/bank-mcp): live Plaid/Teller/
# Tink/Enable Banking access tokens and API secrets are written straight to
# disk as plaintext JSON, with a 0o600 file mode as the ONLY protection --
# directly contradicting the project's own SECURITY.md "Design Principles"
# section, which presents that same 600-permission local file as the
# *complete* credential-storage guarantee. Deliberately distinct from
# SRC-010 (fires on a missing chmod, only when the repo hardens permissions
# elsewhere -- about the FILE) and from credential_scanner.py's CRED-* rules
# (STATIC config-sourced secrets) -- this rule fires on the VALUE itself,
# regardless of file permissions, for a token obtained dynamically at
# runtime. Known limitation, shared with SRC-004/010: the static-env
# exclusion only inspects the RHS of the specific matched assignment, so a
# static env-derived token routed through an intermediate variable across
# two lines can still fire -- a single-hop check, not a full dataflow trace.
_RUNTIME_TOKEN_ASSIGN = re.compile(
    r"\b(\w*(?:access_token|accessToken|refresh_token|refreshToken|"
    r"session_token|sessionToken|api_secret|apiSecret|bank_token|bankToken|"
    r"token|secret)\w*)\s*[:=]\s*([^\n;]*)",
    re.IGNORECASE,
)
_STATIC_ENV_SOURCE = re.compile(r"os\.environ|process\.env|getenv\(", re.IGNORECASE)
_PLAINTEXT_WRITE_CALL = re.compile(
    r"\bjson\.dump\(|\.write_text\(|fs\.writeFileSync\(|writeFileSync\(|"
    r"\bwriteFile\(|open\([^)]*\)\.write\(",
)
_ENCRYPTION_CALL = re.compile(
    r"\bencrypt\(|Fernet\(|AES\.|crypto\.createCipher|cipher\.update\(",
    re.IGNORECASE,
)

# SRC-026: a server bound to loopback (127.0.0.1/localhost/::1) -- or a
# WebSocket server constructed with no explicit public-interface bind in the
# construction call itself -- has no Origin-header check anywhere in the
# file. Binding to loopback only is an implicit security claim ("only the
# local machine can reach me"); DNS rebinding (for a plain HTTP/SSE
# endpoint) or, for WebSocket, an ordinary same-machine browser tab
# (WebSocket connections are exempt from the same-origin policy entirely)
# reaches that "local-only" listener from any website open in a browser on
# the same machine. This is the inbound direction -- a malicious webpage
# attacking a local service -- not classic SSRF (SRC-011/023). Distinct from
# SRC-021 (no auth mechanism at all): a server can have a real auth/token
# check and still be exploitable this way, since the attacking page's
# request looks, at the transport level, identical to the legitimate local
# client's -- Origin is the one signal that tells them apart.
#
# Two real findings this generalizes (unity-mcp, mcp-unity-cg -- both bind
# loopback/localhost by default with no Origin check anywhere), plus a bonus
# sub-case (fast-mcp): an Origin check DOES exist, but its validation regex
# has a wildcard and no start/end anchor, so it's satisfied by any string
# that merely CONTAINS the expected host as a substring.
_LOOPBACK_BIND = re.compile(
    r"""(?:\bhost\b|http_host|HTTP_HOST)\s*[:=][\s\S]{0,150}?["'](?:127\.0\.0\.1|localhost|::1)["']|"""
    r"""\b(?:bind|Bind|listen|Listen)\s*\(\s*\(?\s*["'](?:127\.0\.0\.1|localhost|::1)["']|"""
    r"""(?:ws|http)s?://(?:127\.0\.0\.1|localhost|::1)\b"""
)
_WS_SERVER_CTOR = re.compile(
    r"""\bnew\s+WebSocketServer\(([^;\n]{0,150})|\bnew\s+ws\.Server\(([^;\n]{0,150})|"""
    r"""\bws\.Server\(([^;\n]{0,150})|\bsocket\.io\(([^;\n]{0,150})"""
)
_PUBLIC_LITERAL_IN_CALL = re.compile(r"0\.0\.0\.0")
_ORIGIN_CHECK_PRESENT = re.compile(
    r"""req(?:uest)?\.headers(?:\.get)?\(?\s*\[?\s*["']origin["']|"""
    r"""headers\.get\(\s*["']origin["']|Context\.Headers\s*\[\s*["']Origin["']\s*\]|"""
    r"""\.origin\s*(?:==|!=|in\s|not\s+in\s)|checkOrigin\(|verifyOrigin\(|validate_origin\(|"""
    r"""validateOrigin\(|allowed_origins|allowedOrigins|ALLOWED_ORIGINS""",
    re.IGNORECASE,
)
_ORIGIN_REGEX_UNANCHORED = re.compile(
    r"""(?:Regexp\.new\(|re\.compile\(|RegExp\(|new\s+RegExp\()\s*"""
    r"""(f?r?["'])((?:(?!\1)[^\n])*?(?:\.\*|\.\+)(?:(?!\1)[^\n])*?)\1"""
)
_ANCHOR_TOKENS = re.compile(r"\\A|\\z|\\Z|\^|\$|\\b|fullmatch")

# SRC-022: a SQL/SoQL/query-API fragment is built by hand-quoting an
# f-string- or concatenation-interpolated value directly into the query
# text, instead of binding it as a parameter (CWE-89/943). Derived from two
# independently-confirmed real findings: apple-health-mcp-server's four
# DuckDB-backed tools (f-string-interpolate record_type/source_name/
# date_from/date_to/value into SQL WHERE clauses -- exploitable via
# DuckDB's read_csv() for arbitrary local file read even with
# read_only=True) and cdc-places-mcp-server's area_summary_stats tool
# (state_code/county f-string-interpolated into a Socrata SoQL $where
# clause -- a single quote and an always-true clause silently defeats the
# tool's documented geographic scoping).
#
# The obvious first version of this rule -- require execute()/.query() to
# directly wrap the f-string -- FAILED against BOTH real vulnerable code
# paths when actually run against them: neither builds the unsafe fragment
# inline in the call. apple-health's helper functions return the fragment
# to a caller several stack frames away, and cdc-places assigns it into a
# dict key, only sent by a later, unrelated fetch call -- the same
# "build here, use there" split SRC-014's module comment already documents
# for redirect_uri. The signal that actually fires on both real bugs is
# structural, not call-site-bound: a comparison operator immediately
# followed by a quote-wrapped, brace-interpolated value (worded here to
# avoid literally reproducing the trigger shape, so this doc comment
# doesn't self-match the rule it's describing) -- hand-quoting an
# interpolated value to build a query literal is itself the bug, regardless
# of where the resulting string is executed.
# _SQL_QUERY_EXEC_CALL/_SQL_FSTRING_OR_CONCAT_ARG are a
# broader-recall companion for the more common single-line
# cursor.execute(f"...") shape, the same SRC-009/SRC-019 relationship.
_SQL_UNSAFE_QUERY_INTERP = re.compile(
    r"""[=<>!]=?\s*['"]\{[^{}\n]+\}['"]"""
    r"""|['"][^"'\n]{0,80}['"]\s*\+\s*\w+(?:\.\w+)*\s*\+\s*['"]"""
)
_SQL_QUERY_EXEC_CALL = re.compile(
    r"\b(?:cursor\.execute|conn\.execute|\.execute|\.query|\.sql)\s*\("
)
_SQL_FSTRING_OR_CONCAT_ARG = re.compile(
    r"""f["'][^\n]{0,100}?\{[^{}\n]+\}|['"][^"'\n]*['"]\s*\+\s*\w+"""
)
# Parameterization exclusion: %s / ?-placeholder / $1 / :named / params=
# alongside the match means this is a correctly-parameterized query that
# also happens to f-string something else -- don't flag it. `:[A-Za-z_]\w*\b`
# (not `:\w+\b`) deliberately excludes a bare `:digits`: an earlier version
# matched `:\w+\b` and was falsely excluding real matches whose nearby text
# included a `file.py:74`-style line-number citation in a comment, verified
# against the actual cdc-places PoC snippet, which carries exactly that
# comment shape.
_SQL_PARAMETERIZED = re.compile(
    r"%s|\?\s*[,)]|\$\d+\b|:[A-Za-z_]\w*\b|\bparams\s*=|\bparameters\s*="
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

        # SRC-021: network listener starts, no INBOUND auth check anywhere in
        # file. Excludes stdio transport -- a server serving over stdio
        # (`transport::stdio()`, `StdioServerTransport`, etc.) isn't
        # network-exposed at all; it's only reachable by whoever can spawn
        # the local process, so "authentication" isn't a meaningful concept
        # there. Verified: an earlier version without this exclusion
        # false-positived on a real, confirmed-clean stdio-only MCP server.
        nsm = _NETWORK_SERVE_CALL.search(text)
        nsm_context = text[max(0, nsm.start() - 60):nsm.start() + 60] if nsm else ""
        if nsm and "stdio" not in nsm_context.lower() and not _INBOUND_AUTH_CHECK.search(text):
            file_findings.append(SourceFinding(
                "SRC-021", Severity.CRITICAL,
                "Network listener starts with no authentication mechanism anywhere in the file",
                "This file starts a network listener (HTTP/SSE server), and "
                "no inbound authentication check (reading an Authorization/"
                "API-key header from the incoming request, or a real auth "
                "middleware/decorator) appears anywhere in it. Any network "
                "caller who can reach this listener can invoke every tool "
                "it exposes with no credential of any kind. This was the "
                "single most common real bug shape this project's own "
                "disclosure campaign found -- more common than any other "
                "single class -- across government and commercial MCP "
                "servers alike.",
                f"{rel}:{_line_of(text, nsm.start())}",
                text[nsm.start():nsm.start() + 90].strip(),
                "Require a credential (API key, bearer token, OAuth) on "
                "every request before dispatching to a tool, not just on "
                "the listener's existence. If this is intentionally a "
                "public, unauthenticated read-only service, say so "
                "explicitly in the file and confirm no tool it exposes can "
                "read/write anything sensitive.",
                9.1,
            ))

        # SRC-027: an OAuth scope parameter taken straight from the request,
        # fed into a token/authorization-code minting call somewhere in the
        # file, with no check of the requested scope against the
        # authenticating user's role anywhere in the file (see the pattern
        # comment above for why the role check is searched file-wide, the
        # same discipline SRC-014 uses for redirect_uri validation).
        scm = _OAUTH_SCOPE_FROM_REQUEST.search(text)
        tcm = _OAUTH_SCOPE_IN_TOKEN_CALL.search(text) if scm else None
        if scm and tcm and not _ROLE_CHECK_PRESENT.search(text):
            file_findings.append(SourceFinding(
                "SRC-027", Severity.HIGH,
                "OAuth scope taken from request with no role check before token issuance",
                "A scope parameter is read directly from the incoming "
                "request and flows into a token/authorization-code minting "
                "call somewhere in this file, with no comparison of the "
                "requested scope against the authenticating user's "
                "role/entitlements anywhere in the file. This is the exact "
                "bug an independent re-verification agent confirmed the "
                "same night in mcp-construction: /oauth/authorize checked "
                "only email/password, never the user's role column, so any "
                "authenticated org member -- including one explicitly "
                "created with the lowest role, viewer -- could request "
                "scope=admin and receive a fully-privileged access token, "
                "a full same-tenant privilege escalation to owner.",
                f"{rel}:{_line_of(text, scm.start())}",
                text[scm.start():scm.start() + 90].strip(),
                "Before persisting or issuing a token with the requested "
                "scope, derive the maximum grantable scope from the "
                "authenticating user's actual role/entitlements (e.g. a "
                "role-to-scope map) and intersect the requested scope "
                "against it -- never trust the client-supplied scope "
                "string as-is, and never check it only against the OAuth "
                "client's own registered scope, which says nothing about "
                "this particular user's privilege.",
                8.1,
            ))

        # SRC-030: CORS wildcard, or a dev-server host-validation guard
        # explicitly disabled -- either sub-pattern alone is a real finding
        # (see the pattern comment above for the Alpic/Skybridge provenance).
        for cwm in _CORS_WILDCARD.finditer(text):
            file_findings.append(SourceFinding(
                "SRC-030", Severity.HIGH,
                "CORS wildcard or disabled dev-server host check exposes sensitive endpoints",
                "CORS is configured with no origin restriction -- a bare "
                "CORS-middleware call with no options object (wildcard by "
                "default), or an explicit wildcard/boolean origin value. "
                "Any website a victim merely has open in a browser tab can "
                "make cross-origin requests against this server with no "
                "user interaction beyond the page loading. This is the "
                "exact shape found in Alpic's Skybridge (1,990+ GitHub "
                "stars, Alpic's flagship MCP cloud framework): wildcard "
                "CORS on the dev router reached the /mcp endpoint and the "
                "devtools deploy-control router, letting any page enumerate "
                "and invoke every MCP tool and trigger the developer's "
                "cloud deploy pipeline.",
                f"{rel}:{_line_of(text, cwm.start())}",
                text[max(0, cwm.start() - 20):cwm.start() + 70].strip(),
                "Replace the wildcard with an explicit allowlist of "
                "expected origins (e.g. cors({ origin: allowedOrigins })), "
                "or remove the blanket CORS call and add narrow, "
                "path-specific CORS only where genuinely needed -- never on "
                "an MCP endpoint or a deploy/control endpoint.",
                8.1,
            ))

        for dhm in _DEV_HOST_CHECK_DISABLED.finditer(text):
            file_findings.append(SourceFinding(
                "SRC-030", Severity.HIGH,
                "CORS wildcard or disabled dev-server host check exposes sensitive endpoints",
                "A dev-server's Host-header validation guard is explicitly "
                "disabled (Vite's or webpack-dev-server's host-allowlist "
                "override set to bypass the check), rather than left at "
                "its default. "
                "This is the DNS-rebinding protection dev servers rely on; "
                "disabling it lets any website that gets a victim's browser "
                "to send a request with a forged Host header reach the dev "
                "server as if it were a trusted local origin. In the real "
                "Alpic/Skybridge finding this was set unconditionally and "
                "spread in after the developer's own config, making it "
                "non-overridable, and combined with wildcard CORS let any "
                "website read arbitrary files across the whole workspace "
                "source tree.",
                f"{rel}:{_line_of(text, dhm.start())}",
                text[max(0, dhm.start() - 20):dhm.start() + 70].strip(),
                "Remove the override and let the dev server's default "
                "Host-header allowlist apply, or make it explicitly "
                "configurable rather than hardcoded and unconditional. "
                "Never disable dev-server host validation in a config path "
                "that could ship to production.",
                8.1,
            ))

        # SRC-023: outbound fetch/clone of a caller-derived URL, with no
        # SSRF validation call anywhere in the file (see the pattern
        # comment above for why this deliberately overlaps with, but
        # never double-fires alongside, SRC-011). Try the inline shape
        # first, then the assign-then-call shape.
        if not _SSRF_VALIDATE_CALL.search(text):
            um = _SSRF_FETCH_WITH_URLVAR_INLINE.search(text)
            if um is None:
                for am in _URL_ARG_DERIVED_ASSIGN.finditer(text):
                    var = am.group(1)
                    lookahead = text[am.end():am.end() + 400]
                    cm3 = _SSRF_OUTBOUND_CALL_BARE.search(lookahead)
                    if cm3 and re.search(rf"\b{re.escape(var)}\b", lookahead[cm3.start():cm3.end() + 120]):
                        um = am  # anchor the reported location at the assignment
                        break
            if um:
                file_findings.append(SourceFinding(
                    "SRC-023", Severity.HIGH,
                    "Outbound fetch of a caller-derived URL with no SSRF validation",
                    "A caller/request-derived URL or target is passed "
                    "directly into an outbound network call (HTTP fetch or "
                    "git clone), and no SSRF-guard call (validate_url/"
                    "check_ssrf/is_safe_url/validate_host/"
                    "resolve_and_check, or similar) appears anywhere in "
                    "this file. Unlike SRC-011 (a guard exists but is "
                    "bypassed by a separate, unpinned DNS resolution), this "
                    "is the simpler and far more common case: no "
                    "validation of any kind is attempted before the "
                    "request goes out. A caller can point the server at an "
                    "internal service, a loopback address, or the cloud "
                    "metadata endpoint and have the server fetch it on "
                    "their behalf -- the exact pattern this project's "
                    "campaign confirmed in ark-forge/mcp-eu-ai-act (git "
                    "clone of a caller-supplied repo_url), the French "
                    "government's datagouv-mcp (machine_documentation_url "
                    "fetched unvalidated), and Bybit's open-source kaas "
                    "(URL-ingestion feature with zero scheme/host/IP "
                    "validation).",
                    f"{rel}:{_line_of(text, um.start())}",
                    text[um.start():um.start() + 90].strip(),
                    "Before making the outbound call, resolve the target's "
                    "host and reject any private/loopback/link-local/"
                    "reserved address (RFC 1918, 127.0.0.0/8, "
                    "169.254.0.0/16, and the 169.254.169.254 metadata "
                    "address) -- or restrict targets to an explicit "
                    "allowlist -- and re-validate after any redirect the "
                    "client follows.",
                    8.1,
                ))

        # SRC-024: a resource-ID lookup call inside a tool/route-handler
        # function, with no ownership/tenant/scope-check vocabulary anywhere
        # in the file. Anchors the finding at the nearest handler
        # declaration preceding the lookup call (same "find the enclosing
        # entry point" idea SRC-016 uses), not at the lookup call itself,
        # so the report points where a caller enters, not an internal detail.
        lkm = _ID_LOOKUP_CALL.search(text)
        handler_m = None
        if lkm:
            for hm in _TOOL_OR_ROUTE_HANDLER.finditer(text, 0, lkm.start()):
                handler_m = hm
        if handler_m and not _SCOPE_OWNERSHIP_VOCAB.search(text):
            file_findings.append(SourceFinding(
                "SRC-024", Severity.HIGH,
                "Resource ID used as a read/approval lookup key with no ownership check (BOLA)",
                "A tool/resource-handler function takes a resource-ID "
                "parameter (project_id/board_id/trust_id/claim_id/"
                "request_id/...) and passes it directly into a lookup or "
                "approval call, with no ownership/tenant/scope-check "
                "vocabulary anywhere in this file tying the resource to "
                "the authenticated caller. A caller who supplies -- or "
                "guesses, or is handed via prompt injection -- another "
                "party's resource ID can read or approve access to that "
                "resource: broken object-level authorization (BOLA/IDOR, "
                "OWASP API1:2023). This is a heuristic file-scoped check, "
                "the lowest-confidence rule in this file (see the pattern "
                "comment above): confirm by reading the handler, its "
                "sibling handlers, and any shared access-check helper "
                "before treating this as confirmed -- a non-firing result "
                "elsewhere does not mean a file is BOLA-safe.",
                f"{rel}:{_line_of(text, handler_m.start())}",
                text[handler_m.start():handler_m.start() + 90].strip(),
                "Before returning or acting on the resource, verify "
                "server-side that the authenticated caller owns it or is "
                "scoped to it (a membership/tenant lookup keyed by the "
                "caller's own identity, not the client-supplied ID) -- "
                "the same access check this file's other handlers may "
                "already apply to sibling operations.",
                8.1,
            ))

        # SRC-025: request query/form parameter interpolated unescaped into
        # an HTML response string (reflected XSS). See the pattern comment
        # above for why this searches the whole file by variable name rather
        # than a small window.
        if not _JINJA_AUTOESCAPE_FILE.search(text):
            seen_vars: set[str] = set()
            for rpm in _REQUEST_PARAM_ASSIGN.finditer(text):
                var = rpm.group(1)
                if var in seen_vars:
                    continue
                escaped_re = re.compile(
                    rf"(?:html\.escape|markupsafe\.escape|cgi\.escape|(?<!\.)escape)\(\s*{re.escape(var)}\b"
                )
                if escaped_re.search(text):
                    continue
                interp_re = re.compile(rf"\{{\s*{re.escape(var)}\s*\}}")
                im = interp_re.search(text)
                if not im:
                    continue
                if not _HTML_TAG_LITERAL.search(text[max(0, im.start() - 2000):im.start()]):
                    continue
                seen_vars.add(var)
                file_findings.append(SourceFinding(
                    "SRC-025", Severity.HIGH,
                    "Unescaped request parameter interpolated into HTML response (reflected XSS)",
                    f"'{var}' is read from a request query/form parameter and "
                    "later interpolated directly into an HTML-building "
                    "f-string/template with no html.escape()/markupsafe."
                    "escape() call applied to it anywhere in this file. A "
                    "value containing a quote-then-angle-bracket sequence "
                    "breaks out of the surrounding HTML attribute/tag and "
                    "injects arbitrary markup or script into the response "
                    "(CWE-79). This is the exact shape of this project's "
                    "own confirmed finding in "
                    "adwiteeymauriya/ibkr-portfolio-builder-mcp: a `next` "
                    "query/form parameter spliced unescaped into the OAuth "
                    "login page's value attribute, executing attacker "
                    "script on the very page asking the victim for the "
                    "password that gates the whole connector.",
                    f"{rel}:{_line_of(text, im.start())}",
                    text[max(0, im.start() - 40):im.start() + 40].strip(),
                    "HTML-escape the value at the point of interpolation "
                    "(html.escape(value, quote=True)) or switch to a "
                    "templating engine with autoescaping enabled (Jinja2) "
                    "instead of building HTML with raw string interpolation.",
                    6.1,
                ))

        # SRC-028: the full exception/upstream-response body is logged at
        # error level with no redaction -- the VA Claims MCP server shape
        # (see pattern comment above). Bounded to the rest of the log call's
        # own line so a safe, curated call on an adjacent line (e.g. one
        # that only logs e.response.status_code) is never swept in by a
        # sibling call's window (see the "first version failed" note above).
        for elm in _ERROR_LOG_CALL.finditer(text):
            line_end = text.find("\n", elm.end())
            if line_end == -1:
                line_end = len(text)
            window = text[elm.end():min(line_end, elm.end() + 200)]
            bm = _RAW_BODY_LOGGED.search(window)
            if not bm or _REDACTION_APPLIED.search(window[:bm.end()]):
                continue
            file_findings.append(SourceFinding(
                "SRC-028", Severity.HIGH,
                "Full upstream response/exception body logged with no redaction",
                "An error handler logs the complete upstream response or "
                "exception body (e.response.text/.data/.body, String(err), "
                "JSON.stringify(err.response), or similar) at error level, "
                "rather than a curated status/message field. This is the "
                "VA Claims MCP server shape (GSA-TTS va-claims-mcp-server-"
                "DEMO, src/va_claims/utils.py:88-97): every one of its 8 "
                "tools logs the VA Benefits Claims API's raw error body on "
                "every failed call, and that API's own validation errors "
                "routinely echo back the submitted SSN, name, date of "
                "birth, or address that caused the failure -- turning an "
                "ordinary, non-adversarial usage mistake into a route for "
                "PII/credentials to land in plaintext application logs.",
                f"{rel}:{_line_of(text, elm.start())}",
                text[elm.start():elm.start() + 90].strip(),
                "Log a curated, redacted message instead of the raw "
                "upstream body: the HTTP status code and an error code/"
                "title field, not the full response text. If the full body "
                "is genuinely needed for debugging, redact PII/credential-"
                "shaped fields first (or gate it behind an explicit, "
                "off-by-default debug flag never enabled against a real "
                "upstream).",
                7.5,
            ))

        # SRC-029: a runtime-obtained token/secret (assigned from something
        # other than a static os.environ/process.env read -- an OAuth
        # exchange, an API response) is written to disk in this file via a
        # plain file-write call, with no encryption call applied to the
        # value anywhere near that write.
        tok_matches = [
            tm for tm in _RUNTIME_TOKEN_ASSIGN.finditer(text)
            if not _STATIC_ENV_SOURCE.search(tm.group(2))
        ]
        if tok_matches:
            wm = _PLAINTEXT_WRITE_CALL.search(text)
            if wm and wm.start() > tok_matches[0].start():
                window = text[max(0, wm.start() - 150):wm.start() + 250]
                if not _ENCRYPTION_CALL.search(window):
                    file_findings.append(SourceFinding(
                        "SRC-029", Severity.HIGH,
                        "Live access token/secret written to disk in plaintext",
                        "A token/secret variable (access_token, refresh_token, "
                        "session_token, api_secret, bank_token, or a generic "
                        "token/secret) is assigned earlier in this file from "
                        "something other than a static os.environ/process.env "
                        "read -- i.e. obtained at runtime, such as an OAuth "
                        "exchange or an API response -- and this file also "
                        "writes to disk via a plain file-write call with no "
                        "encrypt()/Fernet()/AES./crypto.createCipher/"
                        "cipher.update() call anywhere near it. Derived from "
                        "the bank-mcp finding (elcukro/bank-mcp): live Plaid/"
                        "Teller/Tink/Enable Banking access tokens and API "
                        "secrets, obtained through real OAuth/bank-linking "
                        "flows, are written straight to disk as plaintext "
                        "JSON, with a 0o600 file mode as the ONLY protection "
                        "applied -- directly contradicting the project's own "
                        "SECURITY.md 'Design Principles' section, which "
                        "presents that same 600-permission local file as the "
                        "complete credential-storage guarantee for financial "
                        "credentials it explicitly calls out as sensitive. "
                        "File permissions alone do not defend against the "
                        "realistic MCP threat model: a compromised "
                        "dependency, an unrelated MCP server, or any other "
                        "code running as the same OS user can simply read "
                        "the file.",
                        f"{rel}:{_line_of(text, wm.start())}",
                        text[wm.start():wm.start() + 90].strip(),
                        "Never write a runtime-obtained access token or "
                        "secret to disk as plaintext, regardless of file "
                        "permissions. Prefer OS-native secret storage "
                        "(macOS Keychain, libsecret, Windows Credential "
                        "Manager); where unavailable, encrypt the value "
                        "(Fernet/AES-256-GCM, key derived via Argon2id/"
                        "scrypt) before it reaches any write call, and "
                        "decrypt only in memory when actually needed.",
                        7.5,
                    ))

        # SRC-026: loopback-bound (or WebSocket-ctor) server, no Origin check
        # anywhere in the file -- DNS rebinding / cross-site WebSocket
        # hijacking against a service that only ever claimed to be reachable
        # from the local machine. Excludes a `host = ...` assignment whose
        # RHS parses an existing URL (.hostname, urlparse(/parse_url() in
        # the same statement) -- that's extracting a SCAN TARGET's hostname
        # (with a "localhost" fallback default), not declaring where this
        # server itself binds. Verified via this project's own dogfooding:
        # server.py's `host = parsed.hostname or "localhost"` (building the
        # target host for an outbound endpoint probe) matched the naive
        # version of this pattern despite not being a bind statement at all.
        loopback_m = None
        for lbm in _LOOPBACK_BIND.finditer(text):
            stmt_end = text.find("\n", lbm.end())
            statement = text[lbm.start():stmt_end if stmt_end != -1 else len(text)]
            if ".hostname" in statement or "urlparse(" in statement or "parse_url(" in statement:
                continue
            loopback_m = lbm
            break
        if loopback_m is None:
            for wsm in _WS_SERVER_CTOR.finditer(text):
                call_args = next((g for g in wsm.groups() if g is not None), "")
                if not _PUBLIC_LITERAL_IN_CALL.search(call_args):
                    loopback_m = wsm
                    break
        if loopback_m and not _ORIGIN_CHECK_PRESENT.search(text):
            file_findings.append(SourceFinding(
                "SRC-026", Severity.HIGH,
                "Loopback-bound server has no Origin-header check (DNS rebinding / cross-site WebSocket hijacking)",
                "This file binds a server to loopback (127.0.0.1/localhost) "
                "-- or constructs a WebSocket server with no explicit "
                "public-interface bind in the construction call -- "
                "implicitly claiming only the local machine can reach it, "
                "but no Origin header is ever read or compared anywhere in "
                "the file. A hostile website open in any browser on the "
                "same machine can reach this 'local-only' listener: via DNS "
                "rebinding for a plain HTTP/SSE endpoint (a domain whose DNS "
                "record flips to 127.0.0.1 after the page loads still looks "
                "same-origin to the browser), or directly for a WebSocket "
                "endpoint, since WebSocket connections are exempt from the "
                "same-origin policy entirely and need no DNS trick at all. "
                "This is the inbound CSRF/DNS-rebinding class, not classic "
                "SSRF -- the attacker's page is attacking the local "
                "service, not asking the server to fetch an attacker URL.",
                f"{rel}:{_line_of(text, loopback_m.start())}",
                text[loopback_m.start():loopback_m.start() + 90].strip(),
                "Validate the incoming Origin header against an "
                "exact-match allowlist (never substring/prefix matching) "
                "before accepting any request or WebSocket upgrade on a "
                "loopback-bound listener -- treat 'binds to loopback' as a "
                "claim that needs enforcing, not a security boundary the "
                "OS provides for free.",
                8.1,
            ))

        # SRC-026 (sub-case): an Origin/hostname check exists, but its
        # validation regex has a wildcard and no start/end anchor, so it's
        # satisfied by a substring match instead of a full-string match --
        # the fast-mcp shape (see the pattern comment above).
        for um in _ORIGIN_REGEX_UNANCHORED.finditer(text):
            pattern_text = um.group(2)
            if not _ANCHOR_TOKENS.search(pattern_text):
                file_findings.append(SourceFinding(
                    "SRC-026", Severity.HIGH,
                    "Origin/hostname check regex has no anchor (substring-match bypass)",
                    "An Origin or hostname value is validated against a "
                    "regex built with a wildcard (.*/.+) and no start/end "
                    "anchor (\\A/\\z, ^/$, or a fullmatch call). An "
                    "unanchored wildcard pattern intended to match "
                    "'foo.example.com' is satisfied by any string that "
                    "merely CONTAINS that host as a substring, e.g. "
                    "'evilexample.com' or 'x.example.com.evil.io' -- "
                    "letting an attacker-controlled Origin through a check "
                    "that looks correct at a glance.",
                    f"{rel}:{_line_of(text, um.start())}",
                    text[um.start():um.start() + 90].strip(),
                    "Anchor the comparison to the full string (\\A...\\z in "
                    "Ruby, re.fullmatch in Python, ^...$ in a JS RegExp) or "
                    "use an exact-match allowlist instead of pattern "
                    "matching for Origin/hostname validation.",
                    7.5,
                ))
                break

        # SRC-022: a query fragment built by hand-quoting an interpolated
        # value directly into the query text instead of binding it as a
        # parameter -- fires on every occurrence (like SRC-004/013/015),
        # since a real file can build several such fragments (cdc-places'
        # area_summary_stats.py does it in three separate geo_type branches).
        s22_hit = False
        for qm in _SQL_UNSAFE_QUERY_INTERP.finditer(text):
            window = text[max(0, qm.start() - 100):qm.end() + 100]
            if _SQL_PARAMETERIZED.search(window):
                continue
            s22_hit = True
            file_findings.append(SourceFinding(
                "SRC-022", Severity.HIGH,
                "SQL/query injection via unescaped string interpolation",
                "A query fragment is built by hand-quoting an interpolated "
                "value directly into the query text (an f-string or "
                "concatenation produces a comparison operator directly "
                "followed by a quoted, brace-interpolated value) rather "
                "than binding it as a parameter, with no parameterization "
                "marker (%s/?/$1/:name/params=) nearby. This is the exact "
                "root cause behind two independently-confirmed real "
                "findings: apple-health-mcp-server's DuckDB-backed tools "
                "(interpolate record_type/source_name/date_from/date_to/"
                "value into SQL WHERE clauses -- exploitable via DuckDB's "
                "read_csv() for arbitrary local file read even with "
                "read_only=True) and cdc-places-mcp-server's "
                "area_summary_stats tool (state_code/county interpolated "
                "into a Socrata SoQL $where clause -- a single quote and "
                "an always-true clause silently defeats the tool's "
                "documented geographic scoping). Any MCP client -- in "
                "practice, whatever an LLM agent decides to pass as a "
                "tool argument -- can inject arbitrary query logic "
                "through this shape.",
                f"{rel}:{_line_of(text, qm.start())}",
                text[max(0, qm.start() - 40):qm.end() + 20].strip(),
                "Use the database/query API's native parameterization "
                "(%s, ?, $1, or named placeholders bound via a params= "
                "mapping) instead of interpolating values into the query "
                "text. Where a value must still be embedded as a literal, "
                "escape it with the query API's own escaping (e.g. "
                "doubling single quotes for SQL/SoQL) as defense-in-depth "
                "in addition to -- never instead of -- parameterization.",
                8.6,
            ))

        # SRC-022 (broader-recall companion): the classic single-line shape
        # where the query-execution call directly wraps an f-string/
        # concatenation argument. Only checked when no interpolation-shape
        # finding already fired above, mirroring SRC-018's inline-then-
        # fallback structure.
        if not s22_hit:
            cqm = _SQL_QUERY_EXEC_CALL.search(text)
            if cqm:
                call_window = text[cqm.start():cqm.start() + 200]
                fm = _SQL_FSTRING_OR_CONCAT_ARG.search(call_window)
                if fm and not _SQL_PARAMETERIZED.search(call_window):
                    file_findings.append(SourceFinding(
                        "SRC-022", Severity.HIGH,
                        "SQL/query injection via unescaped string interpolation",
                        "A query-execution call (execute/.query/.sql) is "
                        "given an argument built via f-string or string "
                        "concatenation containing a variable, with no "
                        "parameterization marker (%s/?/$1/:name/params=) "
                        "in the call. Same root cause as the two real "
                        "findings cited above (apple-health-mcp-server, "
                        "cdc-places-mcp-server): the query text itself "
                        "carries attacker-influenceable content instead of "
                        "binding it as a parameter.",
                        f"{rel}:{_line_of(text, cqm.start())}",
                        call_window[:90].strip(),
                        "Use the database/query API's native "
                        "parameterization (%s, ?, $1, or named "
                        "placeholders bound via a params= mapping) instead "
                        "of interpolating values into the query text "
                        "passed to execute()/.query()/.sql().",
                        8.6,
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
