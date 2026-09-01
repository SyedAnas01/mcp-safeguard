"""Tests for the SRC-005..SRC-012 source-scanner rules.

Each rule gets a trigger fixture (should produce that rule_id) and a
non-trigger fixture (same shape, minus the bug) to guard against obvious
false positives -- same discipline as test_source_scanner.py for SRC-001..004.
"""

from mcp_shield.scanner.source_scanner import scan_source_tree

# --- SRC-005: auth flag parsed and only warned about, never gated ----------

def test_src005_auth_token_checked_but_only_warned_is_flagged(tmp_path):
    """The exact terminator-mcp-agent shape: auth_token is parsed and even
    tested with .is_none(), but the branch only prints a warning -- it never
    exits or refuses to serve. The listener starts regardless."""
    (tmp_path / "main.rs").write_text(
        '''
        fn main() {
            let auth_token = std::env::var("AUTH_TOKEN").ok();
            if auth_token.is_none() {
                eprintln!("Warning: no auth_token set, server running without authentication");
            }
            SseServer::serve(addr).await;
        }
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert any(f.rule_id == "SRC-005" for f in findings), (
        f"Expected SRC-005, got: {findings}"
    )


def test_src005_auth_token_gated_with_exit_is_not_flagged(tmp_path):
    """Same shape, but the missing-token branch actually refuses to start."""
    (tmp_path / "main.rs").write_text(
        '''
        fn main() {
            let auth_token = std::env::var("AUTH_TOKEN").ok();
            if auth_token.is_none() {
                eprintln!("Error: AUTH_TOKEN is required");
                std::process::exit(1);
            }
            SseServer::serve(addr).await;
        }
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-005" for f in findings), (
        f"Did not expect SRC-005 when the missing-token path exits, got: {findings}"
    )


# --- SRC-006: client-supplied ID keys shared state, no ownership check -----

def test_src006_chat_id_keys_history_with_no_ownership_check_is_flagged(tmp_path):
    """bot_id ownership is checked, but chat_id itself is never verified to
    belong to the caller before it keys a shared Redis history object --
    the aperag shape."""
    (tmp_path / "chat_service.py").write_text(
        '''
        def get_history(chat_id, bot_id):
            if not bot_owned_by_caller(bot_id):
                raise PermissionError()
            history = RedisChatMessageHistory(chat_id)
            return history
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert any(f.rule_id == "SRC-006" for f in findings), (
        f"Expected SRC-006, got: {findings}"
    )


def test_src006_chat_id_ownership_verified_is_not_flagged(tmp_path):
    """Same shape, but the chat itself is looked up and its owner is checked
    against the caller before the ID is used to key shared state."""
    (tmp_path / "chat_service.py").write_text(
        '''
        def get_history(chat_id, bot_id):
            chat = get_chat(chat_id)
            if chat.owner != current_user:
                raise PermissionError()
            history = RedisChatMessageHistory(chat_id)
            return history
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-006" for f in findings), (
        f"Did not expect SRC-006 when chat_id ownership is verified, got: {findings}"
    )


# --- SRC-007: type-only classifier trusted as a security gate --------------

def test_src007_type_only_classifier_used_as_gate_is_flagged(tmp_path):
    """is_readonly() only checks the leading keyword and is actually used to
    block execution -- it will miss a SELECT that wraps a side-effecting
    call like setval()."""
    (tmp_path / "safety.py").write_text(
        '''
        def is_readonly(query):
            return query.strip().lower().startswith("select")

        def execute(query):
            if not is_readonly(query):
                raise PermissionError("destructive query blocked")
            return db.run(query)
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert any(f.rule_id == "SRC-007" for f in findings), (
        f"Expected SRC-007, got: {findings}"
    )


def test_src007_classifier_not_used_as_gate_is_not_flagged(tmp_path):
    """A type-only classifier that exists but is only logged/reported, never
    used to block execution, is not a security-control overclaim -- do not
    flag it. (This is the false-positive shape from the earlier manual-audit
    mistake: a classifier's mere existence is not evidence it is enforced.)"""
    (tmp_path / "safety.py").write_text(
        '''
        def is_readonly(query):
            return query.strip().lower().startswith("select")

        def log_query_type(query):
            logger.info("query is readonly: %s", is_readonly(query))
            return db.run(query)
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-007" for f in findings), (
        f"Did not expect SRC-007 when the classifier is not used as a gate, "
        f"got: {findings}"
    )


def test_src007_classifier_that_also_checks_call_names_is_not_flagged(tmp_path):
    """Same gate usage, but the classifier also checks for side-effecting
    function calls -- it is doing semantic analysis, not syntax-only
    matching, so this is not a finding."""
    (tmp_path / "safety.py").write_text(
        '''
        def is_readonly(query):
            if not query.strip().lower().startswith("select"):
                return False
            if "setval(" in query or "nextval(" in query:
                return False
            return True

        def execute(query):
            if not is_readonly(query):
                raise PermissionError("destructive query blocked")
            return db.run(query)
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-007" for f in findings), (
        f"Did not expect SRC-007 when the classifier also checks call names, "
        f"got: {findings}"
    )


# --- SRC-008: client-supplied ownership field trusted on a mutation --------

def test_src008_client_supplied_user_id_on_update_is_flagged(tmp_path):
    """The metatool-ai shape: a tRPC mutation writes input.user_id straight
    into the update payload instead of deriving it from the session."""
    (tmp_path / "router.ts").write_text(
        '''
        export const updateBot = proc.mutation(async ({ input }) => {
            return db.bot.update({
                where: { id: input.id },
                data: { user_id: input.user_id, name: input.name },
            });
        });
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert any(f.rule_id == "SRC-008" for f in findings), (
        f"Expected SRC-008, got: {findings}"
    )


def test_src008_server_derived_user_id_is_not_flagged(tmp_path):
    """Same mutation, but the ownership field comes from the authenticated
    session, not client input."""
    (tmp_path / "router.ts").write_text(
        '''
        export const updateBot = proc.mutation(async ({ ctx, input }) => {
            return db.bot.update({
                where: { id: input.id },
                data: { user_id: ctx.session.user.id, name: input.name },
            });
        });
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-008" for f in findings), (
        f"Did not expect SRC-008 when user_id is server-derived, got: {findings}"
    )


# --- SRC-009: unescaped shell interpolation (only when repo knows better) --

def test_src009_unescaped_interpolation_flagged_when_repo_has_safe_helper(tmp_path):
    """The same repository defines shellQuote elsewhere, so it knows the
    risk -- this call site interpolating raw input into a shell string is
    the inconsistent exception."""
    (tmp_path / "utils" / "quote.ts").parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / "utils" / "quote.ts").write_text(
        "export function shellQuote(s: string) { "
        "return \"'\" + s.replace(/'/g, \"'\\\\''\") + \"'\"; }"
    )
    (tmp_path / "ping.ts").write_text(
        "child_process.exec(`ping -c 1 ${host}`);"
    )
    findings = scan_source_tree(tmp_path)
    assert any(f.rule_id == "SRC-009" for f in findings), (
        f"Expected SRC-009, got: {findings}"
    )


def test_src009_same_interpolation_not_flagged_without_a_safe_pattern_elsewhere(tmp_path):
    """Same vulnerable call, but nothing in the repo demonstrates a safer
    pattern -- deliberately not flagged, to keep this rule's false-positive
    rate low (it trades recall for precision by design)."""
    (tmp_path / "ping.ts").write_text(
        "child_process.exec(`ping -c 1 ${host}`);"
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-009" for f in findings), (
        f"Did not expect SRC-009 with no safe pattern elsewhere in the repo, "
        f"got: {findings}"
    )


# --- SRC-010: credential file written with no permission hardening --------

def test_src010_key_write_without_chmod_flagged_when_repo_hardens_elsewhere(tmp_path):
    """The repo sets restrictive permissions on some other file write, but
    not on this private-key write -- the inconsistent case."""
    (tmp_path / "safe.swift").write_text(
        "try FileManager.default.setAttributes([.posixPermissions: 0o600], "
        "ofItemAtPath: p)"
    )
    (tmp_path / "bad.swift").write_text("try data.write(to: privateKeyURL)")
    findings = scan_source_tree(tmp_path)
    assert any(f.rule_id == "SRC-010" for f in findings), (
        f"Expected SRC-010, got: {findings}"
    )


def test_src010_key_write_with_chmod_nearby_is_not_flagged(tmp_path):
    """Same write, but permissions are hardened right after it."""
    (tmp_path / "safe.swift").write_text(
        "try FileManager.default.setAttributes([.posixPermissions: 0o600], "
        "ofItemAtPath: p)"
    )
    (tmp_path / "bad.swift").write_text(
        "try data.write(to: privateKeyURL)\n"
        "try FileManager.default.setAttributes([.posixPermissions: 0o600], "
        "ofItemAtPath: privateKeyURL.path)"
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-010" for f in findings), (
        f"Did not expect SRC-010 when permissions are hardened nearby, got: {findings}"
    )


# --- SRC-011: SSRF guard validates once, fetch re-resolves separately ------

def test_src011_validate_then_raw_url_fetch_is_flagged(tmp_path):
    """The URL is validated, but the actual request is a separate call that
    takes the original URL string and re-resolves DNS -- a TOCTOU window for
    DNS rebinding."""
    (tmp_path / "fetch.py").write_text(
        '''
        def do_fetch(url):
            if not validate_url(url):
                raise ValueError("blocked")
            return requests.get(url, timeout=5)
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert any(f.rule_id == "SRC-011" for f in findings), (
        f"Expected SRC-011, got: {findings}"
    )


def test_src011_validate_then_pinned_ip_connect_is_not_flagged(tmp_path):
    """Same validation, but the request connects to the already-resolved,
    pinned IP instead of re-resolving the URL."""
    (tmp_path / "fetch.py").write_text(
        '''
        def do_fetch(url):
            resolved_ip = validate_url(url)
            return connect(resolved_ip)
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-011" for f in findings), (
        f"Did not expect SRC-011 when the fetch uses the pinned IP, got: {findings}"
    )


# --- SRC-012: manifest entries dropped with only debug-level logging ------

def test_src012_dropped_entry_with_debug_only_logging_is_flagged(tmp_path):
    """An entry with an unresolved version is dropped before the list
    reaches a vuln scanner, and the drop is logged only at debug level --
    invisible to an operator running with default log levels."""
    (tmp_path / "manifest.py").write_text(
        '''
        def parse(entries):
            result = []
            for e in entries:
                if e.version == "unknown":
                    log.debug("skipping unresolved version for %s", e.name)
                    continue
                result.append(e)
            return scan_for_vulns(result)
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert any(f.rule_id == "SRC-012" for f in findings), (
        f"Expected SRC-012, got: {findings}"
    )


def test_src012_dropped_entry_with_warn_logging_is_not_flagged(tmp_path):
    """Same drop, but logged at warning level -- visible by default, so this
    is not the invisibility bug the rule targets."""
    (tmp_path / "manifest.py").write_text(
        '''
        def parse(entries):
            result = []
            for e in entries:
                if e.version == "unknown":
                    log.warning("skipping unresolved version for %s", e.name)
                    continue
                result.append(e)
            return scan_for_vulns(result)
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-012" for f in findings), (
        f"Did not expect SRC-012 when the drop is logged at warning level, "
        f"got: {findings}"
    )
