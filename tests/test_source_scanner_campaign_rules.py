"""Tests for the SRC-013..SRC-017 source-scanner rules.

Unlike SRC-001..012, each of these was derived directly from a real,
independently-confirmed finding in this project's own coordinated-disclosure
campaign against live MCP servers -- see source_scanner.py's module docstring
for the provenance of each. Same discipline as the other rule test files:
a trigger fixture and a non-trigger fixture per rule.
"""

from mcp_safeguard.scanner.source_scanner import scan_source_tree

# --- SRC-013: TLS certificate verification disabled -------------------------


def test_src013_verify_false_is_flagged(tmp_path):
    (tmp_path / "client.py").write_text(
        '''
        import httpx

        async def fetch(url):
            async with httpx.AsyncClient(verify=False) as client:
                return await client.get(url)
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert any(f.rule_id == "SRC-013" for f in findings), f"Expected SRC-013, got: {findings}"


def test_src013_default_verification_is_not_flagged(tmp_path):
    (tmp_path / "client.py").write_text(
        '''
        import httpx

        async def fetch(url):
            async with httpx.AsyncClient() as client:
                return await client.get(url)
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-013" for f in findings), (
        f"Did not expect SRC-013 with default (verified) TLS, got: {findings}"
    )


# --- SRC-014: redirect_uri used in a redirect with no allowlist check ------


def test_src014_unvalidated_redirect_uri_is_flagged(tmp_path):
    """The Emporia Energy shape: redirect_uri is read straight from the
    request and handed to a redirect response with nothing in between."""
    (tmp_path / "oauth.py").write_text(
        '''
        def authorize(request):
            redirect_uri = request.query.get("redirect_uri")
            client_id = request.query.get("client_id")
            code = issue_authorization_code(client_id)
            return redirect(f"{redirect_uri}?code={code}")
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert any(f.rule_id == "SRC-014" for f in findings), f"Expected SRC-014, got: {findings}"


def test_src014_allowlisted_redirect_uri_is_not_flagged(tmp_path):
    (tmp_path / "oauth.py").write_text(
        '''
        def authorize(request):
            redirect_uri = request.query.get("redirect_uri")
            if redirect_uri not in registered_redirect_uris(client_id):
                raise InvalidRedirectUri()
            code = issue_authorization_code(client_id)
            return redirect(f"{redirect_uri}?code={code}")
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-014" for f in findings), (
        f"Did not expect SRC-014 when redirect_uri is checked, got: {findings}"
    )


# --- SRC-015: inbound Authorization header re-forwarded outbound -----------


def test_src015_token_passthrough_is_flagged(tmp_path):
    """The Dify shape: the caller's own live Authorization header is
    forwarded to a caller-configurable upstream URL."""
    (tmp_path / "proxy.py").write_text(
        '''
        import httpx

        async def relay(request, upstream_url):
            auth = request.headers.get("authorization")
            async with httpx.AsyncClient() as client:
                return await client.get(upstream_url, headers={"Authorization": auth})
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert any(f.rule_id == "SRC-015" for f in findings), f"Expected SRC-015, got: {findings}"


def test_src015_server_own_credential_is_not_flagged(tmp_path):
    (tmp_path / "proxy.py").write_text(
        '''
        import httpx
        import os

        async def relay(request, upstream_url):
            auth = request.headers.get("authorization")
            server_token = os.environ["SERVICE_TOKEN"]
            async with httpx.AsyncClient() as client:
                return await client.get(
                    upstream_url, headers={"Authorization": f"Bearer {server_token}"}
                )
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-015" for f in findings), (
        f"Did not expect SRC-015 when the server uses its own credential, got: {findings}"
    )


# --- SRC-016: write flag gates tool-list, not tool-call ---------------------


def test_src016_flag_only_gates_list_tools_is_flagged(tmp_path):
    """The Fireblocks shape: ENABLE_WRITE_OPERATIONS decides what tools/list
    returns, but tools/call never checks it -- the tool still runs."""
    (tmp_path / "server.py").write_text(
        '''
        def list_tools():
            tools = [read_tool]
            if os.environ.get("ENABLE_WRITE_OPERATIONS") == "true":
                tools.append(create_transaction_tool)
            return tools

        def call_tool(name, args):
            if name == "create_transaction":
                return create_transaction(args)
            return dispatch(name, args)
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert any(f.rule_id == "SRC-016" for f in findings), f"Expected SRC-016, got: {findings}"


def test_src016_flag_also_gates_call_tool_is_not_flagged(tmp_path):
    (tmp_path / "server.py").write_text(
        '''
        def list_tools():
            tools = [read_tool]
            if os.environ.get("ENABLE_WRITE_OPERATIONS") == "true":
                tools.append(create_transaction_tool)
            return tools

        def call_tool(name, args):
            if name == "create_transaction":
                if os.environ.get("ENABLE_WRITE_OPERATIONS") != "true":
                    raise PermissionError("write operations disabled")
                return create_transaction(args)
            return dispatch(name, args)
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-016" for f in findings), (
        f"Did not expect SRC-016 when call_tool re-checks the same flag, got: {findings}"
    )


# --- SRC-017: header used as authz identity, no auth check in file ---------


def test_src017_header_identity_with_no_auth_check_is_flagged(tmp_path):
    """The Microsoft retail-sample shape: a header directly picks which
    tenant's data the query scopes to, with no authentication anywhere."""
    (tmp_path / "sales_analysis.py").write_text(
        '''
        def get_rls_user_id(request):
            user_id = request.headers.get("x-rls-user-id", "00000000-0000-0000-0000-000000000000")
            return user_id

        def run_query(request, sql):
            rls_user_id = get_rls_user_id(request)
            conn.execute(f"SET app.current_rls_user_id = '{rls_user_id}'")
            return conn.fetch(sql)
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert any(f.rule_id == "SRC-017" for f in findings), f"Expected SRC-017, got: {findings}"


def test_src017_header_identity_with_auth_check_is_not_flagged(tmp_path):
    (tmp_path / "sales_analysis.py").write_text(
        '''
        def get_rls_user_id(request):
            authenticate(request)
            user_id = request.headers.get("x-rls-user-id")
            return user_id

        def run_query(request, sql):
            rls_user_id = get_rls_user_id(request)
            conn.execute(f"SET app.current_rls_user_id = '{rls_user_id}'")
            return conn.fetch(sql)
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-017" for f in findings), (
        f"Did not expect SRC-017 when the file authenticates the caller, got: {findings}"
    )


# --- SRC-018: path traversal (real containment check, not "named 'path'") --


def test_src018_unbounded_path_join_is_flagged(tmp_path):
    (tmp_path / "files.py").write_text(
        '''
        def read_file(request):
            filename = request.args.get("filename")
            full_path = os.path.join(BASE_DIR, filename)
            with open(full_path) as f:
                return f.read()
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert any(f.rule_id == "SRC-018" for f in findings), f"Expected SRC-018, got: {findings}"


def test_src018_path_join_with_containment_check_is_not_flagged(tmp_path):
    (tmp_path / "files.py").write_text(
        '''
        def read_file(request):
            filename = request.args.get("filename")
            full_path = os.path.join(BASE_DIR, filename)
            resolved = Path(full_path).resolve()
            if not resolved.is_relative_to(BASE_DIR):
                raise PermissionError("path traversal blocked")
            with open(resolved) as f:
                return f.read()
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-018" for f in findings), (
        f"Did not expect SRC-018 when the resolved path is containment-checked, got: {findings}"
    )


# --- SRC-019: unescaped shell interpolation, no repo-wide gate needed ------


def test_src019_unescaped_shell_interpolation_is_flagged_without_repo_signal(tmp_path):
    """Unlike SRC-009, this must fire even when the repo has NO other safe
    shell helper anywhere -- that's the whole point of the broader rule."""
    (tmp_path / "runner.py").write_text(
        '''
        import subprocess

        def run(request):
            target = request.args.get("host")
            subprocess.run(f"ping -c 1 {target}", shell=True)
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert any(f.rule_id == "SRC-019" for f in findings), f"Expected SRC-019, got: {findings}"


def test_src019_escaped_shell_interpolation_is_not_flagged(tmp_path):
    (tmp_path / "runner.py").write_text(
        '''
        import subprocess
        import shlex

        def run(request):
            target = request.args.get("host")
            subprocess.run(f"ping -c 1 {shlex.quote(target)}", shell=True)
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-019" for f in findings), (
        f"Did not expect SRC-019 when the value is shlex.quote()'d, got: {findings}"
    )


# --- SRC-020: unencoded value in a URL query string -------------------------


def test_src020_unencoded_query_string_is_flagged(tmp_path):
    (tmp_path / "client.py").write_text(
        '''
        def fetch_user(user_id):
            url = f"https://api.example.com/lookup?id={user_id}"
            return requests.get(url)
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert any(f.rule_id == "SRC-020" for f in findings), f"Expected SRC-020, got: {findings}"


def test_src020_urlencoded_query_string_is_not_flagged(tmp_path):
    (tmp_path / "client.py").write_text(
        '''
        from urllib.parse import urlencode

        def fetch_user(user_id):
            query = urlencode({"id": user_id})
            url = f"https://api.example.com/lookup?{query}"
            return requests.get(url)
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-020" for f in findings), (
        f"Did not expect SRC-020 when the query string is built via urlencode, got: {findings}"
    )
