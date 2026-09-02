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


# --- SRC-021: network listener with no auth vocabulary anywhere -----------


def test_src021_listener_with_zero_auth_vocabulary_is_flagged(tmp_path):
    """The codespar shape: a real HTTP listener, real tool dispatch, and
    genuinely no auth mechanism of any kind anywhere in the file."""
    (tmp_path / "index.ts").write_text(
        '''
        import express from "express";

        const app = express();
        app.use(express.json());

        app.post("/mcp", async (req, res) => {
            const { name, args } = req.body;
            if (name === "create_transfer") {
                const result = await stpRequest("POST", "/transfers", args);
                return res.json(result);
            }
        });

        app.listen(8080, () => console.log("listening"));
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert any(f.rule_id == "SRC-021" for f in findings), f"Expected SRC-021, got: {findings}"


def test_src021_listener_with_any_auth_mention_is_not_flagged(tmp_path):
    (tmp_path / "index.ts").write_text(
        '''
        import express from "express";

        const app = express();
        app.use(express.json());

        app.post("/mcp", async (req, res) => {
            const apiKey = req.headers["x-api-key"];
            if (apiKey !== process.env.SERVER_API_KEY) {
                return res.status(401).json({ error: "unauthorized" });
            }
            const { name, args } = req.body;
            if (name === "create_transfer") {
                const result = await stpRequest("POST", "/transfers", args);
                return res.json(result);
            }
        });

        app.listen(8080, () => console.log("listening"));
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-021" for f in findings), (
        f"Did not expect SRC-021 when the file has real auth vocabulary, got: {findings}"
    )


def test_src021_stdio_transport_is_not_flagged(tmp_path):
    """stdio-served MCP servers aren't network-exposed -- only reachable by
    whoever can spawn the local process -- so "no auth check" isn't a real
    finding there. A real, confirmed-clean stdio-only server false-positived
    on an earlier version of this rule that didn't exclude stdio."""
    (tmp_path / "mcp.rs").write_text(
        '''
        async fn main() -> Result<()> {
            let service = server.serve(transport::stdio()).await?;
            service.waiting().await?;
            Ok(())
        }
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-021" for f in findings), (
        f"Did not expect SRC-021 for a stdio-served MCP server, got: {findings}"
    )


# --- SRC-023: outbound fetch of a caller-derived URL, no SSRF validation ---


def test_src023_unvalidated_fetch_is_flagged(tmp_path):
    """The ark-forge/mcp-eu-ai-act shape: a caller-supplied repo_url is
    passed straight into `git clone` with only a scheme prefix check --
    no host/IP validation of any kind."""
    (tmp_path / "scan_repo.py").write_text(
        '''
        import subprocess

        def scan_repo_url(repo_url: str):
            if not repo_url.startswith("https://"):
                raise ValueError("repo_url must be an HTTPS URL")
            subprocess.run(
                ["git", "clone", "--depth", "1", repo_url, clone_dir],
                check=True, capture_output=True, text=True, timeout=60,
            )
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert any(f.rule_id == "SRC-023" for f in findings), f"Expected SRC-023, got: {findings}"


def test_src023_validated_fetch_is_not_flagged(tmp_path):
    (tmp_path / "scan_repo.py").write_text(
        '''
        import subprocess

        def scan_repo_url(repo_url: str):
            if not validate_url(repo_url):
                raise ValueError("repo_url failed SSRF validation")
            subprocess.run(
                ["git", "clone", "--depth", "1", repo_url, clone_dir],
                check=True, capture_output=True, text=True, timeout=60,
            )
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-023" for f in findings), (
        f"Did not expect SRC-023 when repo_url is passed through validate_url(), got: {findings}"
    )


# --- SRC-024: resource ID used as a read/approval lookup key, no ownership check (BOLA) ---


def test_src024_id_keyed_lookup_with_no_ownership_check_is_flagged(tmp_path):
    """The Agorai shape: get_memory takes a project_id and hands it straight
    to a lookup call, with no getProject() access check anywhere in the
    file -- any caller who knows another team's project_id reads its
    memory, including memory in projects marked hidden."""
    (tmp_path / "server.ts").write_text(
        '''
        server.tool(
          "get_memory",
          "Get project memory entries filtered by clearance",
          GetMemorySchema.shape,
          async (args) => {
            const entries = await store.getMemory(args.project_id, agentId, {
              type: args.type,
            });
            return { content: [{ type: "text", text: JSON.stringify(entries) }] };
          },
        );
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert any(f.rule_id == "SRC-024" for f in findings), f"Expected SRC-024, got: {findings}"


def test_src024_id_keyed_lookup_with_ownership_check_is_not_flagged(tmp_path):
    (tmp_path / "server.ts").write_text(
        '''
        server.tool(
          "get_memory",
          "Get project memory entries filtered by clearance",
          GetMemorySchema.shape,
          async (args) => {
            const project = await store.getProject(args.project_id, agentId);
            if (!project) return ACCESS_DENIED;
            const entries = await store.getMemory(args.project_id, agentId, {
              type: args.type,
            });
            return { content: [{ type: "text", text: JSON.stringify(entries) }] };
          },
        );
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-024" for f in findings), (
        f"Did not expect SRC-024 when getProject() checks ownership first, got: {findings}"
    )


# --- SRC-025: unescaped request parameter interpolated into HTML (XSS) -----


def test_src025_unescaped_next_param_in_html_is_flagged(tmp_path):
    """The IBKR shape: a `next` query/form parameter is read straight from
    the request and spliced unescaped into the OAuth login page's HTML via
    a raw f-string, landing inside a value="..." attribute."""
    (tmp_path / "auth.py").write_text(
        '''
        def _login_page(next_url="/"):
            return f"""<!doctype html>
        <html lang="en">
        <body>
        <form method="post" action="/login">
        <input type="hidden" name="next" value="{next_url}" />
        <input id="password" name="password" type="password" />
        </form>
        </body>
        </html>"""

        async def _login_get(request):
            next_url = request.query_params.get("next", "/")
            return HTMLResponse(_login_page(next_url=next_url))
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert any(f.rule_id == "SRC-025" for f in findings), f"Expected SRC-025, got: {findings}"


def test_src025_html_escaped_next_param_is_not_flagged(tmp_path):
    (tmp_path / "auth.py").write_text(
        '''
        import html

        def _login_page(next_url="/"):
            return f"""<!doctype html>
        <html lang="en">
        <body>
        <form method="post" action="/login">
        <input type="hidden" name="next" value="{html.escape(next_url)}" />
        <input id="password" name="password" type="password" />
        </form>
        </body>
        </html>"""

        async def _login_get(request):
            next_url = request.query_params.get("next", "/")
            return HTMLResponse(_login_page(next_url=next_url))
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-025" for f in findings), (
        f"Did not expect SRC-025 when the value is html.escape()'d, got: {findings}"
    )


# --- SRC-027: OAuth scope from request, no role check before token issuance -


def test_src027_scope_from_request_no_role_check_is_flagged(tmp_path):
    """The mcp-construction shape: scope is read straight off the request
    and handed to the authorization-code call with no role comparison
    anywhere in the file -- a viewer can request scope=admin."""
    (tmp_path / "routes.ts").write_text(
        '''
        authRoutes.post('/oauth/authorize', async (c) => {
          const body = await c.req.parseBody();
          const scope = body['scope'] as string;
          const [user] = await db.select().from(usersTable).where(eq(usersTable.email, email)).limit(1);

          const code = await createAuthorizationCode({
            clientId,
            userId: user.id,
            scope,
            codeChallenge,
          });
          return c.redirect(redirectUrl);
        });
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert any(f.rule_id == "SRC-027" for f in findings), f"Expected SRC-027, got: {findings}"


def test_src027_scope_checked_against_role_is_not_flagged(tmp_path):
    (tmp_path / "routes.ts").write_text(
        '''
        authRoutes.post('/oauth/authorize', async (c) => {
          const body = await c.req.parseBody();
          const scope = body['scope'] as string;
          const [user] = await db.select().from(usersTable).where(eq(usersTable.email, email)).limit(1);

          if (!hasRole(user, scope)) {
            return c.json({ error: 'insufficient_role' }, 403);
          }

          const code = await createAuthorizationCode({
            clientId,
            userId: user.id,
            scope,
            codeChallenge,
          });
          return c.redirect(redirectUrl);
        });
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-027" for f in findings), (
        f"Did not expect SRC-027 when scope is checked against the user's role, got: {findings}"
    )


# --- SRC-028: full exception/response body logged with no redaction -------


def test_src028_full_response_body_logged_is_flagged(tmp_path):
    """The VA Claims MCP server shape (GSA-TTS va-claims-mcp-server-DEMO,
    src/va_claims/utils.py:88-97): every failed call logs the VA Benefits
    Claims API's raw error body, which routinely echoes back the veteran
    SSN/name/DOB/address that triggered the failure."""
    (tmp_path / "utils.py").write_text(
        '''
        async def call_api(token, endpoint):
            try:
                response = await client.get(url)
                response.raise_for_status()
                return response.json()
            except httpx.HTTPStatusError as e:
                logger.error(f"HTTP error: {e.response.status_code}")
                logger.error(f"Response body: {e.response.text}")
                raise
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert any(f.rule_id == "SRC-028" for f in findings), f"Expected SRC-028, got: {findings}"


def test_src028_redacted_body_is_not_flagged(tmp_path):
    (tmp_path / "utils.py").write_text(
        '''
        async def call_api(token, endpoint):
            try:
                response = await client.get(url)
                response.raise_for_status()
                return response.json()
            except httpx.HTTPStatusError as e:
                logger.error(f"Request to upstream API failed with status {e.response.status_code}")
                raise
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-028" for f in findings), (
        f"Did not expect SRC-028 when only a curated status code is logged, got: {findings}"
    )


# --- SRC-030: CORS wildcard / disabled dev-server host check --------------


def test_src030_cors_wildcard_and_disabled_host_check_is_flagged(tmp_path):
    """The Alpic/Skybridge shape: `cors()` with no options object sets
    wildcard CORS reaching /mcp, and Vite's allowedHosts: true forces off
    its DNS-rebinding Host-header allowlist, non-overridably."""
    (tmp_path / "viewsDevServer.ts").write_text(
        '''
        const vite = await createServer({
          ...devConfig,
          server: {
            ...userServer,
            allowedHosts: true,
            middlewareMode: true,
          },
        });

        router.use(cors());
        router.use("/", vite.middlewares);
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert any(f.rule_id == "SRC-030" for f in findings), f"Expected SRC-030, got: {findings}"


def test_src030_allowlisted_cors_and_real_host_list_is_not_flagged(tmp_path):
    (tmp_path / "viewsDevServer.ts").write_text(
        '''
        const corsOptions = { origin: allowedOriginsList };

        const vite = await createServer({
          ...devConfig,
          server: {
            ...userServer,
            allowedHosts: ["myhost.local", "dev.internal"],
            middlewareMode: true,
          },
        });

        router.use(cors(corsOptions));
        router.use("/", vite.middlewares);
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-030" for f in findings), (
        f"Did not expect SRC-030 with an origin allowlist and a real allowedHosts list, got: {findings}"
    )


# --- SRC-029: runtime-obtained token/secret written to disk in plaintext ---


def test_src029_runtime_token_written_plaintext_is_flagged(tmp_path):
    """The bank-mcp shape (elcukro/bank-mcp): a Plaid access_token obtained
    from a real OAuth token-exchange response is persisted straight to disk
    via writeFileSync with no encryption of the value -- the project's own
    SECURITY.md presents 600 file permissions alone as the complete
    credential-storage guarantee, which this rule flags as insufficient."""
    (tmp_path / "config.ts").write_text(
        '''
        async function exchangePublicToken(publicToken) {
            const response = await plaidClient.itemPublicTokenExchange({ public_token: publicToken });
            const accessToken = response.data.access_token;
            return accessToken;
        }

        export function saveConfig(config) {
            const data = JSON.stringify(config, null, 2) + "\\n";
            writeFileSync(CONFIG_PATH, data, { mode: 0o600 });
        }
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert any(f.rule_id == "SRC-029" for f in findings), f"Expected SRC-029, got: {findings}"


def test_src029_encrypted_token_before_write_is_not_flagged(tmp_path):
    (tmp_path / "config.ts").write_text(
        '''
        async function exchangePublicToken(publicToken) {
            const response = await plaidClient.itemPublicTokenExchange({ public_token: publicToken });
            const accessToken = response.data.access_token;
            return accessToken;
        }

        export function saveConfig(config) {
            const encryptedToken = encrypt(config.accessToken, masterKey);
            const data = JSON.stringify({ ...config, accessToken: encryptedToken });
            writeFileSync(CONFIG_PATH, data, { mode: 0o600 });
        }
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-029" for f in findings), (
        f"Did not expect SRC-029 when the token is encrypted before writing, got: {findings}"
    )


# --- SRC-026: loopback-bound server, no Origin-header check ----------------


def test_src026_loopback_websocket_with_no_origin_check_is_flagged(tmp_path):
    """The mcp-unity-cg shape: a WebSocket bridge binds to localhost by
    default and never reads the Origin header, so any same-machine browser
    tab connects directly -- no DNS rebinding even required."""
    (tmp_path / "server.cs").write_text(
        '''
        void StartServerInternal()
        {
            var host = AllowRemoteConnections ? "0.0.0.0" : "localhost";
            webSocketServer = new WebSocketServer($"ws://{host}:{Port}");
            webSocketServer.Start();
        }

        protected override void OnOpen()
        {
            NameValueCollection headers = Context.Headers;
            if (headers != null && headers.Contains("X-Client-Name"))
            {
                clientName = headers["X-Client-Name"];
            }
        }
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert any(f.rule_id == "SRC-026" for f in findings), f"Expected SRC-026, got: {findings}"


def test_src026_loopback_server_with_origin_check_is_not_flagged(tmp_path):
    (tmp_path / "server.cs").write_text(
        '''
        void StartServerInternal()
        {
            var host = "localhost";
            webSocketServer = new WebSocketServer($"ws://{host}:{Port}");
            webSocketServer.Start();
        }

        protected override void OnOpen()
        {
            string origin = Context.Headers["Origin"];
            if (string.IsNullOrEmpty(origin) || !AllowedOrigins.Contains(origin))
            {
                Context.WebSocket.Close();
                return;
            }
        }
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-026" for f in findings), (
        f"Did not expect SRC-026 when the file validates Origin, got: {findings}"
    )


def test_src026_hostname_extracted_from_scan_target_url_is_not_flagged(tmp_path):
    """`host = parsed.hostname or "localhost"` extracts a SCAN TARGET's
    hostname (with a localhost fallback default) -- it is not this file
    declaring where a server of its own binds. A real false positive this
    exact shape produced during this project's own dogfooding."""
    (tmp_path / "prober.py").write_text(
        '''
        from urllib.parse import urlparse

        def probe(url: str):
            parsed = urlparse(url)
            host = parsed.hostname or "localhost"
            port = parsed.port or 80
            return scan_endpoints(host=host, port=port)
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-026" for f in findings), (
        f"Did not expect SRC-026 for a scan-target hostname extraction, got: {findings}"
    )


# --- SRC-022: SQL/query injection via unescaped string interpolation -------


def test_src022_fstring_sql_interpolation_is_flagged(tmp_path):
    """The apple-health-mcp-server / cdc-places-mcp-server shape: a query
    fragment built by hand-quoting an f-string-interpolated value directly
    into the query text instead of binding it as a parameter."""
    (tmp_path / "duckdb_queries.py").write_text(
        '''
        def get_statistics_by_type_from_duckdb(con, record_type):
            query = f"""
                SELECT type, COUNT(*) FROM records
                WHERE type = '{record_type}' GROUP BY type
            """
            return con.execute(query).fetchall()
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert any(f.rule_id == "SRC-022" for f in findings), f"Expected SRC-022, got: {findings}"


def test_src022_parameterized_query_is_not_flagged(tmp_path):
    (tmp_path / "duckdb_queries.py").write_text(
        '''
        def get_statistics_by_type_from_duckdb(con, record_type):
            query = "SELECT type, COUNT(*) FROM records WHERE type = %s GROUP BY type"
            return con.execute(query, (record_type,)).fetchall()
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-022" for f in findings), (
        f"Did not expect SRC-022 when the query is parameterized, got: {findings}"
    )


def test_src031_credential_in_get_query_params_is_flagged(tmp_path):
    """The real trackmage-mcp-server shape: client_secret sent as an axios
    GET params object instead of a POST body (RFC 6749 SS3.2 violation)."""
    (tmp_path / "trackmage-client.js").write_text(
        '''
        this.refreshPromise = axios
          .get(`${this.apiUrl}/oauth/v2/token`, {
            params: {
              grant_type: 'client_credentials',
              client_id: this.clientId,
              client_secret: this.clientSecret,
            },
          })
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert any(f.rule_id == "SRC-031" for f in findings), f"Expected SRC-031, got: {findings}"


def test_src031_token_read_from_response_after_params_object_closed_is_not_flagged(tmp_path):
    """Regression test for a real false positive caught during validation:
    reading a token BACK off the response, after the params object that
    built the request has already closed, is not the same bug -- a
    window-based-only check (no brace-depth tracking) flagged this."""
    (tmp_path / "trackmage-client.js").write_text(
        '''
        this.refreshPromise = axios
          .get(`${this.apiUrl}/oauth/v2/token`, {
            params: {
              grant_type: 'client_credentials',
            },
          })
          .then((response) => {
            this.accessToken = response.data.access_token;
            this.tokenExpiresAt = Date.now() + response.data.expires_in * 1000;
          })
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-031" for f in findings), (
        f"Did not expect SRC-031 for a token read off the response after the "
        f"params object closed, got: {findings}"
    )


def test_src031_credential_in_post_body_is_not_flagged(tmp_path):
    (tmp_path / "client.js").write_text(
        '''
        axios.post(`${this.apiUrl}/oauth/v2/token`, {
          grant_type: 'client_credentials',
          client_id: this.clientId,
          client_secret: this.clientSecret,
        })
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-031" for f in findings), (
        f"Did not expect SRC-031 for a credential sent in a POST body, got: {findings}"
    )
