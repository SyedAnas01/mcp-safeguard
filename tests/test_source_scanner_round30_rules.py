"""Tests for SRC-032..SRC-034, mined from a fresh Round 30 recall measurement
against the rule set as it stood at v0.7.3 (see source_scanner.py's module
docstring for the full provenance of each), plus regression coverage for the
precision fixes made to SRC-021/SRC-023/SRC-026 while measuring false
positives on independently-confirmed-clean repos in the same session.

Same discipline as the other rule test files: a trigger fixture and a
non-trigger fixture per rule/fix. Every new rule here was ALSO validated
against the real vulnerable source it was mined from (Repliers-io/mcp-server,
nirholas/UCAI, microsoft/AKS-Lab-GitHubCopilot) during development -- these
synthetic fixtures are the regression-test layer, not a substitute for that.
"""

from mcp_safeguard.scanner.source_scanner import scan_source_tree

# --- SRC-032: session id from a header reused with no ownership check ------


def test_src032_session_id_from_header_with_no_ownership_check_is_flagged(tmp_path):
    """The Repliers-io/mcp-server shape: a per-request bearer token IS
    verified, but the looked-up session's stored owner is never compared
    against the currently authenticated caller."""
    (tmp_path / "mcpServer.js").write_text(
        '''
        app.all(["/", "/mcp"], verifyOAuthToken, async (req, res) => {
            const sessionId = req.headers["mcp-session-id"];
            if (sessionId) {
                const session = sessions[sessionId];
                if (!session) {
                    return res.status(404).json({ error: "Session not found" });
                }
                await session.transport.handleRequest(req, res, req.body);
                return;
            }
        });
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert any(f.rule_id == "SRC-032" for f in findings), (
        f"Expected SRC-032, got: {findings}"
    )


def test_src032_session_id_with_ownership_check_is_not_flagged(tmp_path):
    """Same lookup shape, but the session's owner is compared against the
    authenticated caller before it's reused."""
    (tmp_path / "mcpServer.js").write_text(
        '''
        app.all(["/", "/mcp"], verifyOAuthToken, async (req, res) => {
            const sessionId = req.headers["mcp-session-id"];
            if (sessionId) {
                const session = sessions[sessionId];
                if (!session || session.userId !== req.user.id) {
                    return res.status(403).json({ error: "Forbidden" });
                }
                await session.transport.handleRequest(req, res, req.body);
                return;
            }
        });
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-032" for f in findings), (
        f"Did not expect SRC-032 when the session owner is checked, got: {findings}"
    )


# --- SRC-033: caller-controlled simulate flag before a signing call --------


def test_src033_simulate_default_true_before_sign_transaction_is_flagged(tmp_path):
    """The nirholas/UCAI generated-tool shape: `simulate` defaults to the
    safe value but is entirely caller-controlled, and flipping it to False
    reaches a real private-key sign+broadcast with no other gate."""
    (tmp_path / "generated_tool.py").write_text(
        '''
        def transfer(to: str, amount: str, simulate: bool = True) -> dict:
            tx = build_transaction(to, amount)
            if simulate:
                result = func.call({"from": signer.address})
                return {"simulated": True, "result": result}

            signed = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
            tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
            return {"simulated": False, "tx_hash": tx_hash.hex()}
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert any(f.rule_id == "SRC-033" for f in findings), (
        f"Expected SRC-033, got: {findings}"
    )


def test_src033_simulate_with_independent_confirmation_is_not_flagged(tmp_path):
    """Same shape, but a separate, independent confirmation token is
    required before the real send -- an adequately-gated design."""
    (tmp_path / "generated_tool.py").write_text(
        '''
        def transfer(to: str, amount: str, simulate: bool = True,
                     confirmation_token: str | None = None) -> dict:
            tx = build_transaction(to, amount)
            if simulate:
                result = func.call({"from": signer.address})
                return {"simulated": True, "result": result}

            require_approval(confirmation_token, tx)
            signed = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
            tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
            return {"simulated": False, "tx_hash": tx_hash.hex()}
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-033" for f in findings), (
        f"Did not expect SRC-033 with an independent confirmation gate, got: {findings}"
    )


# --- SRC-034: state-changing FastAPI/Flask route, no auth dependency -------


def test_src034_post_route_with_no_auth_dependency_is_flagged(tmp_path):
    """The microsoft/AKS-Lab-GitHubCopilot shape: an importable FastAPI
    `app` object with no in-file serve call at all (served externally via
    a Dockerfile CMD), so SRC-021 can't see it -- and no Depends()/auth
    vocabulary anywhere in the file."""
    (tmp_path / "server.py").write_text(
        '''
        from fastapi import FastAPI

        app = FastAPI(title="agent-server")

        @app.post("/invoke", response_model=InvokeResponse)
        async def invoke(request: InvokeRequest) -> InvokeResponse:
            result = await agent.run(request.goal)
            return InvokeResponse(run_id=request.run_id, output=result.output_text)
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert any(f.rule_id == "SRC-034" for f in findings), (
        f"Expected SRC-034, got: {findings}"
    )


def test_src034_post_route_with_auth_dependency_is_not_flagged(tmp_path):
    """Same shape, but the route requires a real auth dependency."""
    (tmp_path / "server.py").write_text(
        '''
        from fastapi import FastAPI, Depends

        app = FastAPI(title="agent-server")

        @app.post("/invoke", response_model=InvokeResponse)
        async def invoke(request: InvokeRequest, user=Depends(verify_token)) -> InvokeResponse:
            result = await agent.run(request.goal)
            return InvokeResponse(run_id=request.run_id, output=result.output_text)
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-034" for f in findings), (
        f"Did not expect SRC-034 with a Depends()-based auth check, got: {findings}"
    )


# --- Precision fixes: SRC-021, delegated-registration entrypoint files -----


def test_src021_thin_entrypoint_delegating_registration_is_not_flagged(tmp_path):
    """A thin FastMCP entrypoint that delegates ALL tool registration to
    another module, and defines no handler of its own, gives no reliable
    same-file evidence about auth either way -- verified false positive
    against DIDA-AI/Dida-Hotel-MCP-Global, whose real per-request auth
    check lives only in a separate auth.py the delegated tools import."""
    (tmp_path / "server.py").write_text(
        '''
        import os
        from fastmcp import FastMCP
        from .tools import register_tools

        mcp = FastMCP("Some MCP", version="1.0.0")
        register_tools(mcp)

        def main():
            mcp.run(transport="http", host=os.getenv("HOST", "127.0.0.1"), port=8000)
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-021" for f in findings), (
        f"Did not expect SRC-021 on a delegating entrypoint with no handler of its own, got: {findings}"
    )


def test_src021_file_defining_its_own_tool_is_still_flagged(tmp_path):
    """Same `mcp.run(transport=...)` idiom, but this file defines its own
    tool directly -- SRC-021's original, already-validated true positive
    shape (microsoft/AKS-Lab-GitHubCopilot's MCP servers) must still fire."""
    (tmp_path / "server.py").write_text(
        '''
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("pricing-mcp", host="0.0.0.0", port=8080)

        @mcp.tool()
        async def recommend_price(query):
            return await recommend_price_for(query)

        if __name__ == "__main__":
            mcp.run(transport="streamable-http")
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert any(f.rule_id == "SRC-021" for f in findings), (
        f"Expected SRC-021 on a file defining its own tool with no auth, got: {findings}"
    )


# --- Precision fixes: SRC-023, hardcoded/config URL is not caller-derived --


def test_src023_fetch_of_hardcoded_config_url_is_not_flagged(tmp_path):
    """A `fetch(url, ...)` call whose `url` variable is built entirely from
    an operator env var and a hardcoded literal path is not caller-derived
    -- verified false positive against chargebee/agentkit's API client and
    oilst/kraken-mcp's public-endpoint helper."""
    (tmp_path / "client.ts").write_text(
        '''
        const BASE = process.env.AGENTKIT_BASE_URL;

        async function request(endpoint) {
            const url = `${BASE}${endpoint}`;
            const response = await fetch(url, { headers: { "Content-Type": "application/json" } });
            return response.json();
        }

        request("/documentation_search");
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-023" for f in findings), (
        f"Did not expect SRC-023 on a fetch of a hardcoded/env-configured URL, got: {findings}"
    )


def test_src023_fetch_of_request_derived_url_is_still_flagged(tmp_path):
    """Same call shape, but the url variable is built from a real request
    parameter -- SRC-023's original true-positive shape must still fire."""
    (tmp_path / "client.ts").write_text(
        '''
        async function proxyFetch(req) {
            const url = req.query.get('target_url');
            const response = await fetch(url, { headers: { "Content-Type": "application/json" } });
            return response.json();
        }
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert any(f.rule_id == "SRC-023" for f in findings), (
        f"Expected SRC-023 on a fetch of a request-derived URL, got: {findings}"
    )


# --- Precision fixes: SRC-026, test code / prose are not real bind evidence -


def test_src026_loopback_literal_inside_test_function_is_not_flagged(tmp_path):
    """A loopback URL used as an intentionally-unreachable test target
    inside a Rust `#[tokio::test]` function is not this file's own server
    binding -- verified false positive against
    awslabs/iam-policy-autopilot."""
    (tmp_path / "client.rs").write_text(
        '''
        #[tokio::test]
        async fn test_emit_fire_and_forget_on_connection_refused() {
            TelemetryClient::with_endpoint("http://127.0.0.1:1".to_string())
                .emit(&TelemetryEvent::new("test"))
                .await;
        }
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-026" for f in findings), (
        f"Did not expect SRC-026 on a loopback literal inside a #[tokio::test] fn, got: {findings}"
    )


def test_src026_loopback_bind_outside_test_code_is_still_flagged(tmp_path):
    """Same loopback literal, but in real (non-test) server-construction
    code -- SRC-026's original true-positive shape must still fire."""
    (tmp_path / "server.rs").write_text(
        '''
        fn main() {
            let host = "127.0.0.1";
            let server = HttpServer::new(app_factory).bind((host, 8080)).unwrap();
            server.run();
        }
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert any(f.rule_id == "SRC-026" for f in findings), (
        f"Expected SRC-026 on a real loopback bind outside test code, got: {findings}"
    )


def test_src026_host_substring_inside_unrelated_help_string_is_not_flagged(tmp_path):
    """A `--url` CLI option's own help text describing a URI FORMAT
    (`user:pass@host:port/db`) contains the substring "host:", and an
    unrelated `--host` option's `default="127.0.0.1"` a few lines below
    must not be stitched together into a phantom bind statement --
    verified false positive against redis/mcp-redis."""
    (tmp_path / "main.py").write_text(
        '''
        import click

        @click.command()
        @click.option(
            "--url",
            help="Redis connection URI (redis://user:pass@host:port/db or rediss:// for SSL)",
        )
        @click.option("--host", default="127.0.0.1", help="Redis host")
        def main(url, host):
            mcp.run()
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-026" for f in findings), (
        f"Did not expect SRC-026 from a host[:=] match inside unrelated help-text prose, got: {findings}"
    )
