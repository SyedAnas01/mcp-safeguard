"""Tests for the fixes and new rules mined from a real, honest holdout-recall
measurement against Round 31 (see source_scanner.py's module docstring for
full provenance): the .mjs/.cjs/.mts/.cts extension-allowlist fix, the
SRC-021 transport=<variable> widening, the SRC-018 readFileSync/nested-paren
fix, and the two new rules SRC-035/SRC-036.

Same discipline as the other rule test files: a trigger fixture and a
non-trigger fixture per rule/fix. Every fix and new rule here was ALSO
validated against the real vulnerable source it was mined from (aliyun/
alibaba-cloud-ops-mcp-server, gomission/mcp, OjasKord/bizfile-mcp,
eren-solutions/mcp-security-audit) during development -- these synthetic
fixtures are the regression-test layer, not a substitute for that.
"""

from mcp_safeguard.scanner.source_scanner import scan_source_tree

# --- extension allowlist: .mjs/.cjs/.mts/.cts are scanned at all ----------


def test_mjs_file_is_scanned_not_silently_skipped(tmp_path):
    """Before this fix, _SRC_EXTS didn't include .mjs at all -- the scanner
    read zero bytes of a repo like gomission/mcp, whose entire source tree
    is .mjs. A finding in a .mjs file must be reachable at all."""
    (tmp_path / "proxy.mjs").write_text(
        '''
        const file = path.join(baseDir(this.workspace), `${args.receipt_id}.json`);
        if (!fs.existsSync(file)) return null;
        return fs.readFileSync(file, "utf8");
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert any(f.rule_id == "SRC-018" for f in findings), (
        f"Expected SRC-018 to fire in a .mjs file, got: {findings}"
    )


def test_cjs_mts_cts_files_are_scanned_not_silently_skipped(tmp_path):
    """Same coverage gap, the other three real Node/TS module extensions."""
    for ext in ("cjs", "mts", "cts"):
        (tmp_path / f"server.{ext}").write_text(
            'mcp.run(transport=transportArg)\n'
        )
    findings = scan_source_tree(tmp_path)
    hit_files = {f.location.split(":")[0] for f in findings if f.rule_id == "SRC-021"}
    assert hit_files == {"server.cjs", "server.mts", "server.cts"}, (
        f"Expected SRC-021 to fire in all three extensions, got findings in: {hit_files}"
    )


# --- SRC-021: mcp.run(transport=<variable>) ---------------------------


def test_src021_transport_as_bare_variable_is_flagged(tmp_path):
    """The real aliyun/alibaba-cloud-ops-mcp-server shape: `transport` is a
    click.Choice-parsed CLI argument, not a literal string, and the file
    defines its own tool handlers with no inbound auth check anywhere."""
    (tmp_path / "server.py").write_text(
        '''
        @click.option("--transport", type=click.Choice(["stdio", "sse", "streamable-http"]), default="stdio")
        def main(transport: str):
            mcp = FastMCP(name="demo")

            @mcp.tool()
            def run_shell_script(script: str):
                return subprocess.run(script, shell=True)

            mcp.run(transport=transport)
        '''
    )
    findings = scan_source_tree(tmp_path)
    src021 = [f for f in findings if f.rule_id == "SRC-021"]
    assert src021, f"Expected SRC-021, got: {findings}"
    assert "server.py:" in src021[0].location


def test_src021_transport_none_sentinel_is_not_flagged(tmp_path):
    """`transport=None` is FastMCP's own "use the constructor default"
    sentinel, not evidence of a runtime-selectable network transport --
    must not be treated the same as a real CLI-parsed variable."""
    (tmp_path / "server.py").write_text(
        '''
        def main():
            mcp = FastMCP(name="demo")

            @mcp.tool()
            def ping():
                return "pong"

            mcp.run(transport=None)
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-021" for f in findings), (
        f"Did not expect SRC-021 for transport=None, got: {findings}"
    )


def test_src021_transport_variable_with_auth_check_is_not_flagged(tmp_path):
    """Same variable-transport shape, but the file DOES check an inbound
    Authorization header -- must not fire."""
    (tmp_path / "server.py").write_text(
        '''
        def main(transport: str):
            mcp = FastMCP(name="demo")

            @mcp.tool()
            def ping(request):
                token = request.headers.get("authorization")
                if not verify_token(token):
                    raise PermissionError
                return "pong"

            mcp.run(transport=transport)
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-021" for f in findings), (
        f"Did not expect SRC-021 when an inbound auth check is present, got: {findings}"
    )


# --- SRC-018: readFileSync/writeFileSync + nested-paren join gap ----------


def test_src018_readfilesync_with_nested_call_in_join_is_flagged(tmp_path):
    """The real gomission/mcp shape: `path.join(receiptsDir(this.workspace),
    \\`${args.receipt_id}.json\\`)` then `fs.readFileSync(file, "utf8")` --
    the nested receiptsDir(...) call's own closing paren used to stop the
    old character-class gap before it ever reached "args", and
    readFileSync wasn't in the file-operation vocabulary at all."""
    (tmp_path / "proxy.mjs").write_text(
        '''
        async callBuiltin(name, args) {
            if (name === "get_receipt") {
                const file = path.join(receiptsDir(this.workspace), `${args.receipt_id}.json`);
                if (!fs.existsSync(file)) return this.textContent("missing");
                return this.textContent(fs.readFileSync(file, "utf8"));
            }
        }
        '''
    )
    findings = scan_source_tree(tmp_path)
    src018 = [f for f in findings if f.rule_id == "SRC-018"]
    assert src018, f"Expected SRC-018, got: {findings}"
    assert "proxy.mjs:" in src018[0].location


def test_src018_readfilesync_with_containment_check_is_not_flagged(tmp_path):
    """Same shape, but a realpath+containment check guards the read."""
    (tmp_path / "proxy.mjs").write_text(
        '''
        async callBuiltin(name, args) {
            if (name === "get_receipt") {
                const file = path.join(receiptsDir(this.workspace), `${args.receipt_id}.json`);
                const resolved = path.resolve(file);
                if (!resolved.startsWith(base)) return this.textContent("forbidden");
                return this.textContent(fs.readFileSync(resolved, "utf8"));
            }
        }
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-018" for f in findings), (
        f"Did not expect SRC-018 with a containment check, got: {findings}"
    )


# --- SRC-035: hardcoded fallback credential behind an env-var read --------


def test_src035_hardcoded_fallback_secret_js_is_flagged(tmp_path):
    """The real OjasKord/bizfile-mcp shape: `process.env.STATS_KEY ||
    'ojas2026'` gates 4 admin/stats endpoints."""
    (tmp_path / "server.js").write_text(
        "const STATS_KEY = process.env.STATS_KEY || 'ojas2026';\n"
        "if (req.headers['x-stats-key'] !== STATS_KEY) { res.writeHead(401); return; }\n"
    )
    findings = scan_source_tree(tmp_path)
    src035 = [f for f in findings if f.rule_id == "SRC-035"]
    assert src035, f"Expected SRC-035, got: {findings}"
    assert "server.js:1" in src035[0].location


def test_src035_hardcoded_fallback_secret_python_is_flagged(tmp_path):
    (tmp_path / "server.py").write_text(
        "API_SECRET = os.environ.get('API_SECRET', 'dev-secret-123')\n"
    )
    findings = scan_source_tree(tmp_path)
    assert any(f.rule_id == "SRC-035" for f in findings), (
        "Expected SRC-035 for the Python os.environ.get(...) shape"
    )


def test_src035_empty_string_fallback_is_not_flagged(tmp_path):
    """The real, adjacent, non-vulnerable bizfile-mcp line: an EMPTY-string
    fallback leaves the value falsy/unset rather than a real hardcoded
    credential."""
    (tmp_path / "server.js").write_text(
        "const OWNER_KEY = process.env.OWNER_KEY || '';\n"
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-035" for f in findings), (
        f"Did not expect SRC-035 for an empty-string fallback, got: {findings}"
    )


def test_src035_non_secret_constant_name_is_not_flagged(tmp_path):
    """A fallback-bearing constant whose name has nothing to do with a
    credential (e.g. a numeric-looking default port name, or a plain
    database primary-key column name) must not fire."""
    (tmp_path / "server.js").write_text(
        "const REDIS_PREFIX = process.env.REDIS_PREFIX || 'bizfile';\n"
        "const PRIMARY_KEY = process.env.PRIMARY_KEY || 'id';\n"
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-035" for f in findings), (
        f"Did not expect SRC-035 for a non-secret-shaped constant name, got: {findings}"
    )


# --- SRC-036: DNS-rebinding protection explicitly disabled ----------------


def test_src036_dns_rebinding_protection_disabled_is_flagged(tmp_path):
    """The real eren-solutions/mcp-security-audit shape."""
    (tmp_path / "server.py").write_text(
        '''
        def main():
            mcp.settings.host = args.host
            mcp.settings.port = args.port
            mcp.settings.transport_security.enable_dns_rebinding_protection = False
            mcp.run(transport=args.transport)
        '''
    )
    findings = scan_source_tree(tmp_path)
    src036 = [f for f in findings if f.rule_id == "SRC-036"]
    assert src036, f"Expected SRC-036, got: {findings}"
    assert "server.py:" in src036[0].location


def test_src036_dns_rebinding_protection_left_enabled_is_not_flagged(tmp_path):
    (tmp_path / "server.py").write_text(
        '''
        def main():
            mcp.settings.transport_security.enable_dns_rebinding_protection = True
            mcp.run(transport=args.transport)
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-036" for f in findings), (
        f"Did not expect SRC-036 when the protection is left enabled, got: {findings}"
    )
