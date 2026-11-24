"""False-positive regressions found by scanning popular MCP servers (0.10.2)."""
from mcp_safeguard.scanner.source_scanner import scan_source_tree


def _rules(tmp_path, name, body):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    return {f.rule_id: f for f in scan_source_tree(tmp_path)}


def test_src021_unix_socket_listen_not_flagged(tmp_path):
    r = _rules(tmp_path, "daemon.ts", """
import net from 'node:net';
const server = net.createServer(handle);
server.listen({ path: socketPath, readableAll: false, writableAll: false });
""")
    assert "SRC-021" not in r


def test_src021_build_script_serve_not_flagged(tmp_path):
    r = _rules(tmp_path, "web/build.js", """
const esbuild = require('esbuild');
ctx.serve({ servedir: dirName, port: 3226 });
""")
    assert "SRC-021" not in r


def test_src021_bearer_auth_manager_not_flagged(tmp_path):
    r = _rules(tmp_path, "http-server.ts", """
import express from 'express';
import { AuthManager } from './utils/auth';
const app = express();
app.post('/mcp', (req, res) => { handle(req, res); });
app.listen(port, host);
""")
    assert "SRC-021" not in r


def test_src021_still_fires_without_auth(tmp_path):
    r = _rules(tmp_path, "server.ts", """
import express from 'express';
const app = express();
app.post('/mcp', (req, res) => { handle(req, res); });
app.listen(port, host);
""")
    assert "SRC-021" in r


def test_src026_outbound_loopback_client_not_flagged(tmp_path):
    r = _rules(tmp_path, "BrowserManager.ts", """
const browserWSEndpoint = `ws://127.0.0.1:${port}${rawPath}`;
await puppeteer.connect({ browserWSEndpoint });
""")
    assert "SRC-026" not in r


def test_src026_log_line_url_not_flagged(tmp_path):
    r = _rules(tmp_path, "index.ts", """
const httpServer = app.listen(port);
httpServer.once("listening", () => {
  console.error(
    `running on HTTP at http://localhost:${address.port}/mcp`
  );
});
""")
    assert "SRC-026" not in r


def test_src026_trusted_hosts_not_flagged(tmp_path):
    r = _rules(tmp_path, "dashboard.py", """
def start(host: str = "127.0.0.1", trusted_hosts=None):
    app.run(host=host, port=port)
""")
    assert "SRC-026" not in r


def test_src026_still_fires_on_real_loopback_server(tmp_path):
    r = _rules(tmp_path, "server.py", """
def start(host: str = "127.0.0.1"):
    app.run(host=host, port=port)
""")
    assert "SRC-026" in r


def test_src028_message_with_string_fallback_not_flagged(tmp_path):
    r = _rules(tmp_path, "cli.ts", """
try { run(); } catch (err) {
  console.error("roots/list: " + (err instanceof Error ? err.message : String(err)));
}
""")
    assert "SRC-028" not in r


def test_src029_unrelated_write_not_flagged(tmp_path):
    r = _rules(tmp_path, "doctor.ts", """
const token = await getToken();
use(token);
writeFileSync(file, body);
""")
    assert "SRC-029" not in r


def test_src029_mode_0600_is_medium(tmp_path):
    r = _rules(tmp_path, "auth.ts", """
const accessToken = response.data.access_token;
fs.writeFileSync(credentialsFile, JSON.stringify({ accessToken }), { mode: 0o600 });
""")
    assert r["SRC-029"].severity.name == "MEDIUM"


def test_src029_plain_token_write_still_high(tmp_path):
    r = _rules(tmp_path, "auth.ts", """
const accessToken = response.data.access_token;
fs.writeFileSync(tokenFile, accessToken);
""")
    assert r["SRC-029"].severity.name == "HIGH"


def test_src023_fetch_wrapper_definition_not_flagged(tmp_path):
    r = _rules(tmp_path, "client.ts", """
const transport = {
  async fetch(input: Request | URL | string, init?: RequestInit) {
    return globalThis.fetch(input, init);
  },
};
""")
    assert "SRC-023" not in r


def test_src023_constant_base_url_not_flagged(tmp_path):
    r = _rules(tmp_path, "api.ts", """
import { CONTEXT7_API_BASE_URL } from './config';
export async function check() {
  return fetch(`${CONTEXT7_API_BASE_URL}${AUTH_CHECK_PATH}`, { headers });
}
export async function who() {
  return fetch(`${getBaseUrl()}/api/whoami`, { headers });
}
""")
    assert "SRC-023" not in r


def test_src023_caller_url_param_still_flagged(tmp_path):
    r = _rules(tmp_path, "tool.py", """
def fetch_page(url):
    return requests.get(url, timeout=10).text
""")
    assert "SRC-023" in r


def test_src032_one_finding_per_file(tmp_path):
    p = tmp_path / "srv.ts"
    p.write_text("""
app.post('/mcp', (req, res) => {
  const sessionId = req.headers['mcp-session-id'];
  const t = transports[sessionId];
});
app.get('/mcp', (req, res) => {
  const sid = req.headers['mcp-session-id'];
  const t = transports[sid];
});
""")
    findings = [f for f in scan_source_tree(tmp_path) if f.rule_id == "SRC-032"]
    assert len(findings) == 1


def test_scripts_and_fixtures_dirs_skipped(tmp_path):
    body = "import subprocess\ndef run(cmd):\n    subprocess.run(cmd, shell=True)\n"
    for d in ("scripts", "fixtures", "e2e"):
        (tmp_path / d).mkdir()
        (tmp_path / d / "x.py").write_text(body)
    assert scan_source_tree(tmp_path) == []
    (tmp_path / "server.py").write_text(body)
    assert any(f.rule_id == "SRC-019" for f in scan_source_tree(tmp_path))


def test_bundled_js_skipped(tmp_path):
    (tmp_path / "dist.js").write_text(
        "// node_modules/a/index.js\n// node_modules/b/index.js\n// node_modules/c/index.js\n"
        "const { exec } = require('child_process');\nfunction run(cmd) { exec('ls ' + cmd); }\n"
    )
    assert scan_source_tree(tmp_path) == []
