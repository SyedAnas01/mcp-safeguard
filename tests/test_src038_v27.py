"""v27: SRC-038 argv option-injection finder -- synthetic fixtures only."""
import pytest
from mcp_safeguard.scanner.source_scanner import _find_argv_injection_sites as f

POS = {
    "node_git_clone": 'await execFile("git", ["clone", url, dest]);',
    "node_spawn_template": 'spawn("curl", ["-s", `${base}/x`]);',
    "node_execa": 'await execa("npm", ["install", pkg]);',
    "py_list_git": 'subprocess.run(["git", "clone", repo_url])',
    "py_popen_tar": 'subprocess.Popen(["tar", "xf", archive_name], cwd=d)',
    "go_git": 'cmd := exec.Command("git", "clone", repoURL)',
    "go_ctx": 'exec.CommandContext(ctx, "ssh", host, "ls")',
    "second_site": 'execFile("git", ["status"]);\nexecFile("git", ["log", ref]);',
}
NEG = {
    "all_literal": 'execFile("git", ["status", "--short"]);',
    "dashdash": 'execFile("git", ["clone", "--", url, dest]);',
    "py_dashdash": 'subprocess.run(["git", "checkout", "--", path])',
    "unlisted_binary": 'execFile("ls", ["-la", dir]);',
    "quoted": 'execFile("git", ["log", shellQuote(ref)]);',
    "go_literal": 'exec.Command("git", "status")',
    "shell_string_not_argv": 'execSync(`git log ${ref}`);',
}


@pytest.mark.parametrize("name", POS)
def test_fires(name):
    assert f(POS[name]), name


@pytest.mark.parametrize("name", NEG)
def test_silent(name):
    assert not f(NEG[name]), name
