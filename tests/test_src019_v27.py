"""v27: SRC-019 generic shell-sink finder -- synthetic fixtures only."""
import pytest
from mcp_safeguard.scanner.source_scanner import _find_shell_injection_sites as f

POS = {
    "execSync_template": 'const out = execSync(`git log ${ref}`);',
    "execAsync_concat": 'await execAsync("convert " + input + " out.png");',
    "promisified_exec_var": 'const cmd = `nmap ${target}`;\nconst r = await execP(cmd);',
    "spawn_shell_true": "spawn(`ls ${dir}`, { shell: true });",
    "py_os_system_fstring": 'os.system(f"tar xf {name}")',
    "py_subprocess_shell_format": 'subprocess.check_output("grep {} f".format(pat), shell=True)',
    "py_var_then_popen": 'cmd = "ls " + path\nos.popen(cmd)',
    "go_sh_c": 'exec.Command("sh", "-c", "ls "+dir)',
    "second_site_only": 'exec("ls -la");\nfoo();\nexec(`rm ${x}`);',
}
NEG = {
    "literal": 'execSync("git status");',
    "execFile_argv": 'execFile("git", ["log", ref]);',
    "regex_exec_method": "const m = re.exec(str); const t = `${a}`;",
    "py_list_noshell": 'subprocess.run(["ls", path])',
    "quoted": 'os.system("ls " + shlex.quote(path))',
}


@pytest.mark.parametrize("name", POS)
def test_fires(name):
    assert f(POS[name]), name


@pytest.mark.parametrize("name", NEG)
def test_silent(name):
    assert not f(NEG[name]), name


def test_reports_every_site_not_just_first():
    sites = f(POS["second_site_only"])
    assert len(sites) == 1 and POS["second_site_only"][sites[0][0]:].startswith("exec(`rm")


def test_src018_reports_second_site_and_arguments_name(tmp_path):
    from mcp_safeguard.scanner.source_scanner import scan_source_tree
    (tmp_path / "a.js").write_text(
        'const a = fs.readFileSync(path.join(BASE, "x.json"));\n'
        'function h(arguments) {\n  return fs.readFileSync(path.join(BASE, arguments.name));\n}\n'
    )
    hits = [x for x in scan_source_tree(tmp_path) if x.rule_id == "SRC-018"]
    assert hits and hits[0].location.endswith(":3")


def test_src037_dynamic_eval():
    from mcp_safeguard.scanner.source_scanner import _find_dynamic_eval_sites as g
    assert g("const r = eval(expr);", ".js")
    assert g("const fn = new Function('a', body);", ".ts")
    assert g("x = parse_expr(user_text)", ".py")
    assert g("exec(code)", ".py")
    assert not g('eval("1+1")', ".js")
    assert not g("m = re.exec(s)", ".js")
    assert not g("const r = JSON.parse(x)", ".js")
    assert not g("v = ast.literal_eval(x)", ".py")


@pytest.mark.parametrize("src,suffix,want", [
    ('execSync("npm ci", { cwd: path.join(root, "pkg") })', ".js", False),
    ('exec(f"x={v}")', ".py", False),
    ('exec.Command("bash","-c", fmt.Sprintf("git log %s", ref))', ".go", True),
    ('script := "ls "+dir\nexec.Command("sh","-c",script)', ".go", True),
    ('out = subprocess.getoutput(f"df {mount}")', ".py", True),
    ('cmd = shlex.join(["ls", p]); os.system(cmd)', ".py", False),
    ('let cmd = "ls"; cmd += " " + dir; execSync(cmd)', ".js", True),
    ('execSync (`ls ${d}`)', ".js", True),
])
def test_review_fixes_shell(src, suffix, want):
    assert bool(f(src, suffix)) is want, src


@pytest.mark.parametrize("src,suffix,want", [
    ('exec(f"x={v}")', ".py", True),
    ('exec(self.code)', ".py", True),
    ('window.eval(code)', ".js", True),
    ('(0, eval)(code)', ".js", True),
])
def test_review_fixes_eval(src, suffix, want):
    from mcp_safeguard.scanner.source_scanner import _find_dynamic_eval_sites as g
    assert bool(g(src, suffix)) is want, src


def test_src018_filename_input_html_not_flagged(tmp_path):
    from mcp_safeguard.scanner.source_scanner import scan_source_tree
    (tmp_path / "a.js").write_text('const t = fs.readFileSync(path.join(__dirname, "templates", "input.html"));\n')
    assert not [x for x in scan_source_tree(tmp_path) if x.rule_id == "SRC-018"]
