"""v28: sink-site enumeration -- synthetic tree."""
from mcp_safeguard.scanner.sites import enumerate_sites


def test_enumerates_each_kind(tmp_path):
    (tmp_path / "a.ts").write_text(
        "const p = path.join(ROOT, categoryName);\n"
        "await fetch(meta.registration_endpoint, {});\n"
        "args.push(options.session_id);\n"
        "switch (m) { case 'tools/call': break; }\n"
        "const q = path.join(ROOT, 'static');\n"
    )
    (tmp_path / "b.py").write_text("tarfile.open(upload).extractall(dest)\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "t.ts").write_text("const p = path.join(R, run_id);\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.js").write_text("path.join(a, name)\n")
    kinds = {(k, f, n) for k, f, n, _ in enumerate_sites(tmp_path)}
    assert ("path_join", "a.ts", 1) in kinds
    assert ("doc_derived_fetch", "a.ts", 2) in kinds
    assert ("argv_builder", "a.ts", 3) in kinds
    assert ("dispatcher", "a.ts", 4) in kinds
    assert ("archive_extract", "b.py", 1) in kinds
    assert not any(f.startswith(("tests", "node_modules")) for _, f, _ in kinds)
    assert ("path_join", "a.ts", 5) not in kinds


def test_cap_per_kind(tmp_path):
    (tmp_path / "a.py").write_text("\n".join(f"x{i} = os.path.join(base, name)" for i in range(40)))
    assert len([1 for k, *_ in enumerate_sites(tmp_path, per_kind_cap=5) if k == "path_join"]) == 5
