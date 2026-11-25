"""v28: fix-line primary selection -- synthetic fixtures only."""
from mcp_safeguard.scanner.fixline import is_assignment_of, refile_line_fixed, select_primary

SRC = {
    "a.ts": "\n".join([
        "import fs from 'fs';",                       # 1
        "export function save(name, data) {",         # 2
        "  const target = path.join(ROOT, name);",    # 3
        "  log('saving');",                           # 4
        "  fs.writeFileSync(target, data);",          # 5
        "}",
    ]),
    "b.ts": "\n".join(["x", "  const res = await fetch(url);", "  if (url) {", "// check url here"]),
}
text_of = SRC.get


def F(sink, guard=None, file="a.ts", line=5, lf=None):
    c = [{"role": "sink", "file": "a.ts", "line": sink}]
    if guard:
        c.append({"role": "guard", "file": "a.ts", "line": guard})
    return {"file": file, "line": line, "citations": c}


def test_construction_line_beats_sink():
    assert select_primary(F(5, 3), 5, text_of) == ("a.ts", 3)

def test_guard_that_is_not_assignment_is_ignored():
    assert select_primary(F(5, 4), None, text_of) == ("a.ts", 5)

def test_inline_sink_keeps_sink():
    f = {"file": "b.ts", "line": 2, "citations": [{"role": "sink", "file": "b.ts", "line": 2},
                                                    {"role": "guard", "file": "b.ts", "line": 3}]}
    assert select_primary(f, None, text_of) == ("b.ts", 2)

def test_comment_guard_ignored():
    f = {"file": "b.ts", "line": 2, "citations": [{"role": "sink", "file": "b.ts", "line": 2},
                                                    {"role": "guard", "file": "b.ts", "line": 4}]}
    assert select_primary(f, None, text_of) == ("b.ts", 2)

def test_line_fixed_refiled_to_matching_citation_file():
    f = {"file": "a.ts", "line": 229, "citations": [{"role": "sink", "file": "c.ts", "line": 210}]}
    assert refile_line_fixed(f, 210) == ("c.ts", 210)
    assert refile_line_fixed(f, None) is None

def test_unrelated_assignment_not_chosen():
    assert not is_assignment_of("  const other = 1;", "fs.writeFileSync(target, data)")
    assert is_assignment_of("  const target = path.join(a, b);", "fs.writeFileSync(target, data)")
    assert not is_assignment_of("  if (x == target) {", "fs.writeFileSync(target, data)")

def test_adversary_line_used_when_no_def_use():
    assert select_primary(F(5), 4, text_of) == ("a.ts", 4)

def test_no_citations_falls_back_to_finding():
    assert select_primary({"file": "z.py", "line": 7}, None, text_of) == ("z.py", 7)


def test_explicit_line_fixed_file_wins():
    f = {"file": "a.ts", "line": 5, "citations": [{"role": "sink", "file": "a.ts", "line": 5}]}
    assert refile_line_fixed(f, 3, "b.ts") == ("b.ts", 3)
    assert select_primary(f, 3, text_of, "b.ts") == ("b.ts", 3)
