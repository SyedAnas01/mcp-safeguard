"""Tests for SRC-037: a compiled .pyc in __pycache__ either has no .py
source next to it, or disassembles to different bytecode than compiling
that .py fresh does.

Same discipline as the other rule test files: a trigger fixture and a
non-trigger fixture per shape. SRC-037 was mined the same way as SRC-035/
SRC-036 -- not from a Round-N measurement this time, but from checking
mcp-safeguard's own coverage against "PyCache Trap" (arXiv 2610.10612,
Oct 2026) right after it published, and finding scan_source_tree reported
zero findings on a directory where a planted __pycache__ entry ran
different code than the .py file sitting next to it. These fixtures
reproduce that same shape: a real compiled .pyc, written with
invalidation_mode=UNCHECKED_HASH so it is never re-validated against its
source by Python's own import system either, compiled from source that
differs from what's on disk.
"""

import importlib.util
import py_compile

import pytest

from mcp_safeguard.scanner.source_scanner import scan_source_tree


def _write_pyc(py_path, compiled_from_source: str) -> None:
    """Writes py_path.py with whatever is currently on disk at py_path,
    then compiles `compiled_from_source` (which may differ) into the
    __pycache__ entry Python would actually load for py_path --
    UNCHECKED_HASH so the real import system treats it as valid too,
    exactly the invalidation mode the real attack technique relies on."""
    tmp_compile_source = py_path.parent / f"_compile_src_{py_path.stem}.py"
    tmp_compile_source.write_text(compiled_from_source)
    pyc_target = importlib.util.cache_from_source(str(py_path))
    py_compile.compile(
        str(tmp_compile_source),
        cfile=pyc_target,
        dfile=str(py_path),
        invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
    )
    tmp_compile_source.unlink()


def test_src037_divergent_bytecode_is_flagged_critical(tmp_path):
    """The real PyCache Trap shape: a clean-looking handler.py sits next
    to a __pycache__ entry that was actually compiled from different
    source. The malicious code lives inside the function body (a nested
    code object), not at module level, matching the real technique."""
    handler = tmp_path / "handler.py"
    handler.write_text(
        "def handler(payload):\n"
        "    return {'status': 'ok', 'echo': payload}\n"
    )
    _write_pyc(
        handler,
        compiled_from_source=(
            "def handler(payload):\n"
            "    EXFIL_MARKER = True\n"
            "    return {'status': 'ok', 'echo': payload}\n"
        ),
    )

    findings = scan_source_tree(tmp_path)
    src037 = [f for f in findings if f.rule_id == "SRC-037"]
    assert len(src037) == 1, f"Expected exactly one SRC-037 finding, got: {findings}"
    assert src037[0].severity.name == "CRITICAL"
    assert "handler.py" in src037[0].description


def test_src037_matching_bytecode_is_not_flagged(tmp_path):
    """The .pyc genuinely compiled from the .py sitting next to it (the
    normal, legitimate case) must not fire -- this is Python's own
    __pycache__ behavior on every real install, SRC-037 would be useless
    (and the scanner unusable) if it flagged every ordinary cache entry."""
    handler = tmp_path / "handler.py"
    source = (
        "def handler(payload):\n"
        "    return {'status': 'ok', 'echo': payload}\n"
    )
    handler.write_text(source)
    _write_pyc(handler, compiled_from_source=source)

    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-037" for f in findings), (
        f"Expected no SRC-037 finding for a genuinely matching .pyc, got: {findings}"
    )


def test_src037_orphan_pyc_with_no_py_is_flagged(tmp_path):
    """A __pycache__ entry with no .py file next to it at all -- nothing
    for a human or a source-only scanner to read, but Python will still
    run it on import if anything imports that module name."""
    handler = tmp_path / "handler.py"
    handler.write_text("def handler(payload):\n    return payload\n")
    _write_pyc(handler, compiled_from_source="def handler(payload):\n    return payload\n")
    handler.unlink()  # remove the .py, leave only the __pycache__ entry

    findings = scan_source_tree(tmp_path)
    src037 = [f for f in findings if f.rule_id == "SRC-037"]
    assert len(src037) == 1, f"Expected exactly one SRC-037 finding, got: {findings}"
    assert src037[0].severity.name == "HIGH"
    assert "no corresponding" in src037[0].title.lower()


def test_src037_does_not_leak_into_the_main_text_based_loop(tmp_path):
    """__pycache__ stays in _SKIP_DIRS for every other rule -- this is a
    regression guard that a clean-looking .py file paired with a
    DIVERGENT .pyc still reports nothing from the unrelated text-based
    rules (e.g. nothing about the .py's own harmless content), only
    SRC-037 itself, confirming the two passes stay cleanly separated."""
    handler = tmp_path / "handler.py"
    handler.write_text(
        "def handler(payload):\n"
        "    return {'status': 'ok', 'echo': payload}\n"
    )
    _write_pyc(
        handler,
        compiled_from_source=(
            "def handler(payload):\n"
            "    EXFIL_MARKER = True\n"
            "    return {'status': 'ok', 'echo': payload}\n"
        ),
    )

    findings = scan_source_tree(tmp_path)
    assert {f.rule_id for f in findings} == {"SRC-037"}, (
        f"Expected only SRC-037 to fire on this directory, got: {findings}"
    )


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
