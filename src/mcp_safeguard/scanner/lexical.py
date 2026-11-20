"""Lexical pre-processing for source_scanner.py's regex rules: comment/
docstring stripping and file-role classification.

Milestone: precision fix. The 148-rule lexical engine in source_scanner.py
matches regex patterns directly against raw file text, with two consequences
measured as real false-positive drivers in a 36-repo real-world campaign
(Round 40, 1,580 raw HIGH/CRITICAL hits, ~98% false-positive rate on the
CRITICAL-severity subset):

1. Comments and docstrings are scanned as if they were live code -- a rule
   can fire on a code comment that literally documents "SSRF protection
   applied here" or a docstring whose example snippet shows the vulnerable
   shape being warned against, not the vulnerability itself.
2. Test fixtures, vendored/bundled dependencies, minified bundles, and
   example/demo code get scanned as production source, even though a
   security lead in a `*.test.ts` file, a `node_modules/`-style vendored
   bundle, or an `examples/` walkthrough is not a real finding about the
   scanned server's own shipped behavior.

Both fixes are applied once, at file-iteration time, in
`source_scanner._iter_source()`:
  - `classify_file()` decides whether a file is production source at all;
    non-production files (test/vendored/example/minified/generated) are
    skipped entirely rather than scanned-and-downgraded. This was a
    deliberate choice over "scan but tag/downgrade": every one of the 36
    rule blocks in source_scanner.py independently constructs and appends
    its own `SourceFinding`, so downgrading would mean threading a new
    parameter through 36 call sites; skipping the file needs exactly one
    change, at the single existing file-iteration entry point, and a
    security lead inside a test fixture or a vendored dependency is not
    actionable against the scanned server's own code regardless of its
    severity, so there is no real value in surfacing it at a lower severity
    rather than not surfacing it at all.
  - `strip_comments_and_docstrings()` returns a same-length, same-line-count
    copy of a file's text with comment and docstring interiors blanked to
    spaces (newlines preserved). Every downstream regex rule in
    source_scanner.py keeps matching against `text` exactly as before --
    only what `_iter_source()` yields as `text` changes -- and evidence
    slices taken from that text at a match's offsets are byte-identical to
    slices from the original raw text, since a match can only land outside
    a blanked span.
"""

from __future__ import annotations

import io
import re
import tokenize
from enum import Enum
from pathlib import Path


class FileRole(str, Enum):
    PRODUCTION = "production"
    TEST = "test"
    VENDORED = "vendored"
    EXAMPLE = "example"
    MINIFIED = "minified"
    GENERATED = "generated"


# --------------------------------------------------------------------------
# File-role classification
# --------------------------------------------------------------------------

# Directory-name components (exact match against a path part, same
# component-matching discipline as source_scanner._SKIP_DIRS -- substring
# matching on "test" would also match a real "testUtils/" package or a
# "latest-changes/" directory).
_VENDORED_DIRS = {"node_modules", "vendor", "third_party", "thirdparty", ".yarn"}
_EXAMPLE_DIRS = {"examples", "example", "demo", "demos", "sample", "samples", "spike", "spikes"}
_TEST_DIRS = {"test", "tests", "spec", "specs", "__tests__"}

# Filename shapes: `.test.*`/`.spec.*` (Jest/Vitest/Mocha convention) and
# Python's `test_*.py`/`*_test.py` (pytest/unittest convention).
_TEST_FILENAME = re.compile(r"\.(?:test|spec)\.[jt]sx?$", re.IGNORECASE)
_PY_TEST_FILENAME = re.compile(r"^(?:test_.+|.+_test)\.py$", re.IGNORECASE)

# Minified: `.min.js`/`.min.css`-style suffix, or a file whose longest line
# is implausibly long relative to its total size (bundlers/minifiers emit
# most or all of the file as one or a few lines).
_MINIFIED_FILENAME = re.compile(r"\.min\.[jt]sx?$", re.IGNORECASE)
_MINIFIED_LINE_LENGTH = 2000

# Generated: an explicit header marker within the first few lines, or a
# common generated-file name pattern (protobuf/gRPC, Python's *_pb2.py).
_GENERATED_MARKER = re.compile(
    r"^\s*(?:#|//|/\*)\s*(?:Code generated|@generated|DO NOT EDIT|"
    r"This file (?:is|was) auto(?:matically)?[ -]generated)",
    re.IGNORECASE | re.MULTILINE,
)
_GENERATED_FILENAME = re.compile(r"(?:_pb2|\.pb|\.g|\.generated)\.(?:py|go|cs|ts|js)$", re.IGNORECASE)


def classify_file(path: Path, root: Path) -> FileRole:
    """Classify a source file's role so non-production files can be
    excluded from the security-audit rules entirely. `path` must be
    relative-to-`root` resolvable (as in `_iter_source`)."""
    try:
        rel_parts = path.relative_to(root).parts
    except ValueError:
        rel_parts = path.parts
    dir_parts = {p.lower() for p in rel_parts[:-1]}
    name = path.name

    if dir_parts & _VENDORED_DIRS:
        return FileRole.VENDORED
    if dir_parts & _EXAMPLE_DIRS:
        return FileRole.EXAMPLE
    if dir_parts & _TEST_DIRS:
        return FileRole.TEST
    if _TEST_FILENAME.search(name) or _PY_TEST_FILENAME.match(name):
        return FileRole.TEST
    if _MINIFIED_FILENAME.search(name):
        return FileRole.MINIFIED
    if _GENERATED_FILENAME.search(name):
        return FileRole.GENERATED
    return FileRole.PRODUCTION


def classify_file_content(role: FileRole, text: str) -> FileRole:
    """Second classification pass that needs the file's actual content
    (minified-by-shape, generated-header marker) -- kept separate from
    `classify_file()` so callers that already know a file is non-production
    from its path alone can skip reading/scanning it at all."""
    if role is not FileRole.PRODUCTION:
        return role
    if _GENERATED_MARKER.search(text[:400]):
        return FileRole.GENERATED
    lines = text.splitlines()
    if lines:
        longest = max(len(line) for line in lines)
        if longest > _MINIFIED_LINE_LENGTH and len(lines) <= max(10, len(text) // _MINIFIED_LINE_LENGTH + 2):
            return FileRole.MINIFIED
    return FileRole.PRODUCTION


# --------------------------------------------------------------------------
# Comment / docstring stripping
# --------------------------------------------------------------------------


def _blank_span(chars: list[str], start: int, end: int) -> None:
    """Overwrite chars[start:end] with spaces, leaving any '\\n' inside the
    span untouched so line numbers/line count don't shift."""
    for i in range(start, end):
        if chars[i] != "\n":
            chars[i] = " "


def _line_start_offsets(text: str) -> list[int]:
    offsets = [0]
    pos = text.find("\n")
    while pos != -1:
        offsets.append(pos + 1)
        pos = text.find("\n", pos + 1)
    return offsets


def _strip_python(text: str) -> str:
    """Blank Python comments (# ...) and bare string-literal statements
    (docstrings, and the same "string used as a comment" mid-function shape)
    using the real `tokenize` module, so this can't be fooled by a '#' or a
    quote character inside an unrelated string literal the way a regex-only
    pass could be."""
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenizeError, SyntaxError, IndentationError):
        # Not valid/tokenizable Python (partial file, syntax error in a
        # fixture, etc.) -- leave the text unchanged rather than fail the
        # whole scan; rules just see it exactly as they did before this fix.
        return text

    line_offsets = _line_start_offsets(text)
    chars = list(text)
    # Tracks the last token type that represents real code, so a STRING
    # token can be recognized as a standalone statement (module/class/def
    # docstring, or a bare string used as an inline comment) when it
    # immediately follows a logical-line boundary.
    prev_code_tok: int | None = None
    for tok in tokens:
        toktype, _tokstr, start, end, _line = tok
        if toktype in (tokenize.COMMENT,):
            s = line_offsets[start[0] - 1] + start[1]
            e = line_offsets[end[0] - 1] + end[1]
            _blank_span(chars, s, e)
            continue
        if toktype == tokenize.STRING and prev_code_tok in (
            None,
            tokenize.NEWLINE,
            tokenize.INDENT,
            tokenize.DEDENT,
        ):
            s = line_offsets[start[0] - 1] + start[1]
            e = line_offsets[end[0] - 1] + end[1]
            _blank_span(chars, s, e)
            # A blanked docstring is still a statement -- treat it as the
            # previous code token so a second, adjacent bare string isn't
            # miscounted as also being at a logical-line start it isn't.
            prev_code_tok = tokenize.STRING
            continue
        if toktype not in (
            tokenize.NL,
            tokenize.COMMENT,
            tokenize.ENCODING,
            tokenize.INDENT,
            tokenize.DEDENT,
        ):
            prev_code_tok = toktype
        elif toktype in (tokenize.INDENT, tokenize.DEDENT):
            prev_code_tok = toktype
    return "".join(chars)


def _is_escaped(text: str, i: int) -> bool:
    """True if `text[i]` is preceded by an odd number of consecutive
    backslashes, i.e. it is itself an escaped literal character rather than
    a real delimiter. Outside of string literals (which are tracked
    separately and skipped over whole), a bare backslash in well-formed
    JS/TS/Go/etc. source only occurs inside a regex literal -- e.g. the
    `\\/` in `/^https?:\\/\\//i` -- so this also doubles as "is this `/`
    part of a regex literal's own escaped slash, not a comment delimiter".
    """
    count = 0
    j = i - 1
    while j >= 0 and text[j] == "\\":
        count += 1
        j -= 1
    return count % 2 == 1


def _strip_c_style(text: str) -> str:
    """Blank `//` line comments and `/* */` block comments for the brace-
    language extensions (.js/.ts/.mjs/.cjs/.mts/.cts/.go/.cs/.rs/.swift/.kt),
    without stripping `//` or `/*` that appear inside a string literal, or
    that appear inside a regex literal (e.g. the closing `\\//` of
    `/^https?:\\/\\//i`, where the escaped `\\/` immediately before the
    real closing `/` must not be misread as a `//` line-comment start; the
    same escaping applies to a `/*`-shaped pair formed by an escaped slash
    followed by a literal `*` quantifier, e.g. `\\/*` in a trailing-slash
    regex like `/^\\/uploads\\/*$/`). Deliberately a character-scanning
    pass, not a real parser: it tracks only "am I inside a string / line
    comment / block comment right now", with backslash-escape handling for
    string literals and for a leading `/` or `*` that is itself escaped,
    which is enough to not be fooled by the shapes this project's own rules
    look for (a `//` inside a URL string, a `/*` inside a regex literal
    assigned to a string-typed variable, a regex literal's own escaped
    slashes, etc.) without needing full language grammars. Block comments
    are treated as non-nesting (the first `*/` closes them), which is
    correct for every one of these languages except Rust and Swift's
    rarely-used nested `/* /* */ */` form -- an accepted, documented
    limitation of a lightweight pass. Kotlin's own triple-double-quoted raw
    strings are a SECOND, similarly-accepted limitation added at the same
    time (v10 consolidation merge, wiring Kotlin into
    `reconstruct_path_kotlin` -- see bench/FINAL_COMPLETE_V10_STATUS.md):
    this scanner only recognizes single-character string delimiters, so a
    triple-quoted raw string is seen as an (immediately-closed, empty)
    string followed by two more single-quote opens/closes, not one
    contiguous raw-string span -- which can misinterpret a line-comment or
    block-comment marker that happens to appear inside that raw string's own
    content as a real comment. Not exercised by this milestone's own real
    validation target (JetBrains/teamcity-mcp uses only ordinary
    double-quoted strings in every file this project's Kotlin support
    actually reads), so left as a stated, not silently-hidden, limitation
    rather than a full triple-quote-aware rewrite of this character scanner.
    """
    n = len(text)
    out = list(text)
    i = 0
    STRING_DELIMS = "\"'`"
    while i < n:
        c = text[i]
        if c in STRING_DELIMS:
            delim = c
            i += 1
            while i < n:
                if text[i] == "\\" and i + 1 < n:
                    i += 2
                    continue
                if text[i] == delim:
                    i += 1
                    break
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/" and not _is_escaped(text, i):
            start = i
            while i < n and text[i] != "\n":
                i += 1
            _blank_span(out, start, i)
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*" and not _is_escaped(text, i):
            start = i
            i += 2
            while i < n and not (text[i - 1] == "*" and text[i] == "/"):
                i += 1
            end = min(i + 1, n)
            _blank_span(out, start, end)
            i = end
            continue
        i += 1
    return "".join(out)


_PY_SUFFIXES = {".py"}
_C_STYLE_SUFFIXES = {".go", ".ts", ".js", ".cs", ".rs", ".swift", ".mjs", ".cjs", ".mts", ".cts", ".kt"}


def strip_comments_and_docstrings(text: str, suffix: str) -> str:
    """Return a same-length, same-line-count copy of `text` with comments
    and (for Python) bare string-literal statements blanked to spaces, so a
    regex rule that matches against the result can't fire on a comment or
    docstring. Unrecognized suffixes are returned unchanged."""
    if suffix in _PY_SUFFIXES:
        return _strip_python(text)
    if suffix in _C_STYLE_SUFFIXES:
        return _strip_c_style(text)
    return text
