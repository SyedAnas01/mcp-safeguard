"""Tests for the shared untrusted-content delimiting helper
(untrusted_text.py) -- see hunter.py/adversary.py/critic.py for the real
prompt-building functions that use it, and their own tests for the
integration-level coverage (real injection-attempt strings through the real
prompt-building code, not just this module in isolation).
"""

from __future__ import annotations

from mcp_safeguard.scanner.untrusted_text import (
    UNTRUSTED_BEGIN,
    UNTRUSTED_CONTENT_WARNING,
    UNTRUSTED_END,
    wrap_untrusted,
)


def test_wrap_untrusted_places_text_between_the_delimiter_pair():
    wrapped = wrap_untrusted("some target text")
    assert wrapped == f"{UNTRUSTED_BEGIN}\nsome target text\n{UNTRUSTED_END}"


def test_wrap_untrusted_wraps_even_empty_text():
    wrapped = wrap_untrusted("")
    assert UNTRUSTED_BEGIN in wrapped
    assert UNTRUSTED_END in wrapped


def test_wrap_untrusted_does_not_alter_the_wrapped_text_itself():
    """The real text is preserved byte-for-byte inside the delimiters -- the
    wrapping is purely additive, never a transform/escape of the content."""
    original = "a README sentence with \"quotes\" and a\nnewline"
    wrapped = wrap_untrusted(original)
    assert original in wrapped


def test_warning_names_both_delimiter_strings():
    """The warning must actually reference the real delimiter constants (not
    a hand-typed copy that could drift from them), so a model reading it can
    match the warning's description to what it sees in the prompt."""
    assert UNTRUSTED_BEGIN in UNTRUSTED_CONTENT_WARNING
    assert UNTRUSTED_END in UNTRUSTED_CONTENT_WARNING


def test_warning_states_data_not_instructions():
    assert "not instruction" in UNTRUSTED_CONTENT_WARNING.lower() or "never as an instruction" in UNTRUSTED_CONTENT_WARNING.lower()
