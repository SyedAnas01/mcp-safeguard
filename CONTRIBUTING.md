# Contributing to mcp-safeguard

Thank you for helping make MCP servers more secure!

## Development Setup

```bash
git clone https://github.com/SyedAnas01/mcp-safeguard
cd mcp-safeguard
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
cp .env.example .env
```

## Running Tests

```bash
pytest tests/ -v
```

All PRs must pass the full test suite. Add tests for any new scanner rules or features.

## Code Style

```bash
black src/ tests/          # Format
ruff check src/ tests/     # Lint
```

The CI pipeline enforces both. Fix all issues before submitting.

## Adding a New Detection Rule

1. Choose the appropriate scanner module (`prompt_injection.py`, `credential_scanner.py`, etc.)
2. Add the rule tuple to the relevant `_PATTERNS` list with:
   - A regex pattern
   - A `Severity` level
   - A unique `RULE-ID` (e.g., `PI-016`, `CRED-018`)
   - A human-readable title
   - A CVSS score
3. Add remediation text to the `_get_*_remediation()` function
4. Write at least two test cases: one that triggers the rule, one that confirms clean input passes
5. Document the rule in the PR description

**If the rule is derived from a real, confirmed vulnerability** (the strongest
kind — see the SRC-013..020 comments in `source_scanner.py` for the pattern),
also test it against the *actual* vulnerable code, not only your synthetic
fixture, before opening the PR. Several rules in this codebase looked correct
against a hand-written test but missed (or falsely flagged) the real thing on
first contact — real code has indirection, multi-line calls, and surrounding
logic a clean synthetic fixture doesn't exercise. If the source is
permissively licensed (MIT/Apache/BSD) and you can attribute it (repo, exact
commit, license, one line on the real disclosed finding), add a minimal
excerpt under `tests/fixtures/confirmed_vulnerable/<name>/` and a test in
`tests/test_benchmark_confirmed_vulnerable.py` following the existing example
— this is the project's real-world benchmark corpus, and it's meant to grow
with every rule that comes from an actual finding.

**Rules in `source_scanner.py` (SRC-*) don't use a flat `_PATTERNS` list** —
each is its own regex + a short block of matching logic (see any `SRC-0XX:`
comment there for the pattern), since several need multi-step control flow
(e.g. SRC-016 checks a flag is present in one function and absent elsewhere
in the file) that a flat pattern tuple can't express. Add your rule's ID and
title to the `RULE_IDS` list at the top of the file too — that's what makes
it show up in the `security://rules` resource and the doc-count totals, so
skipping it means the rule works but is invisible to introspection.

## Adding a New Tool

1. Add the tool function to `src/mcp_safeguard/server.py` decorated with `@mcp.tool`
2. Follow the existing pattern: validate inputs, rate-limit, audit-log, return structured dict
3. Add integration tests in `tests/test_server.py`
4. Document in README.md Tools Reference section

## Submitting a PR

- Keep PRs focused — one feature or fix per PR
- Reference any related issue in the PR description
- Ensure `pytest`, `black --check`, and `ruff check` all pass
- Update CHANGELOG.md under `## [Unreleased]`

## Reporting Security Issues

See [SECURITY.md](SECURITY.md) — please do **not** open public issues for security vulnerabilities.

## Code of Conduct

Be respectful. This is a security tool used to protect real systems; take that responsibility seriously.
