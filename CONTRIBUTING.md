# Contributing to mcp-shield

Thank you for helping make MCP servers more secure!

## Development Setup

```bash
git clone https://github.com/mcp-shield/mcp-shield
cd mcp-shield
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

## Adding a New Tool

1. Add the tool function to `src/mcp_shield/server.py` decorated with `@mcp.tool`
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
