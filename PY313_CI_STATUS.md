# Python 3.13 investigation — status

## What was asked

A sibling agent, while rebasing separate work on top of tonight's 0.9.2
release, reported that the exact `TypeError` from the 0.9.1 incident
(`_PinnedSNITransport`/`_make_pinned_httpx_client_factory` built on the wrong
`httpx` package) still reproduces on Python 3.13, with the same 3 tests in
`tests/test_mcp_protocol_client.py` failing. Task: reproduce for real, find
the real 3.13-specific root cause, fix it, add 3.13 to CI.

## What actually reproduced

**It does not reproduce on current `main`.** Ran `tests/test_mcp_protocol_client.py`
and the full suite inside a real `python:3.13-slim` Docker container against
commit `8161d9b` (current main — includes both the 0.9.2 `httpx2` fix,
`05c18d5`, and the endpoint_scanner DNS-rebinding fix, `8161d9b` itself):

- `tests/test_mcp_protocol_client.py`: 7/7 passed, 5 consecutive runs (checked
  for async/port-binding flakiness — none).
- Full suite: **252/252 passed** on Python 3.13.15.
- Same full suite also re-run clean on `python:3.11-slim` (252/252) and
  `python:3.12-slim` (252/252) to confirm nothing regressed.

`pip show httpx2 httpcore2` inside the 3.13 container resolves the identical
`2.12.0` for both packages as on 3.11 and 3.12 — ruling out a
version-resolution skew from an unpinned constraint as the cause of anything.

## Root cause of the *sibling agent's* report

To make sure the test methodology itself would actually catch a real
regression, the exact same 3.13 container was run against `77db556` (the
0.9.1 release commit, i.e. `main` as it stood **before** `05c18d5` fixed the
httpx/httpx2 mismatch). That reproduces the identical 3 failures the sibling
agent described, on the identical 3 tests
(`test_fetch_tools_via_mcp_retrieves_real_tool_definitions`,
`test_scan_mcp_server_finds_injection_via_real_protocol`,
`test_scan_mcp_server_wires_in_ssrf_scanner`), with the identical
`assert 0 == 1` / empty-tools-list signature as the original 0.9.1 incident.

This is the same bug as before, not a new 3.13-specific one, and it is
Python-version-independent (0.9.1's real CI run failed it on 3.11 and 3.12
too, the night this was first found). The most likely explanation is that
the sibling agent's rebase was running against a branch state that predated
`05c18d5` landing on `main` — not a 3.13-specific behavioral difference in
`httpx2`/`httpcore2`. No code fix was applied to `server.py` because there is
nothing currently broken there on 3.13.

## What was actually changed

Nothing in `server.py` — it's already correct on 3.13. Two small,
independently-justified changes:

1. `.github/workflows/ci.yml`: added `"3.13"` to the `test` job's matrix
   (`["3.11", "3.12", "3.13"]`).
2. `pyproject.toml`: added the `Programming Language :: Python :: 3.13`
   classifier.

Why this is still worth doing even though the specific alleged regression
doesn't exist: `requires-python = ">=3.11"` has no upper bound, so `pip
install mcp-safeguard` on a real Python 3.13 interpreter already succeeds
today and always has — CI simply never tested that environment. That's the
actual version of "an untested version could ship broken" that applies here,
independent of tonight's specific false alarm.

## Verification before push

- `tests/` full suite: 252/252 on `python:3.11-slim`, `python:3.12-slim`,
  and `python:3.13-slim` (fresh `pip install -e ".[dev]"` each time, matching
  what CI's `test` job does).
- `ruff check src/` — not modified by this change; not re-run beyond what CI
  itself will run on push.
- `git fetch origin && git log origin/main` checked immediately before
  pushing (see commit log / CI run link in the final report for this
  session).

## Not done (out of scope for this task)

No PyPI release was cut. This is a CI-coverage change only.
