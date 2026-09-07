# CI/Publish gating fix

## The gap

`.github/workflows/ci.yml` and `.github/workflows/publish.yml` had zero
dependency on each other. `ci.yml` triggers on `push`/`pull_request` to
`main`. `publish.yml` triggers independently on `release: types: [published]`
(plus manual `workflow_dispatch`) and went straight to building and
uploading to PyPI with no check of CI status at all.

## What actually happened (v0.9.1, 2026-09-07)

Verified directly from the GitHub Actions API on this repo:

- Commit `77db5565c2abc973e981064dc188e719a6035697` ("Release 0.9.1: credit
  Taig Mac Carthy, bump version") was pushed to `main`.
- CI run `34094211246` for that commit: `test (3.11)` **failed** ("Process
  completed with exit code 1"), `test (3.12)` was cancelled by fail-fast,
  `lint` and the security-scan job passed. Overall CI conclusion: failure.
  Finished 2026-09-07T07:10:55Z.
- The `v0.9.1` tag (annotated) peels to that exact same commit
  (`git rev-parse v0.9.1^{commit}` == `77db5565...`).
- The GitHub Release for `v0.9.1` was published, firing `publish.yml`'s
  `release: published` trigger. Run `34094239025` built and uploaded the
  package to PyPI successfully, finishing 2026-09-07T07:11:15Z — **20
  seconds after CI had already failed on the identical commit.**

Nothing in either workflow file referenced the other, so there was no
mechanism that could have stopped this.

## The fix

Added a `test` job directly inside `publish.yml` (matrix Python 3.11/3.12,
same install + `pytest tests/ -v --tb=short` steps as `ci.yml`'s `test`
job), and made the `publish` job depend on it with `needs: [test]`.
`docker-publish` already had `needs: [publish]`, so it is gated
transitively.

This was chosen over the alternatives considered:

- **`workflow_run` trigger on `ci.yml`'s completion** — rejected. In the
  actual incident, CI had already *finished* (with a failure) before the
  release was published; a `workflow_run` trigger only fires when the
  referenced workflow run starts or completes, not when a release is later
  published against an already-finished commit. Wiring `publish.yml` to
  fire only on a fresh CI *run* would mean a release published any time
  after CI last ran (the normal case) would never trigger publish at all —
  trading the "never blocks" bug for an "always blocks" bug, which is worse.
- **Branch protection / rulesets requiring CI to pass** — checked directly
  against the live repo: `main` has no branch protection
  (`GET .../branches/main/protection` → 404 "Branch not protected") and no
  rulesets (`GET .../rulesets` → `[]`). Moot regardless, since branch
  protection and rulesets gate branch pushes and PR merges, not release
  publication on a commit already sitting on the branch — they would not
  have stopped this even if configured.
- **Self-contained prerequisite test job (chosen)** — runs the actual test
  suite against the actual commit being released, inside the same workflow
  run that does the publishing. No cross-workflow timing to get right, no
  commit-SHA matching, no dependency on the GitHub Checks API having data
  for the right job names. GitHub Actions' default `if: success()` on a job
  with `needs:` means if any matrix leg of `test` fails or is cancelled,
  `publish` (and therefore `docker-publish`) is skipped outright.

## Why this would have blocked v0.9.1 specifically

`publish.yml`'s new `test` job runs `pytest tests/ -v --tb=short` against
the exact commit the release points to — the identical command that failed
in `ci.yml` on `77db5565...`. Since it's the same code and same test suite,
it fails the same way. `publish` has `needs: [test]`, so with `test`
concluding `failure` (one matrix leg failing is enough — GitHub's default
fail-fast also cancels the other leg, as it did in the real run), `publish`
would be skipped and never reach the PyPI upload step. `docker-publish`
would be skipped transitively.

## Validation performed

- Confirmed via `gh api` against the live repo that the CI failure and the
  PyPI publish really did happen on the identical commit, 20 seconds apart
  (see above) — this is not a hypothetical.
- Confirmed branch protection/rulesets are absent, so option (c) doesn't
  apply.
- Parsed the new `publish.yml` with `yaml.safe_load` — valid YAML.
- Ran `actionlint` (installed via Homebrew) against both `ci.yml` and
  `publish.yml` — zero findings.
- Could not fully dry-run the `release: published` trigger locally (that
  requires actually cutting a GitHub release), but traced the job-dependency
  logic by hand against GitHub Actions' documented `needs:`/`if: success()`
  semantics, which are unconditional and don't depend on external state.

## Confidence

High that this closes the specific gap that caused the v0.9.1 incident: a
failing `test` job now structurally prevents `publish` from running,
verified against the real commit and real CI failure, not a hypothetical
one. The one thing not verified end-to-end is a live release run against
the new workflow (no new release was cut as part of this fix), so the
untested edge is GitHub Actions' exact scheduling behavior on a
`workflow_dispatch` vs `release` triggered run with a matrix prerequisite —
low risk, since this is a standard, widely-used pattern and `needs:`
gating has no special-casing per trigger type.
