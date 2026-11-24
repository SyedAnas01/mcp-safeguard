"""S8: polling-based diff-triggered re-scan (`mcp-safeguard rescan`).

## Honest correction to the original design

The original S8 design called for "continuous diff-triggered re-audit via
registry/npm/PyPI release webhooks, re-hunting only changed handlers." That
exact mechanism is NOT buildable as designed: we do not own or control the
third-party MCP server repos being audited, so we cannot register inbound
webhooks on their releases -- webhooks require the repo owner to configure
them, pointing at an endpoint we control. Nobody is going to add
mcp-safeguard as a webhook target on their own repo.

What this module builds instead is the honest, real substitute: a
**polling-based** diff-triggered re-scan. `rescan()` is invoked (by hand, by
a cron job, by whatever calls this CLI -- see the "not continuous" limitation
below) against a list of previously-scanned targets. For each one it checks
whether the target has new commits since the last scan (a cheap
`git ls-remote`, then a real `git fetch` only when that check says something
changed), computes the REAL file-level diff between the old and new commit,
and only re-runs the expensive `hunt()` pipeline when a changed file actually
touches a previously-identified MCP handler file. This is polling, not a
push-based webhook -- it must be invoked to check anything, it does not
receive notifications. See `bench/S8_RESCAN_STATUS.md` for the full
correction and for why this is a real, honest gap worth naming rather than
silently calling this "continuous" or "webhook-triggered".

## Determining "does a changed file touch a known handler?"

The "actual entrypoint-recovery data" this cross-references against is
`threat_model.py`'s own `build_threat_model()` cache: `hunt()` already calls
`build_threat_model()` (which runs `entrypoints.py`'s `recover_entrypoints()`
and `entrypoints_js.py`'s `recover_js_entrypoints()`, Stage 1 of the
pipeline) and caches the result at the GLOBAL, user-owned
`~/.cache/mcp_safeguard/tmd/` directory (NEVER inside the scanned repo --
see `threat_model.py`'s own module docstring "Security" note on why an
in-target cache is a real cache-poisoning vulnerability), keyed by the
exact commit that was scanned. If a target was `hunt()`-ed before, that cache
holds the exact file paths of every function this project has ever recovered
as a real MCP tool/resource/prompt handler for that commit -- this module
reads it back (`_load_cached_handler_files`) rather than re-deriving it, so
"touches a known handler" means the same thing here as it means everywhere
else in this project.

If no such cache exists for the previously-recorded commit (the target was
cloned/scored but never actually `hunt()`-ed, or the cache was deleted), this
module does NOT guess: it falls back to a full re-hunt rather than silently
skipping a target it has no real handler data for. Same discipline for a
target whose old commit is no longer git-diffable (a non-git local directory,
or a shallow clone whose old commit object is somehow gone) -- no diff, no
skip, a full re-hunt.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .. import __version__ as _MCP_SAFEGUARD_VERSION
from . import threat_model as _threat_model_mod
from .ledger import DEFAULT_LEDGER_PATH
from .pipeline import hunt as _real_hunt
from .threat_model import (
    ThreatModelDocument,
    _cache_path,
    _repo_identity_key,
    _resolve_commit,
    _run_git,
)

# NOTE: the global TMD cache directory is read as `_threat_model_mod._DEFAULT_CACHE_DIR`
# (a module attribute lookup at call time), deliberately NOT imported as a bare name
# (`from .threat_model import _DEFAULT_CACHE_DIR`) -- a bare-name import copies the
# value once at import time, so a test (or any caller) monkeypatching
# `threat_model._DEFAULT_CACHE_DIR` to an isolated directory would silently miss this
# module's own lookup. `_cache_path()` itself (used by `_load_cached_handler_files`
# below) already does the right thing since it's DEFINED in threat_model.py and reads
# its own module globals -- this only matters for `_bootstrap_commit_from_tmd_cache`'s
# direct reference below.

# `fleet_scan.py` (S9, a sibling milestone branch not present in this
# checkout) already has a `clone_or_reuse`/`resolve_target` pair that does
# exactly this same "local dir wins outright, otherwise clone/reuse a git
# URL under a cache dir" job. Rather than importing a module this checkout
# doesn't have, or porting its whole file (its `TargetOutcome`/
# `FleetScanReport`/per-target-deadline machinery is S9's own concern, not
# this module's), this is the same minimal logic, standalone.
DEFAULT_CACHE_DIR = Path.home() / ".cache" / "mcp_safeguard" / "fleet_scan"
_CLONE_TIMEOUT_SECONDS = 180


def parse_targets_file(path: str | Path) -> list[str]:
    """One target (a local repo path or a git URL) per line. Blank lines
    and `#`-prefixed comments are skipped."""
    targets: list[str] = []
    for raw_line in Path(path).read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        targets.append(line)
    return targets


def _looks_like_git_url(target: str) -> bool:
    return (
        target.startswith("http://")
        or target.startswith("https://")
        or target.startswith("git@")
        or target.startswith("ssh://")
        or target.endswith(".git")
    )


def _safe_cache_dirname(url: str) -> str:
    """A deterministic, filesystem-safe cache directory name for a git URL
    -- `https://github.com/org/repo`, `.../repo.git`, and the
    `git@github.com:org/repo.git` SSH form all resolve to the SAME
    directory, so reusing an existing clone works regardless of which URL
    form a targets file happens to use for the same repo."""
    name = url.strip()
    if name.endswith(".git"):
        name = name[: -len(".git")]
    for prefix in ("https://", "http://", "ssh://", "git@"):
        if name.startswith(prefix):
            name = name[len(prefix):]
            break
    name = name.replace(":", "/").strip("/")
    return name.replace("/", "__") or "target"


def clone_or_reuse(url: str, cache_dir: Path) -> Path:
    """Clone `url` under `cache_dir`, or reuse an existing clone there
    without re-cloning. A destination that exists but isn't a real git
    checkout is a real error, never silently reused or overwritten."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    dest = cache_dir / _safe_cache_dirname(url)
    if dest.is_dir():
        if (dest / ".git").exists():
            return dest
        raise RuntimeError(f"cache path {dest} already exists but is not a git checkout -- refusing to reuse or overwrite it")
    result = subprocess.run(
        ["git", "clone", "--depth", "1", "--quiet", url, str(dest)],
        capture_output=True,
        text=True,
        timeout=_CLONE_TIMEOUT_SECONDS,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git clone failed for {url}: {result.stderr.strip()[:500] or 'no stderr output'}")
    return dest


def resolve_target(target: str, cache_dir: Path) -> Path:
    """A local directory wins outright; otherwise `target` must look like a
    git URL and is cloned/reused under `cache_dir`."""
    local = Path(target)
    if local.is_dir():
        return local.resolve()
    if _looks_like_git_url(target):
        return clone_or_reuse(target, cache_dir)
    raise RuntimeError(f"target is neither an existing local directory nor a recognizable git URL: {target!r}")


# Where the per-target "last scanned at this commit" record lives when the
# caller doesn't pass `state_path` explicitly. A small companion JSON file
# (not a ledger extension -- see module... the ledger is a per-FINDING
# append-only log; "what commit was this whole target last examined at" is a
# per-TARGET fact with a different shape and a different update discipline
# (this file is read-then-overwritten per target, the ledger never is), so
# it does not belong inside ledger.py's append-only file.
DEFAULT_STATE_PATH = Path("bench/rescan_state.json")

_GIT_NETWORK_TIMEOUT_SECONDS = 30


class RescanError(Exception):
    """Raised only for a caller/setup mistake (e.g. an unreadable state
    file) -- never for one target's own git/hunt failure, which is always
    recorded on that target's own `RescanOutcome` instead."""


# --------------------------------------------------------------------------
# State file: {target: {resolved_path, last_scanned_commit, last_scanned_at,
# last_action, reason}} -- read-modify-write as a whole, same as any small
# JSON settings file; never appended to line-by-line like the ledger.
# --------------------------------------------------------------------------


def load_state(state_path: str | Path = DEFAULT_STATE_PATH) -> dict[str, Any]:
    path = Path(state_path)
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RescanError(f"rescan state file {path} exists but is not valid JSON: {exc}") from exc


def save_state(state: dict[str, Any], state_path: str | Path = DEFAULT_STATE_PATH) -> None:
    path = Path(state_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------
# Git helpers -- all best-effort: a failure here is reported on the
# target's own outcome, never allowed to raise out of `rescan()`.
# --------------------------------------------------------------------------


def _is_git_checkout(root: Path) -> bool:
    return (root / ".git").exists()


def _remote_head(root: Path) -> str | None:
    """The origin remote's current default-branch HEAD commit, via a cheap
    `git ls-remote` -- no fetch, no local object transfer. `None` (not an
    exception) if there is no `origin` remote, the network is unreachable,
    or the command otherwise fails; a `None` here means "polling could not
    check the remote right now", handled by the caller as "fall back to
    comparing local state only", never as "nothing changed"."""
    try:
        result = _run_git(["ls-remote", "origin", "HEAD"], root, timeout=_GIT_NETWORK_TIMEOUT_SECONDS)
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0 or not result.stdout.strip():
        return None
    return result.stdout.split()[0]


def _fetch_and_checkout(root: Path, commit: str) -> str | None:
    """Fetch `commit` from origin and check it out (detached), updating the
    working tree to that commit's real content -- required before `hunt()`
    scans `root`, since `hunt()` reads whatever is on disk, not a git ref.
    Returns an error string on failure, `None` on success."""
    try:
        fetch = _run_git(["fetch", "--quiet", "origin", commit], root, timeout=180)
        if fetch.returncode != 0:
            # Some servers reject fetching a bare commit SHA directly if it
            # isn't advertised; a full default-branch fetch still brings it
            # in as long as it's reachable from a fetched ref.
            fetch = _run_git(["fetch", "--quiet", "origin"], root, timeout=180)
            if fetch.returncode != 0:
                return f"git fetch failed: {fetch.stderr.strip()[:500]}"
        checkout = _run_git(["checkout", "--quiet", "--detach", commit], root, timeout=60)
        if checkout.returncode != 0:
            return f"git checkout {commit} failed: {checkout.stderr.strip()[:500]}"
    except (OSError, subprocess.SubprocessError) as exc:
        return f"{type(exc).__name__}: {exc}"
    return None


def _diffable_name_only(root: Path, old_commit: str, new_commit: str) -> list[str] | None:
    """`git diff --name-only old..new`, or `None` if either commit isn't a
    real, locally-present git commit object in this checkout (a non-git
    target, or an old commit that is no longer available) -- `None` means
    "a real diff could not be computed", the caller's cue to fall back to a
    full re-hunt rather than treating an empty/failed diff as "no changes"."""
    if not _is_git_checkout(root):
        return None
    try:
        for commit in (old_commit, new_commit):
            check = _run_git(["cat-file", "-e", f"{commit}^{{commit}}"], root, timeout=15)
            if check.returncode != 0:
                return None
        diff = _run_git(["diff", "--name-only", old_commit, new_commit], root, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    if diff.returncode != 0:
        return None
    return [line for line in diff.stdout.splitlines() if line.strip()]


# --------------------------------------------------------------------------
# Cross-reference against the real entrypoint-recovery data (Stage 1's
# `entrypoints.py`/`entrypoints_js.py`, cached per-commit by
# `threat_model.build_threat_model()`).
# --------------------------------------------------------------------------


def _load_cached_handler_files(root: Path, commit: str) -> set[str] | None:
    """The set of absolute file paths `build_threat_model()` recovered as
    real MCP handler files, for `root` at `commit` -- read from its own
    on-disk cache, never re-derived. `None` (not `set()`) if no cache exists
    for that exact commit: a target that was cloned/scored but never
    actually `hunt()`-ed has no entrypoint data to cross-reference against
    at all, which is a different, more dangerous situation than "we checked
    and there were zero handlers" (`set()`) -- callers must tell the two
    apart, see module docstring."""
    cache_path = _cache_path(root, root.name, commit, None)
    if not cache_path.is_file():
        return None
    try:
        tmd = ThreatModelDocument.from_dict(json.loads(cache_path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, KeyError, TypeError):
        return None
    return {ep.file for ep in tmd.entrypoints}


def _touched_handlers(root: Path, changed_files: list[str], handler_files: set[str]) -> list[str]:
    touched = []
    for rel in changed_files:
        if str((root / rel).resolve()) in handler_files:
            touched.append(rel)
    return touched


# --------------------------------------------------------------------------
# Result shape
# --------------------------------------------------------------------------


@dataclass
class RescanOutcome:
    target: str
    resolved_path: str | None = None
    action: str = "failed"
    old_commit: str | None = None
    new_commit: str | None = None
    changed_files: list[str] = field(default_factory=list)
    touched_handlers: list[str] = field(default_factory=list)
    hunt_counts: dict[str, int] | None = None
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "resolved_path": self.resolved_path,
            "action": self.action,
            "old_commit": self.old_commit,
            "new_commit": self.new_commit,
            "changed_files": self.changed_files,
            "touched_handlers": self.touched_handlers,
            "hunt_counts": self.hunt_counts,
            "reason": self.reason,
        }


# `action` values, each set in exactly one place below:
#   "baseline_full_hunt"              -- never scanned before, no state and
#                                         no cached TMD to bootstrap from;
#                                         full hunt() to establish a baseline
#   "no_change"                        -- HEAD (remote or local) is
#                                         unchanged since the recorded commit
#   "rehunt_targeted"                  -- a changed file touches a
#                                         previously-identified handler
#   "skipped_no_handler_touch"         -- files changed, cached handler data
#                                         exists, none of them touch it
#   "rehunt_full_fallback_no_cache"    -- files changed but no cached
#                                         handler data exists for the old
#                                         commit -- honest fallback
#   "rehunt_full_fallback_no_diff"     -- files changed but a real
#                                         file-level diff could not be
#                                         computed -- honest fallback
#   "failed"                           -- resolve/fetch/checkout/hunt raised


def _process_one(
    target: str,
    cache_dir: Path,
    state: dict[str, Any],
    ledger_path: str | Path,
    hunt_fn: Callable[..., Any],
) -> RescanOutcome:
    outcome = RescanOutcome(target=target)
    try:
        root = resolve_target(target, cache_dir)
        outcome.resolved_path = str(root)

        prior = state.get(target)
        old_commit = prior.get("last_scanned_commit") if prior else None
        if old_commit is None:
            old_commit = _bootstrap_commit_from_tmd_cache(root)

        if old_commit is None:
            result = hunt_fn(root, ledger_path=ledger_path)
            outcome.action = "baseline_full_hunt"
            outcome.old_commit = None
            outcome.new_commit = result.commit
            outcome.hunt_counts = result.counts()
            outcome.reason = (
                "no prior rescan record and no cached entrypoint data for this target -- ran a full hunt() "
                "to establish the baseline commit for future rescans"
            )
            return outcome

        outcome.old_commit = old_commit
        is_git = _is_git_checkout(root)
        remote_head = _remote_head(root) if is_git else None
        new_commit_candidate = remote_head if remote_head is not None else _resolve_commit(root)

        if new_commit_candidate == old_commit:
            outcome.action = "no_change"
            outcome.new_commit = old_commit
            outcome.reason = (
                f"HEAD is unchanged since the last scan ({old_commit[:12]}) -- nothing to re-hunt"
                if is_git
                else f"content is unchanged since the last scan ({old_commit[:12]}) -- nothing to re-hunt"
            )
            return outcome

        fetch_error: str | None = None
        if is_git and remote_head is not None:
            fetch_error = _fetch_and_checkout(root, remote_head)

        new_commit = _resolve_commit(root)
        changed_files = _diffable_name_only(root, old_commit, new_commit) if fetch_error is None else None
        outcome.new_commit = new_commit
        if changed_files is not None:
            outcome.changed_files = changed_files

        if fetch_error is not None:
            result = hunt_fn(root, ledger_path=ledger_path)
            outcome.action = "rehunt_full_fallback_no_diff"
            outcome.new_commit = result.commit
            outcome.hunt_counts = result.counts()
            outcome.reason = f"could not update the checkout to re-diff it ({fetch_error}) -- fell back to a full re-hunt"
            return outcome

        if changed_files is None:
            result = hunt_fn(root, ledger_path=ledger_path)
            outcome.action = "rehunt_full_fallback_no_diff"
            outcome.hunt_counts = result.counts()
            outcome.reason = (
                f"content changed since {old_commit[:12]} but no real file-level diff could be computed "
                "(not a git checkout, or the previous commit is no longer available locally) -- fell back "
                "to a full re-hunt rather than silently skipping"
            )
            return outcome

        handler_files = _load_cached_handler_files(root, old_commit)
        if handler_files is None:
            result = hunt_fn(root, ledger_path=ledger_path)
            outcome.action = "rehunt_full_fallback_no_cache"
            outcome.hunt_counts = result.counts()
            outcome.reason = (
                f"{len(changed_files)} file(s) changed since {old_commit[:12]}, but no cached entrypoint-"
                f"recovery data exists for that commit (this target was never actually hunt()-ed before) "
                "-- fell back to a full re-hunt rather than risking a silent under-scan"
            )
            return outcome

        touched = _touched_handlers(root, changed_files, handler_files)
        outcome.touched_handlers = touched
        if touched:
            result = hunt_fn(root, ledger_path=ledger_path)
            outcome.action = "rehunt_targeted"
            outcome.hunt_counts = result.counts()
            shown = ", ".join(touched[:10]) + (", ..." if len(touched) > 10 else "")
            outcome.reason = f"{len(touched)} changed file(s) touch a previously-identified MCP handler file: {shown}"
        else:
            outcome.action = "skipped_no_handler_touch"
            shown = ", ".join(changed_files[:10]) + (", ..." if len(changed_files) > 10 else "")
            outcome.reason = (
                f"{len(changed_files)} file(s) changed, but none touch any of the {len(handler_files)} "
                f"previously-identified handler file(s) -- changed: {shown}"
            )
        return outcome
    except Exception as exc:  # noqa: BLE001 -- one bad target must never kill the batch
        outcome.action = "failed"
        outcome.reason = f"{type(exc).__name__}: {exc}"
        return outcome


def _bootstrap_commit_from_tmd_cache(root: Path) -> str | None:
    """No rescan state exists for this target yet -- if it was already
    `hunt()`-ed at some point (a TMD cache file exists in the GLOBAL
    `~/.cache/mcp_safeguard/tmd/` directory for this exact repo), treat
    that commit as the baseline instead of re-hunting a target this
    project has already real data for. Picks the most-recently-written
    cache file if more than one commit was ever cached. Returns `None`
    (never a guess) if no cache exists at all.

    Deliberately reads ONLY the global cache directory -- NEVER a path
    inside `root` itself. An earlier version of this function globbed
    `<repo>/.mcp_safeguard_cache/tmd/` (inside the target), which let a
    malicious target plant its own fabricated "last scanned at commit X"
    record for this function to trust; see `threat_model.py`'s module
    docstring "Security" note for the same class of bug in
    `build_threat_model()`'s own cache and why an in-target cache can
    never be trusted. A forged commit string read from here feeds into
    `_process_one`'s own "bogus old commit" handling, which already falls
    back to a full re-hunt rather than trusting it for anything beyond
    establishing a baseline (see module docstring) -- but this function no
    longer gives an attacker anywhere to plant one in the first place."""
    cache_dir = _threat_model_mod._DEFAULT_CACHE_DIR
    if not cache_dir.is_dir():
        return None
    prefix = f"{root.name}-{_repo_identity_key(root)}-{_MCP_SAFEGUARD_VERSION}-"
    candidates = sorted(
        (p for p in cache_dir.glob(f"{prefix}*.json")),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if not candidates:
        return None
    return candidates[0].stem[len(prefix):]


# --------------------------------------------------------------------------
# Public entry point
# --------------------------------------------------------------------------


def rescan(
    targets_file: str | Path,
    *,
    cache_dir: str | Path = DEFAULT_CACHE_DIR,
    state_path: str | Path = DEFAULT_STATE_PATH,
    ledger_path: str | Path = DEFAULT_LEDGER_PATH,
    hunt_fn: Callable[..., Any] = _real_hunt,
) -> list[RescanOutcome]:
    """Check every target in `targets_file` for new commits since its
    recorded last-scanned commit and, where a real change actually touches a
    previously-identified MCP handler file, re-run the real `hunt()`
    pipeline and write any new findings to `ledger_path`. See the module
    docstring for the honest webhooks-vs-polling substitution this
    implements, and `_process_one`'s `action` values for exactly what
    happened to each target. Never raises for one target's own failure --
    see `RescanOutcome.action == "failed"`."""
    targets = parse_targets_file(targets_file)
    cache_dir = Path(cache_dir)
    state = load_state(state_path)

    outcomes: list[RescanOutcome] = []
    for target in targets:
        outcome = _process_one(target, cache_dir, state, ledger_path, hunt_fn)
        outcomes.append(outcome)
        if outcome.action != "failed":
            state[target] = {
                "resolved_path": outcome.resolved_path,
                "last_scanned_commit": outcome.new_commit,
                "last_scanned_at": datetime.now(UTC).isoformat(),
                "last_action": outcome.action,
                "reason": outcome.reason,
            }

    save_state(state, state_path)
    return outcomes
