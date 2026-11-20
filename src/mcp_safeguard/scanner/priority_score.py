"""S0: cheap pre-audit priority scorer.

This is the stage that runs BEFORE `threat_model.py`'s per-entrypoint
authority analysis (which is itself already cheap, but still walks every
recovered entrypoint's own function body with `ast`/tree-sitter). At registry
scale -- potentially thousands of cloned repos -- even that is too much to run
on everything. `score_repo()` answers one narrower, much cheaper question
first: *is this repo worth spending a deep audit on at all?*

No LLM calls, no network access, no semgrep invocation. Three independent,
transparently-reported sub-scores (never collapsed into one opaque number --
see `PriorityScore`) are combined into a single `tier` recommendation:

1. **Attack surface** (`AttackSurfaceScore`): reuses `entrypoints.py`'s
   `recover_entrypoints()` (Python) and `entrypoints_js.py`'s
   `recover_js_entrypoints()` (JS/TS, optional -- same `ImportError`-only
   tolerance `taint_scanner.py` and `threat_model.py` already use) to count
   real MCP tool handlers, then a plain grep/regex pass -- reusing
   `lexical.py`'s `classify_file()`/`classify_file_content()` to skip
   test/vendored/example/minified/generated files, and
   `strip_comments_and_docstrings()` so a comment or docstring mentioning
   "subprocess" can't inflate the count -- for five dangerous-sink
   categories: process execution, filesystem access, outbound network
   calls, database queries, and credential-shaped variable/env-var names.
   Deliberately MULTIPLICATIVE, not additive: a repo with many handlers but
   zero dangerous-sink categories anywhere scores near zero, because it is
   genuinely low-value to deep-audit regardless of how many tools it
   exposes (this is the explicit design requirement, not an accident of the
   formula).
2. **Popularity / blast radius** (`PopularityScore`): an optional
   `repo_metadata` dict (`stars`, `is_official_org`, `weekly_downloads`).
   Any provided signal is log-scaled (or, for `is_official_org`, a flat
   value) onto 0-100, and the score is the MAX of whatever signals were
   given -- a single strong indicator of wide reach (huge star count, huge
   download volume, or an official org) is enough to call a repo
   high-blast-radius; there's no reason a repo with a quiet download count
   but backed by a major vendor should be scored down by averaging.
   Genuinely unknown (no metadata given) is a distinct, neutral 50.0 --
   this stage never fails or guesses when the caller has no data.
3. **Novelty / freshness** (`NoveltyScore`): an optional
   `last_scanned_commit` compared against the repo's actual current HEAD
   commit (`git rev-parse HEAD`, no fallback content hash here -- unlike
   `threat_model.py`'s cache key, this score's whole point is to answer
   "has this exact commit already been looked at", so a repo this module
   can't even resolve a commit for is treated the same as "never scanned":
   conservatively HIGH, not silently skipped). Unchanged since the last
   scan scores near-zero, which is what makes diff-triggered continuous
   scanning possible: re-running this scorer nightly across a whole
   registry costs almost nothing extra for repos nothing happened to.

Combining: attack-surface and popularity are weighted (0.7 / 0.3) into a
base score, then novelty acts as a MULTIPLIER on that base (not a fourth
additive term) -- an unchanged repo's base score is scaled down to under
10% of itself, which is what actually makes "already covered, don't bother"
work as a recommendation rather than just a footnote next to a still-high
number. The three sub-scores are always reported individually on
`PriorityScore`, and `combined_score`/`tier` are derived, inspectable
fields -- never the only output.
"""

from __future__ import annotations

import math
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .entrypoints import _is_skip_dir_part, recover_entrypoints
from .lexical import FileRole, classify_file, classify_file_content, strip_comments_and_docstrings

_SOURCE_SUFFIXES = (".py", ".js", ".jsx", ".ts", ".tsx")

# The five dangerous-sink categories the task spec names, each ONE compiled
# alternation of sub-patterns (checked against comment/docstring-STRIPPED
# text -- see `strip_comments_and_docstrings` -- so a comment or docstring
# that merely mentions "subprocess" can't inflate a count; combined into a
# single pattern per category, rather than a tuple of separately-`findall`'d
# patterns, purely as a speed optimization -- one `findall` per file per
# category instead of one per file per sub-pattern measurably matters at
# thousands-of-files scale, see `_MAX_SINK_SCAN_FILES` below for the rest of
# that story). Deliberately grep-level, not AST-based: this stage's entire
# purpose is to be cheap enough to run before deciding whether a real
# (AST/taint) audit is warranted at all, so false positives here are an
# accepted cost -- a category is a LEAD toward "this repo has this kind of
# surface", not a finding. The `database_query` sub-patterns are
# deliberately NOT just bare `.find(`/`.findOne(`/`.aggregate(` (those are
# also plain Array/Figma-scene-graph/etc. methods in any JS/TS codebase --
# confirmed as a real false positive against `grab/cursor-talk-to-figma-mcp`
# during this module's own validation pass, see bench/S0_RANKING_STATUS.md)
# -- they require a DB-shaped receiver name first.
_SINK_PATTERNS: dict[str, re.Pattern[str]] = {
    "process_exec": re.compile(
        r"\bsubprocess\.(?:run|call|Popen|check_output|check_call)\s*\("
        r"|\bos\.(?:system|popen)\s*\("
        r"|\bos\.exec[lv]p?e?\s*\("
        r"|\bshell\s*=\s*True\b"
        r"|\bchild_process\.(?:exec|execSync|spawn|spawnSync|execFile|execFileSync|fork)\s*\("
        r"|\bRuntime\.getRuntime\(\)\.exec\s*\("
        r"|\bnew\s+ProcessBuilder\s*\("
    ),
    "filesystem_access": re.compile(
        r"""\bopen\s*\([^)]*["'](?:w|wb|a|ab|x|xb|r\+|rb\+)["']"""
        r"""|\bopen\s*\(\s*[^,)]+[,)]"""
        r"|\.(?:write_text|write_bytes|read_text|read_bytes)\s*\("
        r"|\bos\.(?:remove|unlink|rmdir|makedirs|mkdir)\s*\("
        r"|\bshutil\.(?:rmtree|move|copy\w*)\s*\("
        r"|\bfs(?:Promises)?\.(?:writeFile|writeFileSync|readFile|readFileSync|"
        r"appendFile|appendFileSync|unlink|unlinkSync|mkdir|mkdirSync|rm|rmSync)\s*\("
        r"|\bcreate(?:Read|Write)Stream\s*\("
    ),
    "network_outbound": re.compile(
        r"\brequests\.(?:get|post|put|delete|patch|request)\s*\("
        r"|\bhttpx\.(?:get|post|put|delete|patch|AsyncClient|Client)\s*\("
        r"|\burllib\.request\.urlopen\s*\("
        r"|\baiohttp\.ClientSession\s*\("
        r"|\bfetch\s*\("
        r"|\baxios(?:\.(?:get|post|put|delete|patch))?\s*\("
        r"|\bhttps?\.request\s*\("
        r"|\bnet\.connect\s*\("
        r"|\bsocket\.(?:socket|create_connection)\s*\("
    ),
    "database_query": re.compile(
        r"\bcursor\.execute\s*\("
        r"""|\.execute\s*\(\s*["'`]?\s*(?:SELECT|INSERT|UPDATE|DELETE)\b"""
        r"|\b(?:session|db|pool|dbClient)\.query\s*\("
        r"|\b(?:collection|table|Model|model)\.(?:find|findOne|findMany|aggregate|"
        r"insertOne|insertMany|updateOne|updateMany|deleteOne|deleteMany)\s*\("
        r"|\b(?:psycopg2|pymysql|sqlite3)\.connect\s*\("
        r"|\bmysql\.createConnection\s*\("
        r"|\bmongoose\.connect\s*\("
        r"|\bnew\s+(?:\w+\.)?Pool\s*\("
    ),
    "credential_handling": re.compile(
        r"""\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret[_-]?key|client[_-]?secret|"""
        r"""private[_-]?key|bearer[_-]?token|password|passwd|service[_-]?account)\s*[:=]"""
        r"""|\bos\.environ(?:\.get)?\s*\(\s*["'][A-Z_]*(?:KEY|TOKEN|SECRET|PASSWORD)[A-Z_]*["']"""
        r"|\bprocess\.env\.[A-Z_]*(?:KEY|TOKEN|SECRET|PASSWORD)[A-Z_]*\b",
        re.IGNORECASE,
    ),
}

# Safety valve for a genuinely huge multi-package monorepo (validated
# against `archestra-ai/archestra`, 2859 production files, where this
# scan's own pre-optimization cost alone was ~10s -- see
# bench/S0_RANKING_STATUS.md's honest accounting of where that repo's total
# time actually goes). Beyond this many candidate files, the dangerous-sink
# grep pass stops after scanning the first `_MAX_SINK_SCAN_FILES` (rglob's
# own deterministic traversal order, not random) rather than every file --
# reported transparently via `AttackSurfaceScore.files_scanned` vs. the true
# candidate count, never silently. Handler recovery itself
# (`recover_entrypoints`/`recover_js_entrypoints`) is NOT capped -- that is
# reused, existing infrastructure this module was told to reuse verbatim,
# not something this module's own cheapness budget governs.
_MAX_SINK_SCAN_FILES = 1500

# Once every category has been seen present in at least this many scanned
# files, `_scan_dangerous_sinks` stops early (see its own docstring) -- a
# small sample floor so "all 5 categories present" isn't declared off a
# single unrepresentative file.
_MIN_FILES_BEFORE_EARLY_EXIT = 20

# Handler-count saturation point for the log-scaled attack-surface factor --
# a repo with this many (or more) recovered MCP entrypoints gets the full
# 1.0 handler factor. Deliberately log-scaled, not linear: a single-
# dispatcher SDK shape (one recovered function serving every tool call --
# see entrypoints.py's own "low_level_dispatcher") should not be scored as
# if it had almost no attack surface just because entrypoint RECOVERY
# resolved to one function.
_HANDLER_SATURATION = 20

# Popularity sub-signal saturation points (log-scaled onto 0-100).
_STAR_SATURATION = 5000
_DOWNLOAD_SATURATION = 100_000

# Tier thresholds on the final 0-100 combined_score. Calibrated against this
# module's own real-repo validation pass (see bench/S0_RANKING_STATUS.md) --
# not arbitrary round numbers picked in isolation.
_TIER_SKIP_MAX = 12.0
_TIER_CHEAP_TAINT_MAX = 40.0


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------


@dataclass
class AttackSurfaceScore:
    """0-100. `handler_count` and `dangerous_sink_hits` are always reported
    verbatim alongside the derived `score`, so a caller can see exactly why
    a repo scored the way it did rather than trusting one number."""

    score: float
    handler_count: int
    dangerous_sink_categories: list[str]
    dangerous_sink_hits: dict[str, int]
    files_scanned: int
    files_skipped_non_production: int
    sink_scan_complete: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "handler_count": self.handler_count,
            "dangerous_sink_categories": self.dangerous_sink_categories,
            "dangerous_sink_hits": self.dangerous_sink_hits,
            "files_scanned": self.files_scanned,
            "files_skipped_non_production": self.files_skipped_non_production,
            "sink_scan_complete": self.sink_scan_complete,
        }


@dataclass
class PopularityScore:
    """0-100. `basis` is `"unknown"` when no metadata was supplied at all
    (this stage never fails or guesses without data) or `"metadata"` when
    at least one of `stars`/`is_official_org`/`weekly_downloads` was given."""

    score: float
    basis: str  # "unknown" | "metadata"
    stars: int | None = None
    is_official_org: bool | None = None
    weekly_downloads: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "basis": self.basis,
            "stars": self.stars,
            "is_official_org": self.is_official_org,
            "weekly_downloads": self.weekly_downloads,
        }


@dataclass
class NoveltyScore:
    """0-100. `basis` explains which of the four cases produced `score`:
    `"never_scanned"` (no `last_scanned_commit` given), `"no_commit_info"`
    (this module couldn't resolve a current commit -- not a git checkout,
    or `git` itself failed), `"changed"` (current HEAD differs from
    `last_scanned_commit`), or `"unchanged"` (identical -- the only case
    that scores near zero)."""

    score: float
    current_commit: str | None
    last_scanned_commit: str | None
    changed: bool
    basis: str  # "never_scanned" | "no_commit_info" | "changed" | "unchanged"

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "current_commit": self.current_commit,
            "last_scanned_commit": self.last_scanned_commit,
            "changed": self.changed,
            "basis": self.basis,
        }


@dataclass
class PriorityScore:
    """The full S0 result for one repo. `combined_score`/`tier` are derived
    from the three sub-scores below -- always reported alongside them, never
    in place of them."""

    repo_path: str
    attack_surface: AttackSurfaceScore
    popularity: PopularityScore
    novelty: NoveltyScore
    combined_score: float
    tier: str  # "skip" | "cheap_taint_pass" | "deep_audit_candidate"

    def to_dict(self) -> dict[str, Any]:
        return {
            "repo_path": self.repo_path,
            "attack_surface": self.attack_surface.to_dict(),
            "popularity": self.popularity.to_dict(),
            "novelty": self.novelty.to_dict(),
            "combined_score": self.combined_score,
            "tier": self.tier,
        }


# --------------------------------------------------------------------------
# Attack surface: handler recovery (reused verbatim) + dangerous-sink grep
# --------------------------------------------------------------------------


def _recover_js_entrypoints_safe(root: Path) -> list:
    """[] if the `static-taint` extra (tree-sitter) isn't installed -- the
    same ImportError-only tolerance `taint_scanner.py` and `threat_model.py`
    already use, so a genuine bug in entrypoints_js.py still surfaces."""
    try:
        from . import entrypoints_js as ejs
    except ImportError:
        return []
    return ejs.recover_js_entrypoints(root)


def _iter_candidate_source_files(root: Path):
    for p in root.rglob("*"):
        if not p.is_file() or p.suffix not in _SOURCE_SUFFIXES:
            continue
        try:
            rel_parts = p.relative_to(root).parts[:-1]
        except ValueError:
            rel_parts = p.parts[:-1]
        if any(_is_skip_dir_part(part) for part in rel_parts):
            continue
        yield p


def _scan_dangerous_sinks(root: Path) -> tuple[dict[str, int], int, int, bool]:
    """Grep (post comment/docstring-stripping) production source files for
    the five dangerous-sink categories. Returns (category -> hit count,
    files_scanned, files_skipped_non_production, scan_complete).

    Two ways this can stop before covering every candidate file, both
    reported via the returned `scan_complete=False`, never silently:

    1. The hard `_MAX_SINK_SCAN_FILES` ceiling, for a genuinely huge
       multi-package monorepo (validated against `archestra-ai/archestra`,
       thousands of production files).
    2. An early exit once all five categories have already been observed
       present in at least `_MIN_FILES_BEFORE_EARLY_EXIT` files -- scanning
       further files at that point can only grow `dangerous_sink_hits`
       counts, never change which categories are present, and category
       PRESENCE is all `score_repo`'s own scoring actually uses. When this
       triggers, `dangerous_sink_hits` are a LOWER BOUND, not an exact
       total -- real, but possibly an undercount.

    A repo where at least one category is never observed present always
    scans every candidate file (no early exit possible), which is correct:
    "no dangerous sinks anywhere" is exactly the claim this stage's own
    "silence, not a guess" discipline requires actually looking everywhere
    for, not stopping early on."""
    hits: dict[str, int] = dict.fromkeys(_SINK_PATTERNS, 0)
    files_scanned = 0
    files_skipped = 0
    scan_complete = True
    for p in _iter_candidate_source_files(root):
        if files_scanned >= _MAX_SINK_SCAN_FILES:
            scan_complete = False
            break
        if files_scanned >= _MIN_FILES_BEFORE_EARLY_EXIT and all(n > 0 for n in hits.values()):
            scan_complete = False
            break
        role = classify_file(p, root)
        if role is not FileRole.PRODUCTION:
            files_skipped += 1
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        role = classify_file_content(role, text)
        if role is not FileRole.PRODUCTION:
            files_skipped += 1
            continue
        stripped = strip_comments_and_docstrings(text, p.suffix)
        files_scanned += 1
        for category, pattern in _SINK_PATTERNS.items():
            hits[category] += len(pattern.findall(stripped))
    return hits, files_scanned, files_skipped, scan_complete


def _handler_factor(handler_count: int) -> float:
    if handler_count <= 0:
        return 0.0
    return min(1.0, math.log1p(handler_count) / math.log1p(_HANDLER_SATURATION))


def _compute_attack_surface_score(root: Path) -> AttackSurfaceScore:
    py_entrypoints = recover_entrypoints(root)
    js_entrypoints = _recover_js_entrypoints_safe(root)
    handler_count = len(py_entrypoints) + len(js_entrypoints)

    sink_hits, files_scanned, files_skipped, scan_complete = _scan_dangerous_sinks(root)
    categories_present = sorted(cat for cat, n in sink_hits.items() if n > 0)

    handler_factor = _handler_factor(handler_count)
    sink_factor = len(categories_present) / len(sink_hits) if sink_hits else 0.0
    score = round(100.0 * handler_factor * sink_factor, 1)

    return AttackSurfaceScore(
        score=score,
        handler_count=handler_count,
        dangerous_sink_categories=categories_present,
        dangerous_sink_hits=sink_hits,
        files_scanned=files_scanned,
        files_skipped_non_production=files_skipped,
        sink_scan_complete=scan_complete,
    )


# --------------------------------------------------------------------------
# Popularity / blast radius
# --------------------------------------------------------------------------


def _compute_popularity_score(repo_metadata: dict[str, Any] | None) -> PopularityScore:
    if not repo_metadata:
        return PopularityScore(score=50.0, basis="unknown")

    stars = repo_metadata.get("stars")
    is_official_org = repo_metadata.get("is_official_org")
    weekly_downloads = repo_metadata.get("weekly_downloads")

    components: list[float] = []
    if isinstance(stars, int | float) and stars >= 0:
        components.append(min(100.0, 100.0 * math.log1p(stars) / math.log1p(_STAR_SATURATION)))
    if isinstance(weekly_downloads, int | float) and weekly_downloads >= 0:
        components.append(min(100.0, 100.0 * math.log1p(weekly_downloads) / math.log1p(_DOWNLOAD_SATURATION)))
    if isinstance(is_official_org, bool):
        components.append(90.0 if is_official_org else 20.0)

    if not components:
        # Metadata dict was given but held none of the three recognized
        # fields (or held them with the wrong type) -- still "unknown", not
        # a guess.
        return PopularityScore(score=50.0, basis="unknown")

    return PopularityScore(
        score=round(max(components), 1),
        basis="metadata",
        stars=stars if isinstance(stars, int) else None,
        is_official_org=is_official_org if isinstance(is_official_org, bool) else None,
        weekly_downloads=weekly_downloads if isinstance(weekly_downloads, int) else None,
    )


# --------------------------------------------------------------------------
# Novelty / freshness
# --------------------------------------------------------------------------


def _current_head_commit(root: Path) -> str | None:
    """Real `git rev-parse HEAD` only -- unlike threat_model.py's cache key,
    there is deliberately no content-hash fallback here: this score answers
    "is the repo at the exact commit already scanned", and a repo this
    can't determine that for is handled explicitly as `no_commit_info`
    (treated as high-priority, same as never-scanned) rather than silently
    substituting a different notion of identity."""
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode == 0 and result.stdout.strip():
        return result.stdout.strip()
    return None


def _compute_novelty_score(root: Path, last_scanned_commit: str | None) -> NoveltyScore:
    current_commit = _current_head_commit(root)

    if last_scanned_commit is None:
        return NoveltyScore(
            score=100.0, current_commit=current_commit, last_scanned_commit=None,
            changed=True, basis="never_scanned",
        )
    if current_commit is None:
        return NoveltyScore(
            score=100.0, current_commit=None, last_scanned_commit=last_scanned_commit,
            changed=True, basis="no_commit_info",
        )
    if current_commit != last_scanned_commit:
        return NoveltyScore(
            score=100.0, current_commit=current_commit, last_scanned_commit=last_scanned_commit,
            changed=True, basis="changed",
        )
    return NoveltyScore(
        score=5.0, current_commit=current_commit, last_scanned_commit=last_scanned_commit,
        changed=False, basis="unchanged",
    )


# --------------------------------------------------------------------------
# Combination + public entry point
# --------------------------------------------------------------------------


def _combine(attack_surface_score: float, popularity_score: float, novelty_score: float) -> tuple[float, str]:
    base = 0.7 * attack_surface_score + 0.3 * popularity_score
    # Novelty is a MULTIPLIER, not a fourth additive term: an unchanged
    # repo's base score is scaled down to 9.75% of itself (0.05 + 0.95 *
    # 0.05), never fully zeroed (a big enough base score can still poke
    # through), but low enough that "already covered" reliably lands in
    # "skip" for anything short of an extreme base score.
    novelty_multiplier = 0.05 + 0.95 * (novelty_score / 100.0)
    combined = round(base * novelty_multiplier, 1)

    if combined < _TIER_SKIP_MAX:
        tier = "skip"
    elif combined < _TIER_CHEAP_TAINT_MAX:
        tier = "cheap_taint_pass"
    else:
        tier = "deep_audit_candidate"
    return combined, tier


def score_repo(
    repo_path: str | Path,
    repo_metadata: dict[str, Any] | None = None,
    *,
    last_scanned_commit: str | None = None,
) -> PriorityScore:
    """Cheaply score one repo's priority for a deep audit. No LLM calls, no
    network, no semgrep -- pure static analysis over files already on disk,
    intended to run across potentially thousands of repos to decide which
    ones get expensive attention next.

    `repo_metadata` (optional): `{"stars": int, "is_official_org": bool,
    "weekly_downloads": int}` -- any subset. Missing entirely -> popularity
    defaults to a neutral 50.0, never guessed.

    `last_scanned_commit` (optional): the commit this repo was last scored
    at. Omitted (or the repo's current HEAD differs from it) -> novelty
    scores high; identical -> novelty scores near zero, which is what makes
    diff-triggered re-scanning cheap at registry scale.
    """
    root = Path(repo_path).resolve()

    attack_surface = _compute_attack_surface_score(root)
    popularity = _compute_popularity_score(repo_metadata)
    novelty = _compute_novelty_score(root, last_scanned_commit)

    combined, tier = _combine(attack_surface.score, popularity.score, novelty.score)

    return PriorityScore(
        repo_path=str(root),
        attack_surface=attack_surface,
        popularity=popularity,
        novelty=novelty,
        combined_score=combined,
        tier=tier,
    )


if __name__ == "__main__":
    import json
    import sys

    result = score_repo(sys.argv[1] if len(sys.argv) > 1 else ".")
    print(json.dumps(result.to_dict(), indent=2))
