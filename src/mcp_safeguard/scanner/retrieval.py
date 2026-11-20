"""S7 (fleet design): mechanism-indexed exemplar retrieval over the evidence
ledger.

From `mcp-safeguard-agent-fleet-design-2026-09-05`: the S7 ledger is meant to
serve three roles at once -- "disclosure record, RAG exemplar bank, and
registry-receipt feed." `ledger.py` builds the append-only disclosure record
and its own read-side primitives (`read_entries`/`query_entries`/
`ledger_stats`), but its own module docstring is explicit that "actual
similarity retrieval (embeddings, a vector index, few-shot prompt assembly)
is explicitly NOT implemented" there. This module is that retrieval layer.

**Honest method, stated up front**: this is LEXICAL retrieval, not semantic
retrieval. There is no `ANTHROPIC_API_KEY`/embedding-API access assumed
available, and no embedding model is bundled in this project's own
dependency tree (checked `pyproject.toml`/`uv.lock` before writing this --
no `numpy`, no `sentence-transformers`, nothing embedding-shaped). So
"mechanism-indexed retrieval" here means: TF-IDF cosine similarity over the
tokenized text of each `ClaimCard`'s own fields (`target_sink`,
`tainted_source`, `caller_authority_assumed`, `precondition`,
`violated_claim`, plus the ledger entry's free-text `notes`), with a small
secondary bonus when the query and a candidate both mention the same coarse
mechanism-keyword bucket (SQL-guard-bypass / credential-forwarding / SSRF /
path-traversal / IDOR / command-injection -- see `_MECHANISM_KEYWORDS`
below). This works well when a query reuses vocabulary a real finding
already uses ("outermost AST node", "read-only", "credential forwarded") --
it will NOT recognize two mechanically-identical bugs described in
completely disjoint vocabulary the way a real embedding model would. See
`bench/S7_RETRIEVAL_STATUS.md` for real query results and an honest
human-judged relevance check, including cases where this weakness shows up.

**Trust tiering, not just retrieval**: `ClaimCard` itself carries no
explicit vulnerability-class field (checked `claim_card.py` before writing
this -- `target_sink`/`tainted_source`/`precondition`/`violated_claim` are
free text; the closest thing to a class tag, `SourceFinding.rule_id`
(`TAINT-CMDI`/`TAINT-SSRF`/...), lives in `pipeline.py`'s own scanner-side
data and is never copied onto the `ClaimCard` it builds). More importantly,
281 real ledger entries as of this module's own data-quality check split
13 confirmed / 2 refuted (the original, individually-vetted campaign
findings, plus two `execution-confirmed` findings from a later fleet-scan
run) against 266 `unconfirmed` (fleet-scan noise -- a hand spot-check found
most of these trace to known false-positive causes already documented in
their own `notes`, e.g. "is not a module-top-level function", "TAINT-IDOR:
sandbox stage skipped by design"). Treating all 281 as equally trustworthy
few-shot exemplars would poison the exemplar bank with noise dressed as
precedent. So `retrieve_exemplars()`'s default (`include_unconfirmed=False`)
searches ONLY `confirmed`/`refuted` entries -- both are real signal
(a refutation teaches what NOT to flag, per `ledger.py`'s own module
docstring) -- and `unconfirmed` entries are excluded unless a caller
explicitly opts in, in which case every returned exemplar still carries its
own `verdict` field so a consumer can see and discount low-trust hits
rather than being handed unlabeled noise.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path

from .claim_card import ClaimCard, ExemplarDict
from .ledger import DEFAULT_LEDGER_PATH, LedgerEntry, read_entries
from .verify import Verdict

# --------------------------------------------------------------------------
# Tokenization
# --------------------------------------------------------------------------

# A handful of English stopwords plus a few words so generic across every
# ClaimCard (regardless of mechanism) that they carry no discriminating
# signal here -- e.g. every single entry's `violated_claim` mentions "file"/
# "line"/"claims" as part of its own fixed phrasing convention. Deliberately
# short and hand-picked, not a general-purpose NLP stopword list -- this is
# the actual vocabulary this project's own ClaimCard text is built from.
_STOPWORDS = frozenset(
    {
        "a", "an", "and", "any", "are", "as", "at", "be", "been", "but", "by",
        "can", "did", "do", "does", "for", "from", "had", "has", "have", "if",
        "in", "into", "is", "it", "its", "no", "not", "of", "on", "or", "own",
        "per", "so", "than", "that", "the", "their", "then", "there", "this",
        "to", "was", "were", "which", "with", "would",
        "file", "line", "lines", "claims", "claim", "actual", "behavior",
        "code",
    }
)

# Matches a run of letters/digits/underscore of length >= 2 -- deliberately
# permissive about identifier shapes (keeps `pg_run_query`, `oauth2`, etc.
# as single raw tokens before the camelCase/snake_case split below breaks
# them down further).
_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]+")

# Splits a camelCase or snake_case identifier into its component words --
# e.g. "validateReadQuery" / "validate_read_query" both yield
# ["validate", "read", "query"] -- so a query written in plain English
# ("the read-only guard only checks the top-level statement") still shares
# vocabulary with a ClaimCard whose text quotes a real camelCase identifier.
_CAMEL_SPLIT_RE = re.compile(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])")


def _split_identifier(token: str) -> list[str]:
    # Split on "_" BEFORE lowercasing -- `_CAMEL_SPLIT_RE` needs the original
    # uppercase letters to find camelCase word boundaries; lowercasing first
    # (as this used to do) collapses e.g. "validateReadQuery" into one fused
    # lowercase token instead of ["validate", "read", "query"]. Each part is
    # lowered only AFTER the camel-split regex has already run on it.
    parts = [p for p in token.split("_") if p]
    out: list[str] = []
    for part in parts:
        sub = _CAMEL_SPLIT_RE.findall(part)
        out.extend(s.lower() for s in sub) if sub else out.append(part.lower())
    return out or [token.lower()]


def _tokenize(text: str) -> list[str]:
    """Lowercase, split on non-identifier characters, further split each
    identifier on camelCase/snake_case boundaries, drop stopwords and
    single-character tokens. Pure stdlib -- no NLP dependency."""
    tokens: list[str] = []
    for raw in _TOKEN_RE.findall(text):
        for sub in _split_identifier(raw):
            if len(sub) > 1 and sub not in _STOPWORDS:
                tokens.append(sub)
    return tokens


def _claim_text(card: ClaimCard, notes: str | None) -> str:
    """The mechanism-relevant text of one ClaimCard (+ its ledger notes,
    which often name the concrete false-positive cause for an `unconfirmed`
    entry -- real signal, not noise, when a caller opts into searching
    unconfirmed entries)."""
    parts = [
        card.target_sink,
        card.tainted_source,
        card.caller_authority_assumed,
        card.precondition,
        card.violated_claim,
    ]
    if notes:
        parts.append(notes)
    return " ".join(parts)


# --------------------------------------------------------------------------
# TF-IDF + cosine similarity (pure stdlib -- no numpy/sklearn dependency)
# --------------------------------------------------------------------------


def _tfidf_vectors(token_lists: list[list[str]]) -> list[dict[str, float]]:
    """Standard TF-IDF: term frequency (within-document, normalized by
    document length) times inverse document frequency (smoothed,
    `log((1+N)/(1+df)) + 1`, the same smoothing scikit-learn's own
    `TfidfVectorizer` uses by default) -- computed here from scratch in
    ~15 lines rather than adding a dependency for it. The IDF corpus is
    exactly the token lists passed in (i.e., whatever candidate pool the
    caller is actually searching, plus the query itself) -- see
    `retrieve_exemplars`'s own note on why that pool is verdict-filtered
    BEFORE this function ever runs."""
    n_docs = len(token_lists)
    doc_freq: Counter[str] = Counter()
    for tokens in token_lists:
        doc_freq.update(set(tokens))

    idf = {term: math.log((1 + n_docs) / (1 + df)) + 1.0 for term, df in doc_freq.items()}

    vectors: list[dict[str, float]] = []
    for tokens in token_lists:
        if not tokens:
            vectors.append({})
            continue
        term_freq = Counter(tokens)
        length = len(tokens)
        vectors.append({term: (count / length) * idf[term] for term, count in term_freq.items()})
    return vectors


def _cosine_similarity(a: dict[str, float], b: dict[str, float]) -> float:
    if not a or not b:
        return 0.0
    shared = a.keys() & b.keys()
    numerator = sum(a[t] * b[t] for t in shared)
    norm_a = math.sqrt(sum(v * v for v in a.values()))
    norm_b = math.sqrt(sum(v * v for v in b.values()))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return numerator / (norm_a * norm_b)


# --------------------------------------------------------------------------
# Coarse mechanism-keyword buckets -- a small, explicit tie-break signal,
# NOT a real taxonomy field (ClaimCard has none -- see module docstring).
# --------------------------------------------------------------------------

_MECHANISM_KEYWORDS: dict[str, frozenset[str]] = {
    "sql-guard-bypass": frozenset({"sql", "query", "ast", "statement", "stmt", "select", "explain", "outermost", "readonly"}),
    "credential-forwarding": frozenset({"credential", "credentials", "token", "secret", "apikey", "bearer", "auth", "oauth", "forward", "forwarded", "forwards"}),
    "ssrf": frozenset({"ssrf", "outbound", "host", "allowlist", "fetch", "url", "confused", "deputy"}),
    "path-traversal": frozenset({"path", "traversal", "directory", "resolve", "relative", "symlink"}),
    "idor": frozenset({"idor", "tenant", "authorization", "scope", "cross", "object", "bola"}),
    "command-injection": frozenset({"shell", "subprocess", "exec", "command", "cmdi", "injection"}),
}

# Bonus added to the TF-IDF cosine score for each mechanism bucket the query
# and a candidate both hit -- small and additive on purpose (see status doc):
# it should be able to break a near-tie in favor of the mechanically-similar
# candidate, never override what the token-overlap similarity already says.
_BUCKET_BONUS = 0.05


def _mechanism_buckets(tokens: set[str]) -> set[str]:
    return {name for name, keywords in _MECHANISM_KEYWORDS.items() if tokens & keywords}


# --------------------------------------------------------------------------
# Public result shapes
# --------------------------------------------------------------------------


@dataclass
class Exemplar:
    """One retrieved prior ledger entry, summarized for reuse as few-shot
    grounding for a future hunter/adversary prompt. Deliberately a flat
    summary (not the full nested `ClaimCard`/`LedgerEntry` objects) -- this
    is what gets attached to `ClaimCard.retrieved_exemplars` and written
    back into the ledger's own JSON, so it is kept small and JSON-plain
    rather than embedding a second full ClaimCard inside a ClaimCard."""

    verdict: Verdict
    score: float
    target_sink: str
    violated_claim: str
    precondition: str
    commit: str
    evidence_ref: str | None
    notes: str | None

    def to_dict(self) -> ExemplarDict:
        return asdict(self)  # type: ignore[return-value]  -- asdict() is untyped; fields match ExemplarDict exactly


@dataclass
class ExemplarIndex:
    """A pre-tokenized candidate pool -- `read_entries(ledger_path)`, already
    verdict-filtered by `include_unconfirmed`, plus each entry's already
    -tokenized text (`_claim_text` + `_tokenize`). Building this is the
    expensive part of a `retrieve_exemplars()` call (disk read, JSON parse,
    tokenizing every entry's text); the actual TF-IDF/cosine scoring against
    one query is comparatively cheap and still runs fresh per call (see
    `retrieve_exemplars`'s own note on why IDF has to be recomputed per
    query). Build once per `hunt()` run with `build_exemplar_index()` and pass
    it to every `retrieve_exemplars(..., index=...)` call in that run, instead
    of each call re-reading and re-tokenizing the entire ledger from
    scratch -- this is purely a caller-side reuse: `retrieve_exemplars()`'s
    own no-`index` behavior (the default) is unchanged."""

    entries: list[LedgerEntry]
    doc_tokens: list[list[str]]
    include_unconfirmed: bool

    def add_entry(self, entry: LedgerEntry) -> None:
        """Incrementally extend this index with ONE newly-written ledger
        entry, instead of rebuilding the whole index from a re-read of
        `ledger_path` -- e.g. `hunt()`'s own per-finding loop appends each
        finding's ClaimCard to the SAME ledger this index was built from
        before moving to the next finding, so a later finding in the same
        run can retrieve an earlier one from this run as a prior (see
        `hunt()`'s own docstring); this keeps that behavior correct without
        re-reading/re-tokenizing the whole ledger on every finding. Respects
        `include_unconfirmed`: an `unconfirmed` entry is silently skipped
        when this index was built with `include_unconfirmed=False`, the same
        filter `build_exemplar_index()` itself applies."""
        if not self.include_unconfirmed and entry.verdict not in ("confirmed", "refuted"):
            return
        self.entries.append(entry)
        self.doc_tokens.append(_tokenize(_claim_text(entry.claim_card, entry.notes)))


def build_exemplar_index(
    include_unconfirmed: bool = False,
    *,
    ledger_path: str | Path = DEFAULT_LEDGER_PATH,
) -> ExemplarIndex:
    """Read and tokenize the candidate pool ONCE, for reuse across many
    `retrieve_exemplars(..., index=...)` calls in the same run (e.g. once per
    finding in `pipeline.py`'s `hunt()` loop) -- see `ExemplarIndex`'s own
    docstring for why this is worth caching."""
    entries: list[LedgerEntry] = read_entries(ledger_path)
    if not include_unconfirmed:
        entries = [e for e in entries if e.verdict in ("confirmed", "refuted")]
    doc_tokens = [_tokenize(_claim_text(e.claim_card, e.notes)) for e in entries]
    return ExemplarIndex(entries=entries, doc_tokens=doc_tokens, include_unconfirmed=include_unconfirmed)


@dataclass
class RetrievalResult:
    """The full result of one `retrieve_exemplars()` call, including the
    bookkeeping (`candidate_pool_size`, `include_unconfirmed`) a caller or a
    status report needs to judge how much to trust an empty or thin result
    (e.g. a query against a ledger that currently has zero `confirmed`/
    `refuted` entries for some mechanism should read as "no prior exists
    yet", not as a retrieval bug)."""

    query: str
    exemplars: list[Exemplar]
    candidate_pool_size: int
    include_unconfirmed: bool


def retrieve_exemplars(
    mechanism_tag_or_description: str,
    k: int = 3,
    include_unconfirmed: bool = False,
    *,
    ledger_path: str | Path = DEFAULT_LEDGER_PATH,
    exclude_target_sink: str | None = None,
    index: ExemplarIndex | None = None,
) -> RetrievalResult:
    """Return the top-`k` ledger entries most lexically similar to
    `mechanism_tag_or_description`, ranked by TF-IDF cosine similarity over
    each `ClaimCard`'s own text (+ ledger notes) with a small bonus for a
    shared coarse mechanism-keyword bucket. See this module's own docstring
    for the honest "lexical, not semantic" scope of what "similar" means
    here.

    `include_unconfirmed=False` (the default and the recommended mode) means
    the candidate pool is filtered to `confirmed`/`refuted` entries only --
    both `read_entries()` and the callers of `retrieve_exemplars()` never
    need to make this trust judgment case by case; it's the module-level
    default. Pass `include_unconfirmed=True` only when the caller genuinely
    wants to see fleet-scan-noise candidates too -- every returned
    `Exemplar` still carries its own `verdict`, so an `unconfirmed` hit is
    never silently indistinguishable from a `confirmed` one.

    `exclude_target_sink` lets a caller already holding a real ClaimCard
    (e.g. `pipeline.py`'s optional enrichment step, retrieving priors for a
    finding that may itself already be sitting in the ledger from an
    earlier run) exclude its own exact target_sink from its own results.

    `index`, if supplied, is a pre-built `ExemplarIndex` (see
    `build_exemplar_index()`) whose already-read/-tokenized candidate pool is
    reused instead of this call re-reading and re-tokenizing `ledger_path`
    from scratch -- the caller's own optimization for a run that calls this
    function many times (e.g. once per finding). `index.include_unconfirmed`
    must match this call's own `include_unconfirmed`; a caller needing both
    modes in one run builds one index per mode. Omitting `index` (the
    default) is byte-for-byte the same per-call behavior as before this
    parameter existed."""
    if index is not None:
        if index.include_unconfirmed != include_unconfirmed:
            raise ValueError(
                f"the supplied ExemplarIndex was built with include_unconfirmed="
                f"{index.include_unconfirmed}, which does not match this call's own "
                f"include_unconfirmed={include_unconfirmed} -- build a separate ExemplarIndex "
                "for each include_unconfirmed setting a caller actually uses."
            )
        entries, doc_tokens = index.entries, index.doc_tokens
    else:
        entries = read_entries(ledger_path)
        if not include_unconfirmed:
            entries = [e for e in entries if e.verdict in ("confirmed", "refuted")]
        doc_tokens = [_tokenize(_claim_text(e.claim_card, e.notes)) for e in entries]

    if exclude_target_sink is not None:
        paired = [(e, t) for e, t in zip(entries, doc_tokens, strict=True) if e.claim_card.target_sink != exclude_target_sink]
        entries = [e for e, _ in paired]
        doc_tokens = [t for _, t in paired]

    if not entries:
        return RetrievalResult(
            query=mechanism_tag_or_description,
            exemplars=[],
            candidate_pool_size=0,
            include_unconfirmed=include_unconfirmed,
        )

    query_tokens = _tokenize(mechanism_tag_or_description)

    # IDF is computed over exactly this candidate pool plus the query --
    # e.g. in the default confirmed/refuted-only mode, "credential" being
    # common across several confirmed entries correctly downweights it
    # there, even though it would be comparatively rarer against the full
    # 281-entry pool. Deliberate: a caller only ever ranks within the pool
    # it actually queried, so IDF should reflect that pool, not a different
    # one it isn't searching.
    vectors = _tfidf_vectors([*doc_tokens, query_tokens])
    doc_vectors, query_vector = vectors[:-1], vectors[-1]
    query_buckets = _mechanism_buckets(set(query_tokens))

    scored: list[tuple[float, LedgerEntry]] = []
    for entry, vector, tokens in zip(entries, doc_vectors, doc_tokens, strict=True):
        cosine = _cosine_similarity(query_vector, vector)
        shared_buckets = query_buckets & _mechanism_buckets(set(tokens))
        score = min(1.0, cosine + _BUCKET_BONUS * len(shared_buckets))
        scored.append((score, entry))

    scored.sort(key=lambda pair: pair[0], reverse=True)

    exemplars = [
        Exemplar(
            verdict=entry.verdict,
            score=round(score, 4),
            target_sink=entry.claim_card.target_sink,
            violated_claim=entry.claim_card.violated_claim,
            precondition=entry.claim_card.precondition,
            commit=entry.commit,
            evidence_ref=entry.evidence_ref,
            notes=entry.notes,
        )
        for score, entry in scored[:k]
    ]
    return RetrievalResult(
        query=mechanism_tag_or_description,
        exemplars=exemplars,
        candidate_pool_size=len(entries),
        include_unconfirmed=include_unconfirmed,
    )
