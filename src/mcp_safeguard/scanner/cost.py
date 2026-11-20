"""Cost/token/time instrumentation for this pipeline's real Anthropic-backed
stages (Stage 4 `verify.py`'s `AnthropicVerifier`, the 4 hunter-fleet LLM
angles' `hunter.py`'s `AnthropicHunter`, `adversary.py`'s `AnthropicAdversary`
gate, and `critic.py`'s cross-tier `AnthropicCriticVerifier` pass).

Real gap this closes: every token/cost figure that has ever appeared in this
project's own status docs was inferred AFTER THE FACT from an agent's own
usage report -- never tracked by the pipeline itself, because no
`ANTHROPIC_API_KEY` has ever existed in this environment to make any of
these `AnthropicX` classes' real API calls live (see each of their own
module docstrings). `CostTracker` is a small, dependency-free accumulator:
each real backend records one `CostEntry` per API call, its token counts
pulled straight from that call's own `response.usage` field (exactly what
the API billed, never estimated) plus a wall-clock measurement taken around
the call itself. A `ManualRecordX` playback backend makes no real call, so
it has no real `response.usage` to read -- recording is a true no-op for it
by default, but a caller with real, externally-supplied usage numbers (e.g.
a real agent-dispatch usage report) can attach a `"usage"` dict alongside a
recorded answer and have it recorded exactly as if it had come off a real
response -- see `record_usage_dict`.

Thread-safety note: `hunter.run_hunter_fleet` dispatches its 6 LLM-backed
angles concurrently against ONE shared `AnthropicHunter` instance (a small
`ThreadPoolExecutor`, see that function's own docstring) -- if that instance
carries a `CostTracker`, multiple threads record into it at once. `record()`
is therefore lock-protected.
"""

from __future__ import annotations

import threading
from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class CostEntry:
    """One real (or supplied-as-real) API call's cost/time. `stage`
    identifies which pipeline stage made the call (`"taint_scan"`,
    `"verify"`, `"hunter:<angle>"`, `"adversary"`, `"critic"`); `label`
    identifies the specific target within that stage (a finding's own
    `finding_key`/`location`, a claim card's `target_sink`, a repo path --
    whatever that stage's own existing keying scheme already uses) so an
    entry can be traced back to what it billed for. Every token field
    defaults to `0`, never `None`, so summing a list of entries never has to
    special-case a missing field -- a call that genuinely reports no cached
    tokens looks the same as one whose SDK version doesn't support caching
    at all."""

    stage: str
    label: str
    model: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    cache_creation_input_tokens: int = 0
    cache_read_input_tokens: int = 0
    wall_seconds: float = 0.0

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens + self.cache_creation_input_tokens + self.cache_read_input_tokens


_ZERO_BUCKET = {
    "calls": 0,
    "input_tokens": 0,
    "output_tokens": 0,
    "cache_creation_input_tokens": 0,
    "cache_read_input_tokens": 0,
    "wall_seconds": 0.0,
}


class CostTracker:
    """Accumulates `CostEntry` records for one `hunt()`/`hunt_fleet()` run
    (or any other caller wanting one shared cost ledger across several
    backend calls). Never raises on a malformed/missing usage value -- a
    real response whose usage shape this tracker doesn't recognize is
    recorded with whatever fields it DOES have (the rest defaulting to `0`)
    rather than losing the entry or crashing the run over instrumentation
    that is, by design, never load-bearing for the pipeline's own verdicts."""

    def __init__(self) -> None:
        self._entries: list[CostEntry] = []
        self._lock = threading.Lock()

    def record(
        self,
        stage: str,
        label: str,
        *,
        model: str = "",
        input_tokens: int = 0,
        output_tokens: int = 0,
        cache_creation_input_tokens: int = 0,
        cache_read_input_tokens: int = 0,
        wall_seconds: float = 0.0,
    ) -> CostEntry:
        """Record one entry directly. Every `AnthropicX`/`ManualRecordX`
        convenience method below (`record_from_response`,
        `record_usage_dict`) ends up here -- this is the one real place an
        entry is actually appended, under the lock."""
        entry = CostEntry(
            stage=stage,
            label=label,
            model=model,
            input_tokens=int(input_tokens or 0),
            output_tokens=int(output_tokens or 0),
            cache_creation_input_tokens=int(cache_creation_input_tokens or 0),
            cache_read_input_tokens=int(cache_read_input_tokens or 0),
            wall_seconds=float(wall_seconds or 0.0),
        )
        with self._lock:
            self._entries.append(entry)
        return entry

    def record_from_response(self, stage: str, label: str, model: str, response: Any, wall_seconds: float) -> CostEntry:
        """Record one entry pulled from a REAL `anthropic` SDK
        `messages.create()` response's own `.usage` field -- the actual
        billed token counts, never an estimate. `getattr(..., 0) or 0`
        throughout: a usage field an older SDK/account doesn't populate
        (e.g. no prompt-caching support, so no
        `cache_read_input_tokens`) is recorded as `0`, never guessed at and
        never allowed to raise."""
        usage = getattr(response, "usage", None)
        return self.record(
            stage,
            label,
            model=model,
            input_tokens=getattr(usage, "input_tokens", 0) or 0,
            output_tokens=getattr(usage, "output_tokens", 0) or 0,
            cache_creation_input_tokens=getattr(usage, "cache_creation_input_tokens", 0) or 0,
            cache_read_input_tokens=getattr(usage, "cache_read_input_tokens", 0) or 0,
            wall_seconds=wall_seconds,
        )

    def record_usage_dict(
        self, stage: str, label: str, model: str, usage: dict[str, Any] | None, wall_seconds: float = 0.0
    ) -> CostEntry | None:
        """The `ManualRecordX` counterpart to `record_from_response`: a
        playback backend makes no real call, so there is no live
        `response.usage` to read. A caller with real, externally-supplied
        usage numbers (e.g. a real agent-dispatch usage report) can attach a
        `"usage"` dict to a recorded answer -- same key shape as the real
        Anthropic API's own usage object
        (`input_tokens`/`output_tokens`/`cache_creation_input_tokens`/
        `cache_read_input_tokens`) -- and have it recorded exactly as if it
        had come off a real response. Returns `None` (a true no-op --
        nothing recorded, nothing raised) when `usage` is `None`, which is
        the default/expected case for a plain recorded-answer replay with no
        supplied cost data attached."""
        if usage is None:
            return None
        return self.record(
            stage,
            label,
            model=model,
            input_tokens=usage.get("input_tokens", 0),
            output_tokens=usage.get("output_tokens", 0),
            cache_creation_input_tokens=usage.get("cache_creation_input_tokens", 0),
            cache_read_input_tokens=usage.get("cache_read_input_tokens", 0),
            wall_seconds=wall_seconds,
        )

    @property
    def entries(self) -> list[CostEntry]:
        """A snapshot copy -- never the live internal list -- so a caller
        iterating this while another thread is still recording never sees a
        mutation mid-iteration."""
        with self._lock:
            return list(self._entries)

    def totals(self) -> dict[str, Any]:
        entries = self.entries
        out = dict(_ZERO_BUCKET)
        out["calls"] = len(entries)
        for e in entries:
            out["input_tokens"] += e.input_tokens
            out["output_tokens"] += e.output_tokens
            out["cache_creation_input_tokens"] += e.cache_creation_input_tokens
            out["cache_read_input_tokens"] += e.cache_read_input_tokens
            out["wall_seconds"] += e.wall_seconds
        return out

    def by_stage(self) -> dict[str, dict[str, Any]]:
        """Per-stage totals, same shape as `totals()`, keyed by `stage`."""
        out: dict[str, dict[str, Any]] = {}
        for e in self.entries:
            bucket = out.setdefault(e.stage, dict(_ZERO_BUCKET))
            bucket["calls"] += 1
            bucket["input_tokens"] += e.input_tokens
            bucket["output_tokens"] += e.output_tokens
            bucket["cache_creation_input_tokens"] += e.cache_creation_input_tokens
            bucket["cache_read_input_tokens"] += e.cache_read_input_tokens
            bucket["wall_seconds"] += e.wall_seconds
        return out

    def to_dict(self) -> dict[str, Any]:
        """JSON-serializable aggregate report: overall `totals`, `by_stage`
        breakdown, and every individual `entries` record -- e.g. for
        `cli.py`'s `--format json` output or a caller wanting the raw
        per-call detail, not just the rollup."""
        return {
            "totals": self.totals(),
            "by_stage": self.by_stage(),
            "entries": [asdict(e) for e in self.entries],
        }

    def report(self) -> str:
        """Human-readable multi-line summary for CLI text output."""
        totals = self.totals()
        if totals["calls"] == 0:
            return "cost: no instrumented API calls recorded for this run"
        lines = [
            f"cost: {totals['calls']} instrumented call(s), "
            f"{totals['input_tokens']} input + {totals['output_tokens']} output token(s) "
            f"({totals['cache_read_input_tokens']} cache-read, {totals['cache_creation_input_tokens']} cache-write), "
            f"{totals['wall_seconds']:.2f}s wall time"
        ]
        for stage, bucket in sorted(self.by_stage().items()):
            lines.append(
                f"    {stage}: {bucket['calls']} call(s), "
                f"{bucket['input_tokens']} in / {bucket['output_tokens']} out token(s), "
                f"{bucket['wall_seconds']:.2f}s"
            )
        return "\n".join(lines)
