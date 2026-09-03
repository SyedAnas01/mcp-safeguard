# Benchmarking discipline

Every detection rule in this project (`SRC-001`..`SRC-034`, and the credential/prompt-injection
rules before them) was mined from a real, confirmed vulnerability found during this project's own
coordinated MCP-server disclosure campaign — see each rule's own doc comment in
`src/mcp_safeguard/scanner/source_scanner.py` for the specific finding it was derived from.

That means one thing has to be true before any recall number is published: **a target can be used
to measure recall, or it can be used to mine a rule — never both.** A rule that fires on the exact
bug it was written from proves the rule works as designed, not that it generalizes to a bug it has
never seen. A recall number computed against contamined targets is a self-consistency check, not
an out-of-sample measurement, and should never be described as the latter.

## The discipline

1. Before adding or widening any detection rule from a newly-found vulnerability, note the exact
   target (repo + commit) it came from.
2. That target — and any benchmark set it belongs to — is now contaminated for recall-measurement
   purposes, permanently. It can still be used as a regression fixture (proving the rule keeps
   catching a real bug across future refactors), just not as evidence of general recall.
3. A recall or precision number is only publishable when reported together with (a) which specific
   holdout set it was measured against, (b) confirmation that set's targets were not used to mine
   any currently-shipped rule, and (c) the rule-set version/commit it was measured against.
4. When a future rule-mining pass does need to draw from a target inside the currently-active
   holdout set (the corpus of real, confirmed MCP vulnerabilities is finite — this will happen),
   that target is retired from the holdout and replaced with a fresh, still-clean one before the
   next measurement, not silently dropped.

## Where the record lives

The authoritative list of which targets are currently clean (safe to hold out) versus contaminated
(already mined), plus every recall number that's actually been measured this way and against what,
is tracked as part of this project's private disclosure-campaign records — not duplicated here,
since it names third-party repos and vulnerability details from an active, partly-unresolved
coordinated-disclosure process that shouldn't be broadcast alongside its own detector's source. If
you're evaluating this tool and want the current honest recall number and methodology, ask the
maintainer directly.

## What this means for any recall number you see elsewhere (a changelog entry, a README line, a
pitch deck)

Treat any number that doesn't cite a specific, named holdout set and rule-set version the way
described above as unverified. In particular: recall figures computed against this project's own
"Round 30" disclosure batch are **not** a valid general recall estimate — several of the rules that
catch Round 30 findings were mined directly from those same findings — and should be read only as
confirmation those specific rules still fire on the bugs that motivated them, not as a claim about
how the tool performs on a vulnerability it hasn't seen before.
