"""
mcp-safeguard CLI — standalone scanner for MCP server configs and tool definitions.

Usage:
    mcp-safeguard scan <config.json>
    mcp-safeguard scan <config.json> --severity HIGH
    mcp-safeguard scan <config.json> --fail-on CRITICAL
    mcp-safeguard scan <config.json> --output report.html
    mcp-safeguard scan <config.json> --format json
"""

from __future__ import annotations

import csv
import html
import io
import json
import sys
import textwrap
from pathlib import Path
from typing import Any

# ANSI colours
_RED = "\033[91m"
_YELLOW = "\033[93m"
_CYAN = "\033[96m"
_GREEN = "\033[92m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RESET = "\033[0m"

_SEVERITY_COLOR = {
    "CRITICAL": _RED,
    "HIGH": _RED,
    "MEDIUM": _YELLOW,
    "LOW": _CYAN,
    "INFO": _DIM,
}

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _color(text: str, code: str) -> str:
    if sys.stdout.isatty():
        return f"{code}{text}{_RESET}"
    return text


def _status(text: str, *, quiet: bool = False) -> None:
    """Print a progress/status line -- to stdout normally, but to stderr when
    a machine-readable format (json/sarif) owns stdout, so piping/redirecting
    stdout captures only the actual report."""
    print(text, file=sys.stderr if quiet else sys.stdout)


def _print_banner(*, quiet: bool = False) -> None:
    banner = textwrap.dedent("""\
        ┌─────────────────────────────────────────────────┐
        │  mcp-safeguard  —  MCP Security Scanner         │
        │  github.com/SyedAnas01/mcp-safeguard            │
        └─────────────────────────────────────────────────┘
    """)
    _status(_color(banner, _BOLD), quiet=quiet)


def _load_config(path: str) -> dict[str, Any]:
    """Load and parse a JSON config file."""
    p = Path(path)
    if not p.exists():
        print(f"Error: File not found: {path}", file=sys.stderr)
        sys.exit(1)
    try:
        return json.loads(p.read_text())
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in {path}: {e}", file=sys.stderr)
        sys.exit(1)


def _extract_tools(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract tool definitions from various config formats."""
    # Direct tools array
    if "tools" in config and isinstance(config["tools"], list):
        return config["tools"]
    # Claude Desktop / MCP client config format: {mcpServers: {name: {tools: [...]}}}
    if "mcpServers" in config:
        tools = []
        for server_name, server_cfg in config["mcpServers"].items():
            for tool in server_cfg.get("tools", []):
                tool["_server"] = server_name
                tools.append(tool)
        return tools
    # Flat list of tools
    if isinstance(config, list):
        return config
    return []


def _severity_value(sev: str) -> int:
    return _SEVERITY_ORDER.get(sev.upper(), 99)


def _load_baseline(path: str) -> set[tuple[str, str]]:
    """
    Load a baseline file (the same shape `--format json` writes) as a set of
    (rule_id, location) keys to suppress in this run -- lets a team adopt the
    scanner on an existing codebase by "accepting" today's findings once,
    then only failing CI on genuinely NEW ones going forward.
    """
    p = Path(path)
    if not p.exists():
        return set()
    try:
        data = json.loads(p.read_text())
    except json.JSONDecodeError:
        print(f"Warning: could not parse baseline file {path} as JSON — ignoring it.", file=sys.stderr)
        return set()
    if not isinstance(data, list):
        return set()
    return {
        (str(f.get("rule_id", "")), str(f.get("location", "")))
        for f in data
        if isinstance(f, dict)
    }


def _apply_baseline(findings: list[dict[str, Any]], baseline_keys: set[tuple[str, str]]) -> list[dict[str, Any]]:
    if not baseline_keys:
        return findings
    return [
        f for f in findings
        if (str(f.get("rule_id", "")), str(f.get("location", ""))) not in baseline_keys
    ]


def _print_finding(rule_id: str, severity: str, title: str, location: str,
                   evidence: str, remediation: str, cvss: float) -> None:
    sev = severity.upper()
    color = _SEVERITY_COLOR.get(sev, _RESET)
    prefix = _color(f"[{sev}]", color + _BOLD)
    rule = _color(rule_id, _BOLD)
    print(f"  {prefix:<20} {rule:<12} {title}")
    print(f"  {' ' * 20} Location:    {location}")
    if evidence:
        masked = evidence[:80] + "…" if len(evidence) > 80 else evidence
        print(f"  {' ' * 20} Evidence:    {_color(masked, _DIM)}")
    print(f"  {' ' * 20} CVSS:        {cvss}")
    print(f"  {' ' * 20} Fix:         {remediation}")
    print()


def _run_scan(config_path: str, min_severity: str = "INFO",
              fail_on: str | None = None, output: str | None = None,
              fmt: str = "text") -> int:
    """Run all scanners against a config file. Returns exit code."""
    from mcp_safeguard.scanner.credential_scanner import scan_for_credentials
    from mcp_safeguard.scanner.prompt_injection import scan_for_prompt_injection
    from mcp_safeguard.scanner.ssrf_scanner import scan_for_ssrf
    from mcp_safeguard.scanner.tool_analyzer import scan_for_tool_poisoning

    # Machine-readable formats must produce ONLY that format on stdout, so
    # `scan config.json --format json > out.json` (or --format sarif) is
    # actually valid JSON/SARIF -- the banner/status lines move to stderr.
    quiet = fmt in ("json", "sarif")
    _print_banner(quiet=quiet)
    _status(f"Scanning: {_color(config_path, _BOLD)}", quiet=quiet)
    _status("─" * 60, quiet=quiet)

    config = _load_config(config_path)
    tools = _extract_tools(config)

    if not tools and config.get("mcpServers"):
        print(
            "Warning: no tool definitions found in 'mcpServers' entries. "
            "Real Claude Desktop configs never embed tool definitions inline "
            "(only command/args/env) — tool-based checks were skipped.",
            file=sys.stderr,
        )

    all_findings: list[dict[str, Any]] = []

    # --- Prompt Injection ---
    if tools:
        pi_findings = scan_for_prompt_injection(tools)
        for f in pi_findings:
            all_findings.append({
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "title": f.title,
                "location": f.location,
                "evidence": getattr(f, "evidence", ""),
                "remediation": f.remediation,
                "cvss": f.cvss_score,
                "category": "prompt-injection",
            })

    # --- Credentials ---
    cred_findings = scan_for_credentials(config)
    for f in cred_findings:
        all_findings.append({
            "rule_id": f.rule_id,
            "severity": f.severity.value,
            "title": f.title,
            "location": f.location,
            "evidence": getattr(f, "evidence", ""),
            "remediation": f.remediation,
            "cvss": f.cvss_score,
            "category": "credentials",
        })

    # --- Tool Poisoning ---
    if tools:
        tp_findings = scan_for_tool_poisoning(tools)
        for f in tp_findings:
            all_findings.append({
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "title": f.title,
                "location": f.location,
                "evidence": getattr(f, "evidence", ""),
                "remediation": f.remediation,
                "cvss": f.cvss_score,
                "category": "tool-poisoning",
            })

    # --- SSRF Detection ---
    if tools:
        ssrf_findings = scan_for_ssrf(tools)
        for f in ssrf_findings:
            all_findings.append({
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "title": f.title,
                "location": f.location,
                "evidence": getattr(f, "evidence", ""),
                "remediation": f.remediation,
                "cvss": f.cvss_score,
                "category": "ssrf",
            })

    # Filter by min severity
    min_val = _severity_value(min_severity)
    filtered = [f for f in all_findings if _severity_value(f["severity"]) <= min_val]
    # Sort by severity then CVSS
    filtered.sort(key=lambda x: (_severity_value(x["severity"]), -x["cvss"]))

    if fmt == "json":
        print(json.dumps(filtered, indent=2))
        return _exit_code(filtered, fail_on)

    if fmt == "sarif":
        from mcp_safeguard.scanner.report_generator import generate_sarif_report

        print(generate_sarif_report(filtered))
        return _exit_code(filtered, fail_on)

    if not filtered:
        print(_color("  ✓ No findings above threshold.", _GREEN))
    else:
        for f in filtered:
            _print_finding(
                f["rule_id"], f["severity"], f["title"],
                f["location"], f["evidence"], f["remediation"], f["cvss"]
            )

    # Summary
    counts: dict[str, int] = {}
    for f in filtered:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    print("─" * 60)
    total = len(filtered)
    summary_parts = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in counts:
            color = _SEVERITY_COLOR[sev]
            summary_parts.append(_color(f"{counts[sev]} {sev}", color + _BOLD))
    summary = ", ".join(summary_parts) if summary_parts else _color("0 findings", _GREEN)
    print(f"{_color(str(total), _BOLD)} finding{'s' if total != 1 else ''}: {summary}")

    if output:
        _write_output(filtered, output, config_path)

    return _exit_code(filtered, fail_on)


def _exit_code(findings: list[dict], fail_on: str | None) -> int:
    if fail_on is None:
        return 0
    fail_val = _severity_value(fail_on)
    for f in findings:
        if _severity_value(f["severity"]) <= fail_val:
            return 1
    return 0


def _run_source_scan(root_path: str, min_severity: str = "INFO",
                      fail_on: str | None = None, output: str | None = None,
                      fmt: str = "text", baseline: str | None = None,
                      static_taint: bool = False, verify: bool = False,
                      include_low_confidence: bool = False) -> int:
    """Walk a source tree and run the code-level heuristic rules. Returns exit code."""
    from pathlib import Path as _Path

    from mcp_safeguard.scanner.source_scanner import scan_source_tree

    root = _Path(root_path)
    if not root.is_dir():
        print(f"Error: not a directory: {root_path}", file=sys.stderr)
        sys.exit(1)

    quiet = fmt in ("json", "sarif")
    _print_banner(quiet=quiet)
    _status(f"Source-scanning: {_color(root_path, _BOLD)}", quiet=quiet)
    _status("─" * 60, quiet=quiet)

    findings = scan_source_tree(root)
    all_findings = [
        {
            "rule_id": f.rule_id,
            "severity": f.severity.value,
            "title": f.title,
            "location": f.location,
            "evidence": f.evidence,
            "remediation": f.remediation,
            "cvss": f.cvss_score,
            "category": "source-audit",
            "tier": f.tier,
        }
        for f in findings
    ]

    # Tier "S" (static-taint): Python-only, additive -- MCP entrypoint
    # recovery + semgrep taint + AST path reconstruction (taint_scanner.py).
    # Opt-in via --static-taint since it shells out to the semgrep CLI and
    # can take noticeably longer on a large tree than the tier "L" rules
    # above, which are plain regex over already-read source text.
    if static_taint:
        _status("Running static-taint (tier S) scan -- requires semgrep on PATH...", quiet=quiet)
        from mcp_safeguard.scanner.taint_scanner import run_static_taint_scan

        taint_findings = run_static_taint_scan(root, include_low_confidence=include_low_confidence)

        # Stage 4 (--verify): upgrade/downgrade each tier "S" finding to tier
        # "V" (confirmed) / "R" (refuted) via grounded LLM verification, two
        # independent runs required to agree (verify_with_agreement) -- see
        # scanner/verify.py. The original tier "S" evidence (taint_path) is
        # never dropped, regardless of the verification outcome.
        verifier = None
        if verify and taint_findings:
            from mcp_safeguard.scanner.verify import AnthropicVerifier

            try:
                verifier = AnthropicVerifier()
            except RuntimeError as exc:
                print(f"Warning: --verify requested but unavailable ({exc}); tier-S findings left unverified.",
                      file=sys.stderr)
            else:
                _status(f"Running Stage-4 grounded verification on {len(taint_findings)} tier-S finding(s)...",
                        quiet=quiet)

        for f in taint_findings:
            entry = {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "title": f.title,
                "location": f.location,
                "evidence": f.evidence,
                "remediation": f.remediation,
                "cvss": f.cvss_score,
                "category": "static-taint",
                "tier": f.tier,
                "taint_path": f.taint_path,
                "confidence": f.confidence,
            }
            if verifier is not None:
                from mcp_safeguard.scanner.verify import verify_with_agreement

                agreement = verify_with_agreement(verifier, f, root)
                entry["tier"] = {"confirmed": "V", "refuted": "R"}.get(agreement.verdict, f.tier)
                entry["verification"] = {
                    "verdict": agreement.verdict,
                    "agreed": agreement.agreed,
                    "reasoning": agreement.run_a.reasoning,
                    "run_a_verdict": agreement.run_a.verdict,
                    "run_b_verdict": agreement.run_b.verdict,
                }
            all_findings.append(entry)

    if baseline:
        baseline_keys = _load_baseline(baseline)
        before = len(all_findings)
        all_findings = _apply_baseline(all_findings, baseline_keys)
        suppressed = before - len(all_findings)
        if suppressed:
            print(
                f"  {_color(str(suppressed), _DIM)} finding(s) suppressed by baseline "
                f"({baseline}); showing only new/changed findings.",
                file=sys.stderr,
            )

    min_val = _severity_value(min_severity)
    filtered = [f for f in all_findings if _severity_value(f["severity"]) <= min_val]
    filtered.sort(key=lambda x: (_severity_value(x["severity"]), -x["cvss"]))

    if fmt == "json":
        print(json.dumps(filtered, indent=2))
        return _exit_code(filtered, fail_on)

    if fmt == "sarif":
        from mcp_safeguard.scanner.report_generator import generate_sarif_report

        print(generate_sarif_report(filtered))
        return _exit_code(filtered, fail_on)

    if not filtered:
        print(_color("  ✓ No source-level findings above threshold.", _GREEN))
    else:
        for f in filtered:
            _print_finding(
                f["rule_id"], f["severity"], f["title"],
                f["location"], f["evidence"], f["remediation"], f["cvss"]
            )

    counts: dict[str, int] = {}
    for f in filtered:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    print("─" * 60)
    total = len(filtered)
    summary_parts = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in counts:
            color = _SEVERITY_COLOR[sev]
            summary_parts.append(_color(f"{counts[sev]} {sev}", color + _BOLD))
    summary = ", ".join(summary_parts) if summary_parts else _color("0 findings", _GREEN)
    print(f"{_color(str(total), _BOLD)} finding{'s' if total != 1 else ''}: {summary}")

    if output:
        _write_output(filtered, output, root_path)

    return _exit_code(filtered, fail_on)


def _run_score(repo_path: str, fmt: str = "text", *, stars: int | None = None,
               is_official_org: bool | None = None, weekly_downloads: int | None = None,
               last_scanned_commit: str | None = None) -> int:
    """S0: cheaply score one repo's priority for a deep audit. Returns exit
    code (always 0 -- this is a ranking signal, not a pass/fail gate)."""
    from mcp_safeguard.scanner.priority_score import score_repo

    root = Path(repo_path)
    if not root.is_dir():
        print(f"Error: not a directory: {repo_path}", file=sys.stderr)
        sys.exit(1)

    metadata: dict[str, Any] = {}
    if stars is not None:
        metadata["stars"] = stars
    if is_official_org is not None:
        metadata["is_official_org"] = is_official_org
    if weekly_downloads is not None:
        metadata["weekly_downloads"] = weekly_downloads

    result = score_repo(root, repo_metadata=metadata or None, last_scanned_commit=last_scanned_commit)

    if fmt == "json":
        print(json.dumps(result.to_dict(), indent=2))
        return 0

    a, p, n = result.attack_surface, result.popularity, result.novelty
    _print_banner()
    print(f"Priority score: {_color(repo_path, _BOLD)}")
    print("─" * 60)
    print(f"  Attack surface   {a.score:6.1f}   handlers={a.handler_count}  "
          f"sinks={','.join(a.dangerous_sink_categories) or 'none'}"
          f"{'  (partial scan)' if not a.sink_scan_complete else ''}")
    print(f"  Popularity       {p.score:6.1f}   basis={p.basis}")
    print(f"  Novelty          {n.score:6.1f}   basis={n.basis}")
    print("─" * 60)
    print(f"  {_color('Combined score', _BOLD)}   {result.combined_score:6.1f}")
    print(f"  {_color('Tier', _BOLD)}             {_color(result.tier, _BOLD)}")
    return 0


def _rows_to_csv(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return ""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue()


def _run_score_batch(dir_path: str, fmt: str = "json", output: str | None = None) -> int:
    """S0 batch mode: score every immediate subdirectory of `dir_path` (each
    one a cloned repo) and print/write a ranked table -- the input a future
    continuous-scanning loop would consume to decide what to audit next."""
    from mcp_safeguard.scanner.priority_score import score_repo

    root = Path(dir_path)
    if not root.is_dir():
        print(f"Error: not a directory: {dir_path}", file=sys.stderr)
        sys.exit(1)

    repo_dirs = sorted(p for p in root.iterdir() if p.is_dir() and not p.name.startswith("."))
    if not repo_dirs:
        print(f"Error: no repo subdirectories found under {dir_path}", file=sys.stderr)
        sys.exit(1)

    rows: list[dict[str, Any]] = []
    for repo_dir in repo_dirs:
        result = score_repo(repo_dir)
        rows.append({
            "repo_name": repo_dir.name,
            "repo_path": str(repo_dir),
            "combined_score": result.combined_score,
            "tier": result.tier,
            "attack_surface_score": result.attack_surface.score,
            "popularity_score": result.popularity.score,
            "novelty_score": result.novelty.score,
            "handler_count": result.attack_surface.handler_count,
            "dangerous_sink_categories": ";".join(result.attack_surface.dangerous_sink_categories),
        })

    rows.sort(key=lambda r: r["combined_score"], reverse=True)

    text = _rows_to_csv(rows) if fmt == "csv" else json.dumps(rows, indent=2)

    if output:
        Path(output).write_text(text)
        print(f"Ranked {len(rows)} repo(s) -> {output}", file=sys.stderr)
    else:
        print(text)
    return 0


def _run_hunt(
    repo_path: str,
    ledger_path: str,
    fmt: str = "text",
    *,
    include_low_confidence: bool = False,
    sandbox_timeout: int = 30,
    no_verify: bool = False,
    allow_unsafe_host_execution: bool = False,
) -> int:
    """S8: run the real, end-to-end hunt pipeline (scanner/pipeline.py)
    against one repo -- taint scan -> per-finding ClaimCard -> Stage 5
    sandbox execution for the sandbox-testable classes -> Stage 4 LLM
    verification if ANTHROPIC_API_KEY is set -> append every resulting
    ClaimCard to the ledger. Returns 0 even when every finding stays
    unconfirmed -- this is a scan/record pass, not a pass/fail CI gate."""
    from mcp_safeguard.scanner.pipeline import hunt

    root = Path(repo_path)
    if not root.is_dir():
        print(f"Error: not a directory: {repo_path}", file=sys.stderr)
        return 1

    result = hunt(
        root,
        ledger_path=ledger_path,
        include_low_confidence=include_low_confidence,
        sandbox_timeout_seconds=sandbox_timeout,
        run_llm_verification=not no_verify,
        allow_unsafe_host_execution=allow_unsafe_host_execution,
    )

    if fmt == "json":
        print(json.dumps({
            "repo_path": result.repo_path,
            "commit": result.commit,
            "findings_scanned": result.findings_scanned,
            "counts": result.counts(),
            "ledger_path": result.ledger_path,
            "outcomes": [
                {
                    "rule_id": o.finding.rule_id,
                    "location": o.finding.location,
                    "verdict": o.verdict,
                    "note": o.note,
                    "ledger_entry_appended": o.ledger_entry is not None,
                }
                for o in result.outcomes
            ],
            "cost": result.cost_tracker.to_dict() if result.cost_tracker is not None else None,
        }, indent=2))
        return 0

    _print_banner()
    print(f"Hunt: {_color(repo_path, _BOLD)} @ {result.commit}")
    print(f"  {result.findings_scanned} tier-\"S\" finding(s) scanned")
    print("─" * 60)
    for o in result.outcomes:
        color = {"confirmed": _GREEN, "refuted": _RED}.get(o.verdict, _DIM)
        print(f"  [{_color(o.verdict.upper(), color)}] {o.finding.rule_id} {o.finding.location}")
        print(f"      {o.note}")
    print("─" * 60)
    counts = result.counts()
    print(f"  confirmed={counts['confirmed']}  refuted={counts['refuted']}  unconfirmed={counts['unconfirmed']}")
    print(f"  ledger: {result.ledger_path}")
    if result.cost_tracker is not None:
        print(f"  {result.cost_tracker.report()}")
    return 0


def _run_hunt_fleet(
    repo_path: str,
    ledger_path: str,
    fmt: str = "text",
    *,
    include_low_confidence: bool = False,
    sandbox_timeout: int = 30,
    run_sandbox: bool = True,
    allow_unsafe_host_execution: bool = False,
) -> int:
    """S3: `mcp-safeguard hunt <repo> --mode fleet` -- dispatch all 7 hunter
    angles (scanner/hunter.py) instead of just the deterministic taint-shaped
    engine. Additive: the default `--mode taint` path above is untouched."""
    from mcp_safeguard.scanner.pipeline import hunt_fleet

    root = Path(repo_path)
    if not root.is_dir():
        print(f"Error: not a directory: {repo_path}", file=sys.stderr)
        return 1

    result = hunt_fleet(
        root,
        ledger_path=ledger_path,
        run_sandbox=run_sandbox,
        sandbox_timeout_seconds=sandbox_timeout,
        include_low_confidence=include_low_confidence,
        allow_unsafe_host_execution=allow_unsafe_host_execution,
    )
    counts = result.counts()
    verdict_counts = result.verdict_counts()

    if fmt == "json":
        print(json.dumps({
            "repo_path": result.repo_path,
            "counts": counts,
            "verdict_counts": verdict_counts,
            "ledger_path": ledger_path,
            "per_angle": {
                angle: [
                    {
                        "target_sink": outcome.card.target_sink,
                        "violated_claim": outcome.card.violated_claim,
                        "impossibility_argument": outcome.card.impossibility_argument,
                        "verdict": outcome.verdict,
                        "severity": outcome.card.severity.value if outcome.card.severity else None,
                        "cwe": outcome.card.cwe,
                        "note": outcome.note,
                    }
                    for outcome in outcomes
                ]
                for angle, outcomes in result.card_verdicts.items()
            },
            "errors": result.errors,
            "cost": result.cost_tracker.to_dict() if result.cost_tracker is not None else None,
        }, indent=2))
        return 0

    _print_banner()
    print(f"Hunter fleet: {_color(repo_path, _BOLD)}")
    print("─" * 60)
    for angle, outcomes in result.card_verdicts.items():
        print(f"  [{angle}] {len(outcomes)} claim card(s)")
        for outcome in outcomes:
            color = {"confirmed": _GREEN, "refuted": _RED}.get(outcome.verdict, _DIM)
            print(f"      [{_color(outcome.verdict.upper(), color)}] {outcome.card.target_sink}")
            if outcome.card.severity is not None:
                print(f"          severity={outcome.card.severity.value}  cwe={outcome.card.cwe or '(none)'}")
            print(f"          {outcome.note}")
        if angle in result.errors:
            print(f"      {_color('ERROR', _RED)}: {result.errors[angle]}")
    print("─" * 60)
    print(f"  total claim cards: {sum(counts.values())}")
    print(f"  confirmed={verdict_counts['confirmed']}  refuted={verdict_counts['refuted']}  unconfirmed={verdict_counts['unconfirmed']}")
    print(f"  ledger: {ledger_path}")
    if result.cost_tracker is not None:
        print(f"  {result.cost_tracker.report()}")
    return 0


def _run_rescan(targets_file: str, ledger_path: str, state_path: str, fmt: str = "text") -> int:
    """S8: polling-based diff-triggered re-scan -- see scanner/rescan.py's
    module docstring for the honest webhooks-vs-polling correction. For
    each target already in `state_path` (or bootstrapped from an existing
    entrypoint-recovery cache), checks for new commits and only re-runs the
    real `hunt` pipeline when a real file-level diff touches a
    previously-identified MCP handler file. Returns 0 -- a scan/record
    pass, not a pass/fail CI gate, same discipline as `hunt` itself."""
    from mcp_safeguard.scanner.rescan import rescan

    if not Path(targets_file).is_file():
        print(f"Error: not a file: {targets_file}", file=sys.stderr)
        return 1

    outcomes = rescan(targets_file, ledger_path=ledger_path, state_path=state_path)

    if fmt == "json":
        print(json.dumps([o.to_dict() for o in outcomes], indent=2))
        return 0

    _print_banner()
    print(f"Rescan: {_color(targets_file, _BOLD)}")
    print("─" * 60)
    action_color = {
        "no_change": _DIM,
        "skipped_no_handler_touch": _CYAN,
        "rehunt_targeted": _GREEN,
        "baseline_full_hunt": _YELLOW,
        "rehunt_full_fallback_no_cache": _YELLOW,
        "rehunt_full_fallback_no_diff": _YELLOW,
        "failed": _RED,
    }
    for o in outcomes:
        color = action_color.get(o.action, _RESET)
        print(f"  [{_color(o.action, color + _BOLD)}] {o.target}")
        if o.old_commit or o.new_commit:
            print(f"      commit: {(o.old_commit or '(none)')[:12]} -> {(o.new_commit or '(none)')[:12]}")
        if o.hunt_counts:
            c = o.hunt_counts
            print(f"      hunt: confirmed={c['confirmed']} refuted={c['refuted']} unconfirmed={c['unconfirmed']}")
        print(f"      {o.reason}")
        print()
    print("─" * 60)
    counts: dict[str, int] = {}
    for o in outcomes:
        counts[o.action] = counts.get(o.action, 0) + 1
    print(f"{len(outcomes)} target(s): " + ", ".join(f"{n} {a}" for a, n in counts.items()))
    print(f"  state: {state_path}")
    print(f"  ledger: {ledger_path}")
    return 0


def _write_output(findings: list[dict], output: str, scanned: str) -> None:
    """Write findings to a file (HTML, JSON, or SARIF based on extension)."""
    p = Path(output)
    if p.suffix == ".json":
        p.write_text(json.dumps(findings, indent=2))
    elif p.suffix == ".sarif" or p.name.endswith(".sarif.json"):
        from mcp_safeguard.scanner.report_generator import generate_sarif_report

        p.write_text(generate_sarif_report(findings))
    else:
        # Simple HTML report. title/location/remediation and rule_id all
        # ultimately derive from the scanned server's own tool names/config
        # (fully attacker-controlled when scanning a hostile server), and
        # `scanned` is the caller-supplied target path/URL — escape all of it
        # before interpolating into the page.
        rows = ""
        for f in findings:
            color = {"CRITICAL": "#e74c3c", "HIGH": "#e67e22", "MEDIUM": "#f1c40f",
                     "LOW": "#3498db", "INFO": "#95a5a6"}.get(f["severity"], "#666")
            rows += f"""
            <tr>
              <td><span style="color:{color};font-weight:bold">{html.escape(str(f['severity']))}</span></td>
              <td><code>{html.escape(str(f['rule_id']))}</code></td>
              <td>{html.escape(str(f['title']))}</td>
              <td>{html.escape(str(f['location']))}</td>
              <td>{html.escape(str(f['cvss']))}</td>
              <td><small>{html.escape(str(f['remediation']))}</small></td>
            </tr>"""
        page = f"""<!DOCTYPE html>
<html><head><title>mcp-safeguard Report</title>
<style>body{{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:2rem}}
h1{{color:#f0f6fc}}table{{width:100%;border-collapse:collapse}}
th{{background:#161b22;padding:8px;text-align:left;border-bottom:1px solid #30363d}}
td{{padding:8px;border-bottom:1px solid #21262d;vertical-align:top}}
code{{background:#161b22;padding:2px 4px;border-radius:3px}}</style></head>
<body><h1>🔒 mcp-safeguard Security Report</h1>
<p>Scanned: <code>{html.escape(str(scanned))}</code> — {len(findings)} finding(s)</p>
<table><tr><th>Severity</th><th>Rule</th><th>Finding</th><th>Location</th>
<th>CVSS</th><th>Remediation</th></tr>{rows}</table>
<p><small>Generated by <a href="https://github.com/SyedAnas01/mcp-safeguard"
style="color:#58a6ff">mcp-safeguard</a></small></p></body></html>"""
        p.write_text(page)
    print(f"\nReport saved: {output}")


# --------------------------------------------------------------------------
# `ledger` subcommand — CLI over the S7 append-only evidence ledger
# (scanner/ledger.py + scanner/claim_card.py). An entry's `id` here is
# always its 1-based position in the ledger file in append order (`list`
# and `show` both use it) -- stable because the ledger is append-only:
# a given entry's id never changes once assigned, it just gets read back
# out on every subsequent call.
# --------------------------------------------------------------------------

def _ledger_prompt_entry() -> dict[str, Any]:
    """Build the same JSON shape `ledger add --file` expects, one field at a
    time from stdin. Deliberately does not prompt for `evidence_path` --
    a list of `Step` objects isn't practical to type in line-by-line; use
    `--file` for an entry that needs one."""
    def ask(prompt: str, required: bool = True) -> str | None:
        while True:
            val = input(f"{prompt}: ").strip()
            if val or not required:
                return val or None

    print("Interactive ledger entry — evidence_path is not supported here; use --file for that.")
    target_sink = ask("target_sink")
    tainted_source = ask("tainted_source")
    caller_authority_assumed = ask("caller_authority_assumed")
    precondition = ask("precondition")
    violated_claim = ask("violated_claim (include its own file:line citation)")

    oracle_trace: dict[str, Any] | None = None
    impossibility_argument: str | None = None
    oracle_trace_raw = ask("oracle_trace as a JSON object (blank if none)", required=False)
    if oracle_trace_raw:
        oracle_trace = json.loads(oracle_trace_raw)
    else:
        impossibility_argument = ask(
            "no oracle_trace given -- impossibility_argument (required per the ClaimCard emit rule)"
        )

    verdict = ask("verdict (confirmed / refuted / unconfirmed)")
    commit = ask("commit")
    evidence_ref = ask("evidence_ref (optional)", required=False)
    notes = ask("notes (optional)", required=False)

    return {
        "claim_card": {
            "target_sink": target_sink,
            "tainted_source": tainted_source,
            "caller_authority_assumed": caller_authority_assumed,
            "precondition": precondition,
            "violated_claim": violated_claim,
            "evidence_path": [],
            "oracle_trace": oracle_trace,
            "impossibility_argument": impossibility_argument,
        },
        "verdict": verdict,
        "commit": commit,
        "evidence_ref": evidence_ref,
        "notes": notes,
    }


def _run_ledger_add(file_path: str | None, ledger_path: str) -> int:
    from mcp_safeguard.scanner.claim_card import ClaimCard, ClaimCardValidationError
    from mcp_safeguard.scanner.ledger import append_entry, read_entries

    if file_path:
        p = Path(file_path)
        if not p.is_file():
            print(f"Error: file not found: {file_path}", file=sys.stderr)
            return 1
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            print(f"Error: invalid JSON in {file_path}: {e}", file=sys.stderr)
            return 1
    else:
        data = _ledger_prompt_entry()

    if "claim_card" not in data or not isinstance(data["claim_card"], dict):
        print('Error: entry must have a top-level "claim_card" object.', file=sys.stderr)
        return 1
    try:
        card = ClaimCard.from_dict(data["claim_card"])
    except ClaimCardValidationError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except (KeyError, TypeError) as e:
        print(f"Error: claim_card is missing a required field: {e}", file=sys.stderr)
        return 1

    verdict = data.get("verdict")
    commit = data.get("commit")
    if not verdict:
        print('Error: top-level "verdict" is required.', file=sys.stderr)
        return 1
    if not commit:
        print('Error: top-level "commit" is required.', file=sys.stderr)
        return 1

    try:
        append_entry(
            card,
            verdict,
            commit,
            evidence_ref=data.get("evidence_ref"),
            notes=data.get("notes"),
            ledger_path=ledger_path,
            timestamp=data.get("timestamp"),
        )
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    new_id = len(read_entries(ledger_path))
    print(_color(f"Appended entry #{new_id} to {ledger_path}", _GREEN))
    print(f"  verdict:     {verdict}")
    print(f"  target_sink: {card.target_sink}")
    return 0


def _run_ledger_list(
    verdict: str | None, target: str | None, commit: str | None,
    since: str | None, until: str | None, fmt: str, ledger_path: str,
) -> int:
    from mcp_safeguard.scanner.ledger import read_entries

    entries = read_entries(ledger_path)
    numbered = list(enumerate(entries, start=1))

    def matches(item: tuple[int, Any]) -> bool:
        _id, e = item
        if verdict and e.verdict != verdict:
            return False
        if target and target.lower() not in e.claim_card.target_sink.lower():
            return False
        if commit and commit.lower() not in e.commit.lower():
            return False
        if since and e.timestamp < since:
            return False
        if until and e.timestamp > until:
            return False
        return True

    filtered = [item for item in numbered if matches(item)]

    if fmt == "json":
        print(json.dumps([{"id": i, **e.to_dict()} for i, e in filtered], indent=2))
        return 0

    if not filtered:
        print(_color("No matching ledger entries.", _DIM))
        return 0

    for i, e in filtered:
        sink = e.claim_card.target_sink
        sink_short = sink if len(sink) <= 60 else sink[:57] + "..."
        verdict_color = {"confirmed": _GREEN, "refuted": _DIM, "unconfirmed": _YELLOW}.get(e.verdict, _RESET)
        ref = f"  ref={e.evidence_ref}" if e.evidence_ref else ""
        print(f"#{i:<4} {_color(f'{e.verdict:<11}', verdict_color)} {e.timestamp}  "
              f"commit={e.commit[:12]:<12} {sink_short}{ref}")

    print("─" * 60)
    print(f"{len(filtered)} of {len(entries)} total entr{'y' if len(entries) == 1 else 'ies'}.")
    return 0


def _run_ledger_stats(fmt: str, ledger_path: str) -> int:
    from mcp_safeguard.scanner.ledger import ledger_stats

    stats = ledger_stats(ledger_path)
    if fmt == "json":
        print(json.dumps(stats, indent=2))
        return 0

    print(_color(f"Ledger: {ledger_path}", _BOLD))
    print("─" * 40)
    # Pad the plain label BEFORE colorizing -- colorizing first would count
    # the (invisible) ANSI escape codes toward the `:<13` width and misalign
    # every row in a real terminal.
    rows = [("total", stats["total"], None), ("confirmed", stats["confirmed"], _GREEN),
            ("refuted", stats["refuted"], _DIM), ("unconfirmed", stats["unconfirmed"], _YELLOW)]
    for label, count, color in rows:
        label_padded = f"{label}:".ljust(13)
        print(f"  {_color(label_padded, color) if color else label_padded} {count}")
    return 0


def _run_ledger_show(entry_id_raw: str, fmt: str, ledger_path: str) -> int:
    from mcp_safeguard.scanner.ledger import read_entries

    try:
        entry_id = int(entry_id_raw)
    except ValueError:
        print(f"Error: <id> must be an integer (1-based position in the ledger); got {entry_id_raw!r}",
              file=sys.stderr)
        return 1

    entries = read_entries(ledger_path)
    if entry_id < 1 or entry_id > len(entries):
        print(f"Error: no entry #{entry_id} -- ledger has {len(entries)} entr{'y' if len(entries) == 1 else 'ies'}.",
              file=sys.stderr)
        return 1
    entry = entries[entry_id - 1]

    if fmt == "json":
        print(json.dumps({"id": entry_id, **entry.to_dict()}, indent=2))
        return 0

    card = entry.claim_card
    print(_color(f"Entry #{entry_id}", _BOLD))
    print("─" * 60)
    print(f"verdict:      {entry.verdict}")
    print(f"timestamp:    {entry.timestamp}")
    print(f"commit:       {entry.commit}")
    print(f"evidence_ref: {entry.evidence_ref or '(none)'}")
    print(f"notes:        {entry.notes or '(none)'}")
    print()
    print(f"target_sink:              {card.target_sink}")
    print(f"tainted_source:           {card.tainted_source}")
    print(f"caller_authority_assumed: {card.caller_authority_assumed}")
    print(f"precondition:             {card.precondition}")
    print(f"violated_claim:           {card.violated_claim}")
    print(f"severity:                 {card.severity.value if card.severity else '(none)'}")
    print(f"cwe:                      {card.cwe or '(none)'}")

    if card.evidence_path:
        print(f"\nevidence_path ({len(card.evidence_path)} step(s)):")
        for i, step in enumerate(card.evidence_path, start=1):
            loc = f"{step.file}:{step.line}" if step.file else f"line {step.line}"
            print(f"  {i}. [{step.kind}] {loc}")
            print(f"     {step.code}")
            if step.note:
                print(f"     note: {step.note}")

    if card.oracle_trace is not None:
        # A real Stage-5 result (scanner/pipeline.py's hunt()) round-trips
        # through the ledger as a typed OracleTrace, not a plain dict (see
        # claim_card.py) -- .to_dict() it first, same as LedgerEntry.to_dict()
        # already does implicitly via dataclasses.asdict() for the --format
        # json path above.
        trace_dict = card.oracle_trace.to_dict() if hasattr(card.oracle_trace, "to_dict") else card.oracle_trace
        print("\noracle_trace:")
        print(textwrap.indent(json.dumps(trace_dict, indent=2), "  "))

    if card.impossibility_argument:
        print(f"\nimpossibility_argument:\n  {card.impossibility_argument}")

    return 0


def _run_ledger(args: list[str]) -> int:
    from mcp_safeguard.scanner.ledger import DEFAULT_LEDGER_PATH

    if not args:
        print("Error: missing ledger subcommand. Try: mcp-safeguard ledger {add|list|stats|show}", file=sys.stderr)
        return 1

    sub = args[0]
    rest = args[1:]

    # `--ledger-path` is shared by every subcommand -- pull it out wherever
    # it appears rather than requiring a fixed position.
    ledger_path = str(DEFAULT_LEDGER_PATH)
    filtered_rest: list[str] = []
    i = 0
    while i < len(rest):
        if rest[i] == "--ledger-path" and i + 1 < len(rest):
            ledger_path = rest[i + 1]
            i += 2
        else:
            filtered_rest.append(rest[i])
            i += 1
    rest = filtered_rest

    if sub == "add":
        file_path = None
        i = 0
        while i < len(rest):
            if rest[i] == "--file" and i + 1 < len(rest):
                file_path = rest[i + 1]
                i += 2
            else:
                print(f"Warning: unknown option {rest[i]}", file=sys.stderr)
                i += 1
        return _run_ledger_add(file_path, ledger_path)

    if sub == "list":
        verdict = target = commit = since = until = None
        fmt = "text"
        i = 0
        while i < len(rest):
            if rest[i] == "--verdict" and i + 1 < len(rest):
                verdict = rest[i + 1]
                i += 2
            elif rest[i] == "--target" and i + 1 < len(rest):
                target = rest[i + 1]
                i += 2
            elif rest[i] == "--commit" and i + 1 < len(rest):
                commit = rest[i + 1]
                i += 2
            elif rest[i] == "--since" and i + 1 < len(rest):
                since = rest[i + 1]
                i += 2
            elif rest[i] == "--until" and i + 1 < len(rest):
                until = rest[i + 1]
                i += 2
            elif rest[i] == "--format" and i + 1 < len(rest):
                fmt = rest[i + 1].lower()
                i += 2
            else:
                print(f"Warning: unknown option {rest[i]}", file=sys.stderr)
                i += 1
        return _run_ledger_list(verdict, target, commit, since, until, fmt, ledger_path)

    if sub == "stats":
        fmt = "text"
        i = 0
        while i < len(rest):
            if rest[i] == "--format" and i + 1 < len(rest):
                fmt = rest[i + 1].lower()
                i += 2
            else:
                print(f"Warning: unknown option {rest[i]}", file=sys.stderr)
                i += 1
        return _run_ledger_stats(fmt, ledger_path)

    if sub == "show":
        if not rest or rest[0].startswith("--"):
            print("Error: missing <id>. Usage: mcp-safeguard ledger show <id>", file=sys.stderr)
            return 1
        entry_id_raw = rest[0]
        fmt = "text"
        i = 1
        while i < len(rest):
            if rest[i] == "--format" and i + 1 < len(rest):
                fmt = rest[i + 1].lower()
                i += 2
            else:
                print(f"Warning: unknown option {rest[i]}", file=sys.stderr)
                i += 1
        return _run_ledger_show(entry_id_raw, fmt, ledger_path)

    print(f"Unknown ledger subcommand: {sub}. Try: add, list, stats, show", file=sys.stderr)
    return 1


def _print_help() -> None:
    print(textwrap.dedent("""
        mcp-safeguard — security scanner for MCP servers

        USAGE:
            mcp-safeguard scan <config.json> [OPTIONS]
            mcp-safeguard scan-source <repo-dir> [OPTIONS]
            mcp-safeguard score <repo-dir> [OPTIONS]
            mcp-safeguard score-batch <dir-of-repos> [OPTIONS]
            mcp-safeguard hunt <repo-dir> [OPTIONS]
            mcp-safeguard rescan <targets-file> [OPTIONS]
            mcp-safeguard ledger {add|list|stats|show} [OPTIONS]

        OPTIONS:
            --severity <LEVEL>   Minimum severity to show: CRITICAL, HIGH, MEDIUM, LOW, INFO (default: INFO)
            --fail-on <LEVEL>    Exit with code 1 if any finding >= this severity (for CI)
            --output <FILE>      Write report to file (.html, .json, or .sarif)
            --format <FORMAT>    Output format: text (default), json, or sarif
            --baseline <FILE>    Suppress findings already present in this JSON
                                  baseline (scan-source only) — generate one with
                                  `scan-source . --format json > baseline.json`
            --static-taint       (scan-source only, Python AND JS/TS repos,
                                  no separate flag per language) Also run the
                                  static-taint pipeline: recover real MCP tool
                                  handlers, generate semgrep taint rules scoped
                                  to their parameters, and report tier "S"
                                  findings with a reconstructed source-to-sink
                                  path. Requires `semgrep` on PATH; JS/TS support
                                  additionally requires tree-sitter + the JS/TS
                                  grammars (`pip install mcp-safeguard[static-taint]`
                                  installs all of the above except the semgrep
                                  binary itself — see pyproject.toml).
                                  Existing tier "L" (lexical) findings are
                                  unaffected either way.
            --verify              (scan-source only, with --static-taint) Also
                                  run Stage 4 grounded LLM verification on
                                  every tier "S" finding, upgrading it to tier
                                  "V" (confirmed) or "R" (refuted) in the
                                  output -- two independent verification runs
                                  must agree, otherwise it stays tier "S"
                                  (unconfirmed). Requires ANTHROPIC_API_KEY and
                                  `pip install mcp-safeguard[verify]`; if
                                  unavailable, prints a warning and leaves
                                  tier "S" findings as-is. The original
                                  taint_path evidence is never dropped.
            --include-low-confidence  (scan-source only, with --static-taint)
                                  By default, a TAINT-IDOR finding in a
                                  project with no measured evidence of
                                  multi-tenancy (no distinct user/org/tenant/
                                  account/workspace id compared across
                                  requests, no user/session/auth model file,
                                  no multi-tenant framework import, no
                                  multi-credential pattern) is suppressed --
                                  "no ownership check" is not a meaningful
                                  finding in a genuinely single-tenant/local
                                  tool. Pass this flag to see those findings
                                  anyway, downgraded to confidence
                                  "very-low". No effect on any other rule.
            --stars <N>           (score only) Star count, for the popularity
                                  sub-score. Omitted -> popularity defaults to
                                  a neutral 50, never guessed.
            --official            (score only) Mark the repo as backed by an
                                  official/vendor org for the popularity
                                  sub-score.
            --downloads <N>       (score only) Weekly download count, for the
                                  popularity sub-score.
            --last-scanned-commit <SHA>  (score only) The commit this repo was
                                  last scored at, for the novelty sub-score --
                                  omitted or different from the repo's current
                                  HEAD scores novelty high; identical scores
                                  it near zero.

        EXAMPLES:
            mcp-safeguard scan config.json
            mcp-safeguard scan config.json --severity HIGH
            mcp-safeguard scan config.json --fail-on CRITICAL
            mcp-safeguard scan config.json --output report.html
            mcp-safeguard scan config.json --format sarif --output results.sarif
            mcp-safeguard scan examples/demo-vulnerable-config.json
            mcp-safeguard scan-source ./path/to/mcp-server-repo
            mcp-safeguard scan-source . --baseline baseline.json --fail-on HIGH
            mcp-safeguard scan-source . --static-taint --format json
            mcp-safeguard scan-source . --static-taint --verify --format json
            mcp-safeguard scan-source . --static-taint --include-low-confidence --format json
            mcp-safeguard score ./path/to/mcp-server-repo
            mcp-safeguard score ./path/to/mcp-server-repo --official --format json
            mcp-safeguard score-batch ./dir-of-cloned-repos --format csv --output ranked.csv
            mcp-safeguard hunt ./path/to/mcp-server-repo
            mcp-safeguard hunt ./path/to/mcp-server-repo --ledger-path bench/ledger/findings.jsonl
            mcp-safeguard hunt ./path/to/mcp-server-repo --format json --no-verify
            mcp-safeguard hunt ./path/to/mcp-server-repo --mode fleet
            mcp-safeguard rescan bench/fleet_targets.txt
            mcp-safeguard rescan bench/fleet_targets.txt --format json

        A source-scanned line can also be silenced inline with a comment:
            # safeguard: ignore[SRC-013] self-signed cert, dev-only client

        CI (GitHub Actions, SARIF -> code scanning):
            - run: pip install mcp-safeguard
            - run: mcp-safeguard scan-source . --format sarif --output results.sarif --fail-on HIGH || true
            - uses: github/codeql-action/upload-sarif@v3
              with:
                sarif_file: results.sarif

        Config format: Claude Desktop mcpServers JSON or {tools: [...], env: {...}}

        `scan` reads a config/tool-definition JSON. `scan-source` walks a
        server's actual source tree for code-level footguns a config scan
        cannot see (SRC-001..SRC-031: credential handling across redirects,
        SQL/SoQL injection, caller-influenced credential destinations,
        unenforced auth flags, unowned resource IDs, syntax-only destructive-
        query classifiers, client-trusted ownership fields, unescaped shell
        interpolation, unhardened credential file writes, SSRF TOCTOU and
        unguarded outbound fetches, silently-dropped manifest entries,
        disabled TLS verification, unchecked OAuth redirect_uri/scope,
        inbound-token passthrough, a write flag that gates listing but not
        execution, a header used as an authorization identity, real path
        traversal, unencoded URL query-string building, a network listener
        with no inbound auth check, broken object-level authorization,
        reflected XSS, loopback servers with no Origin check, unredacted
        error logging, plaintext credential persistence, CORS/dev-server
        misconfiguration, and a credential sent as a URL query parameter on
        a GET request). Source-audit findings are heuristic leads to
        confirm by reading the cited file/line, not proofs.

        `hunt` (S8) is the real, end-to-end pipeline: run the tier "S"
        static-taint scan (Stage 0-3), build a ClaimCard for each finding,
        run it through Stage 5's execution sandbox for the sandbox-testable
        classes (TAINT-CMDI, TAINT-PATHTRAV, TAINT-SSRF, TAINT-CREDFWD --
        TAINT-IDOR is absence-based and always skips the sandbox), run
        Stage 4 grounded LLM verification if ANTHROPIC_API_KEY is set, and
        append every resulting ClaimCard to the ledger with an honest
        verdict (a finding is only "confirmed" by real execution evidence
        or agreeing LLM runs -- never merely because a ClaimCard was
        constructed). `--no-verify` skips Stage 4 even if a key is set.
        `--mode fleet` (S3) dispatches ALL SEVEN hunter angles (scanner/
        hunter.py) instead of just this taint-shaped engine -- claims-vs-
        enforcement, credential-and-secrets, cross-file-authority,
        whole-handler-audit, scope-selector-override, and transport-and-exposure in addition to the taint scan above. The 6 non-taint angles require
        ANTHROPIC_API_KEY (AnthropicHunter); without one they are honestly
        recorded as not-run. `--mode taint` (the default) is this
        unchanged, original single-angle pipeline.
        `score-batch`'s S0 ranking is NOT wired in as a pre-filter here --
        run `score`/`score-batch` separately to decide what to `hunt` next.

        `rescan` (S8, polling-based diff-triggered re-scan -- see
        scanner/rescan.py's own module docstring for why this is polling,
        not the originally-designed webhooks, and why that's an honest,
        real substitution rather than the mechanism as first specified) --
        for each target in a targets file (same one-per-line local-path-or-
        git-URL format `fleet-scan`/`score-batch` use), checks for new
        commits since its recorded last-scanned commit (`bench/
        rescan_state.json` by default) and, only when a real file-level
        diff touches a previously-identified MCP handler file (cross-
        referenced against the SAME cached entrypoint-recovery data `hunt`
        itself produces), re-runs the real `hunt` pipeline and appends any
        new findings to the ledger. A target with no prior record is given
        one full `hunt` to establish a baseline. A target whose entrypoint
        data isn't cached, or whose old commit can't be diffed, falls back
        to a full re-hunt rather than silently under-scanning -- it never
        guesses "probably fine, skip it". This is a manually-invoked
        command, not a running daemon -- there is no scheduler here; see
        bench/S8_RESCAN_STATUS.md for that real, separate, still-open gap.

        `score` (S0) is a cheap, no-LLM, no-semgrep pre-audit ranking pass --
        recovered MCP-handler count, dangerous-sink presence (process exec,
        filesystem, network, database, credentials), optional popularity
        metadata, and commit-diff novelty, combined into a skip /
        cheap_taint_pass / deep_audit_candidate recommendation. `score-batch`
        runs it across every subdirectory of a directory of cloned repos and
        prints/writes a ranked table -- what a continuous-scanning loop would
        consume to decide what to run `scan-source --static-taint` on next.

        LEDGER (the S7 append-only evidence ledger — scanner/ledger.py):
            mcp-safeguard ledger add --file <entry.json> [--ledger-path <path>]
            mcp-safeguard ledger add [--ledger-path <path>]
                                  (no --file: prompts for each field on stdin;
                                  cannot set evidence_path this way, use --file)
            mcp-safeguard ledger list [--verdict confirmed|refuted|unconfirmed]
                                       [--target <substring>] [--commit <substring>]
                                       [--since <iso-timestamp>] [--until <iso-timestamp>]
                                       [--format text|json] [--ledger-path <path>]
            mcp-safeguard ledger stats [--format text|json] [--ledger-path <path>]
            mcp-safeguard ledger show <id> [--format text|json] [--ledger-path <path>]

            <id> in `ledger show`/`ledger list`'s output is the entry's 1-based
            position in the ledger file, in append order — stable, since the
            ledger is append-only (append_entry is the only way anything is
            ever added; nothing rewrites or reorders existing lines).

            --ledger-path defaults to bench/ledger/findings.jsonl (same
            default as scanner/ledger.py's own DEFAULT_LEDGER_PATH),
            resolved relative to the current working directory.

            `ledger add --file entry.json` expects:
            {
              "claim_card": {
                "target_sink": "...", "tainted_source": "...",
                "caller_authority_assumed": "...", "precondition": "...",
                "violated_claim": "... (with its own file:line citation)",
                "evidence_path": [{"kind": "source|assign|call|sink|...",
                                    "line": 1, "code": "...", "note": "",
                                    "file": ""}],
                "oracle_trace": {...} or null,
                "impossibility_argument": "..." or null
              },
              "verdict": "confirmed" | "refuted" | "unconfirmed",
              "commit": "<git sha or content hash>",
              "evidence_ref": "... (optional)",
              "notes": "... (optional)"
            }
            Exactly one of oracle_trace / impossibility_argument is required
            — ClaimCard's own emit-invariant (claim_card.py) rejects an
            entry with neither, same as any other caller of the class.

        EXAMPLES (ledger):
            mcp-safeguard ledger add --file bench/ledger/entries/aiven-pg-read.json
            mcp-safeguard ledger list --verdict confirmed
            mcp-safeguard ledger stats
            mcp-safeguard ledger show 1

        GitHub: https://github.com/SyedAnas01/mcp-safeguard
    """))


def main() -> None:
    args = sys.argv[1:]

    if not args or args[0] in ("-h", "--help", "help"):
        _print_help()
        sys.exit(0)

    if args[0] == "scan":
        if len(args) < 2:
            print("Error: missing config file. Usage: mcp-safeguard scan <config.json>", file=sys.stderr)
            sys.exit(1)
        config_path = args[1]
        severity = "INFO"
        fail_on = None
        output = None
        fmt = "text"

        i = 2
        while i < len(args):
            if args[i] == "--severity" and i + 1 < len(args):
                severity = args[i + 1].upper()
                i += 2
            elif args[i] == "--fail-on" and i + 1 < len(args):
                fail_on = args[i + 1].upper()
                i += 2
            elif args[i] == "--output" and i + 1 < len(args):
                output = args[i + 1]
                i += 2
            elif args[i] == "--format" and i + 1 < len(args):
                fmt = args[i + 1].lower()
                i += 2
            else:
                print(f"Warning: unknown option {args[i]}", file=sys.stderr)
                i += 1

        code = _run_scan(config_path, severity, fail_on, output, fmt)
        sys.exit(code)

    elif args[0] == "scan-source":
        if len(args) < 2:
            print("Error: missing target directory. Usage: mcp-safeguard scan-source <path>", file=sys.stderr)
            sys.exit(1)
        root_path = args[1]
        severity = "INFO"
        fail_on = None
        output = None
        fmt = "text"
        baseline = None
        static_taint = False
        verify = False
        include_low_confidence = False

        i = 2
        while i < len(args):
            if args[i] == "--severity" and i + 1 < len(args):
                severity = args[i + 1].upper()
                i += 2
            elif args[i] == "--fail-on" and i + 1 < len(args):
                fail_on = args[i + 1].upper()
                i += 2
            elif args[i] == "--output" and i + 1 < len(args):
                output = args[i + 1]
                i += 2
            elif args[i] == "--format" and i + 1 < len(args):
                fmt = args[i + 1].lower()
                i += 2
            elif args[i] == "--baseline" and i + 1 < len(args):
                baseline = args[i + 1]
                i += 2
            elif args[i] == "--static-taint":
                static_taint = True
                i += 1
            elif args[i] == "--verify":
                verify = True
                i += 1
            elif args[i] == "--include-low-confidence":
                include_low_confidence = True
                i += 1
            else:
                print(f"Warning: unknown option {args[i]}", file=sys.stderr)
                i += 1

        code = _run_source_scan(root_path, severity, fail_on, output, fmt, baseline, static_taint, verify,
                                 include_low_confidence)
        sys.exit(code)

    elif args[0] == "score":
        if len(args) < 2:
            print("Error: missing target directory. Usage: mcp-safeguard score <repo-dir>", file=sys.stderr)
            sys.exit(1)
        repo_path = args[1]
        fmt = "text"
        stars = None
        is_official_org = None
        weekly_downloads = None
        last_scanned_commit = None

        i = 2
        while i < len(args):
            if args[i] == "--format" and i + 1 < len(args):
                fmt = args[i + 1].lower()
                i += 2
            elif args[i] == "--stars" and i + 1 < len(args):
                stars = int(args[i + 1])
                i += 2
            elif args[i] == "--official":
                is_official_org = True
                i += 1
            elif args[i] == "--downloads" and i + 1 < len(args):
                weekly_downloads = int(args[i + 1])
                i += 2
            elif args[i] == "--last-scanned-commit" and i + 1 < len(args):
                last_scanned_commit = args[i + 1]
                i += 2
            else:
                print(f"Warning: unknown option {args[i]}", file=sys.stderr)
                i += 1

        code = _run_score(repo_path, fmt, stars=stars, is_official_org=is_official_org,
                           weekly_downloads=weekly_downloads, last_scanned_commit=last_scanned_commit)
        sys.exit(code)

    elif args[0] == "score-batch":
        if len(args) < 2:
            print("Error: missing target directory. Usage: mcp-safeguard score-batch <dir-of-repos>",
                  file=sys.stderr)
            sys.exit(1)
        dir_path = args[1]
        fmt = "json"
        output = None

        i = 2
        while i < len(args):
            if args[i] == "--format" and i + 1 < len(args):
                fmt = args[i + 1].lower()
                i += 2
            elif args[i] == "--output" and i + 1 < len(args):
                output = args[i + 1]
                i += 2
            else:
                print(f"Warning: unknown option {args[i]}", file=sys.stderr)
                i += 1

        code = _run_score_batch(dir_path, fmt, output)
        sys.exit(code)

    elif args[0] == "hunt":
        if len(args) < 2:
            print("Error: missing target directory. Usage: mcp-safeguard hunt <repo-dir>", file=sys.stderr)
            sys.exit(1)
        from mcp_safeguard.scanner.ledger import DEFAULT_LEDGER_PATH

        repo_path = args[1]
        ledger_path = str(DEFAULT_LEDGER_PATH)
        fmt = "text"
        mode = "taint"
        include_low_confidence = False
        sandbox_timeout = 30
        no_verify = False
        no_sandbox = False
        allow_unsafe_host_execution = False

        i = 2
        while i < len(args):
            if args[i] == "--ledger-path" and i + 1 < len(args):
                ledger_path = args[i + 1]
                i += 2
            elif args[i] == "--format" and i + 1 < len(args):
                fmt = args[i + 1].lower()
                i += 2
            elif args[i] == "--mode" and i + 1 < len(args):
                mode = args[i + 1].lower()
                i += 2
            elif args[i] == "--include-low-confidence":
                include_low_confidence = True
                i += 1
            elif args[i] == "--sandbox-timeout" and i + 1 < len(args):
                sandbox_timeout = int(args[i + 1])
                i += 2
            elif args[i] == "--no-verify":
                no_verify = True
                i += 1
            elif args[i] == "--no-sandbox":
                no_sandbox = True
                i += 1
            elif args[i] == "--allow-unsafe-host-execution":
                allow_unsafe_host_execution = True
                i += 1
            else:
                print(f"Warning: unknown option {args[i]}", file=sys.stderr)
                i += 1

        if mode == "fleet":
            code = _run_hunt_fleet(repo_path, ledger_path, fmt, include_low_confidence=include_low_confidence,
                                    sandbox_timeout=sandbox_timeout, run_sandbox=not no_sandbox,
                                    allow_unsafe_host_execution=allow_unsafe_host_execution)
        elif mode == "taint":
            code = _run_hunt(repo_path, ledger_path, fmt, include_low_confidence=include_low_confidence,
                              sandbox_timeout=sandbox_timeout, no_verify=no_verify,
                              allow_unsafe_host_execution=allow_unsafe_host_execution)
        else:
            print(f"Error: unknown --mode {mode!r}. Try: taint (default) or fleet.", file=sys.stderr)
            code = 1
        sys.exit(code)

    elif args[0] == "rescan":
        if len(args) < 2:
            print("Error: missing targets file. Usage: mcp-safeguard rescan <targets-file>", file=sys.stderr)
            sys.exit(1)
        from mcp_safeguard.scanner.ledger import DEFAULT_LEDGER_PATH
        from mcp_safeguard.scanner.rescan import DEFAULT_STATE_PATH

        targets_file = args[1]
        ledger_path = str(DEFAULT_LEDGER_PATH)
        state_path = str(DEFAULT_STATE_PATH)
        fmt = "text"

        i = 2
        while i < len(args):
            if args[i] == "--ledger-path" and i + 1 < len(args):
                ledger_path = args[i + 1]
                i += 2
            elif args[i] == "--state-path" and i + 1 < len(args):
                state_path = args[i + 1]
                i += 2
            elif args[i] == "--format" and i + 1 < len(args):
                fmt = args[i + 1].lower()
                i += 2
            else:
                print(f"Warning: unknown option {args[i]}", file=sys.stderr)
                i += 1

        code = _run_rescan(targets_file, ledger_path, state_path, fmt)
        sys.exit(code)

    elif args[0] == "ledger":
        sys.exit(_run_ledger(args[1:]))

    elif args[0] == "version":
        try:
            from importlib.metadata import version
            print(f"mcp-safeguard {version('mcp-safeguard')}")
        except Exception:
            print("mcp-safeguard (version unknown)")
    else:
        print(f"Unknown command: {args[0]}. Try: mcp-safeguard scan <config.json>", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
