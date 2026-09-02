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

import html
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
                      fmt: str = "text", baseline: str | None = None) -> int:
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
        }
        for f in findings
    ]

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


def _print_help() -> None:
    print(textwrap.dedent("""
        mcp-safeguard — security scanner for MCP servers

        USAGE:
            mcp-safeguard scan <config.json> [OPTIONS]
            mcp-safeguard scan-source <repo-dir> [OPTIONS]

        OPTIONS:
            --severity <LEVEL>   Minimum severity to show: CRITICAL, HIGH, MEDIUM, LOW, INFO (default: INFO)
            --fail-on <LEVEL>    Exit with code 1 if any finding >= this severity (for CI)
            --output <FILE>      Write report to file (.html, .json, or .sarif)
            --format <FORMAT>    Output format: text (default), json, or sarif
            --baseline <FILE>    Suppress findings already present in this JSON
                                  baseline (scan-source only) — generate one with
                                  `scan-source . --format json > baseline.json`

        EXAMPLES:
            mcp-safeguard scan config.json
            mcp-safeguard scan config.json --severity HIGH
            mcp-safeguard scan config.json --fail-on CRITICAL
            mcp-safeguard scan config.json --output report.html
            mcp-safeguard scan config.json --format sarif --output results.sarif
            mcp-safeguard scan examples/demo-vulnerable-config.json
            mcp-safeguard scan-source ./path/to/mcp-server-repo
            mcp-safeguard scan-source . --baseline baseline.json --fail-on HIGH

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
        cannot see (SRC-001..SRC-021: credential handling across redirects,
        SQL read-only enforcement, caller-influenced credential destinations,
        unenforced auth flags, unowned resource IDs, syntax-only destructive-
        query classifiers, client-trusted ownership fields, unescaped shell
        interpolation, unhardened credential file writes, SSRF TOCTOU,
        silently-dropped manifest entries, disabled TLS verification,
        unchecked OAuth redirect_uri, inbound-token passthrough, a write
        flag that gates listing but not execution, a header used as an
        authorization identity, real path traversal, unencoded URL
        query-string building, and a network listener with no inbound auth
        check at all). Source-audit findings are heuristic leads to
        confirm by reading the cited file/line, not proofs.

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
            else:
                print(f"Warning: unknown option {args[i]}", file=sys.stderr)
                i += 1

        code = _run_source_scan(root_path, severity, fail_on, output, fmt, baseline)
        sys.exit(code)

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
