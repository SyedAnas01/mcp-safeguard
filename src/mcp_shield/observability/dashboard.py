"""
Streamlit dashboard for mcp-shield real-time scan statistics.

Run with: streamlit run src/mcp_shield/observability/dashboard.py
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def main() -> None:
    """Launch the Streamlit dashboard."""
    try:
        import streamlit as st
    except ImportError:
        print("Streamlit not installed. Run: pip install streamlit", file=sys.stderr)
        sys.exit(1)

    st.set_page_config(
        page_title="mcp-shield Dashboard",
        page_icon="🛡️",
        layout="wide",
    )

    st.title("🛡️ mcp-shield — Security Dashboard")
    st.caption("Real-time MCP server security scan statistics")

    # Load scan history from report directory
    report_dir = Path(os.environ.get("MCP_SHIELD_REPORT_DIR", "/tmp/mcp-shield-reports"))
    scan_files = sorted(report_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)

    scans = []
    for f in scan_files[:100]:
        try:
            with open(f) as fh:
                data = json.load(fh)
            scans.append(data)
        except Exception:
            continue

    if not scans:
        st.info("No scan results found. Run your first scan with `scan_mcp_server`.")
        return

    # Summary metrics
    total_scans = len(scans)
    total_critical = sum(s.get("summary", {}).get("critical_count", 0) for s in scans)
    total_high = sum(s.get("summary", {}).get("high_count", 0) for s in scans)
    total_findings = sum(s.get("summary", {}).get("total_findings", 0) for s in scans)

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Scans", total_scans)
    col2.metric("Critical Findings", total_critical, delta=None)
    col3.metric("High Findings", total_high)
    col4.metric("Total Findings", total_findings)

    st.divider()

    # Recent scans table
    st.subheader("Recent Scans")
    rows = []
    for s in scans[:20]:
        summary = s.get("summary", {})
        rows.append(
            {
                "Scan ID": summary.get("scan_id", "")[:8] + "...",
                "Target": summary.get("target", ""),
                "Time": summary.get("scan_time", ""),
                "Overall": summary.get("overall_severity", ""),
                "CVSS": summary.get("overall_cvss", 0),
                "Critical": summary.get("critical_count", 0),
                "High": summary.get("high_count", 0),
                "Total": summary.get("total_findings", 0),
            }
        )

    if rows:
        st.table(rows)

    # Severity distribution
    st.subheader("Severity Distribution")
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for s in scans:
        summary = s.get("summary", {})
        severity_counts["CRITICAL"] += summary.get("critical_count", 0)
        severity_counts["HIGH"] += summary.get("high_count", 0)
        severity_counts["MEDIUM"] += summary.get("medium_count", 0)
        severity_counts["LOW"] += summary.get("low_count", 0)
        severity_counts["INFO"] += summary.get("info_count", 0)

    st.bar_chart(severity_counts)

    st.caption(f"mcp-safeguard v0.3.0 | Reports from: {report_dir}")


if __name__ == "__main__":
    main()
