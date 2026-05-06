"""Prometheus metrics for mcp-shield."""

from __future__ import annotations

from prometheus_client import REGISTRY, Counter, Gauge, Histogram

# Use default registry
_registry = REGISTRY

scan_total = Counter(
    "mcp_shield_scans_total",
    "Total number of security scans performed",
    ["status"],  # "success", "failure", "blocked"
)

vulnerability_total = Counter(
    "mcp_shield_vulnerabilities_total",
    "Total vulnerabilities found across all scans",
    ["severity", "category"],  # category: injection, credential, endpoint, poisoning
)

scan_duration_seconds = Histogram(
    "mcp_shield_scan_duration_seconds",
    "Scan duration in seconds",
    buckets=[0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0],
)

active_scans = Gauge(
    "mcp_shield_active_scans",
    "Number of scans currently in progress",
)

scan_history_size = Gauge(
    "mcp_shield_scan_history_size",
    "Number of scan results retained in memory",
)

rate_limit_hits = Counter(
    "mcp_shield_rate_limit_hits_total",
    "Number of requests blocked by rate limiter",
    ["client_id"],
)

auth_failures = Counter(
    "mcp_shield_auth_failures_total",
    "Number of authentication failures",
    ["method"],
)

cvss_score_histogram = Histogram(
    "mcp_shield_finding_cvss_score",
    "Distribution of CVSS scores across findings",
    buckets=[0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0],
)


def record_scan_complete(
    status: str,
    duration_s: float,
    finding_counts: dict[str, dict[str, int]],
    cvss_scores: list[float],
) -> None:
    """
    Record all metrics for a completed scan.

    Args:
        status: "success" or "failure".
        duration_s: Scan duration in seconds.
        finding_counts: Dict of category → {severity: count}.
        cvss_scores: List of CVSS scores for all findings.
    """
    scan_total.labels(status=status).inc()
    scan_duration_seconds.observe(duration_s)

    for category, counts in finding_counts.items():
        for severity, count in counts.items():
            if count > 0:
                vulnerability_total.labels(severity=severity, category=category).inc(count)

    for score in cvss_scores:
        cvss_score_histogram.observe(score)
