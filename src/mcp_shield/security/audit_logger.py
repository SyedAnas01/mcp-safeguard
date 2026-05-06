"""Structured audit logging for all scan operations."""

from __future__ import annotations

import json
import logging
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any


@dataclass
class AuditEvent:
    """A structured audit log event."""

    event_type: str
    timestamp: str
    client_id: str
    scan_id: str | None
    target: str | None
    action: str
    outcome: str  # "success", "failure", "blocked"
    duration_ms: float | None
    details: dict[str, Any]
    severity: str = "INFO"


class AuditLogger:
    """
    Structured JSON audit logger for security-relevant events.

    All scans, auth attempts, and rate limit events are logged here.
    """

    def __init__(self, name: str = "mcp-shield.audit") -> None:
        self._logger = logging.getLogger(name)
        if not self._logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(logging.Formatter("%(message)s"))
            self._logger.addHandler(handler)
        self._logger.setLevel(logging.INFO)

    def _emit(self, event: AuditEvent) -> None:
        """Emit a structured JSON log line."""
        try:
            self._logger.info(json.dumps(asdict(event)))
        except Exception:
            pass  # Never let logging break the server

    def log_scan_start(
        self,
        client_id: str,
        scan_id: str,
        target: str,
        categories: list[str],
    ) -> None:
        """Log the start of a security scan."""
        self._emit(
            AuditEvent(
                event_type="SCAN_START",
                timestamp=datetime.now(UTC).isoformat(),
                client_id=client_id,
                scan_id=scan_id,
                target=target,
                action="scan_mcp_server",
                outcome="started",
                duration_ms=None,
                details={"categories": categories},
                severity="INFO",
            )
        )

    def log_scan_complete(
        self,
        client_id: str,
        scan_id: str,
        target: str,
        duration_ms: float,
        finding_counts: dict[str, int],
        overall_severity: str,
    ) -> None:
        """Log the completion of a scan."""
        self._emit(
            AuditEvent(
                event_type="SCAN_COMPLETE",
                timestamp=datetime.now(UTC).isoformat(),
                client_id=client_id,
                scan_id=scan_id,
                target=target,
                action="scan_mcp_server",
                outcome="success",
                duration_ms=duration_ms,
                details={
                    "finding_counts": finding_counts,
                    "overall_severity": overall_severity,
                },
                severity="INFO" if overall_severity in ("INFO", "LOW") else "WARN",
            )
        )

    def log_auth_failure(self, client_ip: str, method: str) -> None:
        """Log an authentication failure."""
        self._emit(
            AuditEvent(
                event_type="AUTH_FAILURE",
                timestamp=datetime.now(UTC).isoformat(),
                client_id=client_ip,
                scan_id=None,
                target=None,
                action="authenticate",
                outcome="failure",
                duration_ms=None,
                details={"method": method},
                severity="WARN",
            )
        )

    def log_rate_limit(self, client_id: str, endpoint: str) -> None:
        """Log a rate limit event."""
        self._emit(
            AuditEvent(
                event_type="RATE_LIMIT",
                timestamp=datetime.now(UTC).isoformat(),
                client_id=client_id,
                scan_id=None,
                target=None,
                action=endpoint,
                outcome="blocked",
                duration_ms=None,
                details={"endpoint": endpoint},
                severity="WARN",
            )
        )

    def log_validation_error(self, client_id: str, field: str, error: str) -> None:
        """Log an input validation failure."""
        self._emit(
            AuditEvent(
                event_type="VALIDATION_ERROR",
                timestamp=datetime.now(UTC).isoformat(),
                client_id=client_id,
                scan_id=None,
                target=None,
                action="validate_input",
                outcome="failure",
                duration_ms=None,
                details={"field": field, "error": error},
                severity="WARN",
            )
        )

    def log_ssrf_blocked(self, client_id: str, target: str) -> None:
        """Log a blocked SSRF attempt."""
        self._emit(
            AuditEvent(
                event_type="SSRF_BLOCKED",
                timestamp=datetime.now(UTC).isoformat(),
                client_id=client_id,
                scan_id=None,
                target=target,
                action="scan",
                outcome="blocked",
                duration_ms=None,
                details={"blocked_target": target},
                severity="ERROR",
            )
        )


audit_logger = AuditLogger()
