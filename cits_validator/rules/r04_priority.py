from __future__ import annotations

from typing import Any

from cits_validator.core.models import Severity, Violation
from cits_validator.core.registry import BaseRule


class PrioritySessionRule(BaseRule):
    """Enforces 4-tuple SREM/SSEM correlation and audits unclosed priority requests."""

    rule_id = "R04"
    name = "SREM/SSEM Priority Session Invariant"
    description = (
        "Correlates vehicle priority requests (SREM) to infrastructure status responses (SSEM) "
        "using the canonical 4-tuple (intersectionId, requestId, sequenceNumber, requestorStationId) "
        "and detects hanging priority leaks."
    )

    def __init__(self, timeout_seconds: float = 5.0) -> None:
        self.timeout_seconds = timeout_seconds

    def audit_event(self, event: dict[str, Any], state: dict[str, Any]) -> list[Violation]:
        violations: list[Violation] = []
        ev_type = str(event.get("type") or "").upper()
        try:
            timestamp = float(event.get("timestamp", 0.0))
        except (TypeError, ValueError):
            violations.append(
                Violation(
                    rule_id=self.rule_id,
                    severity=Severity.WARNING,
                    message=f"Priority event ignored: invalid timestamp {event.get('timestamp')!r}",
                    offending_sample=str(event.get("type")),
                )
            )
            return violations

        intersection_id = event.get("intersectionId")
        request_id = event.get("requestId")
        seq_num = event.get("sequenceNumber")
        station_id = event.get("requestorStationId")

        if None in (intersection_id, request_id, seq_num, station_id):
            return violations

        key = (intersection_id, request_id, seq_num, station_id)
        sessions = state.setdefault("active_priority_sessions", {})

        if ev_type == "SREM":
            if key in sessions:
                violations.append(
                    Violation(
                        rule_id=self.rule_id,
                        severity=Severity.WARNING,
                        message="duplicate SREM for an active priority session; keeping the first",
                        offending_sample=str(key),
                    )
                )
                return violations
            sessions[key] = {
                "request_time": timestamp,
                "role": event.get("role", "unknown"),
            }
        elif ev_type == "SSEM":
            if key in sessions:
                req_time = sessions.pop(key)["request_time"]
                latency = timestamp - req_time
                if latency < 0:
                    violations.append(
                        Violation(
                            rule_id=self.rule_id,
                            severity=Severity.WARNING,
                            message=f"Negative priority response latency ({latency:.3f}s)",
                            offending_sample=str(key),
                        )
                    )
            else:
                # The request may predate the capture window, so this is informational.
                violations.append(
                    Violation(
                        rule_id=self.rule_id,
                        severity=Severity.INFO,
                        message="SSEM with no preceding SREM in this capture",
                        offending_sample=str(key),
                    )
                )

        return violations

    def check_timeouts(self, current_timestamp: float, state: dict[str, Any]) -> list[Violation]:
        violations: list[Violation] = []
        sessions = state.get("active_priority_sessions", {})
        expired_keys = []

        for key, info in list(sessions.items()):
            elapsed = current_timestamp - info["request_time"]
            if elapsed > self.timeout_seconds:
                expired_keys.append(key)
                violations.append(
                    Violation(
                        rule_id=self.rule_id,
                        severity=Severity.WARNING,
                        message=(
                            f"Priority session timeout: request {key} received no SSEM response "
                            f"after {elapsed:.1f}s (threshold={self.timeout_seconds}s)"
                        ),
                        offending_sample=str(key),
                        remediation_hint=(
                            "Check RSU signal controller prioritization logs for unacknowledged "
                            "or dropped SREM priority requests."
                        ),
                    )
                )

        for k in expired_keys:
            sessions.pop(k, None)

        return violations
