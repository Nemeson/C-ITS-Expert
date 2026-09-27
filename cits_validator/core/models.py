from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"


@dataclass
class Violation:
    rule_id: str
    severity: Severity
    message: str
    packet_index: int | None = None
    line_number: int | None = None
    byte_offset: int | None = None
    offending_sample: str | None = None
    remediation_hint: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "message": self.message,
            "packet_index": self.packet_index,
            "line_number": self.line_number,
            "byte_offset": self.byte_offset,
            "offending_sample": self.offending_sample,
            "remediation_hint": self.remediation_hint,
        }


@dataclass
class ValidationReport:
    total_inspected: int = 0
    violations: list[Violation] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def add_violation(self, violation: Violation) -> None:
        self.violations.append(violation)

    @property
    def error_count(self) -> int:
        return sum(1 for v in self.violations if v.severity == Severity.ERROR)

    @property
    def warning_count(self) -> int:
        return sum(1 for v in self.violations if v.severity == Severity.WARNING)

    @property
    def info_count(self) -> int:
        return sum(1 for v in self.violations if v.severity == Severity.INFO)

    @property
    def is_valid(self) -> bool:
        return self.error_count == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "total_inspected": self.total_inspected,
            "error_count": self.error_count,
            "warning_count": self.warning_count,
            "info_count": self.info_count,
            "violations": [v.to_dict() for v in self.violations],
            "metadata": self.metadata,
        }
