from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# Sentinel used whenever a value is genuinely absent from the capture.
# The C-ITS Iron Law ("NEVER SYNTHESIZE OR INVENT PROTOCOL DATA") requires
# missing data to be reported explicitly rather than silently defaulted.
NO_DATA_IN_CAPTURE = "<NONE>"


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
    file_path: str | None = None
    offending_sample: str | None = None
    remediation_hint: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "message": self.message,
            "file_path": self.file_path,
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
    coverage: dict[str, int] = field(default_factory=dict)
    # Findings omitted from `violations` because an identical pattern repeated.
    # The count is authoritative; `violations` holds a representative sample.
    suppressed_by_severity: dict[str, int] = field(default_factory=dict)

    def add_violation(self, violation: Violation) -> None:
        self.violations.append(violation)

    def suppress(self, severity: Severity, count: int = 1) -> None:
        if count <= 0:
            return
        key = severity.value
        self.suppressed_by_severity[key] = self.suppressed_by_severity.get(key, 0) + count

    # -- Data coverage contract -------------------------------------------------
    # Counts how many records of each category were actually observed. A category
    # that stays at zero is surfaced by `missing_categories`, so a report can say
    # "No Data in Capture" instead of quietly implying the check passed.
    def record_coverage(self, category: str, count: int = 1) -> None:
        self.coverage[category] = self.coverage.get(category, 0) + count

    @staticmethod
    def categories_for_dlt(dlt: int) -> list[str]:
        if dlt == 127:
            return ["radiotap", "dot11", "llc_snap", "btp"]
        if dlt == 105:
            return ["dot11", "llc_snap", "btp"]
        if dlt == 1:
            return ["ethernet", "btp"]
        return []

    def missing_categories(self) -> list[str]:
        """Categories that were expected for the inspected link types but never seen."""
        expected: list[str] = []
        for key in ("dlt", "dlts"):
            value = self.metadata.get(key)
            if isinstance(value, int):
                expected.extend(self.categories_for_dlt(value))
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, int):
                        expected.extend(self.categories_for_dlt(item))
        if not expected and self.total_inspected:
            expected = ["btp"]

        seen = set(self.coverage.keys())
        return [c for c in dict.fromkeys(expected) if c not in seen]

    def has_data(self) -> bool:
        """True once at least one inspected record reached the payload layer."""
        if self.coverage.get("btp", 0) > 0:
            return True
        return self.total_inspected > 0 and not self.coverage

    @property
    def error_count(self) -> int:
        inline = sum(1 for v in self.violations if v.severity == Severity.ERROR)
        return inline + self.suppressed_by_severity.get(Severity.ERROR.value, 0)

    @property
    def warning_count(self) -> int:
        inline = sum(1 for v in self.violations if v.severity == Severity.WARNING)
        return inline + self.suppressed_by_severity.get(Severity.WARNING.value, 0)

    @property
    def info_count(self) -> int:
        inline = sum(1 for v in self.violations if v.severity == Severity.INFO)
        return inline + self.suppressed_by_severity.get(Severity.INFO.value, 0)

    @property
    def is_valid(self) -> bool:
        return self.error_count == 0

    def to_dict(self) -> dict[str, Any]:
        missing = self.missing_categories()
        return {
            "is_valid": self.is_valid,
            "total_inspected": self.total_inspected,
            "error_count": self.error_count,
            "warning_count": self.warning_count,
            "info_count": self.info_count,
            "reported_violations": len(self.violations),
            "suppressed_by_severity": self.suppressed_by_severity,
            "violations": [v.to_dict() for v in self.violations],
            "metadata": self.metadata,
            "coverage": self.coverage,
            "has_data": self.has_data(),
            "data_status": "NO DATA IN CAPTURE" if missing else "OK",
            "missing_categories": missing,
        }


def empty_data_notice(categories: list[str]) -> str:
    """Human-readable 'No Data in Capture' notice for a set of missing categories."""
    if not categories:
        return ""
    return f"No Data in Capture: no {', '.join(categories)} records were observed."
