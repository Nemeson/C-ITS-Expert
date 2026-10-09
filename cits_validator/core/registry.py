from __future__ import annotations

from typing import Any, Iterable

from cits_validator.core.models import Violation
from cits_validator.core.stream import PacketRecord


class BaseRule:
    """Base class for all C-ITS validation rules."""

    rule_id: str = "R00"
    name: str = "Base Rule"
    description: str = "Generic C-ITS rule"

    def audit_packet(
        self, record: PacketRecord, dlt: int, state: dict[str, Any]
    ) -> list[Violation]:
        """Audits a raw network packet record."""
        return []

    def audit_code(self, code: str, language: str) -> list[Violation]:
        """Audits a source code snippet."""
        return []

    def metadata(self) -> dict[str, Any]:
        """Machine-readable descriptors for codegen and tooling. Empty by default."""
        return {}


class RuleRegistry:
    """Registry managing active validation rules."""

    def __init__(self) -> None:
        self._rules: dict[str, BaseRule] = {}

    def register(self, rule: BaseRule) -> None:
        self._rules[rule.rule_id] = rule

    def get_rule(self, rule_id: str) -> BaseRule | None:
        return self._rules.get(rule_id)

    def list_rules(self) -> list[BaseRule]:
        return list(self._rules.values())

    def audit_packet(
        self,
        record: PacketRecord,
        dlt: int,
        state: dict[str, Any],
        active_rule_ids: Iterable[str] | None = None,
    ) -> list[Violation]:
        violations: list[Violation] = []
        for r_id, rule in self._rules.items():
            if active_rule_ids is None or r_id in active_rule_ids:
                violations.extend(rule.audit_packet(record, dlt, state))
        return violations

    def audit_code(
        self,
        code: str,
        language: str,
        active_rule_ids: Iterable[str] | None = None,
    ) -> list[Violation]:
        violations: list[Violation] = []
        for r_id, rule in self._rules.items():
            if active_rule_ids is None or r_id in active_rule_ids:
                violations.extend(rule.audit_code(code, language))
        return violations
