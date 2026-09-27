from __future__ import annotations

import ast
import re

from cits_validator.core.models import Severity, Violation
from cits_validator.core.registry import BaseRule


class PythonAstAuditor(ast.NodeVisitor):
    def __init__(self, rule_id: str) -> None:
        self.rule_id = rule_id
        self.violations: list[Violation] = []

    def visit_Assign(self, node: ast.Assign) -> None:
        # Check target variable names
        target_names = [
            t.id for t in node.targets if isinstance(t, ast.Name)
        ]

        # 1. Check for trigonometric coordinate synthesis: lat = ... sin(...)
        is_coord = any(
            any(k in name.lower() for k in ("lat", "lon", "lng", "coord", "pos"))
            for name in target_names
        )

        # Check expression for sin/cos
        for subnode in ast.walk(node.value):
            if isinstance(subnode, ast.Call):
                func_name = ""
                if isinstance(subnode.func, ast.Name):
                    func_name = subnode.func.id
                elif isinstance(subnode.func, ast.Attribute):
                    func_name = subnode.func.attr

                if func_name.lower() in ("sin", "cos"):
                    if is_coord or any(isinstance(a, ast.BinOp) for a in ast.walk(node.value)):
                        self.violations.append(
                            Violation(
                                rule_id=self.rule_id,
                                severity=Severity.ERROR,
                                message="Detected synthetic GNSS coordinate generation using trigonometric function",
                                line_number=node.lineno,
                                remediation_hint=(
                                    "Iron Law: Never synthesize coordinates with trigonometric functions (sin/cos). "
                                    "If GNSS data is missing, field values must remain null."
                                ),
                            )
                        )

            # 2. Check for modulo signal group assignment: (lane % 4) + 1
            if isinstance(subnode, ast.BinOp) and isinstance(subnode.op, ast.Add):
                left = subnode.left
                if isinstance(left, ast.BinOp) and isinstance(left.op, ast.Mod):
                    self.violations.append(
                        Violation(
                            rule_id=self.rule_id,
                            severity=Severity.ERROR,
                            message="Detected prohibited modulo signal group assignment ((id % N) + 1)",
                            line_number=node.lineno,
                            remediation_hint=(
                                "Signal groups must be resolved strictly via MAPEM 'connectsTo[].signalGroup', "
                                "never via modulo arithmetic."
                            ),
                        )
                    )

        self.generic_visit(node)


class AntiHallucinationRule(BaseRule):
    """Detects prohibited synthetic fallback math and LLM hallucination anti-patterns."""

    rule_id = "R02"
    name = "Anti-Hallucination & Zero-Fake-Data Enforcement"
    description = (
        "Audits source code against synthetic GNSS sine drifts, modulo signal group "
        "assignments, and hardcoded 90-second static SPAT cycle loops."
    )

    REGEX_PATTERNS = [
        (
            re.compile(r"(?:lat|lon|lng|coord|pos)\w*\s*[=:]\s*.*(?:sin|cos)\s*\(", re.IGNORECASE),
            "Detected synthetic GNSS coordinate generation using trigonometric function",
            "Iron Law: Never synthesize coordinates. Field values must remain null.",
        ),
        (
            re.compile(r"(?:lane|group|phase)\w*\s*%\s*\d+\s*\+\s*1", re.IGNORECASE),
            "Detected prohibited modulo signal group assignment ((lane % N) + 1)",
            "Signal groups must be resolved strictly via MAPEM 'connectsTo[].signalGroup'.",
        ),
        (
            re.compile(
                r"(?:DEFAULT_CYCLE|cycle_time|cycle)\w*\s*[=:]\s*90\b|%\s*90\b|90-second\s+cycle",
                re.IGNORECASE,
            ),
            "Detected prohibited hardcoded 90-second static cycle loop",
            "Never invent static 90-second SPAT cycles. Read dynamic horizons from SPATEM.",
        ),
    ]

    def audit_code(self, code: str, language: str = "python") -> list[Violation]:
        violations: list[Violation] = []
        lang_lower = language.lower()

        # 1. AST Analysis for Python
        if lang_lower in ("python", "py"):
            try:
                tree = ast.parse(code)
                visitor = PythonAstAuditor(self.rule_id)
                visitor.visit(tree)
                violations.extend(visitor.violations)
            except SyntaxError:
                # If code snippet is incomplete Python, fallback to regex
                pass

        # 2. Polyglot Regex Analysis
        lines = code.splitlines()
        for line_idx, line in enumerate(lines, start=1):
            for pattern, msg, hint in self.REGEX_PATTERNS:
                if pattern.search(line):
                    # Avoid duplicate if AST already flagged it on this line
                    if not any(v.line_number == line_idx for v in violations):
                        violations.append(
                            Violation(
                                rule_id=self.rule_id,
                                severity=Severity.ERROR,
                                message=msg,
                                line_number=line_idx,
                                offending_sample=line.strip(),
                                remediation_hint=hint,
                            )
                        )

        return violations
