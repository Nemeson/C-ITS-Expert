from __future__ import annotations

import ast
import io
import re
import tokenize

from cits_validator.core.models import Severity, Violation
from cits_validator.core.registry import BaseRule

# Suppression pragma. Placed on the offending line or the line immediately
# above it, it silences a finding at that location (e.g. when a trigonometric
# function is genuinely part of a geometric distance formula, not a synthetic
# coordinate generator).
ALLOW_PRAGMA = "cits-lint: allow"

# Function names whose bodies legitimately contain trigonometry (great-circle
# and planar distance math), never synthetic coordinate generation.
_GEO_FUNC_ALLOWLIST = re.compile(
    r"\b(?:haversine|great_circle|distance|dist|geo_dist|euclid|slerp)\w*\b",
    re.IGNORECASE,
)

# Coordinate-ish identifiers. The negative lookbehind keeps compound names such
# as `dLat`, `deltaLon` or `phiLat` from being mistaken for a coordinate.
_COORD_TOKEN = r"(?<![A-Za-z0-9_])(?:lat|lon|lng|coord|pos)\w*"  # noqa: S105 (regex fragment, not a credential)


def _strip_line_comment(line: str, language: str) -> str:
    """Removes a trailing line comment for the given language.

    Only line comments are removed (never string contents), so an anti-pattern
    documented in a comment cannot be reported as live code.
    """
    if language in ("python", "py", "shell", "bash", "yaml", "toml"):
        idx = line.find("#")
    else:
        idx = line.find("//")
        if idx == -1:
            block = line.find("/*")
            if block != -1 and line.rstrip().endswith("*/"):
                return line[:block]
    return line if idx == -1 else line[:idx]


def _mask_string_literals(code: str, language: str) -> list[str]:
    """Returns code lines with string literals and comments blanked out.

    Regex heuristics run against these masked lines so that an anti-pattern
    quoted inside a test fixture string (or written in a comment) is not
    reported as if it were live, executable code. Python uses the tokenizer for
    an exact result; other languages fall back to quote-aware scanning.
    """
    lines = code.splitlines()
    masked = [_strip_line_comment(line, language) for line in lines]

    if language in ("python", "py"):
        try:
            for tok in tokenize.generate_tokens(io.StringIO(code).readline):
                if tok.type != tokenize.STRING:
                    continue
                (sl, sc), (el, ec) = tok.start, tok.end
                for ln in range(sl - 1, el):
                    if ln >= len(masked):
                        continue
                    row = masked[ln]
                    start = sc if ln == sl - 1 else 0
                    end = ec if ln == el - 1 else len(row)
                    start = min(start, len(row))
                    end = min(max(end, start), len(row))
                    masked[ln] = row[:start] + " " * (end - start) + row[end:]
        except (tokenize.TokenError, IndentationError, SyntaxError):
            pass

    # Quote-aware scan for non-Python languages (and as a Python fallback).
    for i, line in enumerate(masked):
        out: list[str] = []
        quote: str | None = None
        j = 0
        while j < len(line):
            ch = line[j]
            if quote:
                if ch == "\\" and j + 1 < len(line):
                    out.append("  ")
                    j += 2
                    continue
                if ch == quote:
                    quote = None
                out.append(" ")
            elif ch in ("'", '"', "`"):
                prev = line[j - 1] if j else ""
                # Do not treat a Python string prefix (r"", f"") as an opener.
                if prev.isalnum() or prev == "_":
                    out.append(ch)
                else:
                    quote = ch
                    out.append(" ")
            else:
                out.append(ch)
            j += 1
        masked[i] = "".join(out)

    return masked


def _pragma_suppressed(lines: list[str], line_no: int) -> bool:
    """True when the ALLOW_PRAGMA appears on the line or the line above it."""
    for candidate in (line_no, line_no - 1):
        if 1 <= candidate <= len(lines) and ALLOW_PRAGMA in lines[candidate - 1]:
            return True
    return False


class PythonAstAuditor(ast.NodeVisitor):
    """AST audit for Python source, with string-literal and pragma awareness."""

    def __init__(self, rule_id: str, lines: list[str] | None = None) -> None:
        self.rule_id = rule_id
        self.lines = lines or []
        self.violations: list[Violation] = []
        self._func_stack: list[str] = []
        self._flagged_lines: set[int] = set()

    # -- helpers ---------------------------------------------------------------
    def _suppressed(self, node: ast.AST) -> bool:
        line_no = getattr(node, "lineno", None)
        if line_no is None or line_no in self._flagged_lines:
            return True
        return _pragma_suppressed(self.lines, line_no)

    def _in_geo_function(self) -> bool:
        return any(_GEO_FUNC_ALLOWLIST.search(name) for name in self._func_stack)

    @staticmethod
    def _is_literal(node: ast.AST) -> bool:
        """True when the value is a constant literal (incl. f-strings).

        An anti-pattern quoted as a string is data for a test or a diagnostic
        message, not executable protocol logic.
        """
        return isinstance(node, (ast.Constant, ast.JoinedStr))

    @staticmethod
    def _trig_calls(node: ast.AST) -> list[str]:
        found: list[str] = []
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                name = ""
                if isinstance(sub.func, ast.Name):
                    name = sub.func.id
                elif isinstance(sub.func, ast.Attribute):
                    name = sub.func.attr
                if name.lower() in ("sin", "cos"):
                    found.append(name.lower())
        return found

    @staticmethod
    def _names(node: ast.AST) -> set[str]:
        return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)} | {
            n.attr for n in ast.walk(node) if isinstance(n, ast.Attribute)
        }

    def _flag(self, node: ast.AST, message: str, hint: str) -> None:
        line_no = getattr(node, "lineno", None)
        if line_no is not None:
            self._flagged_lines.add(line_no)
        self.violations.append(
            Violation(
                rule_id=self.rule_id,
                severity=Severity.ERROR,
                message=message,
                line_number=line_no,
                remediation_hint=hint,
            )
        )

    def _maybe_flag_trig_coords(self, node: ast.AST, value: ast.AST) -> None:
        if self._suppressed(node) or self._in_geo_function() or self._is_literal(value):
            return
        if not self._trig_calls(value):
            return

        target_names: list[str] = []
        if isinstance(node, ast.Assign):
            target_names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name):
                target_names = [node.target.id]
            elif isinstance(node.target, ast.Attribute):
                target_names = [node.target.attr]

        targets_coord = any(re.search(_COORD_TOKEN, n, re.IGNORECASE) for n in target_names)
        value_coord = any(re.search(_COORD_TOKEN, n, re.IGNORECASE) for n in self._names(value))
        # Assignment to a coordinate, or an expression that itself references a
        # coordinate name, is the synthetic-drift signature.
        if targets_coord or (value_coord and target_names):
            self._flag(
                node,
                "Detected synthetic GNSS coordinate generation using trigonometric function",
                "Iron Law: Never synthesize coordinates with trigonometric functions (sin/cos). "
                "If GNSS data is missing, field values must remain null.",
            )

    def _maybe_flag_modulo(self, node: ast.AST, value: ast.AST) -> bool:
        for sub in ast.walk(value):
            if isinstance(sub, ast.BinOp) and isinstance(sub.op, ast.Add):
                left = sub.left
                if isinstance(left, ast.BinOp) and isinstance(left.op, ast.Mod):
                    self._flag(
                        node,
                        "Detected prohibited modulo signal group assignment ((id % N) + 1)",
                        "Signal groups must be resolved strictly via MAPEM "
                        "'connectsTo[].signalGroup', never via modulo arithmetic.",
                    )
                    return True
        return False

    # -- visitors --------------------------------------------------------------
    def _visit_function(self, node: ast.AST) -> None:
        self._func_stack.append(getattr(node, "name", ""))
        self.generic_visit(node)
        self._func_stack.pop()

    visit_FunctionDef = _visit_function  # type: ignore[assignment]
    visit_AsyncFunctionDef = _visit_function  # type: ignore[assignment]

    def visit_Assign(self, node: ast.Assign) -> None:
        if not self._maybe_flag_modulo(node, node.value):
            self._maybe_flag_trig_coords(node, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None and not self._maybe_flag_modulo(node, node.value):
            self._maybe_flag_trig_coords(node, node.value)
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:
        if node.value is None:
            self.generic_visit(node)
            return
        if self._suppressed(node):
            self.generic_visit(node)
            return
        if self._maybe_flag_modulo(node, node.value):
            self.generic_visit(node)
            return
        if self._in_geo_function() or self._is_literal(node.value):
            self.generic_visit(node)
            return
        # A plain `return lat, lon` merely passes real data through — it is not a
        # synthesis signal. Only a trigonometric expression qualifies.
        if not self._trig_calls(node.value):
            self.generic_visit(node)
            return

        names = self._names(node.value)
        coordish = any(re.search(_COORD_TOKEN, n, re.IGNORECASE) for n in names)
        multiplicative_trig = any(
            isinstance(s, ast.BinOp) and isinstance(s.op, ast.Mult) for s in ast.walk(node.value)
        )
        if coordish or multiplicative_trig:
            self._flag(
                node,
                "Detected synthetic GNSS coordinate generation using trigonometric function",
                "Iron Law: Never synthesize coordinates with trigonometric functions (sin/cos). "
                "If GNSS data is missing, field values must remain null.",
            )
        self.generic_visit(node)


class AntiHallucinationRule(BaseRule):
    """Detects prohibited synthetic fallback math and LLM hallucination anti-patterns.

    The rule is deliberately tuned against its own class of false positives:
    anti-patterns quoted inside string literals or written in comments are not
    reported, and trigonometry inside a named distance/great-circle function is
    accepted. Any finding can be silenced locally with the ``cits-lint: allow``
    pragma.
    """

    rule_id = "R02"
    name = "Anti-Hallucination & Zero-Fake-Data Enforcement"
    description = (
        "Audits source code against synthetic GNSS sine drifts, modulo signal group "
        "assignments, and hardcoded 90-second static SPAT cycle loops."
    )

    REGEX_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
        (
            re.compile(
                rf"{_COORD_TOKEN}[^\n]*?(?:sin|cos)\s*\("
                r"|(?:sin|cos)\s*\([^)]*\)\s*\*\s*0\.\d+",
                re.IGNORECASE,
            ),
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
                r"(?:DEFAULT_CYCLE|cycle_time|cycle)\w*\s*[=:]\s*90\b"
                r"|\b(?:timestamp|elapsed|time|clock|cycle|phase|spat|signal)\w*\s*%\s*90\b"
                r"|90-second\s+cycle",
                re.IGNORECASE,
            ),
            "Detected prohibited hardcoded 90-second static cycle loop",
            "Never invent static 90-second SPAT cycles. Read dynamic horizons from SPATEM.",
        ),
    ]

    def __init__(self, audit_strings: bool = False) -> None:
        # `audit_strings` is retained for callers that deliberately want literal
        # string content scanned (e.g. auditing a captured payload dump).
        self.audit_strings = audit_strings

    def audit_code(self, code: str, language: str = "python") -> list[Violation]:
        violations: list[Violation] = []
        lang_lower = language.lower()
        raw_lines = code.splitlines()

        # 1. AST Analysis for Python
        if lang_lower in ("python", "py"):
            try:
                tree = ast.parse(code)
                visitor = PythonAstAuditor(self.rule_id, lines=raw_lines)
                visitor.visit(tree)
                violations.extend(visitor.violations)
            except (SyntaxError, ValueError):
                # Incomplete snippet: fall back to the polyglot regex pass.
                pass

        # 2. Polyglot Regex Analysis over masked (comment/string-free) lines
        scan_lines = raw_lines if self.audit_strings else _mask_string_literals(code, lang_lower)

        for line_idx, line in enumerate(scan_lines, start=1):
            if not line.strip() or _pragma_suppressed(raw_lines, line_idx):
                continue
            for pattern, msg, hint in self.REGEX_PATTERNS:
                if not pattern.search(line):
                    continue
                if any(v.line_number == line_idx for v in violations):
                    continue
                violations.append(
                    Violation(
                        rule_id=self.rule_id,
                        severity=Severity.ERROR,
                        message=msg,
                        line_number=line_idx,
                        offending_sample=raw_lines[line_idx - 1].strip() or None,
                        remediation_hint=hint,
                    )
                )

        return violations
