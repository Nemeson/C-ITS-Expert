from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from cits_validator.core.models import Severity, ValidationReport, Violation
from cits_validator.core.registry import RuleRegistry
from cits_validator.core.stream import PcapStreamingIterator
from cits_validator.rules.r01_link_layer import LinkLayerRule
from cits_validator.rules.r02_anti_fake import AntiHallucinationRule
from cits_validator.rules.r03_topology import MapemTopologyRule
from cits_validator.rules.r04_priority import PrioritySessionRule
from cits_validator.rules.r05_hardware import HardwareStreamRule


def build_default_registry() -> RuleRegistry:
    registry = RuleRegistry()
    registry.register(LinkLayerRule())
    registry.register(AntiHallucinationRule())
    registry.register(MapemTopologyRule())
    registry.register(PrioritySessionRule())
    registry.register(HardwareStreamRule())
    return registry


def detect_language(path: Path) -> str:
    suffix = path.suffix.lower()
    mapping = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".rs": "rust",
        ".cpp": "cpp",
        ".hpp": "cpp",
        ".h": "c",
        ".java": "java",
    }
    return mapping.get(suffix, "text")


def scan_file(
    file_path: Path,
    registry: RuleRegistry,
    active_rules: set[str] | None,
    report: ValidationReport,
) -> None:
    suffix = file_path.suffix.lower()
    if suffix in (".pcap", ".pcapng"):
        streamer = PcapStreamingIterator()
        try:
            with open(file_path, "rb") as f:
                header = streamer.read_header(f)
                state: dict = {}
                for record in streamer.iter_records(f):
                    report.total_inspected += 1
                    violations = registry.audit_packet(
                        record, header.dlt, state, active_rule_ids=active_rules
                    )
                    for v in violations:
                        report.add_violation(v)
        except Exception as e:
            report.add_violation(
                Violation(
                    rule_id="R01",
                    severity=Severity.ERROR,
                    message=f"Failed to read PCAP stream {file_path.name}: {e}",
                    remediation_hint="Check PCAP magic number and record framing.",
                )
            )
    else:
        # Source code file
        lang = detect_language(file_path)
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            report.total_inspected += 1
            violations = registry.audit_code(content, language=lang, active_rule_ids=active_rules)
            for v in violations:
                report.add_violation(v)
        except Exception as e:
            report.add_violation(
                Violation(
                    rule_id="R02",
                    severity=Severity.ERROR,
                    message=f"Failed to read source file {file_path.name}: {e}",
                )
            )


def format_text_report(report: ValidationReport, target: str) -> str:
    lines = []
    lines.append("=" * 60)
    lines.append(f"C-ITS Validator Report: {target}")
    lines.append(f"Total Inspected: {report.total_inspected}")
    lines.append(
        f"Status: {'PASSED' if report.is_valid else 'FAILED'} "
        f"({report.error_count} Errors, {report.warning_count} Warnings, {report.info_count} Info)"
    )
    lines.append("=" * 60)

    for v in report.violations:
        prefix = f"[{v.severity.value}] {v.rule_id}"
        loc = ""
        if v.packet_index is not None:
            loc += f" Packet #{v.packet_index}"
        if v.line_number is not None:
            loc += f" Line {v.line_number}"
        if v.byte_offset is not None:
            loc += f" Byte {v.byte_offset}"

        lines.append(f"{prefix}{loc}: {v.message}")
        if v.offending_sample:
            lines.append(f"    Sample: {v.offending_sample}")
        if v.remediation_hint:
            lines.append(f"    Fix:    {v.remediation_hint}")

    return "\n".join(lines)


def run_cli(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cits-lint",
        description="C-ITS & V2X Protocol Linter and Anti-Hallucination Conformance Checker",
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Path to PCAP file, source code file, or directory to scan",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat warnings as errors (exit code 1 on warnings)",
    )
    parser.add_argument(
        "--rules",
        help="Comma-separated list of rule IDs to run (e.g. R01,R02)",
    )

    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 0

    target_path = Path(args.target)

    active_rules: set[str] | None = None
    if args.rules:
        active_rules = {r.strip().upper() for r in args.rules.split(",") if r.strip()}

    registry = build_default_registry()
    report = ValidationReport()

    if target_path.is_file():
        scan_file(target_path, registry, active_rules, report)
    elif target_path.is_dir():
        for file in target_path.rglob("*"):
            if file.is_file() and not any(part.startswith(".") for part in file.parts):
                if file.suffix.lower() in (
                    ".pcap",
                    ".pcapng",
                    ".py",
                    ".js",
                    ".ts",
                    ".rs",
                    ".cpp",
                    ".hpp",
                    ".java",
                ):
                    scan_file(file, registry, active_rules, report)
    else:
        print(f"Error: Target path '{target_path}' not found.", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(format_text_report(report, str(target_path)))

    if args.strict and (report.error_count > 0 or report.warning_count > 0):
        return 1
    if not report.is_valid:
        return 1

    return 0


def main() -> None:
    sys.exit(run_cli(sys.argv[1:]))


if __name__ == "__main__":
    main()
