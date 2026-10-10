from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from cits_validator import __version__
from cits_validator.asn1.decoder import MESSAGE_TYPES, is_available
from cits_validator.core.models import (
    Severity,
    ValidationReport,
    Violation,
    empty_data_notice,
)
from cits_validator.core.registry import RuleRegistry
from cits_validator.core.stream import PcapStreamingIterator
from cits_validator.rules.r01_link_layer import LinkLayerRule
from cits_validator.rules.r02_anti_fake import AntiHallucinationRule
from cits_validator.rules.r03_topology import MapemTopologyRule
from cits_validator.rules.r04_priority import PrioritySessionRule
from cits_validator.rules.r05_hardware import HardwareStreamRule
from cits_validator.rules.r06_asn1_conformance import Asn1ConformanceRule

SOURCE_SUFFIXES = (".py", ".js", ".ts", ".rs", ".cpp", ".hpp", ".h", ".java")
CAPTURE_SUFFIXES = (".pcap", ".pcapng", ".cap")
SCAN_SUFFIXES = CAPTURE_SUFFIXES + SOURCE_SUFFIXES

# A single malformed pattern can repeat thousands of times in one capture. The
# report keeps the exact count but lists at most this many instances per rule
# per file, so a real signal is not buried under its own repetition.
REPORTED_PER_RULE_LIMIT = 5


def _cap_violations(
    violations: list[Violation], limit: int = REPORTED_PER_RULE_LIMIT
) -> tuple[list[Violation], dict[str, int]]:
    """Keeps at most `limit` findings per rule and reports the suppressed counts."""
    counts: dict[str, int] = {}
    kept: list[Violation] = []
    seen: dict[str, int] = {}
    for v in violations:
        counts[v.rule_id] = counts.get(v.rule_id, 0) + 1
        if seen.get(v.rule_id, 0) < limit:
            kept.append(v)
            seen[v.rule_id] = seen.get(v.rule_id, 0) + 1
    return kept, counts


def build_default_registry(
    max_stopline_chord_meters: float | None = None,
    enable_asn1: bool = False,
    asn1_release: str = "r1",
) -> RuleRegistry:
    registry = RuleRegistry()
    registry.register(LinkLayerRule())
    registry.register(AntiHallucinationRule())
    registry.register(MapemTopologyRule(max_stopline_chord_meters=max_stopline_chord_meters))
    registry.register(PrioritySessionRule())
    registry.register(HardwareStreamRule())
    # R06 needs the optional asn1tools dependency and is only registered when the
    # caller asks for it, so a default scan stays dependency-free and fast.
    if enable_asn1 and is_available():
        registry.register(Asn1ConformanceRule(release=asn1_release))
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
    if suffix in CAPTURE_SUFFIXES:
        streamer = PcapStreamingIterator()
        try:
            with open(file_path, "rb") as f:
                header = streamer.read_header(f)
                state: dict = {}
                effective_dlts: set[int] = set()
                file_violations: list[Violation] = []
                for record in streamer.iter_records(f):
                    report.total_inspected += 1
                    # A PCAPNG may interleave interfaces with different link types;
                    # each record is judged against its own (falling back to the
                    # file-level DLT for classic PCAP).
                    record_dlt = record.dlt if record.dlt is not None else header.dlt
                    effective_dlts.add(record_dlt)
                    for v in registry.audit_packet(
                        record, record_dlt, state, active_rule_ids=active_rules
                    ):
                        v.file_path = str(file_path)
                        file_violations.append(v)

                kept, counts = _cap_violations(file_violations)
                for v in kept:
                    report.add_violation(v)
                # Keep the authoritative count: every omitted ERROR is still an
                # error, so the report's verdict cannot be softened by capping.
                for rule_id, total in counts.items():
                    del rule_id  # the key is only used to group the counts
                    dropped = total - min(total, REPORTED_PER_RULE_LIMIT)
                    if dropped > 0:
                        report.suppress(Severity.ERROR, dropped)
                if sum(counts.values()) > len(kept):
                    report.add_violation(
                        Violation(
                            rule_id="R01",
                            severity=Severity.INFO,
                            message=(
                                f"{file_path.name}: listing at most "
                                f"{REPORTED_PER_RULE_LIMIT} findings per rule; full counts: "
                                + ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
                            ),
                            file_path=str(file_path),
                            remediation_hint=(
                                "Counts above are authoritative; the listed instances are a "
                                "representative sample of a repeating pattern."
                            ),
                        )
                    )

                report.metadata["dlt"] = header.dlt
                report.metadata["is_nanosecond"] = header.is_nanosecond
                report.metadata["is_pcapng"] = header.is_pcapng
                if effective_dlts:
                    report.metadata["dlts"] = sorted(effective_dlts)
                    if len(effective_dlts) == 1:
                        report.metadata["dlt"] = next(iter(effective_dlts))
                if streamer.unsupported_blocks:
                    report.metadata["unsupported_blocks"] = streamer.unsupported_blocks
                if streamer.truncated_eof:
                    report.add_violation(
                        Violation(
                            rule_id="R01",
                            severity=Severity.WARNING,
                            message=f"Capture {file_path.name} ends with a truncated record",
                            file_path=str(file_path),
                            remediation_hint=(
                                "Truncated captures are common after an abrupt stop; the last "
                                "record was dropped. Re-capture with a graceful SIGINT shutdown."
                            ),
                        )
                    )

                for category, count in state.get("_coverage", {}).items():
                    report.record_coverage(category, count)
                ports = state.get("btp_ports")
                if ports:
                    report.metadata["btp_ports"] = {str(k): v for k, v in sorted(ports.items())}
        except Exception as e:
            report.add_violation(
                Violation(
                    rule_id="R01",
                    severity=Severity.ERROR,
                    message=f"Failed to read capture {file_path.name}: {e}",
                    file_path=str(file_path),
                    remediation_hint="Check the capture magic number and block framing.",
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
                v.file_path = str(file_path)
                report.add_violation(v)
        except Exception as e:
            report.add_violation(
                Violation(
                    rule_id="R02",
                    severity=Severity.ERROR,
                    message=f"Failed to read source file {file_path.name}: {e}",
                    file_path=str(file_path),
                )
            )


def scan_topology_file(
    file_path: Path,
    registry: RuleRegistry,
    report: ValidationReport,
) -> None:
    """Audits a MAPEM topology JSON document (connections / fragments) with R03.

    Topology data has no natural place in the file-extension scan (a JSON file is
    not a capture and not source code), so it is addressed explicitly instead of
    being silently skipped.
    """
    rule = registry.get_rule("R03")
    if rule is None or not isinstance(rule, MapemTopologyRule):
        return

    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
    except Exception as e:
        report.add_violation(
            Violation(
                rule_id="R03",
                severity=Severity.ERROR,
                message=f"Failed to parse topology JSON {file_path.name}: {e}",
                file_path=str(file_path),
            )
        )
        return

    connections = data.get("connections", []) if isinstance(data, dict) else []
    for conn in connections:
        report.total_inspected += 1
        for v in rule.audit_lane_connection(conn):
            v.file_path = str(file_path)
            report.add_violation(v)
    if connections:
        report.record_coverage("connections", len(connections))

    fragments = data.get("fragments", []) if isinstance(data, dict) else []
    state: dict = {}
    for frag in fragments:
        report.total_inspected += 1
        for v in rule.audit_fragment(frag, state=state):
            v.file_path = str(file_path)
            report.add_violation(v)
    if fragments:
        report.record_coverage("fragments", len(fragments))


def format_text_report(report: ValidationReport, target: str) -> str:
    lines = ["=" * 60]
    lines.append(f"C-ITS Validator Report: {target}")
    lines.append(f"Total Inspected: {report.total_inspected}")
    lines.append(
        f"Status: {'PASSED' if report.is_valid else 'FAILED'} "
        f"({report.error_count} Errors, {report.warning_count} Warnings, {report.info_count} Info)"
    )

    missing = report.missing_categories()
    if missing:
        lines.append(f"Data Status: {empty_data_notice(missing)}")
    elif report.coverage:
        summary = ", ".join(f"{k}={v}" for k, v in sorted(report.coverage.items()))
        lines.append(f"Data Status: OK ({summary})")

    lines.append("=" * 60)

    for v in report.violations:
        prefix = f"[{v.severity.value}] {v.rule_id}"
        loc = ""
        if v.file_path:
            loc += f" {v.file_path}"
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
        default=None,
        help="Path to PCAP/PCAPNG file, source code file, or directory to scan",
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
    parser.add_argument(
        "--max-chord",
        type=float,
        default=MapemTopologyRule.DEFAULT_MAX_STOPLINE_CHORD_METERS,
        help=(
            "R03 stopline chord bound in metres "
            f"(default: {MapemTopologyRule.DEFAULT_MAX_STOPLINE_CHORD_METERS:g})"
        ),
    )
    parser.add_argument(
        "--topology",
        action="append",
        default=[],
        metavar="PATH",
        help=(
            "Audit a MAPEM topology JSON document (connections/fragments) with R03. "
            "May be given more than once."
        ),
    )
    parser.add_argument(
        "--asn1",
        action="store_true",
        help=(
            "Enable rule R06 (ASN.1/UPER conformance). Requires the optional "
            "dependency: pip install -e '.[asn1]'"
        ),
    )
    parser.add_argument(
        "--release",
        choices=["r1", "r2"],
        default="r1",
        help="ASN.1 release baseline for R06 (default: r1)",
    )
    parser.add_argument(
        "--pdu",
        metavar="HEX",
        help="Decode a single PDU given as a hex string (requires --msg-type and the ASN.1 extra)",
    )
    parser.add_argument(
        "--msg-type",
        choices=list(MESSAGE_TYPES),
        help="Message type of the --pdu payload (CAM, DENM, MAPEM, SPATEM, SREM, SSEM)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"cits-lint (cits-expert) {__version__}",
    )

    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 0

    target_path = Path(args.target) if args.target else None

    active_rules: set[str] | None = None
    if args.rules:
        active_rules = {r.strip().upper() for r in args.rules.split(",") if r.strip()}

    registry = build_default_registry(
        max_stopline_chord_meters=args.max_chord,
        enable_asn1=args.asn1,
        asn1_release=args.release,
    )
    report = ValidationReport()

    if args.pdu:
        if not args.msg_type:
            print("Error: --pdu requires --msg-type.", file=sys.stderr)
            return 2
        try:
            payload = bytes.fromhex(args.pdu.strip().replace(" ", "").replace("0x", ""))
        except ValueError as e:
            print(f"Error: --pdu is not valid hexadecimal: {e}", file=sys.stderr)
            return 2
        rule = Asn1ConformanceRule(release=args.release)
        report.total_inspected = 1
        for violation in rule.audit_pdu(payload, args.msg_type, args.release):
            report.add_violation(violation)
        if args.format == "json":
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print(format_text_report(report, f"pdu:{args.msg_type}"))
        return 0 if report.is_valid else 1

    if target_path is None and not args.topology:
        target_path = Path(".")

    if target_path is not None and target_path.is_file():
        scan_file(target_path, registry, active_rules, report)
    elif target_path is not None and target_path.is_dir():
        for file in sorted(target_path.rglob("*")):
            if not file.is_file():
                continue
            if any(part.startswith(".") for part in file.relative_to(target_path).parts):
                continue
            if file.suffix.lower() in SCAN_SUFFIXES:
                scan_file(file, registry, active_rules, report)
    elif target_path is not None and not args.topology:
        print(f"Error: Target path '{target_path}' not found.", file=sys.stderr)
        return 2

    for topo in args.topology:
        topo_path = Path(topo)
        if not topo_path.is_file():
            print(f"Error: Topology file '{topo_path}' not found.", file=sys.stderr)
            return 2
        scan_topology_file(topo_path, registry, report)

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(format_text_report(report, str(target_path) if target_path else "topology"))

    if args.strict and (report.error_count > 0 or report.warning_count > 0):
        return 1
    if not report.is_valid:
        return 1

    return 0


def main() -> None:
    sys.exit(run_cli(sys.argv[1:]))


if __name__ == "__main__":
    main()
