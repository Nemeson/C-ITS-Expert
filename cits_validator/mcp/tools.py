from __future__ import annotations

from pathlib import Path
from typing import Any

from cits_validator.core.models import ValidationReport
from cits_validator.core.stream import PacketRecord, PcapStreamingIterator
from cits_validator.rules.r01_link_layer import LinkLayerRule
from cits_validator.rules.r02_anti_fake import AntiHallucinationRule
from cits_validator.rules.r03_topology import MapemTopologyRule


def cits_audit_code(code: str, language: str = "python") -> dict[str, Any]:
    """Audits source code for prohibited synthetic V2X data generation and anti-patterns."""
    rule = AntiHallucinationRule()
    violations = rule.audit_code(code, language=language)

    report = ValidationReport(total_inspected=1, violations=violations)
    return report.to_dict()


def cits_inspect_hex(hex_payload: str, dlt: int = 127) -> dict[str, Any]:
    """Decodes a raw packet hex stream and checks Radiotap, 802.11, and LLC/SNAP validity."""
    clean_hex = hex_payload.strip().replace(" ", "").replace("0x", "")
    data = bytes.fromhex(clean_hex)

    record = PacketRecord(
        index=1,
        timestamp=0.0,
        caplen=len(data),
        wirelen=len(data),
        data=data,
    )

    rule = LinkLayerRule()
    state: dict[str, Any] = {}
    violations = rule.audit_packet(record, dlt=dlt, state=state)

    report = ValidationReport(total_inspected=1, violations=violations, metadata=state)
    return report.to_dict()


def cits_check_mapem(lanes_geojson: dict[str, Any]) -> dict[str, Any]:
    """Validates MAPEM lane geometry, multi-fragment accumulation, and stopline chords."""
    rule = MapemTopologyRule()
    report = ValidationReport()

    connections = lanes_geojson.get("connections", [])
    for conn in connections:
        report.total_inspected += 1
        for v in rule.audit_lane_connection(conn):
            report.add_violation(v)

    fragments = lanes_geojson.get("fragments", [])
    state: dict[str, Any] = {}
    for frag in fragments:
        report.total_inspected += 1
        for v in rule.audit_fragment(frag, state=state):
            report.add_violation(v)

    return report.to_dict()


def cits_validate_pcap(file_path: str) -> dict[str, Any]:
    """Audits an entire PCAP file against link-layer and framing invariants."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")

    streamer = PcapStreamingIterator()
    rule = LinkLayerRule()
    report = ValidationReport()
    state: dict[str, Any] = {}

    with open(path, "rb") as f:
        header = streamer.read_header(f)
        for record in streamer.iter_records(f):
            report.total_inspected += 1
            for v in rule.audit_packet(record, dlt=header.dlt, state=state):
                report.add_violation(v)

    report.metadata["dlt"] = header.dlt
    report.metadata["is_nanosecond"] = header.is_nanosecond
    return report.to_dict()
