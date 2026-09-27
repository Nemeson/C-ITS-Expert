from __future__ import annotations

from pathlib import Path
from typing import Any

from cits_validator.core.models import ValidationReport
from cits_validator.core.stream import PacketRecord, PcapStreamingIterator
from cits_validator.geo.glosa import compute_glosa_advisory
from cits_validator.geo.kml_builder import export_mapem_kml
from cits_validator.lisa.parser import parse_lisa_supply
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


def cits_parse_lisa(xml_content: str) -> dict[str, Any]:
    """Parses and classifies LISA LV.XML supply into structured signal groups."""
    catalog = parse_lisa_supply(xml_content)
    return catalog.to_dict()


def cits_compute_glosa(
    distance_m: float,
    speed_kmh: float,
    phase_state: str,
    time_to_phase_end_s: float,
    next_green_duration_s: float = 0.0,
    speed_limit_kmh: float = 50.0,
) -> dict[str, Any]:
    """Computes instant GLOSA speed advisory window and vehicle recommendation."""
    advisory = compute_glosa_advisory(
        distance_m=distance_m,
        current_speed_kmh=speed_kmh,
        speed_limit_kmh=speed_limit_kmh,
        phase_state=phase_state,
        time_to_phase_end_s=time_to_phase_end_s,
        next_green_duration_s=next_green_duration_s,
    )
    return {
        "speed_min_kmh": advisory.speed_min_kmh,
        "speed_max_kmh": advisory.speed_max_kmh,
        "recommendation": advisory.recommendation,
        "time_to_stopline_s": advisory.time_to_stopline_s,
        "is_pass_possible": advisory.is_pass_possible,
        "details": advisory.details,
    }


def cits_export_kml(
    lanes_json: dict[str, Any] | list[dict[str, Any]],
    lisa_xml: str | None = None,
    intersection_name: str = "C-ITS Intersection",
) -> dict[str, Any]:
    """Exports MAPEM topology lanes to an OGC KML 2.2 3D document."""
    lisa_catalog = parse_lisa_supply(lisa_xml) if lisa_xml else None
    kml_str = export_mapem_kml(
        lanes_json, lisa_catalog=lisa_catalog, intersection_name=intersection_name
    )
    return {"kml": kml_str}

