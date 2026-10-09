from __future__ import annotations

from pathlib import Path
from typing import Any

from cits_validator.cli.main import build_default_registry, scan_file
from cits_validator.core.models import NO_DATA_IN_CAPTURE, ValidationReport
from cits_validator.core.registry import RuleRegistry
from cits_validator.geo.geojson_builder import export_mapem_geojson
from cits_validator.geo.glosa import compute_glosa_advisory
from cits_validator.geo.kml_builder import export_mapem_kml
from cits_validator.lisa.parser import parse_lisa_supply


def _registry(rule_ids: list[str] | None) -> tuple[RuleRegistry, set[str] | None]:
    registry = build_default_registry()
    active = {r.strip().upper() for r in rule_ids} if rule_ids else None
    return registry, active


def cits_audit_code(
    code: str,
    language: str = "python",
    rules: list[str] | None = None,
) -> dict[str, Any]:
    """Audits source code for prohibited synthetic V2X data generation and anti-patterns.

    Runs through the same rule registry as the CLI, so ``rules`` (e.g.
    ``["R02"]``) selects the active rule set identically to ``cits-lint --rules``.
    """
    registry, active = _registry(rules)
    report = ValidationReport(total_inspected=1)
    for violation in registry.audit_code(code, language=language, active_rule_ids=active):
        report.add_violation(violation)
    return report.to_dict()


def cits_inspect_hex(hex_payload: str, dlt: int = 127) -> dict[str, Any]:
    """Decodes a raw packet hex stream and checks Radiotap, 802.11, and LLC/SNAP validity."""
    clean_hex = hex_payload.strip().replace(" ", "").replace("0x", "")
    try:
        data = bytes.fromhex(clean_hex)
    except ValueError as exc:
        raise ValueError(f"hex_payload is not valid hexadecimal: {exc}") from exc

    from cits_validator.core.stream import PacketRecord

    record = PacketRecord(
        index=1,
        timestamp=0.0,
        caplen=len(data),
        wirelen=len(data),
        data=data,
    )

    registry, active = _registry(None)
    state: dict[str, Any] = {}
    report = ValidationReport(total_inspected=1)
    for violation in registry.audit_packet(record, dlt=dlt, state=state, active_rule_ids=active):
        report.add_violation(violation)

    coverage = state.get("_coverage", {})
    for category, count in coverage.items():
        report.record_coverage(category, count)
    report.metadata["dlt"] = dlt
    btp_ports = state.get("btp_ports")
    if btp_ports:
        report.metadata["btp_ports"] = {str(k): v for k, v in sorted(btp_ports.items())}
    return report.to_dict()


def cits_check_mapem(
    lanes_geojson: dict[str, Any],
    max_chord_meters: float | None = None,
) -> dict[str, Any]:
    """Validates MAPEM lane geometry, multi-fragment accumulation, and stopline chords."""
    from cits_validator.rules.r03_topology import MapemTopologyRule

    rule = MapemTopologyRule(max_stopline_chord_meters=max_chord_meters)
    report = ValidationReport()
    report.metadata["max_stopline_chord_meters"] = rule.max_stopline_chord_meters

    connections = lanes_geojson.get("connections", [])
    checked = 0
    for conn in connections:
        report.total_inspected += 1
        if conn.get("fromNode") and conn.get("toNode"):
            checked += 1
        for v in rule.audit_lane_connection(conn):
            report.add_violation(v)
    if checked:
        report.record_coverage("connections", checked)

    fragments = lanes_geojson.get("fragments", [])
    state: dict[str, Any] = {}
    for frag in fragments:
        report.total_inspected += 1
        for v in rule.audit_fragment(frag, state=state):
            report.add_violation(v)
    if fragments:
        report.record_coverage("fragments", len(fragments))

    return report.to_dict()


def cits_validate_pcap(file_path: str) -> dict[str, Any]:
    """Audits an entire PCAP/PCAPNG file against link-layer and framing invariants.

    Uses the same scanning path as the ``cits-lint`` CLI, so PCAPNG block
    handling, data-coverage reporting and per-file attribution stay identical.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")

    registry = build_default_registry()
    report = ValidationReport()
    scan_file(path, registry, None, report)
    return report.to_dict()


def cits_parse_lisa(xml_content: str) -> dict[str, Any]:
    """Parses and classifies LISA LV.XML supply into structured signal groups."""
    return parse_lisa_supply(xml_content).to_dict()


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


def cits_decode_pdu(hex_payload: str, msg_type: str, release: str = "r1") -> dict[str, Any]:
    """Decodes one ASN.1 UPER PDU and returns its structured fields.

    Requires the optional ASN.1 extra (``pip install -e '.[asn1]'``). A PDU that
    cannot be decoded raises, so the caller learns that no data was produced
    instead of receiving an empty-but-plausible structure.
    """
    from cits_validator.asn1.decoder import MESSAGE_TYPES, PduDecodeError, decode_pdu

    if msg_type.upper() not in MESSAGE_TYPES:
        raise ValueError(f"msg_type must be one of {MESSAGE_TYPES}, got {msg_type!r}")
    try:
        data = bytes.fromhex(hex_payload.strip().replace(" ", "").replace("0x", ""))
    except ValueError as exc:
        raise ValueError(f"hex_payload is not valid hexadecimal: {exc}") from exc

    try:
        result = decode_pdu(data, msg_type.upper(), release)
    except PduDecodeError as exc:
        raise ValueError(str(exc)) from exc

    payload = result.to_dict()
    payload["ok"] = True
    return payload


def cits_decode_mapem_to_geojson(
    hex_payload: str,
    release: str = "r1",
    lisa_xml: str | None = None,
) -> dict[str, Any]:
    """Decodes a MAPEM PDU and returns its lanes as an RFC 7946 GeoJSON collection.

    This is the path that turns real capture bytes into a visualisation: the
    topology is read from the decoded PDU, never from a hand-authored JSON file.
    """
    from cits_validator.geo.mapem_pdu import mapem_pdu_to_lanes

    decoded = cits_decode_pdu(hex_payload, "MAPEM", release)
    lanes = mapem_pdu_to_lanes(decoded["value"])
    lisa_catalog = parse_lisa_supply(lisa_xml) if lisa_xml else None
    collection = export_mapem_geojson(lanes, lisa_catalog=lisa_catalog)
    # An empty FeatureCollection is indistinguishable from "nothing was drawn yet".
    # The lane count and an explicit status make a PDU without geometry visible
    # instead of looking like a valid but empty map.
    collection["lane_count"] = len(lanes)
    collection["data_status"] = "OK" if lanes else "NO DATA IN CAPTURE"
    collection["message_header"] = decoded["value"].get("header", {})
    collection["standards"] = decoded.get("standards", [])
    return collection


def cits_selftest(profile: str = "host") -> dict[str, Any]:
    """Liveness/health probe for the edge daemon.

    Returns the active capability profile and the running version so a
    supervisor (systemd, a bridge, an agent) can confirm the server is up
    and which surface it is exposing.
    """
    from cits_validator import __version__

    return {"ok": True, "profile": profile, "version": __version__}


__all__ = [
    "NO_DATA_IN_CAPTURE",
    "cits_audit_code",
    "cits_check_mapem",
    "cits_compute_glosa",
    "cits_decode_mapem_to_geojson",
    "cits_decode_pdu",
    "cits_export_kml",
    "cits_inspect_hex",
    "cits_parse_lisa",
    "cits_selftest",
    "cits_validate_pcap",
]
