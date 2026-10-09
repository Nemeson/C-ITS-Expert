"""ASN.1 wiring tests: R06 packet path, MCP tools, CLI and export PDU pipeline."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cits_validator.asn1 import decode_pdu, is_available
from cits_validator.core.geonet import DLT_EN10MB

FIXTURES = Path(__file__).resolve().parent / "fixtures"

pytestmark = pytest.mark.skipif(
    not is_available(), reason="asn1tools not installed (optional [asn1] extra)"
)


def _spatem_hex() -> str:
    return json.loads((FIXTURES / "spatem.json").read_text(encoding="utf-8"))["minimal"]["hex"]


def _mapem_hex() -> str:
    data = json.loads((FIXTURES / "mapem_real.json").read_text(encoding="utf-8"))
    return next(iter(data.values()))["hex"]


def _plaintext_geonet_frame(payload: bytes, btp_port: int = 2004) -> bytes:
    """Builds an Ethernet + GeoNetworking TSB frame carrying a real PDU payload."""
    basic = bytes([0x11, 0x00, 0x1A, 0x03])  # version 1, nextHeader 1 (common)
    common = (
        bytes([0x10, 0x50, 0x00, 0x00])
        + (len(payload) + 4).to_bytes(2, "little")
        + bytes([0x07, 0x00])
    )
    extended = b"\x00" * 28  # TSB single hop: 4 reserved + LongPositionVector
    btp = btp_port.to_bytes(2, "big") + b"\x00\x00"
    return b"\xff" * 6 + b"\x11" * 6 + b"\x89\x47" + basic + common + extended + btp + payload


def _record(data: bytes):
    from cits_validator.core.stream import PacketRecord

    return PacketRecord(index=1, timestamp=0.0, caplen=len(data), wirelen=len(data), data=data)


# --------------------------------------------------------------------------- #
# R06 packet path
# --------------------------------------------------------------------------- #
def test_r06_packet_path_decodes_plaintext_spatem():
    from cits_validator.rules.r06_asn1_conformance import Asn1ConformanceRule

    frame = _plaintext_geonet_frame(bytes.fromhex(_spatem_hex()), btp_port=2004)
    state: dict = {}
    violations = Asn1ConformanceRule(release="r1").audit_packet(
        _record(frame), dlt=DLT_EN10MB, state=state
    )
    assert state.get("decoded_SPATEM") == 1
    # A successful decode yields no violation on the packet path.
    assert violations == []


def test_r06_packet_path_reports_malformed_payload_once():
    from cits_validator.rules.r06_asn1_conformance import Asn1ConformanceRule

    frame = _plaintext_geonet_frame(b"\xff" * 40, btp_port=2004)
    state: dict = {}
    rule = Asn1ConformanceRule(release="r1")

    first = rule.audit_packet(_record(frame), dlt=DLT_EN10MB, state=state)
    assert len(first) == 1
    assert first[0].severity.value == "ERROR"
    assert first[0].packet_index == 1

    # The identical repeat is counted but not re-listed.
    assert rule.audit_packet(_record(frame), dlt=DLT_EN10MB, state=state) == []
    assert state["decode_failures_SPATEM"] == 2


def test_r06_packet_path_skips_unknown_btp_port():
    from cits_validator.rules.r06_asn1_conformance import Asn1ConformanceRule

    frame = _plaintext_geonet_frame(b"\x00" * 20, btp_port=2099)
    state: dict = {}
    assert Asn1ConformanceRule().audit_packet(_record(frame), dlt=DLT_EN10MB, state=state) == []


def test_r06_packet_path_ignores_non_geonetworking():
    from cits_validator.rules.r06_asn1_conformance import Asn1ConformanceRule

    frame = b"\xff" * 6 + b"\x11" * 6 + b"\x08\x00" + b"\x00" * 40  # IPv4
    assert Asn1ConformanceRule().audit_packet(_record(frame), dlt=DLT_EN10MB, state={}) == []


def test_r06_sampling_limit_is_respected():
    from cits_validator.rules.r06_asn1_conformance import Asn1ConformanceRule

    frame = _plaintext_geonet_frame(bytes.fromhex(_spatem_hex()), btp_port=2004)
    state: dict = {}
    rule = Asn1ConformanceRule(release="r1", max_decodes_per_type=2)
    for _ in range(5):
        rule.audit_packet(_record(frame), dlt=DLT_EN10MB, state=state)
    assert state["seen_SPATEM"] == 5
    assert state["decoded_SPATEM"] == 2  # only the sampled frames were decoded


# --------------------------------------------------------------------------- #
# MCP tools
# --------------------------------------------------------------------------- #
def test_mcp_cits_decode_pdu_returns_fields_and_standards():
    from cits_validator.mcp.tools import cits_decode_pdu

    result = cits_decode_pdu(_spatem_hex(), "SPATEM")
    assert result["ok"] is True
    assert result["message_type"] == "SPATEM"
    assert result["value"]["header"]["messageID"] == 4
    assert result["standards"]


def test_mcp_cits_decode_pdu_rejects_bad_inputs():
    from cits_validator.mcp.tools import cits_decode_pdu

    with pytest.raises(ValueError, match="hexadecimal"):
        cits_decode_pdu("zz", "SPATEM")
    with pytest.raises(ValueError, match="msg_type"):
        cits_decode_pdu("0204", "NOPE")
    with pytest.raises(ValueError):
        cits_decode_pdu("deadbeef", "SPATEM")


def test_mcp_decode_mapem_to_geojson_yields_features():
    from cits_validator.mcp.tools import cits_decode_mapem_to_geojson

    collection = cits_decode_mapem_to_geojson(_mapem_hex())
    assert collection["type"] == "FeatureCollection"
    assert collection["lane_count"] > 0
    assert collection["data_status"] == "OK"
    linears = [f for f in collection["features"] if f["geometry"]["type"] == "LineString"]
    assert linears, "no lane geometry produced"


def test_mcp_decode_mapem_to_geojson_flags_missing_geometry():
    """A PDU that decodes but carries no lane geometry must say so, not look empty-but-fine."""
    from cits_validator.mcp.tools import cits_decode_mapem_to_geojson

    # A SPATEM decodes as MAPEM-shaped bytes but has no intersections/lanes.
    collection = cits_decode_mapem_to_geojson(_spatem_hex())
    assert collection["lane_count"] == 0
    assert collection["data_status"] == "NO DATA IN CAPTURE"
    assert collection["features"] == []


def test_mcp_server_exposes_decode_tools():
    from cits_validator.mcp.server import McpServer

    server = McpServer()
    names = [t["name"] for t in server.TOOL_DEFINITIONS]
    assert "cits_decode_pdu" in names
    assert "cits_decode_mapem_to_geojson" in names

    response = server.handle_request(
        {
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "cits_decode_pdu",
                "arguments": {"hex_payload": _spatem_hex(), "msg_type": "SPATEM"},
            },
        }
    )
    payload = json.loads(response["result"]["content"][0]["text"])
    assert payload["ok"] is True


def test_mcp_server_reports_decode_failure_as_error():
    from cits_validator.mcp.server import McpServer

    response = McpServer().handle_request(
        {
            "id": 8,
            "method": "tools/call",
            "params": {
                "name": "cits_decode_pdu",
                "arguments": {"hex_payload": "ff" * 30, "msg_type": "SPATEM"},
            },
        }
    )
    assert response["result"]["isError"] is True


# --------------------------------------------------------------------------- #
# CLI --pdu and --asn1
# --------------------------------------------------------------------------- #
def test_cli_pdu_decodes_and_reports_standards(capsys):
    from cits_validator.cli.main import run_cli

    assert run_cli(["--pdu", _spatem_hex(), "--msg-type", "SPATEM", "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["total_inspected"] == 1
    assert any("decoded" in v["message"] for v in report["violations"])


def test_cli_pdu_failure_exits_one(capsys):
    from cits_validator.cli.main import run_cli

    assert run_cli(["--pdu", "ff" * 30, "--msg-type", "SPATEM", "--format", "json"]) == 1


def test_cli_pdu_without_msg_type_exits_two(capsys):
    from cits_validator.cli.main import run_cli

    assert run_cli(["--pdu", _spatem_hex()]) == 2
    assert "msg-type" in capsys.readouterr().err


def test_cli_pdu_with_bad_hex_exits_two(capsys):
    from cits_validator.cli.main import run_cli

    assert run_cli(["--pdu", "zz", "--msg-type", "SPATEM"]) == 2
    assert "hexadecimal" in capsys.readouterr().err


def test_cli_registers_asn1_rule_only_when_asked():
    from cits_validator.cli.main import build_default_registry

    assert build_default_registry().get_rule("R06") is None
    assert build_default_registry(enable_asn1=True).get_rule("R06") is not None
    assert build_default_registry(enable_asn1=True, asn1_release="r2") is not None


# --------------------------------------------------------------------------- #
# Export --pdu
# --------------------------------------------------------------------------- #
def test_export_pdu_produces_geojson_without_a_mapem_file(tmp_path):
    from cits_validator.cli.export import run_cli

    out = tmp_path / "pdu.geojson"
    assert run_cli(["--pdu", _mapem_hex(), "--format", "geojson", "--output", str(out)]) == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["type"] == "FeatureCollection"
    assert data["features"], "no features from a decoded PDU"


def test_export_requires_a_source(capsys):
    from cits_validator.cli.export import run_cli

    assert run_cli(["--format", "kml"]) == 2
    assert "required" in capsys.readouterr().err


def test_export_pdu_decode_failure_exits_one(capsys):
    from cits_validator.cli.export import run_cli

    assert run_cli(["--pdu", "ff" * 30]) == 1
    assert "decoding failed" in capsys.readouterr().err


def test_export_pdu_without_geometry_is_refused(capsys):
    """A MAPEM that decodes but yields no nodes must not produce an empty map silently."""
    from cits_validator.cli.export import run_cli
    from cits_validator.geo.mapem_pdu import mapem_pdu_to_lanes

    # A SPATEM does decode, but it has no lane geometry.
    assert mapem_pdu_to_lanes(decode_pdu(bytes.fromhex(_spatem_hex()), "SPATEM", "r1").value) == []
    assert run_cli(["--pdu", _spatem_hex(), "--format", "geojson"]) == 1
    assert "no usable lane geometry" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# mapem_pdu adapter edges
# --------------------------------------------------------------------------- #
def test_adapter_ignores_computed_lanes():
    from cits_validator.geo.mapem_pdu import mapem_pdu_to_lanes

    pdu = {
        "map": {
            "intersections": [
                {
                    "refPoint": {"lat": 525201000, "long": 134000000},
                    "laneSet": [
                        {
                            "laneID": 1,
                            "ingressApproach": 1,
                            "nodeList": ("computed", {"refPoint": {"lat": 1, "long": 2}}),
                        }
                    ],
                }
            ]
        }
    }
    # A computed lane has no node points; emitting one would invent geometry.
    assert mapem_pdu_to_lanes(pdu) == []


def test_adapter_empty_pdu_yields_no_lanes():
    from cits_validator.geo.mapem_pdu import mapem_pdu_to_lanes

    assert mapem_pdu_to_lanes({}) == []
    assert mapem_pdu_to_lanes({"map": {}}) == []


def test_adapter_reports_unknown_role_for_lanes_without_approach():
    from cits_validator.geo.mapem_pdu import mapem_pdu_to_lanes

    pdu = {
        "map": {
            "intersections": [
                {
                    "refPoint": {"lat": 525201000, "long": 134000000},
                    "laneSet": [
                        {
                            "laneID": 9,  # no ingress/egress approach number
                            "nodeList": ("nodes", [{"delta": ("node-XY1", {"x": 0, "y": 0})}]),
                        }
                    ],
                }
            ]
        }
    }
    lanes = mapem_pdu_to_lanes(pdu)
    assert len(lanes) == 1
    assert lanes[0]["lane_type"] == "unknown"


def test_adapter_skips_nodes_with_unavailable_reference():
    from cits_validator.geo.mapem_pdu import mapem_pdu_to_lanes

    pdu = {
        "map": {
            "intersections": [
                {
                    "refPoint": {"lat": 900000001, "long": 1800000001},  # unavailable sentinels
                    "laneSet": [
                        {
                            "laneID": 1,
                            "ingressApproach": 1,
                            "nodeList": ("nodes", [{"delta": ("node-XY1", {"x": 10, "y": 10})}]),
                        }
                    ],
                }
            ]
        }
    }
    assert mapem_pdu_to_lanes(pdu) == []


def test_adapter_supports_absolute_latlon_nodes():
    from cits_validator.geo.mapem_pdu import mapem_pdu_to_lanes

    pdu = {
        "map": {
            "intersections": [
                {
                    "refPoint": {"lat": 525201000, "long": 134000000},
                    "laneSet": [
                        {
                            "laneID": 2,
                            "egressApproach": 1,
                            "nodeList": (
                                "nodes",
                                [{"delta": ("node-LatLon", {"lat": 525201500, "long": 134000500})}],
                            ),
                        }
                    ],
                }
            ]
        }
    }
    lanes = mapem_pdu_to_lanes(pdu)
    assert len(lanes) == 1
    assert lanes[0]["lane_type"] == "egress"
    assert abs(lanes[0]["nodes"][0]["lat"] - 52.5201500) < 1e-9
