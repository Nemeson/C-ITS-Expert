"""ASN.1 conformance core tests, driven by real reference vectors.

The vectors in `fixtures/` are byte-exact outputs of an independent encoder
(`asn1tools` compiled against the reviewed ETSI/ISO modules in
cits-inspector-v2) or real field captures. They are the ground truth a decoder
is measured against — not hand-written hex.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cits_validator.asn1 import (
    MESSAGE_TYPES,
    PduDecodeError,
    decode_pdu,
    is_available,
    standards_summary,
)
from cits_validator.asn1.decoder import (
    peek_message_id,
    release_for_message_id,
)
from cits_validator.asn1.provenance import (
    STANDARDS_DIR,
    load_manifest,
    modules_for_release,
    provenance_for_file,
)
from cits_validator.geo.mapem_pdu import mapem_pdu_to_lanes
from cits_validator.rules.r06_asn1_conformance import Asn1ConformanceRule

FIXTURES = Path(__file__).resolve().parent / "fixtures"

pytestmark = pytest.mark.skipif(
    not is_available(), reason="asn1tools not installed (optional [asn1] extra)"
)


def _vectors(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- #
# Vendored standards and provenance
# --------------------------------------------------------------------------- #
def test_standards_are_vendored_for_both_releases():
    for release in ("r1", "r2"):
        modules = modules_for_release(release)
        assert modules, f"no vendored modules for {release}"
        assert all(m.is_file() for m in modules)


def test_manifest_records_standard_version_and_url():
    manifest = load_manifest()
    assert len(manifest) >= 15
    for module in manifest:
        assert module.standard.startswith(("ETSI", "ISO"))
        assert module.version
        assert module.source_url.startswith("https://")


def test_provenance_lookup_by_filename():
    provenance = provenance_for_file("ITS-Container.asn")
    assert provenance is not None
    assert "102 894-2" in provenance.standard


def test_standards_summary_covers_expected_standards():
    labels = {f"{s['standard']} {s['version']}" for s in standards_summary()}
    assert "ETSI TS 103 301 v1.3.1" in labels
    assert "ETSI TS 103 301 v2.2.1" in labels
    assert "ETSI TS 102 894-2 v2.4.1" in labels


# --------------------------------------------------------------------------- #
# Decoding against reference vectors
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("message_type", ["SPATEM", "CAM", "DENM"])
@pytest.mark.parametrize("release", ["r1", "r2"])
def test_reference_vectors_decode_in_both_releases(message_type, release):
    vectors = _vectors(message_type.lower())
    decoded = 0
    for vector in vectors.values():
        hex_payload = vector.get("hex")
        if not hex_payload:
            continue
        result = decode_pdu(bytes.fromhex(hex_payload), message_type, release)
        assert result.message_type == message_type
        assert result.release == release
        assert result.byte_length == len(bytes.fromhex(hex_payload))
        assert result.value.get("header")
        decoded += 1
    assert decoded >= 3


def test_release_1_header_uses_message_id_spelling():
    result = decode_pdu(bytes.fromhex(_vectors("spatem")["minimal"]["hex"]), "SPATEM", "r1")
    assert result.value["header"]["messageID"] == 4
    assert result.value["header"]["stationID"] == 5008


def test_release_2_header_renames_fields():
    # Release 2 renamed messageID/stationID to messageId/stationId. A decoder that
    # assumed one spelling would silently read nothing in the other release.
    result = decode_pdu(bytes.fromhex(_vectors("spatem")["minimal"]["hex"]), "SPATEM", "r2")
    assert result.value["header"]["messageId"] == 4
    assert result.value["header"]["stationId"] == 5008


def test_decoded_pdu_reports_its_standards():
    result = decode_pdu(bytes.fromhex(_vectors("spatem")["minimal"]["hex"]), "SPATEM", "r1")
    joined = " ".join(result.standards)
    assert "103 301" in joined
    assert "102 894-2" in joined


def test_cam_vector_decodes_to_expected_fields():
    vector = _vectors("cam")["minimal"]
    result = decode_pdu(bytes.fromhex(vector["hex"]), "CAM", "r1")
    assert result.value["header"]["messageID"] == 2


def test_denm_vector_decodes_with_management_container():
    vector = _vectors("denm")["minimal"]
    result = decode_pdu(bytes.fromhex(vector["hex"]), "DENM", "r1")
    assert result.value["header"]["messageID"] == 1
    assert "management" in result.value["denm"]


# --------------------------------------------------------------------------- #
# Real field captures
# --------------------------------------------------------------------------- #
def test_real_mapem_fragments_decode():
    vectors = _vectors("mapem_real")
    assert len(vectors) >= 2
    for name, vector in vectors.items():
        result = decode_pdu(bytes.fromhex(vector["hex"]), "MAPEM", "r1")
        assert result.value["header"]["messageID"] == 5, name
        # Multi-fragment MAPEMs are told apart by layerID (21 ingress / 22 egress).
        assert vector["layer_id"] in (21, 22), name


def test_real_mapem_yields_lane_geometry():
    vectors = _vectors("mapem_real")
    total = 0
    for vector in vectors.values():
        result = decode_pdu(bytes.fromhex(vector["hex"]), "MAPEM", "r1")
        lanes = mapem_pdu_to_lanes(result.value)
        total += len(lanes)
        for lane in lanes:
            assert lane["nodes"], "a lane without nodes must not be emitted"
            for node in lane["nodes"]:
                assert 45.0 <= node["lat"] <= 56.0, node  # German corridors
                assert 5.0 <= node["lon"] <= 15.5, node
    assert total >= 40, f"expected real geometry, got {total} lanes"


def test_real_mapem_lanes_carry_signal_groups():
    vectors = _vectors("mapem_real")
    groups: set[int] = set()
    for vector in vectors.values():
        result = decode_pdu(bytes.fromhex(vector["hex"]), "MAPEM", "r1")
        for lane in mapem_pdu_to_lanes(result.value):
            if lane["signal_group"] is not None:
                groups.add(lane["signal_group"])
    assert groups, "no signal group was resolved from real MAPEM connectsTo"


def test_ingress_and_egress_are_distinguished_by_approach_field():
    vectors = _vectors("mapem_real")
    roles: set[str] = set()
    for vector in vectors.values():
        result = decode_pdu(bytes.fromhex(vector["hex"]), "MAPEM", "r1")
        roles.update(lane["lane_type"] for lane in mapem_pdu_to_lanes(result.value))
    assert "ingress" in roles
    assert "egress" in roles


# --------------------------------------------------------------------------- #
# Failure modes: an encoding fault is reported, never a partial decode
# --------------------------------------------------------------------------- #
def test_truncated_pdu_raises():
    full = bytes.fromhex(_vectors("spatem")["minimal"]["hex"])
    with pytest.raises(PduDecodeError):
        decode_pdu(full[:8], "SPATEM", "r1")


def test_garbage_pdu_raises():
    with pytest.raises(PduDecodeError):
        decode_pdu(b"\xff" * 40, "SPATEM", "r1")


def test_empty_pdu_raises():
    with pytest.raises(PduDecodeError, match="Empty"):
        decode_pdu(b"", "SPATEM", "r1")


def test_unknown_release_raises():
    with pytest.raises(PduDecodeError, match="release"):
        decode_pdu(b"\x02\x04\x00\x00\x00\x01", "SPATEM", "r9")


def test_unknown_message_type_raises():
    with pytest.raises(PduDecodeError, match="message type"):
        decode_pdu(b"\x02\x04\x00\x00\x00\x01", "NOPE", "r1")


def test_message_family_from_header_id():
    assert release_for_message_id(2) == "CAM"
    assert release_for_message_id(4) == "SPATEM"
    assert release_for_message_id(99) is None


def test_peek_message_id_reads_second_byte():
    payload = bytes.fromhex(_vectors("spatem")["minimal"]["hex"])
    assert peek_message_id(payload) == 4
    assert peek_message_id(b"\x02") is None


# --------------------------------------------------------------------------- #
# Rule R06
# --------------------------------------------------------------------------- #
def test_r06_reports_info_on_valid_pdu():
    rule = Asn1ConformanceRule(release="r1")
    violations = rule.audit_pdu(bytes.fromhex(_vectors("spatem")["minimal"]["hex"]), "SPATEM")
    assert len(violations) == 1
    assert violations[0].rule_id == "R06"
    assert violations[0].severity.value == "INFO"


def test_r06_reports_error_on_malformed_pdu():
    rule = Asn1ConformanceRule(release="r1")
    violations = rule.audit_pdu(b"\xff" * 32, "SPATEM")
    assert len(violations) == 1
    assert violations[0].severity.value == "ERROR"
    assert violations[0].offending_sample


def test_r06_rejects_bad_release_argument():
    with pytest.raises(ValueError):
        Asn1ConformanceRule(release="r3")


def test_r06_packet_path_skips_secured_frames():
    # A secured GeoNetworking frame must be counted, never decoded as plaintext.
    from cits_validator.core.geonet import DLT_EN10MB
    from tests.validator.test_v130_integrity import _geonet_tsb_frame, _record

    secured = b"\xff" * 6 + b"\x11" * 6 + b"\x89\x47" + _geonet_tsb_frame(2001, secured=True)
    rule = Asn1ConformanceRule()
    state: dict = {}
    assert rule.audit_packet(_record(secured), dlt=DLT_EN10MB, state=state) == []
    assert state["secured_undecodable"] == 1


def test_r06_standards_dir_exists():
    assert Path(Asn1ConformanceRule.standards_dir()).is_dir()
    assert STANDARDS_DIR.is_dir()


def test_message_types_constant_is_complete():
    assert set(MESSAGE_TYPES) == {
        "CAM",
        "DENM",
        "MAPEM",
        "SPATEM",
        "SREM",
        "SSEM",
        "CPM",
        "VAM",
    }
