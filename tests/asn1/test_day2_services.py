"""CPM and VAM conformance: Release 2 day-2 services, and the BTP port registry.

Both vectors are byte-exact output of an independent encoder (`asn1tools`
compiled against the vendored ETSI modules), the same standard the other ASN.1
fixtures are held to.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cits_validator.asn1 import PduDecodeError, decode_pdu, is_available
from cits_validator.core.geonet import BTP_PORTS, message_type_for_port
from cits_validator.rules.r06_asn1_conformance import Asn1ConformanceRule

FIXTURES = Path(__file__).resolve().parent / "fixtures"

pytestmark = pytest.mark.skipif(
    not is_available(), reason="asn1tools not installed (optional [asn1] extra)"
)


def _fixture(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- #
# BTP port registry (ETSI TS 103 248 Table 1)
# --------------------------------------------------------------------------- #
def test_btp_ports_match_etsi_ts_103_248_table_1():
    # Table 1 of ETSI TS 103 248 v2.4.1. These values decide which decoder runs
    # for a captured frame, so a wrong entry silently mis-decodes traffic.
    expected = {
        2001: "CAM",
        2002: "DENM",
        2003: "MAPEM",
        2004: "SPATEM",
        2005: "SAEM",
        2006: "IVIM",
        2007: "SREM",
        2008: "SSEM",
        2009: "CPM",
        2010: "EVCSN",
        2018: "VAM",
    }
    for port, name in expected.items():
        assert BTP_PORTS.get(port) == name, f"port {port} should be {name}"


def test_vam_is_not_on_port_2010():
    # The standard assigns 2 010 to the EVCSN POI message and 2 018 to VA (VAM).
    # VAM on 2010 was carried over from a neighbouring implementation and is
    # wrong; this test keeps the correction from being reverted by habit.
    assert BTP_PORTS[2010] != "VAM"
    assert BTP_PORTS[2018] == "VAM"


def test_cpm_is_on_port_2009():
    assert BTP_PORTS[2009] == "CPM"
    assert message_type_for_port(2009) == "CPM"
    assert message_type_for_port(2018) == "VAM"


# --------------------------------------------------------------------------- #
# CPM
# --------------------------------------------------------------------------- #
def test_cpm_decodes_in_release_2():
    vector = _fixture("cpm")
    result = decode_pdu(bytes.fromhex(vector["minimal"]["hex"]), "CPM", "r2")
    assert result.value["header"]["messageId"] == 14
    assert result.value["header"]["stationId"] == 7788
    assert "managementContainer" in result.value["payload"]
    assert result.byte_length == len(bytes.fromhex(vector["minimal"]["hex"]))


def test_cpm_top_level_type_is_collective_perception_message_not_cpm():
    # The ASN.1 PDU type is `CollectivePerceptionMessage`; asking the decoder for
    # "CPM" must still work because the mapping is explicit.
    result = decode_pdu(bytes.fromhex(_fixture("cpm")["minimal"]["hex"]), "CPM", "r2")
    assert result.message_type == "CPM"


def test_cpm_reports_its_standards():
    result = decode_pdu(bytes.fromhex(_fixture("cpm")["minimal"]["hex"]), "CPM", "r2")
    assert any("103 324" in s for s in result.standards)


def test_cpm_has_no_release_1_baseline():
    # CPM is a Release 2 service; decoding it as R1 would use the wrong CDD
    # module. Refusing is the only honest answer.
    with pytest.raises(PduDecodeError, match="Release 2 service"):
        decode_pdu(bytes.fromhex(_fixture("cpm")["minimal"]["hex"]), "CPM", "r1")


def test_cpm_management_container_fields_survive_the_roundtrip():
    result = decode_pdu(bytes.fromhex(_fixture("cpm")["minimal"]["hex"]), "CPM", "r2")
    management = result.value["payload"]["managementContainer"]
    assert management["referenceTime"] == 1234567
    assert management["referencePosition"]["latitude"] == 505000000


# --------------------------------------------------------------------------- #
# VAM
# --------------------------------------------------------------------------- #
def test_vam_decodes_in_release_2():
    vector = _fixture("vam")
    result = decode_pdu(bytes.fromhex(vector["minimal"]["hex"]), "VAM", "r2")
    assert result.value["header"]["messageId"] == 16
    assert result.value["header"]["stationId"] == 9911


def test_vam_carries_a_vru_station_type():
    result = decode_pdu(bytes.fromhex(_fixture("vam")["minimal"]["hex"]), "VAM", "r2")
    basic = result.value["vam"]["vamParameters"]["basicContainer"]
    assert basic["stationType"] == 1  # pedestrian
    assert basic["referencePosition"]["latitude"] == 525200000


def test_vam_high_frequency_container_is_present():
    result = decode_pdu(bytes.fromhex(_fixture("vam")["minimal"]["hex"]), "VAM", "r2")
    hfc = result.value["vam"]["vamParameters"]["vruHighFrequencyContainer"]
    assert hfc["speed"]["speedValue"] == 120
    assert hfc["heading"]["value"] == 900


def test_vam_has_no_release_1_baseline():
    with pytest.raises(PduDecodeError, match="Release 2 service"):
        decode_pdu(bytes.fromhex(_fixture("vam")["minimal"]["hex"]), "VAM", "r1")


# --------------------------------------------------------------------------- #
# Failure modes shared by the new types
# --------------------------------------------------------------------------- #
def test_cpm_and_vam_reject_garbage():
    for message_type in ("CPM", "VAM"):
        with pytest.raises(PduDecodeError):
            decode_pdu(b"\xff" * 32, message_type, "r2")


def test_cpm_bytes_do_not_decode_as_vam():
    # Both are R2, so only the structure distinguishes them.
    with pytest.raises(PduDecodeError):
        decode_pdu(bytes.fromhex(_fixture("cpm")["minimal"]["hex"]), "VAM", "r2")


def test_r06_accepts_cpm_on_the_pdu_path():
    rule = Asn1ConformanceRule(release="r2")
    violations = rule.audit_pdu(bytes.fromhex(_fixture("cpm")["minimal"]["hex"]), "CPM")
    assert len(violations) == 1
    assert violations[0].severity.value == "INFO"


def test_r06_reports_cpm_decode_failure():
    rule = Asn1ConformanceRule(release="r2")
    violations = rule.audit_pdu(b"\xff" * 24, "CPM")
    assert violations[0].severity.value == "ERROR"


def test_cpm_vam_are_advertised_message_types():
    from cits_validator.asn1.decoder import MESSAGE_TYPES, R2_ONLY

    assert "CPM" in MESSAGE_TYPES
    assert "VAM" in MESSAGE_TYPES
    assert set(R2_ONLY) == {"CPM", "VAM"}
