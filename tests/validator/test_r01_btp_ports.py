"""R01 flags BTP destination ports outside the well-known ITS table, once per port."""

from __future__ import annotations

from cits_validator.core.geonet import DLT_EN10MB
from cits_validator.core.stream import PacketRecord
from cits_validator.rules.r01_link_layer import LinkLayerRule


def _record(port: int, index: int = 1) -> PacketRecord:
    btp = port.to_bytes(2, "big") + b"\x00\x00"
    basic = bytes([0x11, 0x00, 0x1A, 0x03])
    common = bytes([0x10, 0x50, 0x00, 0x00]) + (len(btp) + 4).to_bytes(2, "big") + bytes([7, 0])
    data = b"\xff" * 6 + b"\x11" * 6 + b"\x89\x47" + basic + common + b"\x00" * 28 + btp + b"\x00" * 4
    return PacketRecord(index=index, timestamp=0.0, caplen=len(data), wirelen=len(data), data=data)


def test_unknown_port_is_reported_once_as_info():
    rule = LinkLayerRule()
    state: dict = {}

    first = rule.audit_packet(_record(2999), DLT_EN10MB, state)
    again = rule.audit_packet(_record(2999, 2), DLT_EN10MB, state)

    assert [v.severity.value for v in first] == ["INFO"]
    assert "2999" in first[0].message and first[0].packet_index == 1
    assert again == []


def test_known_ports_including_those_the_old_table_missed_are_silent():
    rule = LinkLayerRule()

    for port in (2001, 2005, 2009, 2018):
        assert rule.audit_packet(_record(port), DLT_EN10MB, {}) == [], port
