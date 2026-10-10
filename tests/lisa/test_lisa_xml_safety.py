"""LISA XML is untrusted input: DTD/entity declarations (billion laughs, XXE) are refused."""

from __future__ import annotations

import pytest

from cits_validator.lisa.parser import parse_lisa_supply

BILLION_LAUGHS = """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
]>
<Knotenpunkt name="&lol2;"><Signalgruppe ObjNr="1" Bezeichnung="K1"/></Knotenpunkt>
"""

XXE = """<?xml version="1.0"?>
<!DOCTYPE x [<!ENTITY secret SYSTEM "file:///etc/passwd">]>
<Knotenpunkt name="&secret;"/>
"""


@pytest.mark.parametrize("payload", [BILLION_LAUGHS, XXE], ids=["billion-laughs", "xxe"])
def test_doctype_and_entities_are_rejected(payload):
    with pytest.raises(ValueError, match="DTD"):
        parse_lisa_supply(payload)


def test_doctype_in_file_is_rejected(tmp_path):
    path = tmp_path / "lisa.xml"
    path.write_text(BILLION_LAUGHS, encoding="utf-8")

    with pytest.raises(ValueError, match="DTD"):
        parse_lisa_supply(path)


def test_plain_document_still_parses():
    catalog = parse_lisa_supply(
        '<Root><Knotenpunkt name="K1"><Signalgruppe ObjNr="1"/></Knotenpunkt></Root>'
    )

    assert catalog.intersection_name == "K1"


def test_utf16_encoded_doctype_cannot_bypass_the_guard(tmp_path):
    path = tmp_path / "lisa16.xml"
    path.write_bytes(BILLION_LAUGHS.encode("utf-16"))

    with pytest.raises(ValueError):
        parse_lisa_supply(path)


# --- MCP passes client text, never a path -------------------------------------------


def test_mcp_tool_never_treats_xml_content_as_a_file_path(tmp_path):
    from cits_validator.mcp.tools import cits_parse_lisa

    secret = tmp_path / "local.xml"
    secret.write_text('<Root><Knotenpunkt name="LOCAL"/></Root>', encoding="utf-8")

    with pytest.raises(ValueError):
        cits_parse_lisa(str(secret))


def test_mcp_lisa_xml_arguments_are_text_only(tmp_path):
    from cits_validator.mcp.tools import cits_export_kml

    secret = tmp_path / "local.xml"
    secret.write_text("<Root/>", encoding="utf-8")

    with pytest.raises(ValueError):
        cits_export_kml(lanes_json=[], lisa_xml=str(secret))
