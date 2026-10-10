"""LISA parsing must not silently lose or invent data."""

from __future__ import annotations

from cits_validator.lisa.models import CLASS_UNKNOWN
from cits_validator.lisa.parser import classify_signal_group, parse_lisa_xml


def test_namespaced_xml_is_parsed():
    xml = (
        '<ns:Root xmlns:ns="urn:lisa"><ns:Knotenpunkt name="K1">'
        '<ns:Signalgruppe ObjNr="3" Bezeichnung="K3"/></ns:Knotenpunkt></ns:Root>'
    )

    catalog = parse_lisa_xml(xml)

    assert catalog.intersection_name == "K1"
    assert list(catalog.groups) == [3]


def test_aspects_are_never_invented():
    catalog = parse_lisa_xml('<Root><Signalgruppe ObjNr="9" Bezeichnung="X9"/></Root>')

    group = catalog.groups[9]
    assert group.aspects == []
    assert group.classification == CLASS_UNKNOWN


def test_duplicate_and_invalid_object_numbers_are_reported():
    xml = (
        '<Root><Signalgruppe ObjNr="3" Bezeichnung="K3"/>'
        '<Signalgruppe ObjNr="3" Bezeichnung="K3b"/>'
        '<Signalgruppe ObjNr="abc" Bezeichnung="K4"/></Root>'
    )

    catalog = parse_lisa_xml(xml)

    assert catalog.groups[3].bezeichnung == "K3"  # first one wins, not silently replaced
    joined = " ".join(catalog.warnings)
    assert "duplicate" in joined and "abc" in joined
    assert catalog.to_dict()["warnings"] == catalog.warnings


def test_document_without_signal_groups_warns_instead_of_looking_valid():
    catalog = parse_lisa_xml("<Root><Other/></Root>")

    assert len(catalog) == 0
    assert any("no signal groups" in w for w in catalog.warnings)


def test_aspect_matching_uses_words_not_substrings():
    assert classify_signal_group("X1", ["protected", "green"]) == CLASS_UNKNOWN
