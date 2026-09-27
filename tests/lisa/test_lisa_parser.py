from cits_validator.lisa.models import (
    CLASS_BICYCLE,
    CLASS_PEDESTRIAN,
    CLASS_TRANSIT,
    CLASS_VEHICLE,
)
from cits_validator.lisa.parser import parse_lisa_supply

SAMPLE_LISA_XML = """<?xml version="1.0" encoding="UTF-8"?>
<LISA_Supply>
  <Knotenpunkt name="Kreuzung B170 / Windbergstraße">
    <SignalgruppeListe>
      <Signalgruppe ObjNr="1" Bezeichnung="K1" Kommentar="B170 Nord (Dresden)">
        <Ansteuerung>
          <Rot/>
          <Gelb/>
          <Gruen/>
        </Ansteuerung>
      </Signalgruppe>
      <Signalgruppe ObjNr="5" Bezeichnung="F5" Kommentar="Fußgänger B170 Nord">
        <Ansteuerung>
          <Rot/>
          <Gruen/>
        </Ansteuerung>
      </Signalgruppe>
      <Signalgruppe ObjNr="11" Bezeichnung="K11" Kommentar="Separater Rechtsabbieger">
        <Ansteuerung>
          <Gelb/>
          <Gruen/>
        </Ansteuerung>
      </Signalgruppe>
      <Signalgruppe ObjNr="17" Bezeichnung="R17" Kommentar="Radfahrer Windberg">
        <Ansteuerung>
          <Rot/>
          <Gelb/>
          <Gruen/>
        </Ansteuerung>
      </Signalgruppe>
      <Signalgruppe ObjNr="20" Bezeichnung="B1" Kommentar="ÖPNV Bus Sonderphase">
        <Ansteuerung>
          <Rot/>
          <Gelb/>
          <Gruen/>
        </Ansteuerung>
      </Signalgruppe>
    </SignalgruppeListe>
  </Knotenpunkt>
</LISA_Supply>
"""


def test_parse_lisa_supply_groups():
    catalog = parse_lisa_supply(SAMPLE_LISA_XML)
    assert len(catalog) == 5
    assert catalog.intersection_name == "Kreuzung B170 / Windbergstraße"

    k1 = catalog.by_obj_nr(1)
    assert k1.bezeichnung == "K1"
    assert k1.classification == CLASS_VEHICLE
    assert k1.is_pedestrian is False

    f5 = catalog.by_obj_nr(5)
    assert f5.bezeichnung == "F5"
    assert f5.classification == CLASS_PEDESTRIAN
    assert f5.is_pedestrian is True

    # K11 has only Gelb+Gruen, but is classified as vehicle
    k11 = catalog.by_obj_nr(11)
    assert k11.bezeichnung == "K11"
    assert k11.classification == CLASS_VEHICLE
    assert k11.is_pedestrian is False

    r17 = catalog.by_obj_nr(17)
    assert r17.bezeichnung == "R17"
    assert r17.classification == CLASS_BICYCLE

    b1 = catalog.by_obj_nr(20)
    assert b1.bezeichnung == "B1"
    assert b1.classification == CLASS_TRANSIT


def test_missing_obj_nr_returns_none():
    catalog = parse_lisa_supply(SAMPLE_LISA_XML)
    assert catalog.by_obj_nr(999) is None


def test_lisa_aspect_attribute_signalbild_and_german_transit_prefix():
    xml = """<?xml version="1.0" encoding="utf-8"?>
    <Versorgung>
      <Knoten Name="Marienplatz" />
      <SignalGruppe Objektnr="30" Bezeichnung="Ö1" Kommentar="Tram Linie 19">
        <Ansteuerung>
          <Signalbild Name="Rot" />
          <Signalbild Name="Gelb" />
          <Signalbild Name="Grün" />
        </Ansteuerung>
      </SignalGruppe>
      <SignalGruppe Objektnr="31" Bezeichnung="OE2" Kommentar="Bus Metro">
        <Ansteuerung>
          <Signalbild Name="F0" />
        </Ansteuerung>
      </SignalGruppe>
    </Versorgung>"""

    catalog = parse_lisa_supply(xml)
    o1 = catalog.by_obj_nr(30)
    assert o1 is not None
    assert o1.bezeichnung == "Ö1"
    assert o1.classification == CLASS_TRANSIT
    assert o1.aspects == ["Rot", "Gelb", "Grün"]

    oe2 = catalog.by_obj_nr(31)
    assert oe2 is not None
    assert oe2.bezeichnung == "OE2"
    assert oe2.classification == CLASS_TRANSIT

