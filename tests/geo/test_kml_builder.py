import pytest
import xml.etree.ElementTree as ET
from cits_validator.geo.kml_builder import export_mapem_kml
from cits_validator.lisa.models import LisaSupplyCatalog, LisaSignalGroup


def test_export_mapem_kml_structure_and_coords():
    lanes = [
        {
            "lane_id": 1,
            "lane_type": "ingress",
            "nodes": [
                {"lat": 53.5501, "lon": 10.0001, "elevation": 12.5},
                {"lat": 53.5508, "lon": 10.0001, "elevation": 13.0},
            ],
            "connects_to": [{"connecting_lane_id": 11, "signal_group": 1}],
        },
        {
            "lane_id": 11,
            "lane_type": "egress",
            "nodes": [
                {"lat": 53.5502, "lon": 10.0003, "elevation": 12.5},
                {"lat": 53.5509, "lon": 10.0005, "elevation": 12.8},
            ],
        },
    ]

    catalog = LisaSupplyCatalog(
        intersection_name="Test Intersection",
        groups={
            1: LisaSignalGroup(
                obj_nr=1,
                name="K1",
                classification="vehicle",
                aspects=["Rot", "Gelb", "Grün"],
            )
        },
    )

    kml_str = export_mapem_kml(lanes, lisa_catalog=catalog, intersection_name="Knoten 42")

    assert kml_str.startswith("<?xml") or "<kml" in kml_str
    # Verify XML validity
    root = ET.fromstring(kml_str)
    # Check namespace
    assert "http://www.opengis.net/kml/2.2" in root.tag

    # Verify Placemarks exist
    placemarks = root.findall(".//{http://www.opengis.net/kml/2.2}Placemark")
    assert len(placemarks) >= 2

    # Check 3D coordinates formatting: lon,lat,alt
    coords_elements = root.findall(".//{http://www.opengis.net/kml/2.2}coordinates")
    found_lane1_coords = False
    for el in coords_elements:
        text = el.text.strip()
        if "10.0001,53.5501,12.5" in text and "10.0001,53.5508,13.0" in text:
            found_lane1_coords = True
            break
    assert found_lane1_coords is True

    # Check that LISA name K1 appears in placemark name or description
    found_lisa = any("K1" in (pm.findtext("{http://www.opengis.net/kml/2.2}name") or "") or
                     "K1" in (pm.findtext("{http://www.opengis.net/kml/2.2}description") or "")
                     for pm in placemarks)
    assert found_lisa is True
