"""KML export follows the same no-invention rules as GeoJSON."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from cits_validator.geo.kml_builder import export_mapem_kml

NS = {"k": "http://www.opengis.net/kml/2.2"}


def _kml(lanes):
    return ET.fromstring(export_mapem_kml(lanes).encode("utf-8"))


def test_node_without_coordinates_is_not_placed_at_null_island():
    lane = {"lane_id": 1, "lane_type": "egress", "nodes": [{"lat": 52.0, "lon": 13.0}, {}, {"lat": 52.1, "lon": 13.1}]}

    text = _kml([lane]).find(".//k:LineString/k:coordinates", NS).text

    assert text == "13.0,52.0,0.0 13.1,52.1,0.0"


def test_lane_without_a_type_is_unknown_and_has_no_stopline():
    lane = {"lane_id": 1, "nodes": [{"lat": 52.0, "lon": 13.0}, {"lat": 52.1, "lon": 13.1}]}

    root = _kml([lane])

    assert "(Unknown)" in root.find(".//k:Placemark/k:name", NS).text
    assert root.findall(".//k:Point", NS) == []


def test_single_node_lane_is_a_point_placemark():
    lane = {"lane_id": 1, "lane_type": "egress", "nodes": [{"lat": 52.0, "lon": 13.0}]}

    root = _kml([lane])

    assert root.findall(".//k:LineString", NS) == []
    assert root.find(".//k:Point/k:coordinates", NS).text == "13.0,52.0,0.0"
