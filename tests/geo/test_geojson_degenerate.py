"""GeoJSON export must not invent positions, roles or invalid geometry."""

from __future__ import annotations

from cits_validator.geo.geojson_builder import export_mapem_geojson


def _features(lanes):
    return export_mapem_geojson(lanes)["features"]


def test_node_without_coordinates_is_skipped_not_placed_at_null_island():
    lane = {"lane_id": 1, "lane_type": "ingress", "nodes": [{"lat": 52.0, "lon": 13.0}, {}, {"lat": 52.1, "lon": 13.1}]}

    line = _features([lane])[0]

    assert line["geometry"]["coordinates"] == [[13.0, 52.0, 0.0], [13.1, 52.1, 0.0]]


def test_lane_without_a_type_is_not_labelled_ingress_and_gets_no_stopline():
    lane = {"lane_id": 1, "nodes": [{"lat": 52.0, "lon": 13.0}, {"lat": 52.1, "lon": 13.1}]}

    features = _features([lane])

    assert [f["properties"]["lane_type"] for f in features] == ["unknown"]
    assert all(f["properties"].get("feature_type") != "stopline" for f in features)


def test_single_valid_node_lane_is_a_point_not_an_invalid_linestring():
    lane = {"lane_id": 1, "lane_type": "egress", "nodes": [{"lat": 52.0, "lon": 13.0}]}

    geometry = _features([lane])[0]["geometry"]

    assert geometry == {"type": "Point", "coordinates": [13.0, 52.0, 0.0]}


def test_lane_with_no_usable_node_is_omitted():
    assert _features([{"lane_id": 1, "lane_type": "ingress", "nodes": [{}, {"lat": None}]}]) == []


def test_sequence_nodes_need_at_least_lat_and_lon():
    lane = {"lane_id": 1, "lane_type": "egress", "nodes": [(52.0, 13.0), (52.0,), (52.1, 13.1, 5.0)]}

    coords = _features([lane])[0]["geometry"]["coordinates"]

    assert coords == [[13.0, 52.0, 0.0], [13.1, 52.1, 5.0]]
