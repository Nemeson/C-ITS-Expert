from cits_validator.geo.geojson_builder import export_mapem_geojson
from cits_validator.lisa.models import LisaSignalGroup, LisaSupplyCatalog


def test_export_mapem_geojson_basic():
    lanes = [
        {
            "lane_id": 1,
            "lane_type": "ingress",
            "nodes": [
                {"lat": 53.5501, "lon": 10.0001, "elevation": 15.0},
                {"lat": 53.5508, "lon": 10.0001, "elevation": 15.2},
            ],
            "connects_to": [{"connecting_lane_id": 11, "signal_group": 2}],
        },
        {
            "lane_id": 11,
            "lane_type": "egress",
            "nodes": [
                {"lat": 53.5502, "lon": 10.0003, "elevation": 15.0},
                {"lat": 53.5509, "lon": 10.0005, "elevation": 15.1},
            ],
        },
    ]

    catalog = LisaSupplyCatalog(
        intersection_name="Test Knotepunkt",
        groups={
            2: LisaSignalGroup(
                obj_nr=2,
                name="K2",
                classification="vehicle",
                aspects=["Rot", "Gelb", "Grün"],
            )
        },
    )

    geojson = export_mapem_geojson(lanes, lisa_catalog=catalog)

    assert geojson["type"] == "FeatureCollection"
    assert len(geojson["features"]) >= 2

    # Find the ingress lane LineString feature
    lane1_features = [
        f for f in geojson["features"]
        if f["properties"].get("lane_id") == 1 and f["geometry"]["type"] == "LineString"
    ]
    assert len(lane1_features) == 1
    lane1 = lane1_features[0]

    # Coordinates format: [lon, lat, alt]
    coords = lane1["geometry"]["coordinates"]
    assert len(coords) == 2
    assert coords[0] == [10.0001, 53.5501, 15.0]
    assert coords[1] == [10.0001, 53.5508, 15.2]

    # Decorated LISA properties
    props = lane1["properties"]
    assert props["lane_type"] == "ingress"
    assert props["signal_group"] == 2
    assert props["lisa_name"] == "K2"
    assert props["lisa_type"] == "vehicle"

    # Stopline marker for ingress lane Node 0
    stoplines = [
        f for f in geojson["features"]
        if f["properties"].get("feature_type") == "stopline" and f["properties"].get("lane_id") == 1
    ]
    assert len(stoplines) == 1
    assert stoplines[0]["geometry"]["type"] == "Point"
    assert stoplines[0]["geometry"]["coordinates"] == [10.0001, 53.5501, 15.0]
