"""Node-XY offsets are 1 cm units, X = East (longitude), Y = North (latitude).

Source: vendored DSRC.asn (Node-XY / Offset-B* definitions): "units of 1 centimeter",
"offset is positive to the East (X) and to the North (Y) directions".
"""

import math

import pytest

from cits_validator.geo.mapem_pdu import mapem_pdu_to_lanes

REF_LAT_E7 = 520000000  # 52.0 deg
REF_LON_E7 = 130000000  # 13.0 deg
METERS_PER_DEGREE = 111_320.0


def _pdu(x: int, y: int) -> dict:
    return {
        "map": {
            "intersections": [
                {
                    "refPoint": {"lat": REF_LAT_E7, "long": REF_LON_E7},
                    "laneSet": [
                        {
                            "laneID": 1,
                            "ingressApproach": 1,
                            "nodeList": ("nodes", [{"delta": ("node-XY3", {"x": x, "y": y})}]),
                        }
                    ],
                }
            ],
        }
    }


def _node(x: int, y: int) -> dict:
    return mapem_pdu_to_lanes(_pdu(x, y))[0]["nodes"][0]


def test_x_offset_moves_east_in_centimeters():
    node = _node(x=10_000, y=0)  # 100 m east

    expected_dlon = 100.0 / (METERS_PER_DEGREE * math.cos(math.radians(52.0)))
    assert node["lon"] - 13.0 == pytest.approx(expected_dlon, rel=1e-6)
    assert node["lat"] == pytest.approx(52.0, abs=1e-9)


def test_y_offset_moves_north_in_centimeters():
    node = _node(x=0, y=10_000)  # 100 m north

    assert node["lat"] - 52.0 == pytest.approx(100.0 / METERS_PER_DEGREE, rel=1e-6)
    assert node["lon"] == pytest.approx(13.0, abs=1e-9)


def test_negative_offsets_move_west_and_south():
    node = _node(x=-10_000, y=-10_000)

    assert node["lon"] < 13.0
    assert node["lat"] < 52.0
