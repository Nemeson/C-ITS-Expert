"""Converts a decoded MAPEM PDU into the lane dictionaries the exporters consume.

This is the bridge between "bytes from a capture" and "geometry on a map". One
rule governs it: a lane's coordinates come from the decoded MAPEM nodes. A lane
with no decodable nodes is omitted, and a PDU with no lanes yields an empty
list, which the callers report as "no geometry" — never a synthesised shape.

Field semantics follow ISO TS 19091 / ETSI-ITS-DSRC:

* An intersection's ``laneSet`` holds lanes directly. ``ingressApproach`` or
  ``egressApproach`` carries the approach number; a lane with neither is a
  crosswalk/bike/sidewalk lane whose role is reported as ``unknown``.
* ``nodeList`` is a CHOICE. The ``nodes`` alternative is a list of nodes whose
  ``delta`` is either ``node-XY*`` (offsets in **10 cm** units, x = lat, y = lon)
  or ``node-LatLon`` (absolute 1e-7 degrees). Offsets are relative to the lane's
  own reference point, inherited from the enclosing intersection when the lane
  does not carry one.
"""

from __future__ import annotations

import math
from typing import Any

# 10 cm per node-XY offset unit (SAE J2735 / ISO TS 19091 NodeOffsetPointXY).
_XY_UNIT_METERS = 0.1
_LL_SCALE = 10_000_000.0
_METERS_PER_DEGREE = 111_320.0

_LAT_UNAVAILABLE = 900000001
_LON_UNAVAILABLE = 1800000001


def _choice(node_list: Any) -> tuple[Any, Any]:
    r"""Unwraps an asn1tools CHOICE, which is encoded as a (name, value) tuple."""
    if isinstance(node_list, (list, tuple)) and len(node_list) == 2:
        return node_list[0], node_list[1]
    if isinstance(node_list, dict) and node_list:
        return next(iter(node_list.items()))
    return None, None


def _num(value: object) -> float | None:
    """Coerces a decoded integer field to float, or None when it is absent."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _find_ref_point(container: dict[str, Any], *fallbacks: dict[str, Any]) -> dict[str, Any]:
    """Locates the reference point a lane's deltas are anchored to.

    A candidate may be a container holding the point (``refPoint``/``refPos``) or
    the reference point itself, because callers resolve the intersection's point
    once and pass it down as a fallback.
    """
    for candidate in (container, *fallbacks):
        if not isinstance(candidate, dict):
            continue
        if candidate.get("lat") is not None and candidate.get("long") is not None:
            return candidate
        ref = candidate.get("refPoint") or candidate.get("refPos") or candidate.get("refPosition")
        if isinstance(ref, dict) and ref.get("lat") is not None:
            return ref
    return {}


def _node_to_lonlat(node: dict[str, Any], ref: dict[str, Any]) -> dict[str, float] | None:
    """Converts one node's delta to an absolute (lat, lon, elevation) point."""
    choice, value = _choice(node.get("delta"))
    if choice is None or not isinstance(value, dict):
        return None

    ref_lat = _num(ref.get("lat"))
    ref_lon = _num(ref.get("long"))
    if (
        ref_lat is None
        or ref_lon is None
        or ref_lat == _LAT_UNAVAILABLE
        or ref_lon == _LON_UNAVAILABLE
    ):
        return None

    if "LatLon" in str(choice):
        raw_lon = value.get("lon") if value.get("lon") is not None else value.get("long")
        lat = _num(value.get("lat"))
        # Node-LLmD-64b names the longitude field `lon` in some revisions and
        # `long` in others; accept either rather than reading None.
        lon = _num(raw_lon)
        if lat is None or lon is None or lat == _LAT_UNAVAILABLE or lon == _LON_UNAVAILABLE:
            return None
        return {"lat": lat / _LL_SCALE, "lon": lon / _LL_SCALE, "elevation": 0.0}

    x = _num(value.get("x"))
    y = _num(value.get("y"))
    if x is None or y is None:
        return None

    # x is the latitudinal offset, y the longitudinal one, both in 10 cm units.
    lat_deg = ref_lat / _LL_SCALE + (x * _XY_UNIT_METERS) / _METERS_PER_DEGREE
    cos_lat = max(0.01, math.cos(math.radians(ref_lat / _LL_SCALE)))
    lon_deg = ref_lon / _LL_SCALE + (y * _XY_UNIT_METERS) / (_METERS_PER_DEGREE * cos_lat)
    return {"lat": lat_deg, "lon": lon_deg, "elevation": 0.0}


def _nodes_from_lane(lane: dict[str, Any], ref: dict[str, Any]) -> list[dict[str, float]]:
    choice, value = _choice(lane.get("nodeList"))
    if choice != "nodes" or not isinstance(value, list):
        # A `computed` lane carries a mathematical description, not node points;
        # it cannot become a LineString without inventing geometry.
        return []

    nodes: list[dict[str, float]] = []
    for node in value:
        if not isinstance(node, dict):
            continue
        point = _node_to_lonlat(node, ref)
        if point is not None:
            nodes.append(point)
    return nodes


def _lane_role(lane: dict[str, Any]) -> str:
    """Ingress/egress only when the MAPEM approach fields say so."""
    if lane.get("egressApproach") is not None:
        return "egress"
    if lane.get("ingressApproach") is not None:
        return "ingress"
    # No approach number: a crosswalk, bike path, sidewalk or median lane. The
    # role is genuinely absent, so it is reported as unknown, not guessed.
    return "unknown"


def _first_signal_group(lane: dict[str, Any]) -> int | None:
    for connection in lane.get("connectsTo") or []:
        if isinstance(connection, dict) and connection.get("signalGroup") is not None:
            return connection["signalGroup"]
    return None


def _connects_to(
    lane: dict[str, Any], lanes_by_id: dict[int, dict[str, Any]]
) -> list[dict[str, Any]]:
    connections: list[dict[str, Any]] = []
    for connection in lane.get("connectsTo") or []:
        if not isinstance(connection, dict):
            continue
        connecting = connection.get("connectingLane")
        lane_ref = connecting.get("lane") if isinstance(connecting, dict) else connecting

        entry: dict[str, Any] = {"connecting_lane_id": lane_ref}
        signal_group = connection.get("signalGroup")
        if signal_group is not None:
            entry["signal_group"] = signal_group
        other = lanes_by_id.get(lane_ref) if isinstance(lane_ref, int) else None
        if other is not None:
            entry["connecting_lane_type"] = other.get("lane_type")
        connections.append(entry)
    return connections


def mapem_pdu_to_lanes(pdu_value: dict[str, Any]) -> list[dict[str, Any]]:
    """Flattens a decoded MAPEM PDU into exporter-ready lane dictionaries.

    Args:
        pdu_value: The ``value`` of a decoded MAPEM (see ``decode_pdu``).

    Returns:
        ``[{lane_id, lane_type, nodes, connects_to, signal_group}, ...]``. Lanes
        without decodable nodes are omitted; an empty list means the PDU carried
        no usable geometry.
    """
    map_body = (pdu_value or {}).get("map") or (pdu_value or {}).get("mapem") or {}
    intersections = map_body.get("intersections") or []

    raw_lanes: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for intersection in intersections:
        if not isinstance(intersection, dict):
            continue
        ref_intersection = _find_ref_point(intersection)
        for lane in intersection.get("laneSet") or intersection.get("lanes") or []:
            if not isinstance(lane, dict):
                continue
            raw_lanes.append((lane, _find_ref_point(lane, ref_intersection)))

    lanes_by_id: dict[int, dict[str, Any]] = {}
    for lane, _ref in raw_lanes:
        lane_id = lane.get("laneID", lane.get("laneId"))
        if isinstance(lane_id, int):
            lanes_by_id[lane_id] = {"lane_id": lane_id, "lane_type": _lane_role(lane)}

    lanes: list[dict[str, Any]] = []
    for lane, ref in raw_lanes:
        nodes = _nodes_from_lane(lane, ref)
        if not nodes:
            continue
        lanes.append(
            {
                "lane_id": lane.get("laneID", lane.get("laneId")),
                "lane_type": _lane_role(lane),
                "nodes": nodes,
                "connects_to": _connects_to(lane, lanes_by_id),
                "signal_group": _first_signal_group(lane),
            }
        )

    return lanes
