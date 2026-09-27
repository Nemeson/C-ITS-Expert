"""RFC 7946 GeoJSON exporter for MAPEM intersection topologies and LISA supply catalogs.

Pure-Python implementation without third-party GIS dependencies.
Produces valid FeatureCollection representations compatible with QGIS,
Mapbox, Kepler.gl, and geojson.io.
"""

from __future__ import annotations

from typing import Any
from cits_validator.lisa.models import LisaSupplyCatalog

COLOR_INGRESS = "#00e5ff"
COLOR_EGRESS = "#00e676"
COLOR_CROSSWALK = "#ff9100"
COLOR_BIKE = "#76ff03"
COLOR_CONNECTION = "#ffea00"
COLOR_STOPLINE = "#ff1744"


def _parse_node_coord(node: Any) -> list[float]:
    """Extracts [lon, lat, alt] from a node dict or tuple."""
    if isinstance(node, dict):
        lat = float(node.get("lat") or node.get("latitude") or 0.0)
        lon = float(node.get("lon") or node.get("longitude") or 0.0)
        alt = float(node.get("elevation") or node.get("alt") or node.get("altitude") or 0.0)
        return [lon, lat, alt]
    elif isinstance(node, (list, tuple)):
        lat = float(node[0])
        lon = float(node[1])
        alt = float(node[2]) if len(node) > 2 else 0.0
        return [lon, lat, alt]
    return [0.0, 0.0, 0.0]


def _get_lane_color(lane_type: str) -> str:
    """Returns stroke color based on lane type."""
    t = lane_type.lower()
    if "ingress" in t or "inbound" in t:
        return COLOR_INGRESS
    if "egress" in t or "outbound" in t:
        return COLOR_EGRESS
    if "crosswalk" in t or "pedestrian" in t:
        return COLOR_CROSSWALK
    if "bike" in t or "cyclist" in t:
        return COLOR_BIKE
    return COLOR_CONNECTION


def export_mapem_geojson(
    lanes_or_topology: list[dict[str, Any]] | dict[str, Any],
    lisa_catalog: LisaSupplyCatalog | None = None,
) -> dict[str, Any]:
    """Exports MAPEM topology lanes to an RFC 7946 GeoJSON FeatureCollection.

    Decorates features with LISA signal group designations and classified
    traffic participant types when a catalog is provided.

    Args:
        lanes_or_topology: List of lane dictionaries or top-level topology dictionary.
        lisa_catalog: Optional parsed LisaSupplyCatalog.

    Returns:
        dict representation of GeoJSON FeatureCollection.
    """
    if isinstance(lanes_or_topology, dict) and "lanes" in lanes_or_topology:
        lanes = lanes_or_topology["lanes"]
    elif isinstance(lanes_or_topology, list):
        lanes = lanes_or_topology
    else:
        lanes = []

    features: list[dict[str, Any]] = []

    for lane in lanes:
        lane_id = lane.get("lane_id") if lane.get("lane_id") is not None else lane.get("laneId")
        lane_type = str(lane.get("lane_type") or lane.get("type") or "ingress")
        raw_nodes = lane.get("nodes") or []

        if not raw_nodes:
            continue

        coordinates = [_parse_node_coord(n) for n in raw_nodes]

        # Extract signal group if present
        signal_group: int | None = lane.get("signal_group") or lane.get("signalGroup")
        if signal_group is None:
            connects_to = lane.get("connects_to") or lane.get("connectsTo") or []
            if connects_to and isinstance(connects_to, list):
                for conn in connects_to:
                    sg = conn.get("signal_group") or conn.get("signalGroup")
                    if sg is not None:
                        signal_group = int(sg)
                        break

        props: dict[str, Any] = {
            "lane_id": lane_id,
            "lane_type": lane_type,
            "stroke": _get_lane_color(lane_type),
            "stroke-width": 3,
        }

        if signal_group is not None:
            props["signal_group"] = signal_group
            if lisa_catalog:
                sg_obj = lisa_catalog.by_obj_nr(signal_group)
                if sg_obj is not None:
                    props["lisa_name"] = sg_obj.bezeichnung or sg_obj.name
                    props["lisa_type"] = sg_obj.classification
                    props["lisa_aspects"] = sg_obj.aspects

        # 1. Lane LineString feature
        features.append({
            "type": "Feature",
            "geometry": {
                "type": "LineString",
                "coordinates": coordinates,
            },
            "properties": props,
        })

        # 2. Ingress Stopline Marker (Node 0 is the stopline per ETSI / ISO TS 19091)
        if "ingress" in lane_type.lower() or "inbound" in lane_type.lower():
            stopline_props: dict[str, Any] = {
                "lane_id": lane_id,
                "feature_type": "stopline",
                "marker-color": COLOR_STOPLINE,
                "marker-symbol": "stop",
            }
            if signal_group is not None:
                stopline_props["signal_group"] = signal_group
                if lisa_catalog:
                    sg_obj = lisa_catalog.by_obj_nr(signal_group)
                    if sg_obj is not None:
                        stopline_props["lisa_name"] = sg_obj.bezeichnung or sg_obj.name
                        stopline_props["lisa_type"] = sg_obj.classification

            features.append({
                "type": "Feature",
                "geometry": {
                    "type": "Point",
                    "coordinates": coordinates[0],
                },
                "properties": stopline_props,
            })

    return {
        "type": "FeatureCollection",
        "features": features,
    }
