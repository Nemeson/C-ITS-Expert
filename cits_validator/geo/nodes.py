"""Shared extraction of map positions from lane node dictionaries/sequences."""

from __future__ import annotations

from typing import Any


def _as_float(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _first_present(node: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if node.get(key) is not None:
            return node[key]
    return None


def parse_node_coord(node: Any) -> list[float] | None:
    """Extracts [lon, lat, alt] from a node, or None when it has no position.

    A node without latitude and longitude is dropped; defaulting it to (0, 0)
    would put an invented point at "null island" into the map.
    """
    if isinstance(node, dict):
        lat = _as_float(_first_present(node, "lat", "latitude"))
        lon = _as_float(_first_present(node, "lon", "longitude"))
        alt = _as_float(_first_present(node, "elevation", "alt", "altitude"))
    elif isinstance(node, (list, tuple)) and len(node) >= 2:
        lat = _as_float(node[0])
        lon = _as_float(node[1])
        alt = _as_float(node[2]) if len(node) > 2 else None
    else:
        return None
    if lat is None or lon is None:
        return None
    return [lon, lat, alt if alt is not None else 0.0]
