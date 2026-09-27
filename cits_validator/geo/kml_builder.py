"""OGC KML 2.2 3D visualizer for MAPEM intersection topologies and LISA catalogs.

Pure-Python implementation generating standards-compliant KML documents
compatible with Google Earth Pro, ArcGIS Earth, Cesium, and QGIS.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from cits_validator.lisa.models import LisaSupplyCatalog

KML_NS = "http://www.opengis.net/kml/2.2"
ET.register_namespace("", KML_NS)


def _qname(tag: str) -> str:
    """Returns qualified element name with default KML namespace."""
    return f"{{{KML_NS}}}{tag}"


def _parse_node_coord(node: Any) -> tuple[float, float, float]:
    """Extracts (lon, lat, alt) tuple from node."""
    if isinstance(node, dict):
        lat = float(node.get("lat") or node.get("latitude") or 0.0)
        lon = float(node.get("lon") or node.get("longitude") or 0.0)
        alt = float(node.get("elevation") or node.get("alt") or node.get("altitude") or 0.0)
        return lon, lat, alt
    elif isinstance(node, (list, tuple)):
        lat = float(node[0])
        lon = float(node[1])
        alt = float(node[2]) if len(node) > 2 else 0.0
        return lon, lat, alt
    return 0.0, 0.0, 0.0


def _add_style(document: ET.Element, style_id: str, kml_color_aabbggrr: str, width: int = 4) -> None:
    style = ET.SubElement(document, _qname("Style"), id=style_id)
    line_style = ET.SubElement(style, _qname("LineStyle"))
    ET.SubElement(line_style, _qname("color")).text = kml_color_aabbggrr
    ET.SubElement(line_style, _qname("width")).text = str(width)


def export_mapem_kml(
    lanes_or_topology: list[dict[str, Any]] | dict[str, Any],
    lisa_catalog: LisaSupplyCatalog | None = None,
    intersection_name: str = "C-ITS Intersection",
) -> str:
    """Exports MAPEM topology lanes to an OGC KML 2.2 3D document.

    Args:
        lanes_or_topology: List of lane dictionaries or top-level topology dictionary.
        lisa_catalog: Optional parsed LisaSupplyCatalog for enriching labels and descriptions.
        intersection_name: Intersection name displayed in KML document title.

    Returns:
        Formatted XML string of the KML 2.2 document.
    """
    if isinstance(lanes_or_topology, dict) and "lanes" in lanes_or_topology:
        lanes = lanes_or_topology["lanes"]
    elif isinstance(lanes_or_topology, list):
        lanes = lanes_or_topology
    else:
        lanes = []

    kml = ET.Element(_qname("kml"))
    document = ET.SubElement(kml, _qname("Document"))

    doc_name = ET.SubElement(document, _qname("name"))
    doc_name.text = intersection_name

    # Color palette (aabbggrr format)
    _add_style(document, "ingress-style", "ffffe500", width=4)    # Cyan
    _add_style(document, "egress-style", "ff76e600", width=4)     # Emerald
    _add_style(document, "crosswalk-style", "ff0091ff", width=4)  # Orange
    _add_style(document, "connection-style", "ff00eaff", width=3) # Yellow

    # Stopline marker style
    stopline_style = ET.SubElement(document, _qname("Style"), id="stopline-style")
    icon_style = ET.SubElement(stopline_style, _qname("IconStyle"))
    ET.SubElement(icon_style, _qname("color")).text = "ff4417ff"  # Red
    ET.SubElement(icon_style, _qname("scale")).text = "1.2"

    lanes_folder = ET.SubElement(document, _qname("Folder"))
    ET.SubElement(lanes_folder, _qname("name")).text = "Approach & Egress Lanes"

    stoplines_folder = ET.SubElement(document, _qname("Folder"))
    ET.SubElement(stoplines_folder, _qname("name")).text = "Ingress Stoplines (Node 0)"

    for lane in lanes:
        lane_id = lane.get("lane_id") if lane.get("lane_id") is not None else lane.get("laneId")
        lane_type = str(lane.get("lane_type") or lane.get("type") or "ingress")
        raw_nodes = lane.get("nodes") or []

        if not raw_nodes:
            continue

        coords = [_parse_node_coord(n) for n in raw_nodes]

        # Extract signal group
        signal_group: int | None = lane.get("signal_group") or lane.get("signalGroup")
        if signal_group is None:
            connects_to = lane.get("connects_to") or lane.get("connectsTo") or []
            if connects_to and isinstance(connects_to, list):
                for conn in connects_to:
                    sg = conn.get("signal_group") or conn.get("signalGroup")
                    if sg is not None:
                        signal_group = int(sg)
                        break

        lisa_label = ""
        desc_parts = [f"Lane ID: {lane_id}", f"Type: {lane_type}"]

        if signal_group is not None:
            desc_parts.append(f"Signal Group: {signal_group}")
            if lisa_catalog:
                sg_obj = lisa_catalog.by_obj_nr(signal_group)
                if sg_obj is not None:
                    sg_name = sg_obj.name or sg_obj.bezeichnung
                    lisa_label = f" [{sg_name}]"
                    desc_parts.append(f"LISA Name: {sg_name}")
                    desc_parts.append(f"LISA Type: {sg_obj.classification}")
                    desc_parts.append(f"LISA Aspects: {', '.join(sg_obj.aspects)}")

        # Style selection
        t = lane_type.lower()
        if "ingress" in t or "inbound" in t:
            style_url = "#ingress-style"
        elif "egress" in t or "outbound" in t:
            style_url = "#egress-style"
        elif "crosswalk" in t or "pedestrian" in t:
            style_url = "#crosswalk-style"
        else:
            style_url = "#connection-style"

        # Placemark for lane LineString
        pm = ET.SubElement(lanes_folder, _qname("Placemark"))
        ET.SubElement(pm, _qname("name")).text = f"Lane {lane_id} ({lane_type.capitalize()}){lisa_label}"
        ET.SubElement(pm, _qname("styleUrl")).text = style_url
        ET.SubElement(pm, _qname("description")).text = "\n".join(desc_parts)

        linestring = ET.SubElement(pm, _qname("LineString"))
        ET.SubElement(linestring, _qname("extrude")).text = "1"
        ET.SubElement(linestring, _qname("altitudeMode")).text = "relativeToGround"
        coords_str = " ".join(f"{lon},{lat},{alt}" for lon, lat, alt in coords)
        ET.SubElement(linestring, _qname("coordinates")).text = coords_str

        # Stopline Placemark for Node 0 of ingress lanes
        if "ingress" in t or "inbound" in t:
            stop_pm = ET.SubElement(stoplines_folder, _qname("Placemark"))
            ET.SubElement(stop_pm, _qname("name")).text = f"Stopline Lane {lane_id}{lisa_label}"
            ET.SubElement(stop_pm, _qname("styleUrl")).text = "#stopline-style"
            ET.SubElement(stop_pm, _qname("description")).text = (
                f"Stopline Node 0 for Lane {lane_id}\n" + "\n".join(desc_parts[1:])
            )
            point = ET.SubElement(stop_pm, _qname("Point"))
            ET.SubElement(point, _qname("altitudeMode")).text = "relativeToGround"
            lon0, lat0, alt0 = coords[0]
            ET.SubElement(point, _qname("coordinates")).text = f"{lon0},{lat0},{alt0}"

    xml_bytes = ET.tostring(kml, encoding="utf-8", xml_declaration=True)
    return xml_bytes.decode("utf-8")
