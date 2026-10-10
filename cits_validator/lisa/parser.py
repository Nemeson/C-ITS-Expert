from __future__ import annotations

import codecs
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Sequence

from cits_validator.lisa.models import (
    CLASS_BICYCLE,
    CLASS_PEDESTRIAN,
    CLASS_TRANSIT,
    CLASS_UNKNOWN,
    CLASS_VEHICLE,
    LisaSignalGroup,
    LisaSupplyCatalog,
)


def classify_signal_group(bezeichnung: str, aspects: Sequence[str]) -> str:
    upper = bezeichnung.strip().upper()
    aspects_lower = [a.lower() for a in aspects]

    has_yellow = any("gelb" in a or "yellow" in a for a in aspects_lower)
    has_green = any("gruen" in a or "grün" in a or "green" in a for a in aspects_lower)
    has_red = any("rot" in a or "red" in a for a in aspects_lower)

    if upper.startswith("F") or upper.startswith("FG") or "FUSS" in upper:
        return CLASS_PEDESTRIAN
    if upper.startswith("R") or upper.startswith("RAD") or (upper.startswith("B") and "BIKE" in upper):
        return CLASS_BICYCLE
    if (
        upper.startswith("B")
        or upper.startswith("BUS")
        or upper.startswith("TRAM")
        or upper.startswith("STRAB")
        or upper.startswith("Ö")
        or upper.startswith("OE")
        or "ÖPNV" in upper
        or "OEPNV" in upper
    ):
        return CLASS_TRANSIT
    if upper.startswith("K") or upper.startswith("KFZ") or upper.startswith("SG"):
        return CLASS_VEHICLE

    # Fallback by aspects: Red + Green without Yellow is typical pedestrian
    if has_red and has_green and not has_yellow:
        return CLASS_PEDESTRIAN
    if has_red and has_yellow and has_green:
        return CLASS_VEHICLE

    return CLASS_UNKNOWN


def _get_ci_attrib(el: ET.Element, *candidates: str) -> str | None:
    for c in candidates:
        for k, v in el.attrib.items():
            if k.lower() == c.lower():
                return v
    return None


_DTD_MARKERS = (b"<!doctype", b"<!entity")


def _parse_untrusted_xml(data: bytes) -> ET.Element:
    """Parses LISA XML bytes, refusing DTD/entity declarations (entity expansion, XXE).

    ElementTree expands internal entities (billion laughs). LISA supply files never
    need a DTD, so rejecting it keeps the parser dependency-free and safe.
    """
    # UTF-16/32 would hide the ASCII markers below from the byte scan.
    if bytes(1) in data or data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        raise ValueError("UTF-16/UTF-32 encoded LISA XML is not supported")

    lowered = data.lower()
    if any(marker in lowered for marker in _DTD_MARKERS):
        raise ValueError("DTD/entity declarations are not allowed in LISA XML")
    try:
        return ET.fromstring(data)
    except ET.ParseError as exc:
        raise ValueError(f"Invalid LISA XML: {exc}") from exc


def parse_lisa_xml(xml_text: str) -> LisaSupplyCatalog:
    """Parses LISA XML given as *text*; never touches the filesystem.

    Use this for untrusted callers (MCP clients). ``parse_lisa_supply`` also accepts
    file paths and is meant for the CLI, where the user names the file themselves.
    """
    if not isinstance(xml_text, str):
        raise ValueError("xml_text must be a string")
    return _catalog_from_root(_parse_untrusted_xml(xml_text.encode("utf-8")))


def parse_lisa_supply(xml_text_or_path: str | Path) -> LisaSupplyCatalog:
    if isinstance(xml_text_or_path, Path) or (
        isinstance(xml_text_or_path, str) and not xml_text_or_path.strip().startswith("<")
    ):
        data = Path(xml_text_or_path).read_bytes()
    else:
        data = xml_text_or_path.encode("utf-8")
    return _catalog_from_root(_parse_untrusted_xml(data))


def _catalog_from_root(root: ET.Element) -> LisaSupplyCatalog:

    catalog = LisaSupplyCatalog()

    # Find intersection name
    knoten = root.find(".//Knotenpunkt")
    if knoten is None:
        knoten = root.find(".//Knoten")
    if knoten is not None:
        catalog.intersection_name = _get_ci_attrib(knoten, "name", "knotenname")

    # Find all signal groups (case-tolerant tags)
    for el in root.iter():
        tag_lower = el.tag.lower()
        if tag_lower in ("signalgruppe", "signalgroup", "signal_group", "sg"):
            obj_nr_str = (
                _get_ci_attrib(el, "objnr", "obj_nr", "objektnr", "id")
                or el.findtext("ObjNr")
                or el.findtext("obj_nr")
                or el.findtext("Objektnr")
            )
            if not obj_nr_str:
                continue

            try:
                obj_nr = int(obj_nr_str)
            except ValueError:
                continue

            bezeichnung = (
                _get_ci_attrib(el, "bezeichnung", "name")
                or el.findtext("Bezeichnung")
                or el.findtext("bezeichnung")
                or f"SG {obj_nr}"
            ).strip()

            name = (
                _get_ci_attrib(el, "kommentar", "description")
                or el.findtext("Kommentar")
                or el.findtext("kommentar")
                or bezeichnung
            ).strip()

            aspects: list[str] = []
            ansteuerung = el.find("Ansteuerung")
            if ansteuerung is None:
                ansteuerung = el.find("ansteuerung")

            if ansteuerung is not None:
                for aspect_el in ansteuerung:
                    aspect_name = (
                        _get_ci_attrib(aspect_el, "name", "signalbild", "aspect", "bezeichnung")
                        or (aspect_el.text and aspect_el.text.strip())
                        or aspect_el.tag
                    )
                    if aspect_name:
                        aspects.append(aspect_name.strip())
            else:
                aspects = ["Rot", "Gelb", "Gruen"]

            classification = classify_signal_group(bezeichnung, aspects)
            group = LisaSignalGroup(
                obj_nr=obj_nr,
                bezeichnung=bezeichnung,
                name=name,
                classification=classification,
                aspects=aspects,
                is_pedestrian=(classification == CLASS_PEDESTRIAN),
            )
            catalog.groups[obj_nr] = group

    return catalog
