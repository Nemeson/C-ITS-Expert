"""CLI for exporting MAPEM intersection topologies to 3D KML and GeoJSON."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from cits_validator.geo.geojson_builder import export_mapem_geojson
from cits_validator.geo.kml_builder import export_mapem_kml
from cits_validator.lisa.models import LisaSupplyCatalog
from cits_validator.lisa.parser import parse_lisa_supply


def run_cli(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cits-export",
        description="Export MAPEM intersection topologies to 3D KML and RFC 7946 GeoJSON with LISA supply metadata.",
    )
    parser.add_argument(
        "-m",
        "--mapem",
        help="Path to MAPEM JSON file (containing lanes or topology)",
    )
    parser.add_argument(
        "--pdu",
        metavar="HEX",
        help="Raw MAPEM PDU as a hex string; decoded directly to geometry (needs the ASN.1 extra)",
    )
    parser.add_argument(
        "--release",
        choices=["r1", "r2"],
        default="r1",
        help="ASN.1 release baseline for --pdu decoding (default: r1)",
    )
    parser.add_argument(
        "-l",
        "--lisa",
        help="Optional path to LISA LV.XML supply file for signal group enrichment",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["kml", "geojson"],
        default="kml",
        help="Export format: kml (default) or geojson",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Path to output file (defaults to stdout if omitted)",
    )
    parser.add_argument(
        "-n",
        "--name",
        default="C-ITS Intersection",
        help="Intersection name for KML document title (default: 'C-ITS Intersection')",
    )
    parser.add_argument(
        "--rules-json",
        action="store_true",
        help="Emit the machine-readable rule catalog as JSON and exit",
    )

    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 0

    if args.rules_json:
        from cits_validator.rules.export import export_rule_catalog

        print(json.dumps(export_rule_catalog(), indent=2))
        return 0

    if not args.mapem and not args.pdu:
        print("Error: one of --mapem or --pdu is required.", file=sys.stderr)
        return 2

    lisa_catalog: LisaSupplyCatalog | None = None
    if args.lisa:
        lisa_path = Path(args.lisa)
        if not lisa_path.is_file():
            print(f"Error: LISA supply file '{lisa_path}' not found.", file=sys.stderr)
            return 2
        try:
            xml_text = lisa_path.read_text(encoding="utf-8")
            lisa_catalog = parse_lisa_supply(xml_text)
        except Exception as e:
            print(f"Error: Failed to parse LISA supply XML '{lisa_path}': {e}", file=sys.stderr)
            return 2

    if args.pdu:
        # Decode the PDU first, then treat the resulting lanes exactly like a
        # hand-authored topology — one code path, so both produce identical output.
        from cits_validator.asn1.decoder import PduDecodeError, decode_pdu
        from cits_validator.geo.mapem_pdu import mapem_pdu_to_lanes

        try:
            raw = bytes.fromhex(args.pdu.strip().replace(" ", "").replace("0x", ""))
        except ValueError as e:
            print(f"Error: --pdu is not valid hexadecimal: {e}", file=sys.stderr)
            return 2
        try:
            decoded = decode_pdu(raw, "MAPEM", args.release)
        except PduDecodeError as e:
            print(f"Error: MAPEM PDU decoding failed: {e}", file=sys.stderr)
            return 1
        lanes = mapem_pdu_to_lanes(decoded.value)
        if not lanes:
            print(
                "Error: the decoded MAPEM carried no usable lane geometry. "
                "No geometry was synthesised.",
                file=sys.stderr,
            )
            return 1
        mapem_data: Any = {"lanes": lanes}
    else:
        mapem_path = Path(args.mapem)
        if not mapem_path.is_file():
            print(f"Error: MAPEM file '{mapem_path}' not found.", file=sys.stderr)
            return 2
        try:
            mapem_data = json.loads(mapem_path.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"Error: Failed to parse MAPEM JSON file '{mapem_path}': {e}", file=sys.stderr)
            return 2

    if args.format == "geojson":
        result_dict = export_mapem_geojson(mapem_data, lisa_catalog=lisa_catalog)
        content = json.dumps(result_dict, indent=2, ensure_ascii=False)
    else:
        name = args.name
        if name == "C-ITS Intersection" and lisa_catalog and lisa_catalog.intersection_name:
            name = lisa_catalog.intersection_name
        content = export_mapem_kml(mapem_data, lisa_catalog=lisa_catalog, intersection_name=name)

    if args.output:
        out_path = Path(args.output)
        try:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(content, encoding="utf-8")
        except Exception as e:
            print(f"Error: Failed to write output file '{out_path}': {e}", file=sys.stderr)
            return 1
    else:
        print(content)

    return 0


def main() -> None:
    sys.exit(run_cli(sys.argv[1:]))


if __name__ == "__main__":
    main()
