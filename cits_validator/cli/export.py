"""CLI for exporting MAPEM intersection topologies to 3D KML and GeoJSON."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

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
        required=True,
        help="Path to MAPEM JSON file (containing lanes or topology)",
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

    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 0

    mapem_path = Path(args.mapem)
    if not mapem_path.is_file():
        print(f"Error: MAPEM file '{mapem_path}' not found.", file=sys.stderr)
        return 2

    try:
        mapem_data = json.loads(mapem_path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"Error: Failed to parse MAPEM JSON file '{mapem_path}': {e}", file=sys.stderr)
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

    if args.format == "geojson":
        result_dict = export_mapem_geojson(mapem_data, lisa_catalog=lisa_catalog)
        content = json.dumps(result_dict, indent=2, ensure_ascii=False)
    else:
        name = args.name
        if lisa_catalog and lisa_catalog.intersection_name:
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
