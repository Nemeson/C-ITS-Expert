#!/usr/bin/env python3
"""Vendors the reviewed ETSI/ISO ASN.1 modules into cits_validator.

The source of truth is the reviewed standards corpus maintained in the sibling
``cits-inspector-v2`` project (``docs/standards``). Only the modules the
conformance core actually compiles are copied, so the package stays small and
every vendored file is recorded in ``manifest.json`` with its standard, version
and origin.

Usage:
    python scripts/vendor_asn1.py [--source <corpus>] [--dest <dir>]
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

DEFAULT_SOURCE = Path(r"C:/PythonTools/cits-inspector-v2/docs/standards/asn")
DEFAULT_DEST = Path(__file__).resolve().parent.parent / "cits_validator" / "asn1" / "standards"

# (relative source path, release, standard, version, message scope, source URL)
MODULES: list[tuple[str, str, str, str, str, str]] = [
    # Release 1 — Common Data Dictionary
    (
        "cdd/ts102894-2/v1.3.1/ITS-Container.asn",
        "r1",
        "ETSI TS 102 894-2",
        "v1.3.1",
        "CDD",
        "https://forge.etsi.org/rep/ITS/asn1/ITS_ASN1",
    ),
    # Release 1 — Infrastructure (SPATEM/MAPEM/SREM/SSEM) + its DSRC and ISO deps
    (
        "infrastructure/ts103301/v1.3.1/SPATEM-PDU-Descriptions.asn",
        "r1",
        "ETSI TS 103 301",
        "v1.3.1",
        "SPATEM",
        "https://forge.etsi.org/rep/ITS/asn1/is_ts103301",
    ),
    (
        "infrastructure/ts103301/v1.3.1/MAPEM-PDU-Descriptions.asn",
        "r1",
        "ETSI TS 103 301",
        "v1.3.1",
        "MAPEM",
        "https://forge.etsi.org/rep/ITS/asn1/is_ts103301",
    ),
    (
        "infrastructure/ts103301/v1.3.1/SREM-PDU-Descriptions.asn",
        "r1",
        "ETSI TS 103 301",
        "v1.3.1",
        "SREM",
        "https://forge.etsi.org/rep/ITS/asn1/is_ts103301",
    ),
    (
        "infrastructure/ts103301/v1.3.1/SSEM-PDU-Descriptions.asn",
        "r1",
        "ETSI TS 103 301",
        "v1.3.1",
        "SSEM",
        "https://forge.etsi.org/rep/ITS/asn1/is_ts103301",
    ),
    (
        "infrastructure/ts103301/v2.2.1/reference/ISO-TS-19091-DSRC.raw.asn",
        "r1",
        "ISO TS 19091",
        "ed-2",
        "DSRC (SPAT/MAP/SRM/SSM)",
        "https://standards.iso.org/iso/ts/19091",
    ),
    (
        "infrastructure/ts103301/v2.1.1/iso-patched/"
        "ISO24534-3_ElectronicRegistrationIdentificationVehicleDataModule-patched.asn",
        "r1",
        "ISO 24534-3",
        "ed-3",
        "ElectronicRegistrationIdentificationVehicleDataModule",
        "https://standards.iso.org/iso/24534/-3",
    ),
    # Release 1 — CAM / DENM
    (
        "cam/en302637-2/v1.4.1/CAM-PDU-Descriptions.asn",
        "r1",
        "ETSI EN 302 637-2",
        "v1.4.1",
        "CAM",
        "https://forge.etsi.org/rep/ITS/asn1/cam_en302637_2",
    ),
    (
        "denm/en302637-3/v1.3.1/DENM-PDU-Descriptions.asn",
        "r1",
        "ETSI EN 302 637-3",
        "v1.3.1",
        "DENM",
        "https://forge.etsi.org/rep/ITS/asn1/denm_en302637_3",
    ),
    # Release 2 — Common Data Dictionary
    (
        "cdd/ts102894-2/v2.4.1/ETSI-ITS-CDD.asn",
        "r2",
        "ETSI TS 102 894-2",
        "v2.4.1",
        "CDD",
        "https://forge.etsi.org/rep/ITS/asn1/ITS_ASN1",
    ),
    # Release 2 — Infrastructure + DSRC
    (
        "infrastructure/ts103301/v2.2.1/SPATEM-PDU-Descriptions.asn",
        "r2",
        "ETSI TS 103 301",
        "v2.2.1",
        "SPATEM",
        "https://forge.etsi.org/rep/ITS/asn1/is_ts103301",
    ),
    (
        "infrastructure/ts103301/v2.2.1/MAPEM-PDU-Descriptions.asn",
        "r2",
        "ETSI TS 103 301",
        "v2.2.1",
        "MAPEM",
        "https://forge.etsi.org/rep/ITS/asn1/is_ts103301",
    ),
    (
        "infrastructure/ts103301/v2.2.1/SREM-PDU-Descriptions.asn",
        "r2",
        "ETSI TS 103 301",
        "v2.2.1",
        "SREM",
        "https://forge.etsi.org/rep/ITS/asn1/is_ts103301",
    ),
    (
        "infrastructure/ts103301/v2.2.1/SSEM-PDU-Descriptions.asn",
        "r2",
        "ETSI TS 103 301",
        "v2.2.1",
        "SSEM",
        "https://forge.etsi.org/rep/ITS/asn1/is_ts103301",
    ),
    (
        "infrastructure/ts103301/v2.2.1/DSRC.asn",
        "r2",
        "ISO TS 19091 / ETSI TS 103 301",
        "v2.2.1",
        "ETSI-ITS-DSRC",
        "https://forge.etsi.org/rep/ITS/asn1/is_ts103301",
    ),
    # Release 2 — CAM / DENM
    (
        "cam/ts103900/v2.3.1/CAM-PDU-Descriptions.asn",
        "r2",
        "ETSI TS 103 900",
        "v2.3.1",
        "CAM",
        "https://forge.etsi.org/rep/ITS/asn1/cam_ts103900",
    ),
    (
        "denm/ts103831/v2.3.1/DENM-PDU-Descriptions.asn",
        "r2",
        "ETSI TS 103 831",
        "v2.3.1",
        "DENM",
        "https://forge.etsi.org/rep/ITS/asn1/denm_ts103831",
    ),
]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--dest", type=Path, default=DEFAULT_DEST)
    args = parser.parse_args(argv[1:])

    if not args.source.is_dir():
        print(f"Source corpus not found: {args.source}", file=sys.stderr)
        return 2

    args.dest.mkdir(parents=True, exist_ok=True)
    manifest = {"source": str(args.source), "modules": []}

    for rel, release, standard, version, scope, url in MODULES:
        src = args.source / rel
        if not src.is_file():
            print(f"MISSING {rel}", file=sys.stderr)
            return 1
        target_dir = args.dest / release
        target_dir.mkdir(parents=True, exist_ok=True)
        dst = target_dir / src.name
        shutil.copy2(src, dst)
        manifest["modules"].append(
            {
                "file": f"{release}/{src.name}",
                "release": release,
                "standard": standard,
                "version": version,
                "scope": scope,
                "source_url": url,
                "source_path": rel,
            }
        )
        print(f"[OK] {release}/{src.name}")

    (args.dest / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    print(f"[OK] manifest.json ({len(manifest['modules'])} modules)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
