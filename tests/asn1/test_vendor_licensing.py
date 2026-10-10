"""Licence bookkeeping for the vendored standards text (BSD-3-Clause from ETSI, ISO-derived files)."""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from cits_validator.asn1.provenance import STANDARDS_DIR, load_manifest

ROOT = Path(__file__).resolve().parents[2]
LICENSE_FILE = STANDARDS_DIR / "LICENSE-ETSI.txt"

# Files whose text is authored by ISO. ETSI republishes them, but ISO's own licence only
# covers unmodified use, so the redistribution right is unconfirmed (see NOTICE).
ISO_DERIVED = {
    "r1/ISO-TS-19091-DSRC.raw.asn",
    "r1/ISO24534-3_ElectronicRegistrationIdentificationVehicleDataModule-patched.asn",
    "r2/DSRC.asn",
}


def test_every_module_records_its_licence():
    modules = load_manifest()

    assert modules
    assert [m.file for m in modules if not m.license] == []


def test_only_the_iso_derived_files_are_flagged_unconfirmed():
    flagged = {m.file for m in load_manifest() if "unconfirmed" in m.license}

    assert flagged == ISO_DERIVED


def test_other_modules_are_attributed_to_etsi_under_bsd_3_clause():
    for module in load_manifest():
        if module.file not in ISO_DERIVED:
            assert module.license.startswith("BSD-3-Clause (Copyright "), module.file
            assert module.license.endswith(" ETSI)"), module.file


def test_source_urls_point_at_existing_etsi_repositories():
    urls = {m.source_url for m in load_manifest()}

    assert not any("ITS_ASN1" in u or u.endswith("/vam_ts103300") for u in urls)
    assert "https://forge.etsi.org/rep/ITS/asn1/vam-ts103300_3" in urls
    assert "https://forge.etsi.org/rep/ITS/asn1/cdd_ts102894_2" in urls


def test_licence_text_is_shipped_with_every_copyright_year():
    text = LICENSE_FILE.read_text(encoding="utf-8")

    for sentence in (
        "Redistributions of source code must retain the above copyright notice",
        "Redistributions in binary form must reproduce the above copyright notice",
        "Neither the name of the copyright holder",
        'THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"',
    ):
        assert sentence in text

    years = {m.license.split("Copyright ")[1].split(" ")[0] for m in load_manifest() if m.file not in ISO_DERIVED}
    for year in years:
        assert f"Copyright {year} ETSI" in text


def test_licence_file_is_part_of_the_package_data():
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    patterns = pyproject["tool"]["setuptools"]["package-data"]["cits_validator"]

    assert "asn1/standards/LICENSE-ETSI.txt" in patterns


@pytest.mark.parametrize("name", sorted(ISO_DERIVED))
def test_notice_names_each_iso_derived_file(name):
    notice = (ROOT / "NOTICE").read_text(encoding="utf-8")

    assert name.split("/")[-1] in notice
    assert "LICENSE-ETSI.txt" in notice
