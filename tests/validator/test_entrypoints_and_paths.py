"""Entry points, version fallback, path-sandbox edge cases and export CLI errors."""

from __future__ import annotations

import importlib
import importlib.metadata
import os
import subprocess
import sys
from pathlib import Path

import pytest

import cits_validator
from cits_validator.cli.export import run_cli as export_main
from cits_validator.mcp.security import ensure_path_allowed

ROOT = Path(__file__).resolve().parents[2]


def test_python_dash_m_entry_point_runs():
    proc = subprocess.run(
        [sys.executable, "-m", "cits_validator", "--version"],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )

    assert proc.returncode == 0
    assert cits_validator.__version__ in (proc.stdout + proc.stderr)


def test_version_falls_back_when_distribution_metadata_is_missing(monkeypatch):
    def missing(_name):
        raise importlib.metadata.PackageNotFoundError

    monkeypatch.setattr(importlib.metadata, "version", missing)
    try:
        importlib.reload(cits_validator)
        assert cits_validator.__version__ == "0.0.0+source"
    finally:
        monkeypatch.undo()
        importlib.reload(cits_validator)


def test_sibling_directory_sharing_a_name_prefix_is_not_inside_the_root(tmp_path):
    root = tmp_path / "data"
    sibling = tmp_path / "data2"
    root.mkdir()
    sibling.mkdir()

    with pytest.raises(PermissionError):
        ensure_path_allowed(sibling / "f.pcap", (root,))


def test_symlink_pointing_outside_the_root_is_refused(tmp_path):
    root = tmp_path / "root"
    outside = tmp_path / "outside.pcap"
    root.mkdir()
    outside.write_bytes(b"")
    link = root / "link.pcap"
    try:
        os.symlink(outside, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted on this system")

    with pytest.raises(PermissionError):
        ensure_path_allowed(link, (root,))


@pytest.mark.parametrize(
    "argv",
    [
        ["--mapem", "missing.json"],
        ["--pdu", "zz-not-hex"],
        ["--pdu", "00", "--lisa", "missing.xml"],
        [],
    ],
    ids=["missing-mapem", "bad-hex", "missing-lisa", "no-input"],
)
def test_export_cli_reports_bad_input_with_exit_code_2(argv, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    assert export_main(argv) == 2
    assert capsys.readouterr().err


def test_export_cli_rejects_invalid_mapem_json(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")

    assert export_main(["--mapem", str(bad)]) == 2
    assert "Failed to parse MAPEM JSON" in capsys.readouterr().err
