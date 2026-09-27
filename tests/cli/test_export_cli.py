import json
import pytest
from pathlib import Path
from cits_validator.cli.export import run_cli

SAMPLE_MAPEM = {
    "intersection_id": 101,
    "lanes": [
        {
            "lane_id": 1,
            "lane_type": "ingress",
            "nodes": [
                {"lat": 53.5501, "lon": 10.0001, "elevation": 10.0},
                {"lat": 53.5508, "lon": 10.0001, "elevation": 10.5},
            ],
            "connects_to": [{"connecting_lane_id": 11, "signal_group": 1}],
        },
        {
            "lane_id": 11,
            "lane_type": "egress",
            "nodes": [
                {"lat": 53.5502, "lon": 10.0003, "elevation": 10.0},
                {"lat": 53.5509, "lon": 10.0005, "elevation": 10.2},
            ],
        },
    ],
}

SAMPLE_LISA_XML = """<?xml version="1.0" encoding="utf-8"?>
<Versorgung>
  <Knoten KnotenName="Test Knoten" />
  <SignalGruppe Objektnr="1" Bezeichnung="K1">
    <Ansteuerung>
      <Signalbild Name="Rot" />
      <Signalbild Name="Gelb" />
      <Signalbild Name="Grün" />
    </Ansteuerung>
  </SignalGruppe>
</Versorgung>
"""


def test_cli_export_kml_stdout(tmp_path, capsys):
    mapem_file = tmp_path / "mapem.json"
    mapem_file.write_text(json.dumps(SAMPLE_MAPEM), encoding="utf-8")

    code = run_cli(["--mapem", str(mapem_file), "--format", "kml"])
    assert code == 0

    captured = capsys.readouterr()
    assert "<kml" in captured.out
    assert "Lane 1" in captured.out


def test_cli_export_geojson_file_with_lisa(tmp_path):
    mapem_file = tmp_path / "mapem.json"
    mapem_file.write_text(json.dumps(SAMPLE_MAPEM), encoding="utf-8")

    lisa_file = tmp_path / "lisa.xml"
    lisa_file.write_text(SAMPLE_LISA_XML, encoding="utf-8")

    out_file = tmp_path / "out.geojson"

    code = run_cli([
        "--mapem", str(mapem_file),
        "--lisa", str(lisa_file),
        "--format", "geojson",
        "--output", str(out_file),
    ])
    assert code == 0
    assert out_file.exists()

    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["type"] == "FeatureCollection"
    # Find feature with LISA name
    features = data["features"]
    has_k1 = any(f["properties"].get("lisa_name") == "K1" for f in features)
    assert has_k1 is True


def test_cli_export_missing_file():
    code = run_cli(["--mapem", "non_existent_file.json"])
    assert code == 2
