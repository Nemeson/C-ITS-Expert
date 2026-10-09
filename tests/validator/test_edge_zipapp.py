import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_zipapp_builds_and_runs_without_asn1(tmp_path):
    out = tmp_path / "cits-edge.pyz"
    subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "build_edge_zipapp.py"), "--output", str(out)],
        check=True,
        capture_output=True,
    )
    assert out.is_file()

    with zipfile.ZipFile(out) as z:
        names = z.namelist()

    # No third-party ASN.1 dependency may be bundled.
    assert not any("asn1tools" in n for n in names)
    # The vendored standard data is excluded from the device distribution.
    assert not any(n.endswith(".asn") for n in names)
    # The core modules are present.
    assert "cits_validator/mcp/server.py" in names


def test_zipapp_selftest_runs_device_profile(tmp_path):
    out = tmp_path / "cits-edge.pyz"
    subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "build_edge_zipapp.py"), "--output", str(out)],
        check=True,
        capture_output=True,
    )
    proc = subprocess.run(
        [sys.executable, str(out), "selftest"],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )
    assert proc.returncode == 0, proc.stderr
    assert '"profile": "device"' in proc.stdout
