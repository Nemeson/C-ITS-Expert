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


def _build(tmp_path, name):
    out = tmp_path / name
    subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "build_edge_zipapp.py"), "--output", str(out)],
        check=True,
        capture_output=True,
    )
    return out


def test_zipapp_build_is_reproducible_and_ships_a_checksum(tmp_path):
    import hashlib
    import os
    import time

    first = _build(tmp_path, "a.pyz")
    time.sleep(1.1)  # a different build time must not change the archive
    second = _build(tmp_path, "b.pyz")

    assert first.read_bytes()[first.read_bytes().index(b"\n") :] == second.read_bytes()[
        second.read_bytes().index(b"\n") :
    ]
    digest = hashlib.sha256(first.read_bytes()).hexdigest()
    assert (tmp_path / "a.pyz.sha256").read_text().split()[0] == digest
    assert os.path.getsize(first) > 0


def test_zipapp_only_contains_the_package(tmp_path):
    with zipfile.ZipFile(_build(tmp_path, "c.pyz")) as z:
        stray = [
            n for n in z.namelist() if n != "__main__.py" and not n.startswith("cits_validator/")
        ]
    assert stray == []


def test_zipapp_honours_environment_configuration(tmp_path):
    import os

    out = _build(tmp_path, "d.pyz")
    env = {**os.environ, "CITS_MCP_MAX_OUTPUT_BYTES": "not-a-number"}

    proc = subprocess.run(
        [sys.executable, str(out), "selftest"], capture_output=True, text=True, env=env
    )

    assert proc.returncode != 0
    assert "CITS_MCP_MAX_OUTPUT_BYTES" in proc.stderr


def test_systemd_unit_is_hardened_and_configures_roots():
    unit = (ROOT / "packaging" / "cits-edge.service").read_text(encoding="utf-8")
    required = [
        "DynamicUser=yes",
        "CapabilityBoundingSet=",
        "ProtectKernelTunables=true",
        "ProtectKernelModules=true",
        "ProtectControlGroups=true",
        "RestrictAddressFamilies=AF_UNIX",
        "SystemCallFilter=@system-service",
        "MemoryDenyWriteExecute=true",
        "PrivateDevices=true",
        "LockPersonality=true",
        "MemoryMax=",
        "Environment=CITS_MCP_ROOTS=",
    ]
    missing = [d for d in required if d not in unit]
    assert missing == []


def test_checksum_file_is_lf_terminated_so_sha256sum_works_everywhere(tmp_path):
    _build(tmp_path, "e.pyz")

    raw = (tmp_path / "e.pyz.sha256").read_bytes()

    assert b"\r" not in raw
    assert raw.endswith(b"e.pyz\n")
