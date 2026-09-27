import json
import struct

from cits_validator.cli.main import run_cli


def test_cli_help(capsys):
    ret = run_cli(["--help"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "cits-lint" in captured.out or "usage:" in captured.out.lower()


def test_cli_scan_clean_pcap(tmp_path, capsys):
    pcap_file = tmp_path / "clean.pcap"
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)  # DLT 1 Ethernet
    # Valid Ethernet V2X frame: 14B eth_hdr + 4B BTP
    frame = b"\xff" * 6 + b"\x11" * 6 + b"\x89\x47" + struct.pack(">HH", 2001, 0)
    rec = struct.pack("<IIII", 1000, 0, len(frame), len(frame)) + frame
    pcap_file.write_bytes(header + rec)

    ret = run_cli([str(pcap_file), "--format", "json"])
    assert ret == 0

    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report["is_valid"] is True
    assert report["total_inspected"] == 1
    assert report["error_count"] == 0


def test_cli_scan_corrupted_pcap(tmp_path, capsys):
    bad_pcap = tmp_path / "bad.pcap"
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127)  # DLT 127
    # Corrupted Radiotap header with length = 4 (illegal)
    bad_frame = struct.pack("<BBHI", 0, 0, 4, 0) + b"\x00" * 20
    rec = struct.pack("<IIII", 1000, 0, len(bad_frame), len(bad_frame)) + bad_frame
    bad_pcap.write_bytes(header + rec)

    ret = run_cli([str(bad_pcap), "--format", "json"])
    assert ret == 1

    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report["is_valid"] is False
    assert report["error_count"] > 0
    assert any(v["rule_id"] == "R01" for v in report["violations"])


def test_cli_scan_code_file_with_anti_pattern(tmp_path, capsys):
    code_file = tmp_path / "bad_logic.py"
    code_file.write_text(
        "def fake_lat(t):\n    return 52.0 + sin(t) * 0.22\n",
        encoding="utf-8",
    )

    ret = run_cli([str(code_file), "--format", "json"])
    assert ret == 1

    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report["is_valid"] is False
    assert any(v["rule_id"] == "R02" for v in report["violations"])
