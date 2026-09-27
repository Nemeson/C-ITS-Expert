import json
import subprocess
import sys
from pathlib import Path


def test_e2e_cli_subprocess_on_real_capture():
    real_pcap = Path(r"C:\PythonTools\cits-inspector-v2\tests\fixtures\pcap\cross_validation_sample.pcap")
    if not real_pcap.exists():
        return  # Skip if environment lacks fixture

    cmd = [sys.executable, "-m", "cits_validator", str(real_pcap), "--format", "json"]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)

    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    assert data["is_valid"] is True
    assert data["total_inspected"] == 7
    assert data["error_count"] == 0


def test_e2e_cli_subprocess_on_bad_code(tmp_path):
    bad_code = tmp_path / "synthetic_gnss.py"
    bad_code.write_text("def fake_traj(t):\n    return sin(t) * 0.22\n", encoding="utf-8")

    cmd = [sys.executable, "-m", "cits_validator", str(bad_code), "--format", "json"]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)

    assert proc.returncode == 1
    data = json.loads(proc.stdout)
    assert data["is_valid"] is False
    assert data["error_count"] > 0
    assert any("synthetic GNSS" in v["message"] for v in data["violations"])


def test_e2e_mcp_server_live_stdio_pipe():
    cmd = [sys.executable, "-m", "cits_validator.mcp.server"]
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        # 1. Initialize Handshake
        req1 = json.dumps({"jsonrpc": "2.0", "id": 100, "method": "initialize", "params": {}}) + "\n"
        proc.stdin.write(req1)
        proc.stdin.flush()
        resp1_raw = proc.stdout.readline()
        resp1 = json.loads(resp1_raw)
        assert resp1["id"] == 100
        assert resp1["result"]["serverInfo"]["name"] == "cits-mcp"

        # 2. Call Tool: cits_audit_code with invalid modulo formula
        req2 = json.dumps({
            "jsonrpc": "2.0",
            "id": 101,
            "method": "tools/call",
            "params": {
                "name": "cits_audit_code",
                "arguments": {"code": "group = (lane % 4) + 1", "language": "python"},
            },
        }) + "\n"
        proc.stdin.write(req2)
        proc.stdin.flush()
        resp2_raw = proc.stdout.readline()
        resp2 = json.loads(resp2_raw)
        assert resp2["id"] == 101
        content_text = resp2["result"]["content"][0]["text"]
        audit_data = json.loads(content_text)
        assert audit_data["is_valid"] is False
        assert any("modulo signal group" in v["message"].lower() for v in audit_data["violations"])

        # 3. Call Tool: cits_inspect_hex with valid frame
        # Radiotap 8B + 802.11 Data 24B + LLC/SNAP 8B
        radiotap = "0000080000000000"
        dot11 = "08000000" + ("ff" * 6) + ("11" * 6) + ("22" * 6) + "0000"
        llc = "aaaa030000008947"
        hex_frame = radiotap + dot11 + llc

        req3 = json.dumps({
            "jsonrpc": "2.0",
            "id": 102,
            "method": "tools/call",
            "params": {
                "name": "cits_inspect_hex",
                "arguments": {"hex_payload": hex_frame, "dlt": 127},
            },
        }) + "\n"
        proc.stdin.write(req3)
        proc.stdin.flush()
        resp3_raw = proc.stdout.readline()
        resp3 = json.loads(resp3_raw)
        assert resp3["id"] == 102
        inspect_data = json.loads(resp3["result"]["content"][0]["text"])
        assert inspect_data["is_valid"] is True
        assert inspect_data["error_count"] == 0

    finally:
        proc.stdin.close()
        proc.terminate()
        proc.wait(timeout=5)
