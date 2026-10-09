"""Build the `cits-edge` zipapp: a device-profile MCP server with no third-party deps.

The device profile only exercises the link-layer, topology and GLOSA paths, so
the vendored ASN.1 standard files (and the optional `asn1tools` dependency) are
left out. All Python modules stay in: the ASN.1 decoder imports `asn1tools`
lazily, so importing the modules does not require the dependency to be present.
"""

from __future__ import annotations

import argparse
import shutil
import tempfile
import zipapp
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_NAME = "cits_validator"

MAIN_TEMPLATE = '''import json
import sys

from cits_validator.mcp.config import Settings
from cits_validator.mcp.server import McpServer


def main() -> int:
    server = McpServer(settings=Settings.from_env({"CITS_MCP_PROFILE": "device"}))
    if len(sys.argv) > 1 and sys.argv[1] == "selftest":
        resp = server.handle_request(
            {"id": 0, "method": "tools/call",
             "params": {"name": "cits_selftest", "arguments": {}}}
        )
        print(resp["result"]["content"][0]["text"])
        return 0
    server.run_stdio()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


def _should_copy(path: Path) -> bool:
    if "__pycache__" in path.parts:
        return False
    if path.suffix != ".py":
        return False
    # Vendored ASN.1 standard files are data, not code.
    if "standards" in path.parts:
        return False
    return True


def build(output: Path) -> Path:
    src_pkg = REPO_ROOT / PACKAGE_NAME
    with tempfile.TemporaryDirectory() as tmp:
        build_dir = Path(tmp) / "app"
        target_pkg = build_dir / PACKAGE_NAME
        for src_file in src_pkg.rglob("*.py"):
            if not _should_copy(src_file):
                continue
            rel = src_file.relative_to(src_pkg)
            dst = target_pkg / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src_file, dst)

        (build_dir / "__main__.py").write_text(MAIN_TEMPLATE, encoding="utf-8")
        output.parent.mkdir(parents=True, exist_ok=True)
        zipapp.create_archive(build_dir, target=str(output), interpreter="/usr/bin/env python3")
    return output


def main() -> None:
    parser = argparse.ArgumentParser(prog="build_edge_zipapp")
    parser.add_argument("--output", required=True, help="Path to write the .pyz to")
    args = parser.parse_args()
    out = build(Path(args.output))
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
