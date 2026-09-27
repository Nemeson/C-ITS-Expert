from __future__ import annotations

import json
import sys
from typing import Any

from cits_validator.mcp.tools import (
    cits_audit_code,
    cits_check_mapem,
    cits_inspect_hex,
    cits_validate_pcap,
)


class McpServer:
    """Lightweight pure-Python STDIO JSON-RPC 2.0 MCP server."""

    SERVER_NAME = "cits-mcp"
    SERVER_VERSION = "1.1.0"

    TOOL_DEFINITIONS = [
        {
            "name": "cits_audit_code",
            "description": (
                "Audits source code (Python, JS, TS, Rust, C++, Java) for prohibited synthetic "
                "V2X fallbacks (e.g. trigonometric GNSS drift, modulo signal groups, static 90s cycles)."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "code": {"type": "string", "description": "Source code snippet to audit"},
                    "language": {
                        "type": "string",
                        "description": "Language name (python, js, ts, rust, cpp, java)",
                        "default": "python",
                    },
                },
                "required": ["code"],
            },
        },
        {
            "name": "cits_inspect_hex",
            "description": (
                "Decodes a raw packet hex stream and checks Radiotap length offsets, "
                "802.11 QoS headers, and LLC/SNAP 0x8947 validity."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "hex_payload": {"type": "string", "description": "Raw packet bytes in hex"},
                    "dlt": {
                        "type": "integer",
                        "description": "Data Link Type (127=Radiotap, 105=Raw 802.11, 1=Ethernet)",
                        "default": 127,
                    },
                },
                "required": ["hex_payload"],
            },
        },
        {
            "name": "cits_check_mapem",
            "description": (
                "Validates MAPEM topology geometries, verifies Node-0 stopline connections, "
                "and flags diagonal overlong chords (>25m)."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "lanes_geojson": {
                        "type": "object",
                        "description": "JSON dict containing 'connections' or 'fragments'",
                    },
                },
                "required": ["lanes_geojson"],
            },
        },
        {
            "name": "cits_validate_pcap",
            "description": "Validates a PCAP/PCAPNG capture file against C-ITS link-layer invariants.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Absolute path to PCAP file"},
                },
                "required": ["file_path"],
            },
        },
    ]

    def __init__(self) -> None:
        self.tool_handlers = {
            "cits_audit_code": lambda args: cits_audit_code(
                args["code"], args.get("language", "python")
            ),
            "cits_inspect_hex": lambda args: cits_inspect_hex(
                args["hex_payload"], args.get("dlt", 127)
            ),
            "cits_check_mapem": lambda args: cits_check_mapem(args["lanes_geojson"]),
            "cits_validate_pcap": lambda args: cits_validate_pcap(args["file_path"]),
        }

    def handle_request(self, req: dict[str, Any]) -> dict[str, Any]:
        req_id = req.get("id")
        method = req.get("method")
        params = req.get("params", {})

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {
                        "name": self.SERVER_NAME,
                        "version": self.SERVER_VERSION,
                    },
                    "capabilities": {"tools": {}},
                },
            }

        elif method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": self.TOOL_DEFINITIONS},
            }

        elif method == "tools/call":
            tool_name = params.get("name")
            tool_args = params.get("arguments", {})

            handler = self.tool_handlers.get(tool_name)
            if not handler:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": f"Tool not found: {tool_name}"},
                }

            try:
                res = handler(tool_args)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(res, indent=2),
                            }
                        ]
                    },
                }
            except Exception as e:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32000, "message": str(e)},
                }

        elif method == "notifications/initialized":
            # Client notification acknowledgment
            return {}

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not supported: {method}"},
        }

    def run_stdio(self) -> None:
        """Runs the STDIO JSON-RPC line loop."""
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue

            try:
                req = json.loads(line)
                resp = self.handle_request(req)
                if resp:  # Notifications don't require responses
                    sys.stdout.write(json.dumps(resp) + "\n")
                    sys.stdout.flush()
            except Exception as e:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {e}"},
                }
                sys.stdout.write(json.dumps(err_resp) + "\n")
                sys.stdout.flush()


def main() -> None:
    server = McpServer()
    server.run_stdio()


if __name__ == "__main__":
    main()
