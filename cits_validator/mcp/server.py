from __future__ import annotations

import json
import sys
from typing import Any

from cits_validator import __version__
from cits_validator.mcp.tools import (
    cits_audit_code,
    cits_check_mapem,
    cits_compute_glosa,
    cits_decode_mapem_to_geojson,
    cits_decode_pdu,
    cits_export_kml,
    cits_inspect_hex,
    cits_parse_lisa,
    cits_validate_pcap,
)

_JSON_TYPES: dict[str, tuple[type, ...]] = {
    "string": (str,),
    "number": (int, float),
    "integer": (int,),
    "object": (dict,),
    "array": (list,),
    "boolean": (bool,),
}


def validate_arguments(schema: dict[str, Any], args: Any) -> list[str]:
    """Minimal JSON-Schema check (required, type, enum) so bad input yields a clear message."""
    if not isinstance(args, dict):
        return ["arguments must be a JSON object"]
    problems = [
        f"missing required argument: {k}" for k in schema.get("required", []) if k not in args
    ]
    for key, spec in schema.get("properties", {}).items():
        if key not in args:
            continue
        value = args[key]
        types = spec.get("type")
        types = [types] if isinstance(types, str) else (types or [])
        if types:
            allowed = tuple(t for name in types for t in _JSON_TYPES.get(name, ()))
            is_bool_for_number = isinstance(value, bool) and bool not in allowed
            if is_bool_for_number or not isinstance(value, allowed):
                problems.append(f"argument {key!r} must be of type {'/'.join(types)}")
                continue
        if "enum" in spec and value not in spec["enum"]:
            problems.append(f"argument {key!r} must be one of {spec['enum']}")
    return problems


def _tool_result(text: str, is_error: bool = False) -> dict[str, Any]:
    result: dict[str, Any] = {"content": [{"type": "text", "text": text}]}
    if is_error:
        result["isError"] = True
    return result


class McpServer:
    """Lightweight pure-Python STDIO JSON-RPC 2.0 MCP server."""

    SERVER_NAME = "cits-mcp"
    SERVER_VERSION = __version__

    TOOL_DEFINITIONS: list[dict[str, Any]] = [
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
                    "rules": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional subset of rule IDs to run (e.g. ['R02'])",
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
                "and flags diagonal overlong chords (default >25m)."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "lanes_geojson": {
                        "type": "object",
                        "description": "JSON dict containing 'connections' or 'fragments'",
                    },
                    "max_chord_meters": {
                        "type": "number",
                        "description": "Optional stopline chord bound in metres (default 25)",
                    },
                },
                "required": ["lanes_geojson"],
            },
        },
        {
            "name": "cits_validate_pcap",
            "description": "Validates a classic PCAP or PCAPNG capture file against C-ITS link-layer invariants.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Absolute path to PCAP/PCAPNG file",
                    },
                },
                "required": ["file_path"],
            },
        },
        {
            "name": "cits_parse_lisa",
            "description": "Parses and classifies LISA LV.XML supply file into structured signal groups with traffic participant classifications.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "xml_content": {
                        "type": "string",
                        "description": "XML text of the LISA supply file",
                    },
                },
                "required": ["xml_content"],
            },
        },
        {
            "name": "cits_compute_glosa",
            "description": "Computes instant GLOSA speed advisory window and driving recommendation based on distance and SPAT countdown.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "distance_m": {
                        "type": "number",
                        "description": "Remaining distance to stop line in meters",
                    },
                    "speed_kmh": {
                        "type": "number",
                        "description": "Current vehicle approach speed in km/h",
                    },
                    "phase_state": {
                        "type": "string",
                        "description": "Signal phase state ('GREEN', 'RED', 'YELLOW')",
                    },
                    "time_to_phase_end_s": {
                        "type": "number",
                        "description": "Remaining seconds of current phase",
                    },
                    "next_green_duration_s": {
                        "type": "number",
                        "description": "Optional duration in seconds of next green phase",
                        "default": 0.0,
                    },
                    "speed_limit_kmh": {
                        "type": "number",
                        "description": "Legal street speed limit in km/h",
                        "default": 50.0,
                    },
                },
                "required": ["distance_m", "speed_kmh", "phase_state", "time_to_phase_end_s"],
            },
        },
        {
            "name": "cits_decode_pdu",
            "description": (
                "Decodes a raw C-ITS ASN.1 UPER PDU (CAM, DENM, MAPEM, SPATEM, SREM, SSEM, CPM, VAM) "
                "against the vendored ETSI/ISO modules and returns the structured fields plus "
                "the standards it was validated against. Requires the optional [asn1] extra."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "hex_payload": {"type": "string", "description": "Raw PDU bytes in hex"},
                    "msg_type": {
                        "type": "string",
                        "description": "One of CAM, DENM, MAPEM, SPATEM, SREM, SSEM, CPM, VAM (CPM/VAM are Release 2 only)",
                        "enum": ["CAM", "DENM", "MAPEM", "SPATEM", "SREM", "SSEM", "CPM", "VAM"],
                    },
                    "release": {
                        "type": "string",
                        "description": "ASN.1 release baseline (r1 = EN 302 637-x/TS 103 301 v1.3.1, r2 = TS 103 900/831/v2.2.1)",
                        "enum": ["r1", "r2"],
                        "default": "r1",
                    },
                },
                "required": ["hex_payload", "msg_type"],
            },
        },
        {
            "name": "cits_decode_mapem_to_geojson",
            "description": (
                "Decodes a MAPEM PDU and returns its lane geometry as an RFC 7946 GeoJSON "
                "FeatureCollection, ready for QGIS / MapLibre. Requires the optional [asn1] extra."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "hex_payload": {"type": "string", "description": "Raw MAPEM PDU bytes in hex"},
                    "release": {"type": "string", "enum": ["r1", "r2"], "default": "r1"},
                    "lisa_xml": {
                        "type": "string",
                        "description": "Optional LISA supply XML for signal group enrichment",
                    },
                },
                "required": ["hex_payload"],
            },
        },
        {
            "name": "cits_export_kml",
            "description": "Generates a standards-compliant OGC KML 2.2 3D document for MAPEM topologies and LISA catalogs.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "lanes_json": {
                        "type": ["object", "array"],
                        "description": "MAPEM topology dictionary or list of lanes",
                    },
                    "lisa_xml": {
                        "type": "string",
                        "description": "Optional LISA supply XML content for signal group enrichment",
                    },
                    "intersection_name": {
                        "type": "string",
                        "description": "Document title",
                        "default": "C-ITS Intersection",
                    },
                },
                "required": ["lanes_json"],
            },
        },
    ]

    # Every tool is a pure function of its input: no writes, no external effects.
    TOOL_ANNOTATIONS = {
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    }
    SUPPORTED_PROTOCOLS = ("2025-06-18", "2025-03-26", "2024-11-05")

    def __init__(self) -> None:
        for tool in self.TOOL_DEFINITIONS:
            tool.setdefault("annotations", dict(self.TOOL_ANNOTATIONS))
        self.tool_handlers = {
            "cits_audit_code": lambda args: cits_audit_code(
                args["code"],
                args.get("language", "python"),
                args.get("rules"),
            ),
            "cits_inspect_hex": lambda args: cits_inspect_hex(
                args["hex_payload"], args.get("dlt", 127)
            ),
            "cits_check_mapem": lambda args: cits_check_mapem(
                args["lanes_geojson"], args.get("max_chord_meters")
            ),
            "cits_validate_pcap": lambda args: cits_validate_pcap(args["file_path"]),
            "cits_parse_lisa": lambda args: cits_parse_lisa(args["xml_content"]),
            "cits_compute_glosa": lambda args: cits_compute_glosa(
                distance_m=float(args["distance_m"]),
                speed_kmh=float(args["speed_kmh"]),
                phase_state=args["phase_state"],
                time_to_phase_end_s=float(args["time_to_phase_end_s"]),
                next_green_duration_s=float(args.get("next_green_duration_s", 0.0)),
                speed_limit_kmh=float(args.get("speed_limit_kmh", 50.0)),
            ),
            "cits_export_kml": lambda args: cits_export_kml(
                lanes_json=args["lanes_json"],
                lisa_xml=args.get("lisa_xml"),
                intersection_name=args.get("intersection_name", "C-ITS Intersection"),
            ),
            "cits_decode_pdu": lambda args: cits_decode_pdu(
                args["hex_payload"],
                args["msg_type"],
                args.get("release", "r1"),
            ),
            "cits_decode_mapem_to_geojson": lambda args: cits_decode_mapem_to_geojson(
                args["hex_payload"],
                args.get("release", "r1"),
                args.get("lisa_xml"),
            ),
        }

    @classmethod
    def _negotiate(cls, requested: Any) -> str:
        return requested if requested in cls.SUPPORTED_PROTOCOLS else cls.SUPPORTED_PROTOCOLS[-1]

    def handle_request(self, req: dict[str, Any]) -> dict[str, Any]:
        req_id = req.get("id")
        method = req.get("method")
        params = req.get("params", {})

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": self._negotiate(params.get("protocolVersion")),
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

            schema = next(t["inputSchema"] for t in self.TOOL_DEFINITIONS if t["name"] == tool_name)
            problems = validate_arguments(schema, tool_args)
            if problems:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": _tool_result("Invalid arguments: " + "; ".join(problems), True),
                }

            # Execution errors are reported in-band (isError) so the model can read
            # them and retry; JSON-RPC errors are reserved for protocol faults.
            try:
                res = handler(tool_args)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": _tool_result(json.dumps(res, indent=2)),
                }
            except Exception as e:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": _tool_result(f"{type(e).__name__}: {e}", True),
                }

        elif method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        elif isinstance(method, str) and method.startswith("notifications/"):
            return {}
        elif "id" not in req:
            return {}  # unknown notification: never answer

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
