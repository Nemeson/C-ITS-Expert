"""Minimal JSON-Schema argument validation for MCP ``tools/call``.

Covers exactly what ``inputSchema`` in ``McpServer.TOOL_DEFINITIONS`` uses:
``required``, ``type`` (single or list), ``enum``. It exists so malformed client
arguments become a clean ``-32602`` instead of a handler crash.
"""

from __future__ import annotations

from typing import Any


class InvalidParams(ValueError):
    """Raised when tool arguments do not satisfy the tool's inputSchema."""


_TYPE_CHECKS = {
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "array": lambda v: isinstance(v, list),
    "object": lambda v: isinstance(v, dict),
}


def _matches(value: Any, expected: str | list[str]) -> bool:
    names = [expected] if isinstance(expected, str) else expected
    return any(_TYPE_CHECKS.get(name, lambda _v: True)(value) for name in names)


def validate_arguments(schema: dict[str, Any], arguments: Any) -> None:
    """Raises InvalidParams when ``arguments`` violates ``schema``."""
    if not isinstance(arguments, dict):
        raise InvalidParams("arguments must be an object")

    for name in schema.get("required", []):
        if name not in arguments:
            raise InvalidParams(f"missing required argument: {name}")

    for name, spec in schema.get("properties", {}).items():
        if name not in arguments:
            continue
        value = arguments[name]
        if "type" in spec and not _matches(value, spec["type"]):
            raise InvalidParams(f"argument {name!r} must be of type {spec['type']}")
        if "enum" in spec and value not in spec["enum"]:
            raise InvalidParams(f"argument {name!r} must be one of {spec['enum']}")
