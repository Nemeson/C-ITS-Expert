"""Read-only MCP resources for cits-mcp.

Resources let an agent *read* catalogs (the rule set, the server version)
instead of abusing a tool call for what is really static reference data.
"""

from __future__ import annotations

import json

from cits_validator import __version__
from cits_validator.rules.export import export_rule_catalog

RESOURCES = [
    {
        "uri": "cits://rules",
        "name": "Rule catalog",
        "description": "Machine-readable catalog of the validation rules (R01-R06).",
        "mimeType": "application/json",
    },
    {
        "uri": "cits://version",
        "name": "Server version",
        "description": "The cits-mcp server and core version.",
        "mimeType": "application/json",
    },
]


def read_resource(uri: str) -> str:
    """Return the JSON text for a resource URI. Raises ValueError if unknown."""
    if uri == "cits://rules":
        return json.dumps(export_rule_catalog(), indent=2)
    if uri == "cits://version":
        return json.dumps({"version": __version__})
    raise ValueError(f"unknown resource: {uri}")


__all__ = ["RESOURCES", "read_resource"]
