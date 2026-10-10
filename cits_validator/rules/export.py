from __future__ import annotations

from typing import Any

from cits_validator import __version__
from cits_validator.cli.main import build_default_registry


def export_rule_catalog() -> dict[str, Any]:
    """Machine-readable rule catalog — the M1 contract consumed by Milestone 3 codegen."""
    registry = build_default_registry(enable_asn1=True)
    return {
        "version": __version__,
        "rules": [
            {
                "rule_id": r.rule_id,
                "name": r.name,
                "description": r.description,
                "metadata": r.metadata(),
            }
            for r in registry.list_rules()
        ],
    }
