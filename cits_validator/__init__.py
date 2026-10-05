"""C-ITS Validator & MCP Toolset.

Provides automated link-layer, wire-framing, topologic, and anti-hallucination
auditing for Cooperative Intelligent Transport Systems (C-ITS) and V2X protocols.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    # Single source of truth: the installed distribution metadata (pyproject.toml).
    __version__ = version("cits-expert")
except PackageNotFoundError:  # Running straight from a checkout without installed metadata.
    __version__ = "0.0.0+source"

__all__ = ["__version__"]
