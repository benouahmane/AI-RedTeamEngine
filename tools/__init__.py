"""Tool Integration Layer.

Every offensive tool is wrapped in a class implementing the `OffensiveTool`
contract from `tools.base`. The agent only ever interacts with tools through
this interface — never via direct subprocess calls.

Importing this package side-effect-registers every wrapper into the global
registry; use `tools.registry.get(name)` to retrieve one.
"""
from tools import (
    active_directory,
    credentials,
    exploitation,
    post_exploit,
    recon,
    simulation,
    vuln_scan,
    web_enum,
)
from tools.base import OffensiveTool, ToolResult, ToolStatus
from tools.registry import all_tools, get, register

__all__ = [
    "OffensiveTool",
    "ToolResult",
    "ToolStatus",
    "all_tools",
    "get",
    "register",
    "recon",
    "web_enum",
    "vuln_scan",
    "exploitation",
    "credentials",
    "post_exploit",
    "active_directory",
    "simulation",
]
