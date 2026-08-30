"""Synthetic MCP surface used only by the P0-S3-A framework gate.

The functions return proposals or metadata. They cannot read, write, move, or
delete user files and do not share the production Hub's security authority.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP


SERVER_NAME = "data-steward-framework-gate"
mcp = FastMCP(SERVER_NAME)


@mcp.tool()
def inspect_authorized_scope() -> dict[str, object]:
    """Return synthetic scope metadata without touching a real filesystem."""
    return {"authorized": False, "mode": "synthetic_gate"}


@mcp.tool()
def search_authorized_assets(query: str) -> dict[str, object]:
    """Return an empty synthetic search result for contract discovery."""
    return {"query_length": len(query), "matches": [], "synthetic": True}


@mcp.tool()
def propose_archive_plan(goal: str) -> dict[str, object]:
    """Propose no operations; execution belongs to Data Steward."""
    return {"goal_length": len(goal), "operations": [], "requires_approval": True}


@mcp.tool()
def recall_approved_preferences() -> dict[str, object]:
    """Return no preferences; product memory belongs to Data Steward."""
    return {"preferences": [], "synthetic": True}


if __name__ == "__main__":
    mcp.run(transport="stdio")
