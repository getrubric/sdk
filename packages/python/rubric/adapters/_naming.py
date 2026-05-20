"""Internal helpers shared across framework adapters.

Tool names that come through MCP servers are seen by hosts as
`mcp__<server>__<tool>`. Policies in this product are authored against the
plain tool name (`delete_file`), so adapters strip the prefix before
evaluating. Centralizing the extractor here keeps every adapter aligned.
"""

from __future__ import annotations

from typing import Callable, TypeAlias

from rubric.constants import (
    MCP_TOOL_NAME_DELIMITER,
    MCP_TOOL_NAME_PARTS,
    MCP_TOOL_NAME_PREFIX,
)

ToolNameExtractor: TypeAlias = Callable[[str], str]


def default_tool_name(raw: str) -> str:
    """Strip the `mcp__<server>__` prefix when present, otherwise pass through."""
    if raw.startswith(MCP_TOOL_NAME_PREFIX):
        parts = raw.split(MCP_TOOL_NAME_DELIMITER, MCP_TOOL_NAME_PARTS - 1)
        if len(parts) == MCP_TOOL_NAME_PARTS:
            return parts[-1]
    return raw
