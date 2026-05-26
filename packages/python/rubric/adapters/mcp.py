"""MCP client adapter.

Wraps an `mcp.ClientSession` so every `call_tool` invocation is gated by the
governance evaluator and produces an audit event. Denied calls return a
native MCP `CallToolResult(isError=True)` with a text-content reason — agents
and frameworks already handle `isError=True` as a tool failure they can adapt
to, so there's nothing for the caller to special-case.

Use it anywhere you have an `mcp.ClientSession` (raw `mcp` clients, custom
agent loops, IDE integrations like Cursor/Cline) — the wrapper is transport-
agnostic and works against `stdio_client`, `sse_client`, and
`streamablehttp_client` alike.

Other session methods (`list_tools`, `read_resource`, etc.) are proxied
unchanged via `__getattr__`, so the wrapper is a drop-in for the wrapped
session.
"""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, Any

from rubric.adapters._naming import ToolNameExtractor, default_tool_name
from rubric.client import Governance
from rubric.constants import DECISION_DENY, FRAMEWORK_MCP
from rubric.types import EvaluationMetadata

if TYPE_CHECKING:
    from mcp import ClientSession
    from mcp.types import CallToolResult

_INSTALL_HINT = (
    "rubric-app[mcp] is not installed. "
    "Run: pip install 'rubric-app[mcp]'"
)


def _import_mcp_types() -> tuple[type[Any], type[Any]]:
    try:
        from mcp.types import CallToolResult, TextContent
    except ImportError as e:
        raise ImportError(_INSTALL_HINT) from e
    return CallToolResult, TextContent


class MCPClientWrapper:
    """Proxy around `mcp.ClientSession` that gates every `call_tool` call."""

    def __init__(
        self,
        governance: Governance,
        session: ClientSession,
        session_id: str,
        *,
        tool_name_extractor: ToolNameExtractor = default_tool_name,
    ) -> None:
        call_tool_result_cls, text_content_cls = _import_mcp_types()
        self._governance = governance
        self._session = session
        self._session_id = session_id
        self._tool_name_extractor = tool_name_extractor
        self._CallToolResult = call_tool_result_cls
        self._TextContent = text_content_cls

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        read_timeout_seconds: timedelta | None = None,
        progress_callback: Any = None,
        *,
        meta: dict[str, Any] | None = None,
    ) -> CallToolResult:
        canonical = self._tool_name_extractor(name)
        result = self._governance.evaluate(
            tool_name=canonical,
            session_id=self._session_id,
            metadata=EvaluationMetadata(input=arguments or {}),
            framework=FRAMEWORK_MCP,
            # Forward the raw `mcp__<server>__<tool>` name so the MCP
            # allow-list gate can check the server even though `tool_name`
            # has been stripped to the canonical form for policy matching.
            mcp_tool_name=name,
        )
        if result.decision == DECISION_DENY:
            reason = (
                f"tool '{canonical}' denied by policy "
                f"{result.matchedPolicyId or '?'} "
                f"rule {result.matchedRuleId or '?'}"
            )
            return self._CallToolResult(
                content=[self._TextContent(type="text", text=reason)],
                isError=True,
            )
        return await self._session.call_tool(
            name,
            arguments,
            read_timeout_seconds,
            progress_callback,
            meta=meta,
        )

    def __getattr__(self, item: str) -> Any:
        # Forward any non-overridden attribute to the wrapped session.
        # Read `_session` via __dict__ to avoid infinite recursion if the
        # attribute is missing (e.g. during __init__ failure).
        session = self.__dict__.get("_session")
        if session is None:
            raise AttributeError(item)
        return getattr(session, item)


def govern_mcp_session(
    governance: Governance,
    session: ClientSession,
    session_id: str,
    *,
    tool_name_extractor: ToolNameExtractor = default_tool_name,
) -> MCPClientWrapper:
    """Return an `MCPClientWrapper` around the given session."""
    return MCPClientWrapper(
        governance,
        session,
        session_id,
        tool_name_extractor=tool_name_extractor,
    )
