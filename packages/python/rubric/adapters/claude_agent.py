"""Claude Agent SDK adapter.

Installs a `PreToolUse` hook on a `ClaudeAgentOptions` config so every tool
call the agent attempts is gated by the governance evaluator and produces an
audit event. Denied calls are surfaced to the model as a `deny` permission
decision (the standard Claude Agent SDK mechanism), so the model can adapt
rather than the harness raising.

Tool names coming through MCP servers (created via `create_sdk_mcp_server`)
are seen by hooks as `mcp__<server>__<tool>`. By default we strip that prefix
before evaluating, so policies can reference plain tool names (`delete_file`).
Pass a custom `tool_name_extractor` to override.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from rubric.adapters._naming import ToolNameExtractor, default_tool_name
from rubric.client import Governance
from rubric.constants import (
    DECISION_DENY,
    FRAMEWORK_CLAUDE_AGENT,
    HOOK_EVENT_PRE_TOOL_USE,
    HOOK_INPUT_FIELD_TOOL_INPUT,
    HOOK_INPUT_FIELD_TOOL_NAME,
    HOOK_OUTPUT_FIELD_EVENT_NAME,
    HOOK_OUTPUT_FIELD_HOOK_SPECIFIC_OUTPUT,
    HOOK_OUTPUT_FIELD_PERMISSION_DECISION,
    HOOK_OUTPUT_FIELD_PERMISSION_REASON,
    PERMISSION_DECISION_DENY,
)
from rubric.types import EvaluationMetadata

HookCallback = Callable[[dict[str, Any], str | None, Any], Awaitable[dict[str, Any]]]


def governance_hook(
    governance: Governance,
    session_id: str,
    *,
    tool_name_extractor: ToolNameExtractor = default_tool_name,
) -> HookCallback:
    """Build a `PreToolUse` hook callback that gates calls via governance."""

    async def _hook(
        input_data: dict[str, Any],
        tool_use_id: str | None,
        _context: Any,
    ) -> dict[str, Any]:
        raw_name = input_data.get(HOOK_INPUT_FIELD_TOOL_NAME, "")
        tool_input = input_data.get(HOOK_INPUT_FIELD_TOOL_INPUT, {})
        tool_name = tool_name_extractor(raw_name)

        result = governance.evaluate(
            tool_name=tool_name,
            session_id=session_id,
            metadata=EvaluationMetadata(input=tool_input, tool_use_id=tool_use_id),
            framework=FRAMEWORK_CLAUDE_AGENT,
        )

        if result.decision == DECISION_DENY:
            reason = (
                f"tool '{tool_name}' denied by policy "
                f"{result.matchedPolicyId or '?'} "
                f"rule {result.matchedRuleId or '?'}"
            )
            return {
                HOOK_OUTPUT_FIELD_HOOK_SPECIFIC_OUTPUT: {
                    HOOK_OUTPUT_FIELD_EVENT_NAME: HOOK_EVENT_PRE_TOOL_USE,
                    HOOK_OUTPUT_FIELD_PERMISSION_DECISION: PERMISSION_DECISION_DENY,
                    HOOK_OUTPUT_FIELD_PERMISSION_REASON: reason,
                }
            }
        return {}

    return _hook


def governance_hook_matchers(
    governance: Governance,
    session_id: str,
    *,
    tool_name_extractor: ToolNameExtractor = default_tool_name,
) -> dict[str, list[Any]]:
    """Build the `hooks=` dict for `ClaudeAgentOptions`.

    Returns a mapping ready to merge into `ClaudeAgentOptions(hooks=...)`.
    Importing `claude_agent_sdk` lazily so the SDK doesn't require it as a
    hard dep.
    """
    try:
        from claude_agent_sdk import HookMatcher  # type: ignore[import-not-found]
    except ImportError as e:
        raise ImportError(
            "rubric-app[claude-agent] is not installed. "
            "Run: pip install 'rubric-app[claude-agent]'"
        ) from e

    hook = governance_hook(governance, session_id, tool_name_extractor=tool_name_extractor)
    return {HOOK_EVENT_PRE_TOOL_USE: [HookMatcher(hooks=[hook])]}
