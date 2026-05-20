"""LangChain adapter.

Wraps any LangChain `BaseTool` so every invocation is gated by the governance
evaluator and produces an audit event. Denied calls raise
`GovernanceDeniedError`, which LangChain agents surface as a tool failure the
model can react to.
"""

from __future__ import annotations

from typing import Any, Callable

from rubric.client import Governance
from rubric.constants import DECISION_DENY, FRAMEWORK_LANGCHAIN
from rubric.types import EvaluationMetadata


class GovernanceDeniedError(PermissionError):
    """Raised when a tool call is denied by an active policy."""


def govern_tools(governance: Governance, tools: list[Any], session_id: str) -> list[Any]:
    """Wrap a list of LangChain tools so each invocation is evaluated.

    Returns a new list of tools with the same names/schemas but governed
    bodies. Importing langchain_core lazily so the SDK doesn't require it as
    a hard dep.
    """
    try:
        from langchain_core.tools import StructuredTool, Tool  # type: ignore[import-not-found]
    except ImportError as e:
        raise ImportError(
            "rubric-app[langchain] is not installed. "
            "Run: pip install 'rubric-app[langchain]'"
        ) from e

    wrapped: list[Any] = []
    for tool in tools:
        original_func: Callable[..., Any] | None = (
            getattr(tool, "func", None) or getattr(tool, "_run", None)
        )
        if original_func is None:
            wrapped.append(tool)
            continue

        tool_name: str = tool.name

        def _governed(
            *args: Any,
            _tool_name: str = tool_name,
            _original: Callable[..., Any] = original_func,
            **kwargs: Any,
        ) -> Any:
            result = governance.evaluate(
                tool_name=_tool_name,
                session_id=session_id,
                metadata=EvaluationMetadata(args=list(args), kwargs=dict(kwargs)),
                framework=FRAMEWORK_LANGCHAIN,
            )
            if result.decision == DECISION_DENY:
                raise GovernanceDeniedError(
                    f"tool '{_tool_name}' denied by policy "
                    f"{result.matchedPolicyId or '?'} rule {result.matchedRuleId or '?'}"
                )
            return _original(*args, **kwargs)

        if isinstance(tool, StructuredTool):
            wrapped.append(
                StructuredTool.from_function(
                    func=_governed,
                    name=tool.name,
                    description=tool.description,
                    args_schema=tool.args_schema,
                )
            )
        else:
            wrapped.append(Tool(name=tool.name, description=tool.description, func=_governed))

    return wrapped
