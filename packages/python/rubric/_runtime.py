"""Sentry-style module-level API: ``init`` once, decorate with ``@tool``.

The ``Governance`` class remains the source of truth for advanced flows
(multiple agents per process, manual lifecycle, tests). This module wraps it
in a process-wide singleton with these conveniences:

- ``init(...)`` — bootstrap once at startup (idempotent, atexit-flushes).
- ``@tool`` — wrap a function so every call is gated by the policy bundle.
- ``evaluate(...)`` — call the bound ``Governance`` directly.
- ``session(...)`` — context manager that sets the session id for nested calls.
- ``trace(...)`` — context manager that attaches a ``TraceContext``.

Example:

    import rubric as ag

    ag.init(agent_name="payments-bot")

    @ag.tool
    def delete_file(path: str) -> str:
        return _do_delete(path)

    with ag.session("conv-42"):
        delete_file("/tmp/foo")  # ⇒ audit row with sessionId="conv-42"
"""

from __future__ import annotations

import asyncio
import atexit
import contextlib
import functools
import logging
import threading
from collections.abc import Callable, Iterator
from contextvars import ContextVar
from typing import Any, TypeVar, overload

from rubric.client import Governance
from rubric.constants import (
    DECISION_DENY,
    DLP_MODE_AUTO,
    DLP_MODE_OFF,
    DLP_MODE_PRESIDIO,
    DLP_MODE_REGEX,
    FRAMEWORK_CUSTOM,
    DlpMode,
)
from rubric.dlp.detector import Detector
from rubric.errors import GovernanceError
from rubric.trace import TraceContext
from rubric.types import EvaluationMetadata, EvaluationResult

log = logging.getLogger(__name__)

# ---- Singleton ------------------------------------------------------------

_GLOBAL: Governance | None = None
_INIT_LOCK = threading.Lock()
_DEFAULT_SESSION_ID = "default"

# ContextVars (per-task in async, per-thread otherwise) for nested overrides.
_SESSION_ID_VAR: ContextVar[str | None] = ContextVar("rubric_session_id", default=None)
_TRACE_VAR: ContextVar[TraceContext | None] = ContextVar("rubric_trace", default=None)


class GovernanceDeniedError(PermissionError, GovernanceError):
    """Raised by ``@tool``-wrapped functions when a policy denies the call."""

    def __init__(self, *, tool_name: str, result: EvaluationResult) -> None:
        self.tool_name = tool_name
        self.result = result
        reason = result.reason or "denied by policy"
        code = result.code or "deny"
        super().__init__(f"tool {tool_name!r} denied [{code}]: {reason}")


class GovernanceNotInitializedError(GovernanceError):
    """Raised when ``@tool`` or ``evaluate()`` is called before ``init()``."""


# ---- init / shutdown ------------------------------------------------------


def init(
    *,
    agent_name: str | None = None,
    enrollment_token: str | None = None,
    api_url: str | None = None,
    bundle_poll_seconds: float = 30.0,
    dlp: bool | DlpMode | Detector | None = None,
    default_session_id: str = _DEFAULT_SESSION_ID,
) -> Governance:
    """Bootstrap the process-wide ``Governance`` singleton.

    Idempotent: calling twice returns the existing instance (subsequent
    arguments are ignored). All arguments fall back to env vars exactly as
    ``Governance.bootstrap`` does.

    Registers an ``atexit`` hook that calls ``shutdown()`` so audit events
    flush on normal process exit. Hard-kill (SIGKILL) signals will skip the
    hook — by design.
    """
    global _GLOBAL
    with _INIT_LOCK:
        if _GLOBAL is not None:
            return _GLOBAL
        gov = Governance.bootstrap(
            agent_name=agent_name,
            enrollment_token=enrollment_token,
            api_url=api_url,
            bundle_poll_seconds=bundle_poll_seconds,
            dlp=dlp,
        )
        _GLOBAL = gov
        # Default session id for callers who don't push a `session(...)` scope.
        _SESSION_ID_VAR.set(default_session_id)
        atexit.register(_atexit_shutdown)
        return gov


def shutdown() -> None:
    """Stop the singleton and flush in-flight events. Safe to call repeatedly."""
    global _GLOBAL
    with _INIT_LOCK:
        if _GLOBAL is None:
            return
        try:
            _GLOBAL.shutdown()
        except Exception as e:
            # `log.exception` would capture bearer-bearing locals from the
            # shutdown stack into structured log handlers — log just the
            # exception class name.
            log.error("rubric shutdown failed: %s", type(e).__name__)
        _GLOBAL = None


def _atexit_shutdown() -> None:
    # Suppress everything — process is going away anyway.
    with contextlib.suppress(Exception):
        shutdown()


def current() -> Governance:
    """Return the singleton, raising if ``init()`` was never called."""
    if _GLOBAL is None:
        raise GovernanceNotInitializedError(
            "rubric.init(agent_name=...) was never called. "
            "Call it once at process startup, then use @rubric.tool "
            "or rubric.evaluate(...)."
        )
    return _GLOBAL


def is_initialized() -> bool:
    return _GLOBAL is not None


# ---- session / trace context ----------------------------------------------


@contextlib.contextmanager
def session(session_id: str) -> Iterator[str]:
    """Set the session id for any tool calls inside the block.

    Works for both sync and async (ContextVars propagate across awaits).
    """
    token = _SESSION_ID_VAR.set(session_id)
    try:
        yield session_id
    finally:
        _SESSION_ID_VAR.reset(token)


@contextlib.contextmanager
def trace(initial: TraceContext | None = None) -> Iterator[TraceContext]:
    """Bind a TraceContext for any ``@tool``-governed calls inside the block.

    The same TraceContext is uploaded with every ``evaluate()`` call in scope,
    so the dashboard's drawer shows the full conversation up to each tool call.
    """
    ctx = initial if initial is not None else TraceContext()
    token = _TRACE_VAR.set(ctx)
    try:
        yield ctx
    finally:
        _TRACE_VAR.reset(token)


def current_session_id() -> str:
    return _SESSION_ID_VAR.get() or _DEFAULT_SESSION_ID


def current_trace() -> TraceContext | None:
    return _TRACE_VAR.get()


# ---- evaluate (module-level) ----------------------------------------------


def evaluate(
    tool_name: str,
    *,
    session_id: str | None = None,
    metadata: EvaluationMetadata | None = None,
    framework: str | None = None,
    trace: TraceContext | None = None,
) -> EvaluationResult:
    """Module-level ``evaluate``. Reads the singleton, the session ContextVar,
    and the trace ContextVar — pass explicit overrides if needed.
    """
    gov = current()
    return gov.evaluate(
        tool_name=tool_name,
        session_id=session_id or current_session_id(),
        metadata=metadata,
        framework=framework,
        trace=trace if trace is not None else current_trace(),
    )


# ---- @tool decorator ------------------------------------------------------

F = TypeVar("F", bound=Callable[..., Any])


@overload
def tool(func: F) -> F: ...
@overload
def tool(
    *,
    name: str | None = None,
    session_id: str | None = None,
    framework: str | None = None,
) -> Callable[[F], F]: ...


def tool(
    func: F | None = None,
    *,
    name: str | None = None,
    session_id: str | None = None,
    framework: str | None = None,
) -> Any:
    """Decorate a function so every call is gated by the policy bundle.

    The wrapped function calls ``evaluate()`` first; if the decision is
    ``deny``, it raises ``GovernanceDeniedError`` and the underlying function
    is **not** invoked. Otherwise the function runs and its return value is
    passed through.

    Tool name defaults to the function's ``__name__``. Override with
    ``@tool(name="explicit_name")``.

    Works on both sync and async functions.
    """

    def _build(f: F) -> F:
        tool_name = name or f.__name__
        fw = framework or FRAMEWORK_CUSTOM

        if asyncio.iscoroutinefunction(f):

            @functools.wraps(f)
            async def async_wrapped(*args: Any, **kwargs: Any) -> Any:
                _gate(tool_name, args, kwargs, session_id, fw)
                return await f(*args, **kwargs)

            return async_wrapped  # type: ignore[return-value]

        @functools.wraps(f)
        def sync_wrapped(*args: Any, **kwargs: Any) -> Any:
            _gate(tool_name, args, kwargs, session_id, fw)
            return f(*args, **kwargs)

        return sync_wrapped  # type: ignore[return-value]

    if func is not None:
        return _build(func)
    return _build


def _gate(
    tool_name: str,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    explicit_session_id: str | None,
    framework: str,
) -> None:
    """Run a single evaluate() and raise on deny. Shared sync/async hot path."""
    gov = current()
    sid = explicit_session_id or current_session_id()
    metadata = EvaluationMetadata(
        args=list(args) if args else None,
        kwargs=dict(kwargs) if kwargs else None,
    )
    result = gov.evaluate(
        tool_name=tool_name,
        session_id=sid,
        metadata=metadata,
        framework=framework,
        trace=current_trace(),
    )
    if result.decision == DECISION_DENY:
        raise GovernanceDeniedError(tool_name=tool_name, result=result)


# Re-export DLP modes for convenience (so callers can pass `dlp=ag.DLP_AUTO`).
__all__ = [
    "DLP_MODE_AUTO",
    "DLP_MODE_OFF",
    "DLP_MODE_PRESIDIO",
    "DLP_MODE_REGEX",
    "GovernanceDeniedError",
    "GovernanceNotInitializedError",
    "current",
    "current_session_id",
    "current_trace",
    "evaluate",
    "init",
    "is_initialized",
    "session",
    "shutdown",
    "tool",
    "trace",
]
