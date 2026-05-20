# Sentry-style top-level API: init() once, decorate with @tool. The `with
# Governance.bootstrap(...)` flow is still available for tests and multi-agent
# processes — the singleton path just covers the 99% case.
from rubric._runtime import (
    GovernanceDeniedError,
    GovernanceNotInitializedError,
    current,
    current_session_id,
    current_trace,
    evaluate,
    init,
    is_initialized,
    session,
    shutdown,
    tool,
    trace,
)
from rubric._version import __version__
from rubric.client import Governance
from rubric.constants import (
    DECISION_ALLOW,
    DECISION_DENY,
    Decision,
)
from rubric.dlp import Detector, DlpDetection, DlpField
from rubric.errors import (
    GovernanceError,
    GovernanceProblemError,
    ProblemDetails,
)
from rubric.trace import (
    AssistantMessage,
    ToolCallMessage,
    ToolResultMessage,
    TraceContext,
    UserMessage,
)
from rubric.types import AuditEvent, EvaluationMetadata, PolicyDocument

__all__ = [
    "AssistantMessage",
    "AuditEvent",
    "DECISION_ALLOW",
    "DECISION_DENY",
    "Decision",
    "Detector",
    "DlpDetection",
    "DlpField",
    "EvaluationMetadata",
    "Governance",
    "GovernanceDeniedError",
    "GovernanceError",
    "GovernanceNotInitializedError",
    "GovernanceProblemError",
    "PolicyDocument",
    "ProblemDetails",
    "ToolCallMessage",
    "ToolResultMessage",
    "TraceContext",
    "UserMessage",
    "__version__",
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
