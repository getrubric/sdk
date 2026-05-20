from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from rubric.constants import (
    Decision,
    POLICY_API_VERSION,
    POLICY_KIND,
    PolicyConditionOperator,
    PolicyVersionStatus,
)

# Re-export the canonical Decision alias so the public surface
# (`from rubric import Decision`) still works.
__all__ = [
    "Decision",
    "PolicyVersionStatus",
    "PolicyConditionOperator",
    "PolicyCondition",
    "PolicyRule",
    "PolicyMetadata",
    "PolicySpec",
    "PolicyDocument",
    "BundlePolicyEntry",
    "Bundle",
    "AuditEvent",
    "EvaluationRequest",
    "EvaluationMetadata",
    "EvaluationResult",
    "POLICY_MAX_RULES_PER_DOCUMENT",
    "POLICY_MAX_CONDITIONS_PER_RULE",
    "POLICY_MAX_POLICIES_PER_BUNDLE",
    "now_iso",
]


# Bundle / document size caps. Mirror Node SDK's `POLICY_MAX_*` constants.
# Prevents a runaway server response from shipping a multi-million-rule
# bundle that hangs every tool-call evaluation.
POLICY_MAX_RULES_PER_DOCUMENT = 1000
POLICY_MAX_CONDITIONS_PER_RULE = 50
POLICY_MAX_POLICIES_PER_BUNDLE = 1000


# Field-path parts that would walk into Object.prototype-style slots on
# any JS consumer of the same bundle. Rejected at the schema layer here,
# and again at runtime inside the evaluator's `_resolve_field`.
_FORBIDDEN_FIELD_PARTS = frozenset({"__proto__", "constructor", "prototype"})


class _StrictModel(BaseModel):
    """Base for SDK models. Forbids unknown fields to catch wire drift early.

    `hide_input_in_errors=True` keeps Pydantic from echoing raw input
    values inside `ValidationError.__str__` — important because audit
    events and bundle entries can carry tokens or PII.
    """

    model_config = ConfigDict(extra="forbid", frozen=False, hide_input_in_errors=True)


class PolicyCondition(_StrictModel):
    field: str = Field(min_length=1)
    operator: PolicyConditionOperator
    value: str | int | float | bool | list[str] | list[int]

    @field_validator("field")
    @classmethod
    def reject_forbidden_parts(cls, v: str) -> str:
        for part in v.split("."):
            if part in _FORBIDDEN_FIELD_PARTS:
                raise ValueError(
                    "field must not contain `__proto__`, `constructor`, or `prototype` parts"
                )
        return v


class PolicyRule(_StrictModel):
    id: str
    description: str | None = None
    conditions: list[PolicyCondition] = Field(
        min_length=1, max_length=POLICY_MAX_CONDITIONS_PER_RULE
    )
    effect: Decision


class PolicyMetadata(_StrictModel):
    name: str = Field(min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=1024)
    labels: dict[str, str] | None = None


class PolicySpec(_StrictModel):
    # Required — no default. A policy that omits `defaultEffect` is a server
    # bug or a manual edit gone wrong; failing the parse is strictly safer
    # than silently treating "missing" as "allow".
    defaultEffect: Decision
    rules: list[PolicyRule] = Field(min_length=1, max_length=POLICY_MAX_RULES_PER_DOCUMENT)


class PolicyDocument(_StrictModel):
    apiVersion: Literal["agent-governance.io/v1"] = POLICY_API_VERSION
    kind: Literal["Policy"] = POLICY_KIND
    metadata: PolicyMetadata
    spec: PolicySpec


class BundlePolicyEntry(_StrictModel):
    policyId: str = Field(pattern=r"^[0-9a-f-]{36}$")
    policyVersion: int = Field(ge=0)
    document: PolicyDocument


class Bundle(_StrictModel):
    bundleVersion: int = Field(ge=0)
    contentHash: str = Field(pattern=r"^[a-f0-9]{64}$")
    builtAt: str
    policies: list[BundlePolicyEntry] = Field(max_length=POLICY_MAX_POLICIES_PER_BUNDLE)
    frozenAgentIds: list[Annotated[str, Field(min_length=1, max_length=128)]] = Field(
        default_factory=list
    )


class EvaluationMetadata(BaseModel):
    """Caller-supplied context attached to an evaluation/audit event.

    Allows extra fields so the adapter layer can stash adapter-specific
    context (LangChain args, MCP tool_use_id, etc.) without changing this
    schema.
    """

    model_config = ConfigDict(extra="allow", hide_input_in_errors=True)

    args: list[Any] | None = None
    kwargs: dict[str, Any] | None = None
    input: dict[str, Any] | None = None
    tool_use_id: str | None = None


class AuditEvent(_StrictModel):
    agentId: str = Field(min_length=1, max_length=128)
    sessionId: str = Field(min_length=1, max_length=128)
    ts: str
    toolName: str = Field(min_length=1, max_length=256)
    decision: Decision
    policyId: str | None = None
    policyVersion: int | None = None
    latencyMs: float = Field(ge=0)
    metadata: dict[str, Any] | None = None
    framework: str | None = None
    version: str | None = None
    traceId: str | None = None
    tracePosition: int | None = None


class EvaluationRequest(BaseModel):
    """Request payload handed to the evaluator.

    `tool_name` is the canonical identifier policies match against; everything
    else is passed through to condition matching as request fields.
    """

    model_config = ConfigDict(extra="allow", hide_input_in_errors=True)

    tool_name: str
    agent_id: str | None = None


class EvaluationResult(_StrictModel):
    decision: Decision
    matchedPolicyId: str | None = None
    matchedPolicyVersion: int | None = None
    matchedRuleId: str | None = None
    latencyMs: float = Field(ge=0, default=0.0)
    code: str | None = None
    reason: str | None = None


def now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
