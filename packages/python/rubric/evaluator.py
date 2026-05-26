"""Policy evaluator.

Uses a native evaluator backend when the optional `[runtime]` extra is
installed. Otherwise falls back to a pure-Python evaluator with matching
condition semantics, so the SDK is fully usable without the optional extra.
"""

from __future__ import annotations

import logging
import time
from threading import RLock
from typing import Any, Callable

# `regex` is the PyPI module (not stdlib `re`). It's API-compatible with
# `re` and additionally supports a `timeout=` kwarg that raises
# `regex.error` if a single search exceeds the budget. Without this, a
# pathological policy pattern like `(a+)+$` against a long input would
# hang the agent process on the Python side just like JS RegExp would on
# the API.
import regex as _regex

from rubric.constants import (
    DECISION_ALLOW,
    DECISION_DENY,
    DENY_REASON_AGENT_FROZEN,
    EVAL_REQUEST_FIELD_MCP_TOOL_NAME as MCP_GATE_FIELD,
    Decision,
    RESULT_CODE_AGENT_FROZEN,
    RESULT_CODE_MCP_NOT_APPROVED,
    deny_reason_mcp_not_approved,
    parse_mcp_server,
)
from rubric.types import (
    Bundle,
    BundlePolicyEntry,
    EvaluationRequest,
    EvaluationResult,
    PolicyCondition,
)

log = logging.getLogger(__name__)


try:
    from agent_os.policies import PolicyDocument as _NativePolicyDocument  # type: ignore[import-not-found]
    from agent_os.policies import PolicyEvaluator as _NativeEvaluator  # type: ignore[import-not-found]

    _native_available = True
except ImportError:
    _native_available = False


_MS_PER_SECOND = 1000.0

# Per-match wall-clock budget passed to `regex.search`. Conservative — even
# the most baroque well-formed pattern matches in single-digit ms; anything
# pushing 500ms is either pathological or running on a deeply
# overcommitted host.
_MATCH_TIMEOUT_SECONDS = 0.5

# Per-evaluation wall-clock budget. A pathologically large bundle (rules ×
# conditions × regex tests) that slips past the schema's static caps would
# otherwise pin the worker for every tool call. 50ms is well above the p99
# of a healthy 1000-rule bundle and well below user-perceivable hook latency.
EVAL_WALL_CLOCK_BUDGET_MS = 50

# Stable result codes surfaced via `EvaluationResult.code`. Audit
# consumers can branch on these without importing the constants module.
RESULT_CODE_NO_POLICIES = "NO_POLICIES"
RESULT_CODE_POLICY_COMPILE_ERROR = "POLICY_COMPILE_ERROR"
RESULT_CODE_EVAL_TIMEOUT = "EVAL_TIMEOUT"
RESULT_CODE_NATIVE_FALLBACK = "NATIVE_FALLBACK"

_REASON_NO_POLICIES = "no bundle loaded — failing closed"
_REASON_POLICY_COMPILE_ERROR = (
    "policy contains a regex pattern that failed to compile — failing closed"
)
_REASON_EVAL_TIMEOUT = "evaluation exceeded wall-clock budget — failing closed"

# Reserved field-path parts. Mirrors the schema-level rejection in
# `types.PolicyCondition.reject_forbidden_parts`; the evaluator also
# refuses to walk into prototype-style slots at resolution time.
_FORBIDDEN_FIELD_PARTS = frozenset({"__proto__", "constructor", "prototype"})


# Argument bag passed to the `on_compile_error` callback so the daemon
# can log/alert with full context (policy id, rule id, field, pattern).
class CompileErrorInfo:
    __slots__ = ("policy_id", "rule_id", "field", "pattern", "cause")

    def __init__(
        self,
        policy_id: str,
        rule_id: str,
        field: str,
        pattern: str,
        cause: BaseException,
    ) -> None:
        self.policy_id = policy_id
        self.rule_id = rule_id
        self.field = field
        self.pattern = pattern
        self.cause = cause


class EvaluatorOptions:
    """Construction-time hooks for the evaluator.

    `on_compile_error` is invoked once per `matches` condition whose
    pattern fails to compile during `update_bundle()`. The containing
    policy is also marked errored, so every evaluation that would touch
    it returns `deny / POLICY_COMPILE_ERROR`; this callback is the
    observability hook on top of that enforcement.
    """

    __slots__ = ("on_compile_error",)

    def __init__(
        self, on_compile_error: Callable[[CompileErrorInfo], None] | None = None
    ) -> None:
        self.on_compile_error = on_compile_error


class Evaluator:
    """Evaluates a tool-call request against the current bundle's policies."""

    def __init__(self, options: EvaluatorOptions | None = None) -> None:
        self._lock = RLock()
        self._bundle: Bundle | None = None
        self._native_evaluator: object | None = None
        # Per-condition compiled patterns. Keyed by `id(condition)` because
        # PolicyCondition is a Pydantic v2 model (not hashable by default).
        # Lifetime is bounded by `self._bundle` keeping each condition alive.
        self._compiled_patterns: dict[int, _regex.Pattern[str]] = {}
        # Policy IDs whose document contains at least one uncompileable
        # `matches` pattern. Populated in `update_bundle`, consulted on
        # every evaluation. Defaults to deny: any request that would touch
        # such a policy returns DENY/POLICY_COMPILE_ERROR.
        self._errored_policy_ids: set[str] = set()
        self._on_compile_error: Callable[[CompileErrorInfo], None] | None = (
            options.on_compile_error if options is not None else None
        )

    def update_bundle(self, bundle: Bundle) -> None:
        with self._lock:
            self._bundle = bundle
            # Invalidate per-bundle caches on every update.
            self._compiled_patterns = {}
            self._errored_policy_ids = set()

            for entry in bundle.policies:
                for rule in entry.document.spec.rules:
                    for condition in rule.conditions:
                        if condition.operator != "matches":
                            continue
                        if not isinstance(condition.value, str):
                            # Non-string `matches` value is a schema oddity
                            # — fail the policy closed rather than silently
                            # never matching.
                            self._mark_compile_error(
                                entry.policyId,
                                rule.id,
                                condition.field,
                                str(condition.value),
                                ValueError("matches value must be a string"),
                            )
                            continue
                        try:
                            self._compiled_patterns[id(condition)] = _regex.compile(
                                condition.value
                            )
                        except _regex.error as cause:
                            self._mark_compile_error(
                                entry.policyId,
                                rule.id,
                                condition.field,
                                condition.value,
                                cause,
                            )

            if _native_available:
                docs = [
                    _NativePolicyDocument(**entry.document.model_dump())  # type: ignore[arg-type]
                    for entry in bundle.policies
                ]
                self._native_evaluator = _NativeEvaluator(policies=docs)  # type: ignore[call-arg]

    def _mark_compile_error(
        self,
        policy_id: str,
        rule_id: str,
        field: str,
        pattern: str,
        cause: BaseException,
    ) -> None:
        self._errored_policy_ids.add(policy_id)
        log.warning(
            "policy regex failed to compile; policy will fail closed "
            "(policy_id=%s rule_id=%s field=%s pattern=%r cause=%s)",
            policy_id,
            rule_id,
            field,
            pattern,
            cause,
        )
        if self._on_compile_error is not None:
            try:
                self._on_compile_error(
                    CompileErrorInfo(policy_id, rule_id, field, pattern, cause)
                )
            except Exception:
                log.exception("on_compile_error hook raised; ignoring")

    def evaluate(self, request: EvaluationRequest) -> EvaluationResult:
        start = time.perf_counter()
        budget_start = start
        with self._lock:
            bundle = self._bundle
            errored_policy_ids = self._errored_policy_ids
            compiled_patterns = self._compiled_patterns

        # Kill-switch: frozen agents are denied before policies run.
        if (
            bundle is not None
            and request.agent_id is not None
            and _is_frozen(bundle, request.agent_id)
        ):
            return EvaluationResult(
                decision=DECISION_DENY,
                code=RESULT_CODE_AGENT_FROZEN,
                reason=DENY_REASON_AGENT_FROZEN,
                latencyMs=_elapsed_ms(start),
            )

        # MCP server allow-list gate. Default-deny any `mcp__<server>__*`
        # call whose server isn't approved, before policy evaluation —
        # mirrors the Node SDK core. `enforce=False` (e.g. solo installs)
        # disables the gate; older bundles default `enforce=True`.
        #
        # Adapters strip the `mcp__<server>__` prefix off `tool_name` so
        # policy *conditions* match the canonical name (`query`), but they
        # forward the RAW prefixed name in `mcp_tool_name` so this gate can
        # still recover the server. Parse the raw name when present and fall
        # back to `tool_name` for callers that pass the prefixed name
        # directly (e.g. the Claude Code daemon).
        if bundle is not None and bundle.mcpAccess.enforce:
            gate_name = (
                getattr(request, MCP_GATE_FIELD, None) or request.tool_name
            )
            parsed = parse_mcp_server(gate_name)
            if parsed is not None and parsed[0] not in bundle.mcpAccess.approvedServers:
                return EvaluationResult(
                    decision=DECISION_DENY,
                    code=RESULT_CODE_MCP_NOT_APPROVED,
                    reason=deny_reason_mcp_not_approved(parsed[0]),
                    latencyMs=_elapsed_ms(start),
                )

        # Empty bundle / cold-start is not permissive. Both "haven't
        # pulled yet" (None) and "server says empty" are treated as
        # "we don't know what the policy is" → deny.
        if bundle is None or len(bundle.policies) == 0:
            return EvaluationResult(
                decision=DECISION_DENY,
                code=RESULT_CODE_NO_POLICIES,
                reason=_REASON_NO_POLICIES,
                latencyMs=_elapsed_ms(start),
            )

        request_dict: dict[str, Any] = request.model_dump()

        if _native_available and self._native_evaluator is not None:
            try:
                result = self._native_evaluator.evaluate(request_dict)  # type: ignore[attr-defined]
                decision: Decision = (
                    DECISION_DENY if str(result.decision).lower() == DECISION_DENY else DECISION_ALLOW
                )
                return EvaluationResult(
                    decision=decision,
                    matchedPolicyId=getattr(result, "policy_id", None),
                    matchedPolicyVersion=getattr(result, "policy_version", None),
                    matchedRuleId=getattr(result, "rule_id", None),
                    latencyMs=_elapsed_ms(start),
                )
            except Exception:
                log.exception("native evaluator raised; falling back to pure-Python")
                return _evaluate_in_tree(
                    bundle,
                    request_dict,
                    start,
                    budget_start,
                    errored_policy_ids,
                    compiled_patterns,
                    native_fallback=True,
                )

        return _evaluate_in_tree(
            bundle,
            request_dict,
            start,
            budget_start,
            errored_policy_ids,
            compiled_patterns,
            native_fallback=False,
        )


def _evaluate_in_tree(
    bundle: Bundle,
    request: dict[str, Any],
    start: float,
    budget_start: float,
    errored_policy_ids: set[str],
    compiled_patterns: dict[int, _regex.Pattern[str]],
    native_fallback: bool,
) -> EvaluationResult:
    fallback_code: str | None = RESULT_CODE_NATIVE_FALLBACK if native_fallback else None
    final_decision: Decision = DECISION_ALLOW
    matched: BundlePolicyEntry | None = None
    matched_rule_id: str | None = None

    for entry in bundle.policies:
        # Any policy with an uncompileable regex fails closed for every
        # request that would have touched it. Checked at the policy
        # level because a deny rule with a broken pattern shouldn't be
        # silently treated as never-matching while sibling allow rules
        # continue to fire.
        if entry.policyId in errored_policy_ids:
            return EvaluationResult(
                decision=DECISION_DENY,
                code=RESULT_CODE_POLICY_COMPILE_ERROR,
                reason=_REASON_POLICY_COMPILE_ERROR,
                matchedPolicyId=entry.policyId,
                matchedPolicyVersion=entry.policyVersion,
                latencyMs=_elapsed_ms(start),
            )

        for rule in entry.document.spec.rules:
            # Bound per-evaluation wall-clock. Checked at the rule
            # boundary — fine-grained enough to bail out of a
            # pathological bundle without paying the check cost on
            # every condition.
            if (time.perf_counter() - budget_start) * _MS_PER_SECOND > EVAL_WALL_CLOCK_BUDGET_MS:
                log.warning(
                    "evaluation exceeded wall-clock budget; failing closed "
                    "(policy_id=%s rule_id=%s budget_ms=%s)",
                    entry.policyId,
                    rule.id,
                    EVAL_WALL_CLOCK_BUDGET_MS,
                )
                return EvaluationResult(
                    decision=DECISION_DENY,
                    code=RESULT_CODE_EVAL_TIMEOUT,
                    reason=_REASON_EVAL_TIMEOUT,
                    latencyMs=_elapsed_ms(start),
                )

            if all(_matches(c, request, compiled_patterns) for c in rule.conditions):
                # First matching rule wins; deny short-circuits.
                final_decision = rule.effect
                matched = entry
                matched_rule_id = rule.id
                if final_decision == DECISION_DENY:
                    return EvaluationResult(
                        decision=DECISION_DENY,
                        matchedPolicyId=matched.policyId,
                        matchedPolicyVersion=matched.policyVersion,
                        matchedRuleId=matched_rule_id,
                        latencyMs=_elapsed_ms(start),
                        code=fallback_code,
                    )

    if matched is None:
        # Fall through to first policy's default.
        default: Decision = (
            bundle.policies[0].document.spec.defaultEffect if bundle.policies else DECISION_ALLOW
        )
        return EvaluationResult(
            decision=default,
            latencyMs=_elapsed_ms(start),
            code=fallback_code,
        )

    return EvaluationResult(
        decision=final_decision,
        matchedPolicyId=matched.policyId,
        matchedPolicyVersion=matched.policyVersion,
        matchedRuleId=matched_rule_id,
        latencyMs=_elapsed_ms(start),
        code=fallback_code,
    )


def _is_frozen(bundle: Bundle, agent_id: str) -> bool:
    """Case-insensitive membership check.

    Operator typo in the dashboard ("Agent-123" vs "agent-123") shouldn't
    silently unfreeze. Lowercase both sides.
    """
    needle = agent_id.lower()
    return any(fid.lower() == needle for fid in bundle.frozenAgentIds)


def _resolve_field(request: dict[str, Any], field: str) -> Any:
    """Walk a dot-separated path through the request dict.

    `kwargs.amount` → request["kwargs"]["amount"]; missing path components or
    non-dict intermediates return None. Any part matching the forbidden-parts
    list (`__proto__`, `constructor`, `prototype`) resolves to None, and
    `in` membership is used so inherited attributes on a mapping subclass
    don't resolve.
    """
    parts = field.split(".")
    cur: Any = request
    for part in parts:
        if part in _FORBIDDEN_FIELD_PARTS:
            return None
        if not isinstance(cur, dict):
            return None
        if part not in cur:
            return None
        cur = cur[part]
        if cur is None:
            return None
    return cur


def _stringify(v: Any) -> str:
    return v if isinstance(v, str) else str(v)


def _in_match(actual: Any, expected: Any) -> bool:
    """Membership check with both sides stringified.

    Numeric request fields rendered as strings on the wire (or vice
    versa) should still match — `1000 in ["1000", "2000"]` returns True.
    None / missing values never match.
    """
    if actual is None:
        return False
    actual_str = _stringify(actual)
    items = expected if isinstance(expected, list) else [expected]
    for item in items:
        if item is None:
            continue
        if _stringify(item) == actual_str:
            return True
    return False


def _string_op_match(
    actual: Any,
    expected: Any,
    op: Callable[[str, str], bool],
) -> bool:
    """`contains` / `starts_with` / `ends_with` with stringified sides.

    Array `expected` is type-system-possible (per the schema) but
    doesn't make semantic sense for these operators; refuse to match
    rather than picking an arbitrary element.
    """
    if actual is None:
        return False
    if isinstance(expected, list):
        return False
    if expected is None:
        return False
    return op(_stringify(actual), _stringify(expected))


def _matches(
    condition: PolicyCondition,
    request: dict[str, Any],
    compiled_patterns: dict[int, _regex.Pattern[str]],
) -> bool:
    actual = _resolve_field(request, condition.field)
    op = condition.operator
    expected = condition.value

    if op == "eq":
        return actual == expected
    if op == "neq":
        return actual != expected
    if op == "in":
        return _in_match(actual, expected)
    if op == "not_in":
        return not _in_match(actual, expected)
    if op == "contains":
        return _string_op_match(actual, expected, lambda a, b: b in a)
    if op == "starts_with":
        return _string_op_match(actual, expected, lambda a, b: a.startswith(b))
    if op == "ends_with":
        return _string_op_match(actual, expected, lambda a, b: a.endswith(b))
    if op == "matches":
        # Patterns are pre-compiled in `update_bundle`; a missing entry
        # here means the pattern failed to compile (in which case the
        # policy-level POLICY_COMPILE_ERROR fires earlier and we don't
        # reach this code path) or that the evaluator is being driven
        # with a condition object that didn't come from the cached
        # bundle. Returns no match either way.
        if actual is None:
            return False
        pattern = compiled_patterns.get(id(condition))
        if pattern is None:
            return False
        actual_str = _stringify(actual)
        # Bounded execution time via `regex`'s `timeout=`. 0.5s is
        # generous for any well-formed pattern. On timeout we treat the
        # match as "did not match" so audit logging continues.
        try:
            return pattern.search(actual_str, timeout=_MATCH_TIMEOUT_SECONDS) is not None
        except TimeoutError:
            log.warning(
                "policy regex search exceeded per-match timeout; treating as no-match "
                "(field=%s pattern=%r)",
                condition.field,
                expected,
            )
            return False
    return False


def _elapsed_ms(start: float) -> float:
    return (time.perf_counter() - start) * _MS_PER_SECOND


def native_backend_available() -> bool:
    return _native_available
