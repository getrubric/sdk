"""Tests: the MCP allow-list gate still applies when adapters strip the prefix.

The framework adapters strip the `mcp__<server>__` prefix off the tool name
before calling `Governance.evaluate`, so the policy *conditions* match the
canonical name (`query`). The MCP allow-list gate in the evaluator only fires
when it can recover the `<server>` segment from the prefixed name, so the raw
prefixed name is threaded to the evaluator via `mcp_tool_name`.

These tests drive the adapter layer and assert the gate still applies to an
unapproved `mcp__<server>__<tool>` call even after the prefix is stripped.
"""

from __future__ import annotations

import asyncio
import hashlib

from rubric.adapters._naming import default_tool_name
from rubric.adapters.claude_agent import governance_hook
from rubric.constants import (
    EVAL_REQUEST_FIELD_MCP_TOOL_NAME,
    HOOK_INPUT_FIELD_TOOL_INPUT,
    HOOK_INPUT_FIELD_TOOL_NAME,
    HOOK_OUTPUT_FIELD_HOOK_SPECIFIC_OUTPUT,
    HOOK_OUTPUT_FIELD_PERMISSION_DECISION,
    PERMISSION_DECISION_DENY,
    RESULT_CODE_MCP_NOT_APPROVED,
)
from rubric.evaluator import Evaluator
from rubric.types import (
    Bundle,
    BundleMcpAccess,
    BundlePolicyEntry,
    EvaluationMetadata,
    EvaluationRequest,
    EvaluationResult,
    PolicyDocument,
    PolicyMetadata,
    PolicyRule,
    PolicySpec,
    now_iso,
)

_POLICY_ID = "00000000-0000-4000-8000-000000000001"


def _allow_all_doc() -> PolicyDocument:
    # defaultEffect=allow + a never-matching deny rule, so the only thing
    # that can deny an approved-server call is... nothing. The MCP gate is
    # the sole denier here.
    return PolicyDocument(
        metadata=PolicyMetadata(name="allow-all"),
        spec=PolicySpec(
            defaultEffect="allow",
            rules=[
                PolicyRule(
                    id="never",
                    conditions=[{"field": "tool_name", "operator": "eq", "value": "__never__"}],
                    effect="deny",
                )
            ],
        ),
    )


def _bundle(*, approved_servers: list[str], enforce: bool = True) -> Bundle:
    return Bundle(
        bundleVersion=0,
        contentHash=hashlib.sha256(b"test").hexdigest(),
        builtAt=now_iso(),
        policies=[
            BundlePolicyEntry(policyId=_POLICY_ID, policyVersion=0, document=_allow_all_doc())
        ],
        mcpAccess=BundleMcpAccess(approvedServers=approved_servers, enforce=enforce),
    )


class _FakeGovernance:
    """Minimal stand-in for `Governance` that runs a real `Evaluator`.

    Mirrors the `evaluate(...)` keyword surface the adapters rely on
    (`tool_name`, `mcp_tool_name`) and threads `mcp_tool_name` into the
    request exactly as the real client does. No network / threads.
    """

    def __init__(self, bundle: Bundle) -> None:
        self._ev = Evaluator()
        self._ev.update_bundle(bundle)
        self.last_request: EvaluationRequest | None = None

    def evaluate(
        self,
        tool_name: str,
        *,
        session_id: str,
        agent_id: str | None = None,
        metadata: EvaluationMetadata | None = None,
        framework: str | None = None,
        trace: object | None = None,
        mcp_tool_name: str | None = None,
    ) -> EvaluationResult:
        gate_fields = (
            {EVAL_REQUEST_FIELD_MCP_TOOL_NAME: mcp_tool_name}
            if mcp_tool_name is not None
            else {}
        )
        req = EvaluationRequest(tool_name=tool_name, agent_id="a", **gate_fields)
        self.last_request = req
        return self._ev.evaluate(req)


def _run_hook(gov: _FakeGovernance, raw_tool_name: str) -> dict:
    hook = governance_hook(gov, session_id="s1")  # type: ignore[arg-type]
    payload = {
        HOOK_INPUT_FIELD_TOOL_NAME: raw_tool_name,
        HOOK_INPUT_FIELD_TOOL_INPUT: {"q": "select 1"},
    }
    return asyncio.run(hook(payload, "tu-1", None))


def test_claude_agent_hook_denies_unapproved_mcp_server() -> None:
    # supabase is NOT approved; the canonical name `query` would otherwise
    # sail past an allow-all policy. The gate must still deny.
    gov = _FakeGovernance(_bundle(approved_servers=[]))
    out = _run_hook(gov, "mcp__supabase__query")

    # The adapter stripped the prefix for policy matching...
    assert gov.last_request is not None
    assert gov.last_request.tool_name == "query"
    # ...but forwarded the raw name so the gate can recover the server.
    assert getattr(gov.last_request, EVAL_REQUEST_FIELD_MCP_TOOL_NAME) == "mcp__supabase__query"

    hook_out = out[HOOK_OUTPUT_FIELD_HOOK_SPECIFIC_OUTPUT]
    assert hook_out[HOOK_OUTPUT_FIELD_PERMISSION_DECISION] == PERMISSION_DECISION_DENY


def test_claude_agent_hook_allows_approved_mcp_server() -> None:
    # supabase approved → canonical `query` falls through allow-all → allow
    # (the adapter returns {} = no permission override = allowed).
    gov = _FakeGovernance(_bundle(approved_servers=["supabase"]))
    out = _run_hook(gov, "mcp__supabase__query")
    assert out == {}


def test_claude_agent_hook_denies_different_unapproved_server() -> None:
    gov = _FakeGovernance(_bundle(approved_servers=["supabase"]))
    out = _run_hook(gov, "mcp__vercel__deploy")
    hook_out = out[HOOK_OUTPUT_FIELD_HOOK_SPECIFIC_OUTPUT]
    assert hook_out[HOOK_OUTPUT_FIELD_PERMISSION_DECISION] == PERMISSION_DECISION_DENY


def test_non_mcp_tool_through_adapter_is_unaffected() -> None:
    gov = _FakeGovernance(_bundle(approved_servers=[]))
    out = _run_hook(gov, "Bash")
    assert out == {}
    assert gov.last_request is not None
    assert gov.last_request.tool_name == "Bash"


def test_evaluator_gate_uses_raw_mcp_name_over_stripped_tool_name() -> None:
    # Direct evaluator check: canonical `tool_name` (stripped) + raw name in
    # `mcp_tool_name`. The gate parses the raw name and denies the
    # unapproved server.
    ev = Evaluator()
    ev.update_bundle(_bundle(approved_servers=[]))
    canonical = default_tool_name("mcp__supabase__query")
    assert canonical == "query"
    req = EvaluationRequest(
        tool_name=canonical,
        agent_id="a",
        **{EVAL_REQUEST_FIELD_MCP_TOOL_NAME: "mcp__supabase__query"},
    )
    result = ev.evaluate(req)
    assert result.decision == "deny"
    assert result.code == RESULT_CODE_MCP_NOT_APPROVED
    assert "supabase" in (result.reason or "")
