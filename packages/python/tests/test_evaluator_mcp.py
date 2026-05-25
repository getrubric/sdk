"""Tests for the evaluator's MCP server allow-list gate.

Mirrors the Node SDK core's MCP gating tests: a bundle with
`mcpAccess.enforce` default-denies any `mcp__<server>__*` call whose server
isn't approved, before policy evaluation. `enforce=False` disables the gate,
and older bundles that omit `mcpAccess` default the gate on.
"""

from __future__ import annotations

import hashlib

from rubric.constants import RESULT_CODE_MCP_NOT_APPROVED, parse_mcp_server
from rubric.evaluator import Evaluator
from rubric.types import (
    Bundle,
    BundleMcpAccess,
    BundlePolicyEntry,
    EvaluationRequest,
    PolicyDocument,
    PolicyMetadata,
    PolicyRule,
    PolicySpec,
    now_iso,
)

_POLICY_ID = "00000000-0000-4000-8000-000000000001"


def _allow_all_doc() -> PolicyDocument:
    # `defaultEffect: allow` with a single never-matching rule, so the bundle
    # is non-empty and the only thing that can deny is the MCP gate.
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


def _eval(bundle: Bundle, tool_name: str) -> str:
    ev = Evaluator()
    ev.update_bundle(bundle)
    return ev.evaluate(EvaluationRequest(tool_name=tool_name, agent_id="a")).decision


def test_parse_mcp_server_splits_server_and_tool() -> None:
    assert parse_mcp_server("mcp__supabase__query") == ("supabase", "query")
    # tool segment may itself contain the delimiter
    assert parse_mcp_server("mcp__vercel__deploy__prod") == ("vercel", "deploy__prod")


def test_parse_mcp_server_rejects_non_mcp_and_empty_server() -> None:
    assert parse_mcp_server("Bash") is None
    assert parse_mcp_server("mcp____query") is None  # empty server segment
    assert parse_mcp_server("mcp__supabase") is None  # no tool delimiter


def test_unapproved_mcp_server_is_denied() -> None:
    bundle = _bundle(approved_servers=[])
    ev = Evaluator()
    ev.update_bundle(bundle)
    result = ev.evaluate(EvaluationRequest(tool_name="mcp__supabase__query", agent_id="a"))
    assert result.decision == "deny"
    assert result.code == RESULT_CODE_MCP_NOT_APPROVED
    assert "supabase" in (result.reason or "")


def test_approved_mcp_server_falls_through_to_policy() -> None:
    bundle = _bundle(approved_servers=["supabase"])
    assert _eval(bundle, "mcp__supabase__query") == "allow"
    # a different, unapproved server is still denied
    assert _eval(bundle, "mcp__vercel__deploy") == "deny"


def test_enforce_false_disables_the_gate() -> None:
    bundle = _bundle(approved_servers=[], enforce=False)
    assert _eval(bundle, "mcp__supabase__query") == "allow"


def test_non_mcp_tools_are_unaffected_by_the_gate() -> None:
    bundle = _bundle(approved_servers=[])
    assert _eval(bundle, "Bash") == "allow"


def test_bundle_without_mcp_access_defaults_gate_on() -> None:
    # A bundle from an older control plane omits `mcpAccess` entirely; it
    # must still parse, and the gate defaults on (enforce=True, empty list).
    bundle = Bundle(
        bundleVersion=0,
        contentHash=hashlib.sha256(b"test").hexdigest(),
        builtAt=now_iso(),
        policies=[
            BundlePolicyEntry(policyId=_POLICY_ID, policyVersion=0, document=_allow_all_doc())
        ],
    )
    assert bundle.mcpAccess.enforce is True
    assert _eval(bundle, "mcp__supabase__query") == "deny"
    assert _eval(bundle, "Bash") == "allow"
