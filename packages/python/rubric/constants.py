"""Cross-cutting string and structural constants for the SDK.

Wire-level constants — route paths, header names, token prefix, problem
type URIs, MCP framework name, and decision values — that need to be in
agreement with the Rubric API.
"""

from __future__ import annotations

import os
from typing import Final, Literal, get_args
from urllib.parse import urlparse

# ---- Policy / API version ----------------------------------------------------

POLICY_API_VERSION: Final = "agent-governance.io/v1"
POLICY_KIND: Final = "Policy"

# ---- HTTP routes -------------------------------------------------------------

API_ROUTE_HEALTH: Final = "/health"
API_ROUTE_POLICIES: Final = "/v1/policies"
API_ROUTE_BUNDLE: Final = "/v1/bundle"
API_ROUTE_EVENTS: Final = "/v1/events"
API_ROUTE_INSIGHTS: Final = "/v1/insights"
API_ROUTE_TRACES: Final = "/v1/traces"
API_ROUTE_AUDIT: Final = "/v1/audit"
API_ROUTE_IDENTITIES_REFRESH: Final = "/v1/identities/refresh"
API_ROUTE_IDENTITIES_ENROLL: Final = "/v1/identities/enroll"

# ---- HTTP headers / content types -------------------------------------------

HTTP_HEADER_AUTHORIZATION: Final = "authorization"
HTTP_HEADER_CONTENT_TYPE: Final = "content-type"
HTTP_HEADER_ETAG: Final = "etag"
HTTP_HEADER_IF_NONE_MATCH: Final = "if-none-match"

CONTENT_TYPE_JSON: Final = "application/json"
CONTENT_TYPE_PROBLEM_JSON: Final = "application/problem+json"

AUTH_BEARER_PREFIX: Final = "Bearer "

# ---- HTTP status codes -------------------------------------------------------

HTTP_OK: Final = 200
HTTP_NO_CONTENT: Final = 204
HTTP_NOT_MODIFIED: Final = 304
HTTP_BAD_REQUEST: Final = 400
HTTP_UNAUTHORIZED: Final = 401
HTTP_FORBIDDEN: Final = 403
HTTP_NOT_FOUND: Final = 404
HTTP_UNPROCESSABLE_ENTITY: Final = 422
HTTP_ACCEPTED: Final = 202

CLIENT_ERROR_RANGE: Final = range(400, 500)

# ---- Decisions / policy effects ---------------------------------------------

Decision = Literal["allow", "deny"]
DECISION_ALLOW: Final[Decision] = "allow"
DECISION_DENY: Final[Decision] = "deny"
DECISION_VALUES: Final[tuple[Decision, ...]] = get_args(Decision)

PolicyEffect = Decision  # alias — same value set, semantically distinct
POLICY_EFFECT_ALLOW: Final[PolicyEffect] = DECISION_ALLOW
POLICY_EFFECT_DENY: Final[PolicyEffect] = DECISION_DENY

# ---- Policy version status ---------------------------------------------------

PolicyVersionStatus = Literal["draft", "active", "archived"]
POLICY_VERSION_STATUS_DRAFT: Final[PolicyVersionStatus] = "draft"
POLICY_VERSION_STATUS_ACTIVE: Final[PolicyVersionStatus] = "active"
POLICY_VERSION_STATUS_ARCHIVED: Final[PolicyVersionStatus] = "archived"

# ---- Policy condition operators ---------------------------------------------

PolicyConditionOperator = Literal[
    "eq", "neq", "in", "not_in", "contains", "starts_with", "ends_with", "matches"
]

# ---- Kill-switch (frozen agent) deny semantics ------------------------------

DENY_REASON_AGENT_FROZEN: Final = "agent frozen by operator"
RESULT_CODE_AGENT_FROZEN: Final = "AGENT_FROZEN"

# ---- DLP types and severities ----------------------------------------------

DlpSeverity = Literal["low", "medium", "high"]
DLP_SEVERITY_LOW: Final[DlpSeverity] = "low"
DLP_SEVERITY_MEDIUM: Final[DlpSeverity] = "medium"
DLP_SEVERITY_HIGH: Final[DlpSeverity] = "high"

# DLP detection type identifiers used in `DlpDetection.type`.
DLP_TYPE_CREDIT_CARD: Final = "CREDIT_CARD"
DLP_TYPE_US_SSN: Final = "US_SSN"
DLP_TYPE_IBAN_CODE: Final = "IBAN_CODE"
DLP_TYPE_AWS_ACCESS_KEY: Final = "AWS_ACCESS_KEY"
DLP_TYPE_GCP_API_KEY: Final = "GCP_API_KEY"
DLP_TYPE_GITHUB_TOKEN: Final = "GITHUB_TOKEN"
DLP_TYPE_GENERIC_API_KEY: Final = "GENERIC_API_KEY"
DLP_TYPE_EMAIL: Final = "EMAIL_ADDRESS"
DLP_TYPE_PHONE: Final = "PHONE_NUMBER"
DLP_TYPE_PERSON: Final = "PERSON"
DLP_TYPE_LOCATION: Final = "LOCATION"
DLP_TYPE_URL: Final = "URL"
DLP_TYPE_IP_ADDRESS: Final = "IP_ADDRESS"

DLP_SEVERITY_BY_TYPE: Final[dict[str, DlpSeverity]] = {
    DLP_TYPE_CREDIT_CARD: DLP_SEVERITY_HIGH,
    DLP_TYPE_US_SSN: DLP_SEVERITY_HIGH,
    DLP_TYPE_IBAN_CODE: DLP_SEVERITY_HIGH,
    DLP_TYPE_AWS_ACCESS_KEY: DLP_SEVERITY_HIGH,
    DLP_TYPE_GCP_API_KEY: DLP_SEVERITY_HIGH,
    DLP_TYPE_GITHUB_TOKEN: DLP_SEVERITY_HIGH,
    DLP_TYPE_GENERIC_API_KEY: DLP_SEVERITY_HIGH,
    "MEDICAL_LICENSE": DLP_SEVERITY_HIGH,
    "US_PASSPORT": DLP_SEVERITY_HIGH,
    "US_DRIVER_LICENSE": DLP_SEVERITY_HIGH,
    DLP_TYPE_EMAIL: DLP_SEVERITY_MEDIUM,
    DLP_TYPE_PHONE: DLP_SEVERITY_MEDIUM,
    DLP_TYPE_PERSON: DLP_SEVERITY_MEDIUM,
    "DATE_TIME": DLP_SEVERITY_MEDIUM,
    DLP_TYPE_LOCATION: DLP_SEVERITY_MEDIUM,
    "NRP": DLP_SEVERITY_MEDIUM,
    DLP_TYPE_URL: DLP_SEVERITY_LOW,
    DLP_TYPE_IP_ADDRESS: DLP_SEVERITY_LOW,
    "CRYPTO": DLP_SEVERITY_LOW,
}

# Field-name heuristics for GENERIC_API_KEY recognizer.
DLP_KEYISH_FIELD_PATTERN: Final = r"(token|key|secret|password|api[_-]?key|auth)"
DLP_MAX_PAYLOAD_BYTES: Final = 64 * 1024
DLP_REQUEST_FIELD_DETECTED: Final = "dlp_detected"
DLP_REQUEST_FIELD_SEVERITY: Final = "dlp_severity"
DLP_REQUEST_FIELD_TYPES: Final = "dlp_types"

# DLP modes — string values exposed via Governance(dlp=...).
DlpMode = Literal["off", "regex", "presidio", "auto"]
DLP_MODE_OFF: Final[DlpMode] = "off"
DLP_MODE_REGEX: Final[DlpMode] = "regex"
DLP_MODE_PRESIDIO: Final[DlpMode] = "presidio"
DLP_MODE_AUTO: Final[DlpMode] = "auto"

ENV_DLP: Final = "RUBRIC_DLP"

# ---- Framework names (for the agent registry) ------------------------------

FRAMEWORK_MCP: Final = "mcp"
FRAMEWORK_CLAUDE_AGENT: Final = "claude-agent"
FRAMEWORK_LANGCHAIN: Final = "langchain"
FRAMEWORK_CUSTOM: Final = "custom"
FRAMEWORK_UNKNOWN: Final = "unknown"

# ---- Enrollment token format ------------------------------------------------

# Enrollment-token format: enr_<prefix>.<secret>
ENROLLMENT_TOKEN_PREFIX: Final = "enr_"
ENROLLMENT_TOKEN_TOKEN_DELIMITER: Final = "."

# Identity TTL knobs are server-side; we only need the lead time the SDK uses
# to schedule its proactive refresh.
IDENTITY_REFRESH_LEAD_SECONDS: Final = 600.0

# ---- MCP tool naming (Claude Agent SDK) -------------------------------------

MCP_TOOL_NAME_PREFIX: Final = "mcp__"
MCP_TOOL_NAME_DELIMITER: Final = "__"
MCP_TOOL_NAME_PARTS: Final = 3  # "mcp", "<server>", "<tool>"

# ---- MCP server gating ------------------------------------------------------
# Default-deny enforcement of the per-agent MCP allow-list carried in the
# bundle (`mcpAccess`). When the control plane ships a bundle with
# `mcpAccess.enforce = true`, a call to an `mcp__<server>__*` tool whose
# server isn't approved fails closed before policy evaluation. Mirrors
# `parseMcpServer` / `RESULT_CODE_MCP_NOT_APPROVED` in the Node SDK core.

RESULT_CODE_MCP_NOT_APPROVED: Final = "MCP_SERVER_NOT_APPROVED"


def parse_mcp_server(tool_name: str) -> tuple[str, str] | None:
    """Split ``mcp__<server>__<tool>`` → ``(server, tool)``; ``None`` if not MCP.

    Returns ``None`` when the name isn't MCP-prefixed or the server segment
    would be empty, matching the Node SDK's ``parseMcpServer``.
    """
    if not tool_name.startswith(MCP_TOOL_NAME_PREFIX):
        return None
    rest = tool_name[len(MCP_TOOL_NAME_PREFIX):]
    idx = rest.find(MCP_TOOL_NAME_DELIMITER)
    if idx <= 0:  # server segment must be non-empty
        return None
    return rest[:idx], rest[idx + len(MCP_TOOL_NAME_DELIMITER):]


def deny_reason_mcp_not_approved(server: str) -> str:
    return (
        f'MCP server "{server}" is not approved for this agent. '
        "Request access in your Rubric dashboard."
    )

# ---- Claude Agent SDK hook names / fields -----------------------------------

HOOK_EVENT_PRE_TOOL_USE: Final = "PreToolUse"

HOOK_INPUT_FIELD_TOOL_NAME: Final = "tool_name"
HOOK_INPUT_FIELD_TOOL_INPUT: Final = "tool_input"

HOOK_OUTPUT_FIELD_HOOK_SPECIFIC_OUTPUT: Final = "hookSpecificOutput"
HOOK_OUTPUT_FIELD_EVENT_NAME: Final = "hookEventName"
HOOK_OUTPUT_FIELD_PERMISSION_DECISION: Final = "permissionDecision"
HOOK_OUTPUT_FIELD_PERMISSION_REASON: Final = "permissionDecisionReason"

PermissionDecision = Literal["allow", "deny", "ask"]
PERMISSION_DECISION_DENY: Final[PermissionDecision] = "deny"
PERMISSION_DECISION_ALLOW: Final[PermissionDecision] = "allow"

# ---- RFC 9457 problem type URIs ---------------------------------------------

_PROBLEM_TYPE_BASE: Final = "https://rubric-app.com/problems"
PROBLEM_TYPE_ABOUT_BLANK: Final = "about:blank"
PROBLEM_TYPE_NOT_FOUND: Final = f"{_PROBLEM_TYPE_BASE}/not-found"
PROBLEM_TYPE_POLICY_VALIDATION_FAILED: Final = f"{_PROBLEM_TYPE_BASE}/policy-validation-failed"
PROBLEM_TYPE_UNAUTHENTICATED: Final = f"{_PROBLEM_TYPE_BASE}/unauthenticated"
PROBLEM_TYPE_NO_ACTIVE_ORG: Final = f"{_PROBLEM_TYPE_BASE}/no-active-org"
PROBLEM_TYPE_INVALID_IDENTITY: Final = f"{_PROBLEM_TYPE_BASE}/invalid-identity"
PROBLEM_TYPE_IDENTITY_AGENT_MISMATCH: Final = f"{_PROBLEM_TYPE_BASE}/identity-agent-mismatch"
PROBLEM_TYPE_FORBIDDEN: Final = f"{_PROBLEM_TYPE_BASE}/forbidden"
PROBLEM_TYPE_INVALID_REQUEST: Final = f"{_PROBLEM_TYPE_BASE}/invalid-request"
PROBLEM_TYPE_INTERNAL_SERVER_ERROR: Final = f"{_PROBLEM_TYPE_BASE}/internal-server-error"

# ---- SDK environment variables ----------------------------------------------

ENV_ENROLLMENT_TOKEN: Final = "RUBRIC_ENROLLMENT_TOKEN"
ENV_AGENT_NAME: Final = "RUBRIC_AGENT_NAME"
ENV_API_URL: Final = "RUBRIC_API_URL"
DEFAULT_API_URL: Final = "https://api.rubric-app.com"

# ---- API URL validation -----------------------------------------------------

# The Rubric API is hosted on the `rubric-app.com` domain. The SDK refuses
# to send bearer-bearing traffic anywhere else. This rules out localhost,
# IP literals, third-party hosts, and `http://` of any kind.
ALLOWED_HOST_EXACT: Final = "rubric-app.com"
ALLOWED_HOST_SUFFIX: Final = ".rubric-app.com"


def validate_api_url(url: str) -> str | None:
    """Validate an API URL string.

    Returns ``None`` if the URL is acceptable, or a human-readable error
    message otherwise. The SDK accepts only ``https://`` URLs whose host
    is ``rubric-app.com`` or a subdomain of it (e.g. ``api.rubric-app.com``,
    ``staging.rubric-app.com``). The platform is hosted; there is no
    localhost or self-hosted path.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return f"not a valid URL: {url}"
    if not parsed.scheme or not parsed.netloc:
        return f"not a valid URL: {url}"
    scheme = parsed.scheme.lower()
    if scheme != "https":
        return f"must use https:// (got {parsed.scheme}://)"
    host = (parsed.hostname or "").lower()
    if host != ALLOWED_HOST_EXACT and not host.endswith(ALLOWED_HOST_SUFFIX):
        return (
            f"host '{host}' is not a Rubric host; "
            f"the API URL must be on {ALLOWED_HOST_EXACT} "
            f"(e.g. https://api.{ALLOWED_HOST_EXACT})"
        )
    return None


# ---- Bundle poller query parameter ------------------------------------------

BUNDLE_QUERY_SINCE: Final = "since"
