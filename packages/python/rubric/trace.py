"""Trace types and synchronous uploader.

Unlike the async audit sink, trace upload is synchronous on the evaluate path:
the SDK needs the server-assigned `traceId` and `tracePosition` to attach to
the audit event before that event ships. Payload is small (one session's
messages), so the blocking call is acceptable.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field

from rubric._scrub import scrub_deep, scrub_secrets
from rubric.constants import (
    API_ROUTE_TRACES,
    AUTH_BEARER_PREFIX,
    HTTP_HEADER_AUTHORIZATION,
    HTTP_UNAUTHORIZED,
)
from rubric.errors import parse_problem_details
from rubric.identity import IdentityRevokedError, TokenStore

log = logging.getLogger(__name__)

# Structured timeout mirrors the Node SDK trace uploader. A small connect/pool
# budget keeps a wedged server from holding the eval hot path; the read
# budget is the dominant factor since we ship full conversations.
_DEFAULT_HTTP_TIMEOUT: httpx.Timeout = httpx.Timeout(
    connect=2.0, read=10.0, write=10.0, pool=2.0
)
_RETRY_BACKOFF_SECONDS = 1.0


def now_iso() -> str:
    return (
        datetime.now(tz=timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=False)


# 4-arm discriminated union over the message roles that can appear in a trace.


class UserMessage(_StrictModel):
    role: Literal["user"] = "user"
    content: str
    ts: str = Field(default_factory=now_iso)


class AssistantMessage(_StrictModel):
    role: Literal["assistant"] = "assistant"
    content: str
    ts: str = Field(default_factory=now_iso)


class ToolCallMessage(_StrictModel):
    role: Literal["tool_call"] = "tool_call"
    toolName: str
    args: Any = None
    toolUseId: str | None = None
    ts: str = Field(default_factory=now_iso)


class ToolResultMessage(_StrictModel):
    role: Literal["tool_result"] = "tool_result"
    toolUseId: str | None = None
    content: str
    isError: bool = False
    ts: str = Field(default_factory=now_iso)


TraceMessage = UserMessage | AssistantMessage | ToolCallMessage | ToolResultMessage


class TraceContext(BaseModel):
    """Mutable bag of trace messages a user passes to `Governance.evaluate(...)`.

    The SDK appends the imminent `tool_call` to this list before uploading,
    so callers should pass a fresh-or-running list of context messages.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    messages: list[TraceMessage] = Field(default_factory=list)

    def append(self, msg: TraceMessage) -> None:
        self.messages.append(msg)


class TraceUpsertResponse(_StrictModel):
    traceId: str
    messageCount: int
    tracePosition: int


class TraceUpsertRequest(_StrictModel):
    sessionId: str
    agentId: str
    messages: list[TraceMessage]


class TraceUploader:
    """Synchronous POST /v1/traces with JWT-SVID bearer auth."""

    def __init__(
        self,
        api_url: str,
        token_store: TokenStore,
        client: httpx.Client | None = None,
    ) -> None:
        self._api_url = api_url.rstrip("/")
        self._token_store = token_store
        # `trust_env=False` so the caller's `HTTPS_PROXY` / `SSL_CERT_FILE`
        # don't redirect trace upload to an unexpected endpoint.
        self._client = client or httpx.Client(
            timeout=_DEFAULT_HTTP_TIMEOUT, trust_env=False
        )
        self._owns_client = client is None
        # Counter exposed for callers/tests so they can see how often the
        # transient-error retry path fires.
        self._failed_uploads: int = 0

    def upload(
        self, session_id: str, agent_id: str, messages: list[TraceMessage]
    ) -> TraceUpsertResponse | None:
        if not messages:
            return None
        # Scrub every string leaf of every message BEFORE serialization. Trace
        # messages carry `args` (tool input) and `content` (tool result /
        # assistant text) — the highest-volume secret-bearing channel in the
        # system. JWTs / postgres creds / AWS keys in these payloads must not
        # leave the host raw.
        scrubbed_messages: list[TraceMessage] = []
        for msg in messages:
            dumped = msg.model_dump()
            cleaned = scrub_deep(dumped)
            scrubbed_messages.append(type(msg).model_validate(cleaned))

        body = TraceUpsertRequest(
            sessionId=session_id, agentId=agent_id, messages=scrubbed_messages
        ).model_dump(mode="json")
        try:
            res = self._post_with_retry(body)
        except IdentityRevokedError:
            log.error("trace upload aborted: identity revoked")
            return None
        except Exception as e:
            self._failed_uploads += 1
            log.error("trace upload request failed: %s", type(e).__name__)
            return None

        if res.is_error:
            problem = parse_problem_details(res)
            if problem is not None:
                log.warning(
                    "trace upload rejected (%d, %s): %s",
                    res.status_code,
                    problem.type,
                    problem.detail or problem.title,
                )
            else:
                # Non-RFC9457 body — surface enough to triage without leaking
                # raw bearer tokens or JWTs that may appear in the response.
                log.warning(
                    "trace upload rejected (%d, non-problem+json body): %s",
                    res.status_code,
                    scrub_secrets(res.text[:200]),
                )
            return None

        try:
            return TraceUpsertResponse.model_validate(res.json())
        except Exception as e:
            log.error("trace upload response parse failed: %s", type(e).__name__)
            return None

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def _post_with_retry(self, body: dict[str, object]) -> httpx.Response:
        """One retry with a 1s sleep on transient httpx errors. Deliberately
        not a full retry loop — trace upload is on the eval hot path.

        A failure on the retry is re-raised to the caller, which increments
        `_failed_uploads` exactly once per upload() invocation."""
        try:
            return self._post(body, retry_on_401=True)
        except httpx.HTTPError as e:
            log.warning(
                "trace upload transient error: %s; retrying once",
                type(e).__name__,
            )
            time.sleep(_RETRY_BACKOFF_SECONDS)
            return self._post(body, retry_on_401=True)

    def _post(self, body: dict[str, object], *, retry_on_401: bool) -> httpx.Response:
        token = self._token_store.token()
        res = self._client.post(
            f"{self._api_url}{API_ROUTE_TRACES}",
            json=body,
            headers={HTTP_HEADER_AUTHORIZATION: f"{AUTH_BEARER_PREFIX}{token}"},
        )
        if res.status_code == HTTP_UNAUTHORIZED and retry_on_401:
            self._token_store.force_refresh()
            return self._post(body, retry_on_401=False)
        return res
