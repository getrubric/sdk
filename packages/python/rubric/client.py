from __future__ import annotations

import json
import logging
import os
from typing import Any

from rubric._scrub import scrub_deep
from rubric._version import __version__
from rubric.audit_sink import AuditSink
from rubric.bundle import BundlePoller
from rubric.constants import (
    DLP_MODE_AUTO,
    DLP_MODE_OFF,
    DLP_MODE_PRESIDIO,
    DLP_MODE_REGEX,
    DLP_REQUEST_FIELD_DETECTED,
    DLP_REQUEST_FIELD_SEVERITY,
    DLP_REQUEST_FIELD_TYPES,
    DLP_SEVERITY_HIGH,
    DlpMode,
    ENV_DLP,
    EVAL_REQUEST_FIELD_MCP_TOOL_NAME,
)
from rubric.dlp.detector import Detector, make_detector
from rubric.dlp.types import DlpDetection
from rubric.evaluator import Evaluator, native_backend_available
from rubric.identity import TokenStore, bootstrap_token_store
from rubric.trace import (
    ToolCallMessage,
    TraceContext,
    TraceUploader,
)
from rubric.types import (
    AuditEvent,
    Bundle,
    EvaluationMetadata,
    EvaluationRequest,
    EvaluationResult,
    now_iso,
)

log = logging.getLogger(__name__)

_DEFAULT_BUNDLE_POLL_SECONDS = 30.0

# Hard cap on the size of `tool_input` (serialized JSON) we'll forward to the
# DLP scanner / evaluator / audit pipeline. Oversized payloads are truncated
# and flagged with `truncated=True` in metadata so policy authors can see
# evidence of trimming downstream.
MAX_TOOL_INPUT_BYTES = 256 * 1024

# Keys a caller is allowed to set via `EvaluationMetadata` (which uses
# ``extra="allow"``). Anything else is dropped before the dict is splatted
# into ``EvaluationRequest`` — otherwise a caller could pass
# ``dlp_detected=False`` and override the in-process DLP scan.
_ALLOWED_METADATA_KEYS: frozenset[str] = frozenset(
    {"session_id", "trace_id", "input", "args", "kwargs", "tool_use_id"}
)


class Governance:
    """Entry point for the Rubric Python SDK.

    Construction is split into two stages:

    1. `Governance.bootstrap(...)` — presents an enrollment token + agent name
       to the Rubric API, receives a 60-minute JWT-SVID, and returns a
       fully-initialized instance with an auto-refresh loop running.
    2. `Governance(token_store=...)` — for tests and advanced flows where the
       caller owns the TokenStore. The store must be already initialized
       (i.e., `initial_enrollment()` must have completed before construction).

    Usage:
        with Governance.bootstrap(agent_name="my-bot") as gov:
            result = gov.evaluate("delete_file", session_id="s1")
            if result.decision == DECISION_DENY:
                raise PermissionError("denied by policy")
    """

    def __init__(
        self,
        token_store: TokenStore,
        api_url: str,
        bundle_poll_seconds: float = _DEFAULT_BUNDLE_POLL_SECONDS,
        autostart: bool = True,
        dlp: bool | DlpMode | Detector | None = None,
    ) -> None:
        self._token_store = token_store
        self._api_url = api_url
        self._agent_id: str = token_store.agent_id
        self._detector: Detector | None = _resolve_detector(dlp)

        self._evaluator = Evaluator()
        self._sink = AuditSink(api_url=api_url, token_store=token_store)
        self._poller = BundlePoller(
            api_url=api_url,
            token_store=token_store,
            on_update=self._evaluator.update_bundle,
            interval_seconds=bundle_poll_seconds,
        )
        self._trace_uploader = TraceUploader(api_url=api_url, token_store=token_store)

        if not native_backend_available():
            log.debug("Using the pure-Python evaluator backend.")

        if autostart:
            self.start()

    @classmethod
    def bootstrap(
        cls,
        *,
        enrollment_token: str | None = None,
        agent_name: str | None = None,
        api_url: str | None = None,
        bundle_poll_seconds: float = _DEFAULT_BUNDLE_POLL_SECONDS,
        autostart: bool = True,
        dlp: bool | DlpMode | Detector | None = None,
    ) -> "Governance":
        """Bootstrap a `Governance` instance against the Rubric API.

        Provide `enrollment_token` and `agent_name`, or set
        `RUBRIC_ENROLLMENT_TOKEN` and `RUBRIC_AGENT_NAME` env vars.
        Idempotent: every cold boot returns the same identity row, fresh
        JWT. `api_url` falls back to `RUBRIC_API_URL` (default
        `https://api.rubric-app.com`).
        """
        store = bootstrap_token_store(
            enrollment_token=enrollment_token,
            agent_name=agent_name,
            api_url=api_url,
        )
        # Resolve the same URL the store used so the Governance instance is
        # internally consistent (constants module pinning).
        from rubric.constants import DEFAULT_API_URL, ENV_API_URL

        resolved_url = api_url or os.environ.get(ENV_API_URL, DEFAULT_API_URL)
        return cls(
            token_store=store,
            api_url=resolved_url,
            bundle_poll_seconds=bundle_poll_seconds,
            autostart=autostart,
            dlp=dlp,
        )

    @property
    def agent_id(self) -> str:
        return self._agent_id

    @property
    def current_bundle(self) -> Bundle | None:
        return self._poller.current

    def start(self) -> None:
        self._sink.start()
        self._poller.start()

    def shutdown(self) -> None:
        self._poller.stop()
        self._sink.stop()
        self._trace_uploader.close()
        self._token_store.stop()

    def wait_until_ready(self, timeout: float = 10.0) -> bool:
        """Block until the first bundle pull completes (success or failure)."""
        return self._poller.wait_for_first_pull(timeout=timeout)

    def evaluate(
        self,
        tool_name: str,
        *,
        session_id: str,
        agent_id: str | None = None,
        metadata: EvaluationMetadata | None = None,
        framework: str | None = None,
        trace: TraceContext | None = None,
        mcp_tool_name: str | None = None,
    ) -> EvaluationResult:
        """Evaluate a tool call against the current bundle and ship an audit event.

        `agent_id` is locked to the identity issued at bootstrap; passing a
        different value is silently ignored (server-side, the JWT-bound
        identity is the source of truth and a mismatch returns 403).

        `mcp_tool_name` carries the *raw* ``mcp__<server>__<tool>`` name when
        the caller has already stripped the prefix off `tool_name` for policy
        matching (the framework adapters do this). The MCP allow-list gate
        parses it so the server check runs on the prefixed name; policy
        *conditions* still see the canonical `tool_name`. When omitted, the
        gate falls back to `tool_name`.
        """
        metadata_dict = metadata.model_dump(exclude_none=True) if metadata else {}

        # Filter caller-supplied metadata to a known-safe key set BEFORE the
        # dict is splatted into `EvaluationRequest`. Without this, a caller
        # could pass `metadata={"dlp_detected": False}` and clobber the
        # in-process DLP scan result downstream.
        truncated_flag = False
        if metadata_dict:
            metadata_dict = {
                k: v for k, v in metadata_dict.items() if k in _ALLOWED_METADATA_KEYS
            }

        # Cap `tool_input` size BEFORE scrubbing / scanning so a pathological
        # 50 MB payload can't stall the eval path or blow the audit row.
        if "input" in metadata_dict and metadata_dict["input"] is not None:
            try:
                serialized = json.dumps(metadata_dict["input"], default=str)
            except (TypeError, ValueError):
                serialized = str(metadata_dict["input"])
            if len(serialized.encode("utf-8", errors="ignore")) > MAX_TOOL_INPUT_BYTES:
                metadata_dict["input"] = serialized[:MAX_TOOL_INPUT_BYTES]
                truncated_flag = True

        # Scrub secrets out of every string leaf of the metadata BEFORE the
        # dict feeds into the evaluator request or the audit event. DLP only
        # *flags* — scrubbing is what actually keeps JWTs / postgres URLs /
        # AWS keys off the wire to the Rubric API.
        if metadata_dict:
            metadata_dict = scrub_deep(metadata_dict)

        # The token's `sub` claim binds this SDK to one agentId — the
        # parameter is kept for API stability but the bound id always wins.
        effective_agent_id = self._agent_id
        if agent_id is not None and agent_id != effective_agent_id:
            log.debug(
                "evaluate(agent_id=%r) ignored; bound agentId is %r",
                agent_id,
                effective_agent_id,
            )

        # Run DLP scan over the args payload (input / args / kwargs combined).
        dlp_detection = _run_dlp(self._detector, metadata_dict)

        # Build the request dict: base metadata + flattened DLP summary so
        # policies can match on `dlp_detected eq true`, `dlp_severity eq high`, etc.
        dlp_request_fields: dict[str, Any] = {}
        if dlp_detection is not None:
            dlp_request_fields = {
                DLP_REQUEST_FIELD_DETECTED: True,
                DLP_REQUEST_FIELD_SEVERITY: dlp_detection.severity,
                DLP_REQUEST_FIELD_TYPES: dlp_detection.types,
            }
        elif self._detector is not None:
            # DLP enabled but nothing detected → still expose `dlp_detected: false`
            # so policies can write `dlp_detected eq true → deny` cleanly.
            dlp_request_fields = {DLP_REQUEST_FIELD_DETECTED: False}

        # Forward the raw `mcp__<server>__<tool>` name (if the caller stripped
        # the prefix for policy matching) so the evaluator's MCP allow-list
        # gate can recover the server. `mcp_tool_name` is intentionally absent
        # from `_ALLOWED_METADATA_KEYS`, so it can't be set via `metadata` —
        # only this trusted parameter sets it.
        gate_fields: dict[str, Any] = (
            {EVAL_REQUEST_FIELD_MCP_TOOL_NAME: mcp_tool_name}
            if mcp_tool_name is not None
            else {}
        )

        request = EvaluationRequest(
            tool_name=tool_name,
            agent_id=effective_agent_id,
            **metadata_dict,
            **dlp_request_fields,
            **gate_fields,
        )
        result = self._evaluator.evaluate(request)

        event_metadata: dict[str, Any] | None = dict(metadata_dict) if metadata_dict else None
        if truncated_flag:
            event_metadata = event_metadata or {}
            event_metadata["truncated"] = True
        if result.code or result.reason:
            event_metadata = event_metadata or {}
            if result.code:
                event_metadata["denyCode"] = result.code
            if result.reason:
                event_metadata["denyReason"] = result.reason
        if dlp_detection is not None:
            event_metadata = event_metadata or {}
            event_metadata["dlp"] = dlp_detection.model_dump(mode="json")

        trace_id: str | None = None
        trace_position: int | None = None
        if trace is not None:
            tool_input = metadata_dict.get("input") if metadata_dict else None
            tool_use_id = metadata_dict.get("tool_use_id") if metadata_dict else None
            # `tool_input` is already scrubbed (it came from metadata_dict).
            trace.append(
                ToolCallMessage(
                    toolName=tool_name,
                    args=tool_input,
                    toolUseId=tool_use_id if isinstance(tool_use_id, str) else None,
                )
            )
            uploaded = self._trace_uploader.upload(
                session_id=session_id,
                agent_id=effective_agent_id,
                messages=trace.messages,
            )
            if uploaded is not None:
                trace_id = uploaded.traceId
                trace_position = uploaded.tracePosition

        event = AuditEvent(
            agentId=effective_agent_id,
            sessionId=session_id,
            ts=now_iso(),
            toolName=tool_name,
            decision=result.decision,
            policyId=result.matchedPolicyId,
            policyVersion=result.matchedPolicyVersion,
            latencyMs=result.latencyMs,
            metadata=event_metadata,
            framework=framework,
            version=__version__,
            traceId=trace_id,
            tracePosition=trace_position,
        )
        self._sink.enqueue(event)
        return result

    def __enter__(self) -> "Governance":
        return self

    def __exit__(self, *args: object) -> None:
        self.shutdown()


# ── DLP helpers ─────────────────────────────────────────────────────────────


def _resolve_detector(
    dlp: bool | DlpMode | Detector | None,
) -> Detector | None:
    """Translate the constructor argument (or env) into a concrete Detector."""

    # Off path
    if dlp is None or dlp is False or dlp == DLP_MODE_OFF:
        env_value = os.environ.get(ENV_DLP, "").lower()
        if env_value in ("", "0", "false", "off"):
            return None
        # Env says enabled — treat as auto.
        return make_detector(DLP_MODE_AUTO)

    # User passed a concrete detector instance
    if hasattr(dlp, "detect"):
        return dlp  # type: ignore[return-value]

    # True or named mode
    if dlp is True:
        return make_detector(DLP_MODE_AUTO)
    if dlp in (DLP_MODE_REGEX, DLP_MODE_PRESIDIO, DLP_MODE_AUTO):
        return make_detector(dlp)

    raise ValueError(f"unknown dlp option: {dlp!r}")


def _run_dlp(detector: Detector | None, metadata: dict[str, Any]) -> DlpDetection | None:
    """Run the detector over likely arg-bearing metadata fields."""
    if detector is None:
        return None
    payload: dict[str, Any] = {}
    for k in ("input", "args", "kwargs"):
        if k in metadata and metadata[k] is not None:
            payload[k] = metadata[k]
    if not payload:
        return None
    try:
        return detector.detect(payload)
    except Exception as e:
        # A detector crash must not become "no detection," or any
        # `dlp_detected eq true → deny` policy would stop firing on the very
        # input that crashed the detector. Surface a synthetic high-severity
        # signal so the policy still applies.
        log.error("DLP detector raised: %s; emitting fallback detection signal", type(e).__name__)
        return DlpDetection(
            detected=True,
            severity=DLP_SEVERITY_HIGH,
            types=["DETECTOR_ERROR"],
            counts={"DETECTOR_ERROR": 1},
            fields=[],
            durationMs=0.0,
        )
