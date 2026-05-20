"""JWT-SVID token store + bootstrap flow.

At boot time the SDK presents an enrollment token + agent name, the server
mints a 60-minute JWT-SVID, and the background refresh thread renews
proactively before expiry. All three HTTP clients (audit sink, bundle poller,
trace uploader) read the bearer token from this store on every request, so
revocation propagates the moment the refresh thread sees a 401.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from datetime import datetime
from typing import Final

import httpx
from pydantic import BaseModel, ConfigDict

from rubric._scrub import scrub_secrets
from rubric.constants import (
    API_ROUTE_IDENTITIES_ENROLL,
    API_ROUTE_IDENTITIES_REFRESH,
    AUTH_BEARER_PREFIX,
    DEFAULT_API_URL,
    ENV_AGENT_NAME,
    ENV_API_URL,
    ENV_ENROLLMENT_TOKEN,
    HTTP_HEADER_AUTHORIZATION,
    HTTP_UNAUTHORIZED,
    IDENTITY_REFRESH_LEAD_SECONDS,
    validate_api_url,
)
from rubric.errors import parse_problem_details

log = logging.getLogger(__name__)

_DEFAULT_HTTP_TIMEOUT_SECONDS: Final = 10.0
_REFRESH_BACKOFF_INITIAL_SECONDS: Final = 1.0
_REFRESH_BACKOFF_MAX_SECONDS: Final = 30.0
_MIN_REFRESH_INTERVAL_SECONDS: Final = 1.0
_THREAD_JOIN_TIMEOUT_SECONDS: Final = 2.0
_MAX_TOKEN_TTL_SECONDS: Final = 60 * 60  # 1 hour
_REFRESH_FALLBACK_SLEEP_SECONDS: Final = 30.0


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=False)


class _ExchangeResponse(_StrictModel):
    token: str
    expiresAt: str
    agentId: str
    identityId: str

    def __repr__(self) -> str:
        return (
            f"_ExchangeResponse(token=<redacted>, expiresAt={self.expiresAt!r}, "
            f"agentId={self.agentId!r}, identityId={self.identityId!r})"
        )

    __str__ = __repr__


class IdentityRevokedError(RuntimeError):
    """The server has rejected our identity. Surface to the agent on next call."""


class IdentityNotInitializedError(RuntimeError):
    """The TokenStore was used before bootstrap() completed."""


def _parse_iso_to_epoch(iso: str) -> float:
    # Server emits ISO with trailing Z; Python's fromisoformat needs +00:00 form
    # (until 3.11+, but staying conservative for 3.10 compatibility).
    if iso.endswith("Z"):
        iso = iso[:-1] + "+00:00"
    return datetime.fromisoformat(iso).timestamp()


def _safe_capped_epoch(iso: str) -> float:
    """Parse server-provided expiresAt and cap at _MAX_TOKEN_TTL_SECONDS.

    A malicious or misconfigured server returning `expiresAt: "9999-12-31"`
    would otherwise push refresh into a never-firing sleep. If the input is
    unparseable, fall back to `now + _REFRESH_FALLBACK_SLEEP_SECONDS` so the
    loop neither hot-spins nor sleeps forever, and warn so operators see it.
    """
    now_epoch = time.time()
    try:
        parsed = _parse_iso_to_epoch(iso)
    except (ValueError, TypeError):
        log.warning(
            "identity: unparseable expiresAt; falling back to %ss",
            _REFRESH_FALLBACK_SLEEP_SECONDS,
        )
        return now_epoch + _REFRESH_FALLBACK_SLEEP_SECONDS
    if not (parsed == parsed) or parsed in (float("inf"), float("-inf")):  # NaN/inf
        log.warning(
            "identity: non-finite expiresAt; falling back to %ss",
            _REFRESH_FALLBACK_SLEEP_SECONDS,
        )
        return now_epoch + _REFRESH_FALLBACK_SLEEP_SECONDS
    return min(parsed, now_epoch + _MAX_TOKEN_TTL_SECONDS)


class TokenStore:
    """Holds the current JWT-SVID and refreshes it before expiry.

    Created by `Governance.bootstrap()`; not meant to be instantiated directly.
    """

    def __init__(
        self,
        api_url: str,
        client: httpx.Client | None = None,
    ) -> None:
        self._api_url = api_url.rstrip("/")
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(connect=2.0, read=10.0, write=10.0, pool=2.0),
            trust_env=False,
        )
        self._owns_client = client is None
        self._lock = threading.Lock()
        self._token: str | None = None
        self._expires_at_epoch: float | None = None
        self._dead = False
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._agent_id: str | None = None
        self._identity_id: str | None = None

    # ---- Public read-only -----------------------------------------------------

    @property
    def agent_id(self) -> str:
        if self._agent_id is None:
            raise IdentityNotInitializedError("TokenStore has not been bootstrapped.")
        return self._agent_id

    @property
    def identity_id(self) -> str:
        if self._identity_id is None:
            raise IdentityNotInitializedError("TokenStore has not been bootstrapped.")
        return self._identity_id

    def token(self) -> str:
        with self._lock:
            if self._dead:
                raise IdentityRevokedError("Identity is no longer valid.")
            if self._token is None:
                raise IdentityNotInitializedError("Token store has no token.")
            return self._token

    def is_dead(self) -> bool:
        with self._lock:
            return self._dead

    # ---- Lifecycle ------------------------------------------------------------

    def initial_enrollment(self, enrollment_token: str, agent_name: str) -> None:
        """One-shot: present an enrollment token + agent name, get a JWT.

        Idempotent on `agent_name` server-side — restarts return the same
        identity row, fresh JWT each time.
        """
        res = self._client.post(
            f"{self._api_url}{API_ROUTE_IDENTITIES_ENROLL}",
            json={"agentName": agent_name},
            headers={
                HTTP_HEADER_AUTHORIZATION: f"{AUTH_BEARER_PREFIX}{enrollment_token}",
            },
        )
        if res.is_error:
            problem = parse_problem_details(res)
            detail = (problem.detail or problem.title) if problem else res.text
            raise RuntimeError(
                f"identity enrollment failed ({res.status_code}): "
                f"{scrub_secrets(detail or '')}"
            )
        body = _ExchangeResponse.model_validate(res.json())
        with self._lock:
            self._token = body.token
            self._expires_at_epoch = _safe_capped_epoch(body.expiresAt)
            self._agent_id = body.agentId
            self._identity_id = body.identityId

    def start_refresh_thread(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._refresh_loop, daemon=True, name="ag-identity-refresh"
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=_THREAD_JOIN_TIMEOUT_SECONDS)
        if self._owns_client:
            self._client.close()

    def force_refresh(self) -> None:
        """Called by HTTP clients when a request returns 401.

        Raises `IdentityRevokedError` if the server says the identity is gone.
        """
        try:
            self._refresh_once()
        except IdentityRevokedError:
            with self._lock:
                self._dead = True
            raise

    # ---- Internals ------------------------------------------------------------

    def _refresh_loop(self) -> None:
        backoff = _REFRESH_BACKOFF_INITIAL_SECONDS
        while not self._stop.is_set():
            with self._lock:
                if self._dead:
                    return
                exp = self._expires_at_epoch
            if exp is None:
                return
            sleep_for = max(
                _MIN_REFRESH_INTERVAL_SECONDS,
                exp - time.time() - IDENTITY_REFRESH_LEAD_SECONDS,
            )
            if self._stop.wait(sleep_for):
                return
            with self._lock:
                if self._dead:
                    return
            try:
                self._refresh_once()
                backoff = _REFRESH_BACKOFF_INITIAL_SECONDS
            except IdentityRevokedError:
                with self._lock:
                    self._dead = True
                log.error("identity revoked by server; SDK is now in dead state")
                return
            except Exception as e:
                log.warning(
                    "identity refresh failed: %s, backing off %ss",
                    type(e).__name__,
                    backoff,
                )
                if self._stop.wait(backoff):
                    return
                with self._lock:
                    if self._dead:
                        return
                backoff = min(_REFRESH_BACKOFF_MAX_SECONDS, backoff * 2)

    def _refresh_once(self) -> None:
        with self._lock:
            current = self._token
        if current is None:
            raise RuntimeError("cannot refresh without a current token")
        res = self._client.post(
            f"{self._api_url}{API_ROUTE_IDENTITIES_REFRESH}",
            headers={HTTP_HEADER_AUTHORIZATION: f"{AUTH_BEARER_PREFIX}{current}"},
        )
        if res.status_code == HTTP_UNAUTHORIZED:
            problem = parse_problem_details(res)
            detail = (problem.detail or problem.title) if problem else res.text
            raise IdentityRevokedError(
                scrub_secrets(detail or "") or "identity refresh rejected"
            )
        if res.is_error:
            raise RuntimeError(f"refresh failed ({res.status_code})")
        body = _ExchangeResponse.model_validate(res.json())
        with self._lock:
            # Identity-rotation guard: agentId/identityId are server-stable
            # across refreshes. A compromised server swapping them mid-flight
            # would silently re-attribute audit events to a different agent.
            if self._agent_id is not None and body.agentId != self._agent_id:
                self._dead = True
                raise IdentityRevokedError("agent identity changed on refresh")
            if (
                self._identity_id is not None
                and body.identityId != self._identity_id
            ):
                self._dead = True
                raise IdentityRevokedError("identity id changed on refresh")
            self._token = body.token
            self._expires_at_epoch = _safe_capped_epoch(body.expiresAt)


def bootstrap_token_store(
    *,
    enrollment_token: str | None = None,
    agent_name: str | None = None,
    api_url: str | None = None,
) -> TokenStore:
    """Resolve env-var fallbacks, perform initial enrollment, return a TokenStore.

    Enrollment is the only supported auth flow. Pass `enrollment_token`
    and `agent_name`, or set `RUBRIC_ENROLLMENT_TOKEN` and
    `RUBRIC_AGENT_NAME`. Idempotent on `agent_name` — every cold boot
    returns the same identity row with a fresh JWT.

    The returned store has its background refresh thread already running.
    """
    resolved_url = api_url or os.environ.get(ENV_API_URL, DEFAULT_API_URL)
    url_err = validate_api_url(resolved_url)
    if url_err is not None:
        raise ValueError(url_err)
    resolved_enrollment = enrollment_token or os.environ.get(ENV_ENROLLMENT_TOKEN)

    if not resolved_enrollment:
        raise ValueError(
            f"enrollment_token is required (or set {ENV_ENROLLMENT_TOKEN})"
        )
    resolved_agent_name = agent_name or os.environ.get(ENV_AGENT_NAME)
    if not resolved_agent_name:
        raise ValueError(
            f"agent_name is required (or set {ENV_AGENT_NAME})"
        )

    store = TokenStore(api_url=resolved_url)
    store.initial_enrollment(resolved_enrollment, resolved_agent_name)
    store.start_refresh_thread()
    return store
