from __future__ import annotations

import logging
import queue
import threading
import time

import httpx

from rubric._scrub import scrub_secrets
from rubric.constants import (
    API_ROUTE_EVENTS,
    AUTH_BEARER_PREFIX,
    CLIENT_ERROR_RANGE,
    HTTP_ACCEPTED,
    HTTP_HEADER_AUTHORIZATION,
    HTTP_UNAUTHORIZED,
)
from rubric.errors import parse_problem_details
from rubric.identity import IdentityRevokedError, TokenStore
from rubric.types import AuditEvent

log = logging.getLogger(__name__)

_DEFAULT_BATCH_SIZE = 100
_DEFAULT_FLUSH_INTERVAL_SECONDS = 5.0
_DEFAULT_MAX_QUEUE = 10_000
_DEFAULT_HTTP_TIMEOUT_SECONDS = 10.0
_QUEUE_GET_TIMEOUT_SECONDS = 0.5
_DEFAULT_DRAIN_TIMEOUT_SECONDS = 5.0
_DRAIN_POLL_INTERVAL_SECONDS = 0.05
_RETRY_INITIAL_BACKOFF_SECONDS = 0.5
_RETRY_MAX_ATTEMPTS = 4
_RETRY_BACKOFF_MULTIPLIER = 2


class AuditSink:
    """Batched, fire-and-forget shipper for audit events.

    Events are queued from the agent's hot path and flushed by a background
    thread on either a count or time threshold. Failures retry with backoff;
    enqueue never blocks the caller.
    """

    def __init__(
        self,
        api_url: str,
        token_store: TokenStore,
        batch_size: int = _DEFAULT_BATCH_SIZE,
        flush_interval_seconds: float = _DEFAULT_FLUSH_INTERVAL_SECONDS,
        max_queue: int = _DEFAULT_MAX_QUEUE,
        client: httpx.Client | None = None,
    ) -> None:
        self._api_url = api_url.rstrip("/")
        self._token_store = token_store
        self._batch_size = batch_size
        self._flush_interval = flush_interval_seconds
        self._queue: queue.Queue[AuditEvent] = queue.Queue(maxsize=max_queue)
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(connect=2.0, read=10.0, write=10.0, pool=2.0),
            trust_env=False,
        )
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True, name="ag-audit-sink")

    def start(self) -> None:
        self._thread.start()

    def stop(self, drain_timeout: float = _DEFAULT_DRAIN_TIMEOUT_SECONDS) -> None:
        self._stop.set()
        deadline = time.time() + drain_timeout
        while time.time() < deadline and not self._queue.empty():
            time.sleep(_DRAIN_POLL_INTERVAL_SECONDS)
        self._thread.join(timeout=drain_timeout)

    def enqueue(self, event: AuditEvent) -> None:
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            log.warning("audit queue full; dropping event")

    def _run(self) -> None:
        last_flush = time.monotonic()
        batch: list[AuditEvent] = []
        while not self._stop.is_set() or not self._queue.empty():
            try:
                event = self._queue.get(timeout=_QUEUE_GET_TIMEOUT_SECONDS)
                batch.append(event)
            except queue.Empty:
                pass

            now = time.monotonic()
            time_to_flush = now - last_flush >= self._flush_interval
            size_to_flush = len(batch) >= self._batch_size
            if batch and (time_to_flush or size_to_flush or self._stop.is_set()):
                try:
                    self._flush(batch)
                except IdentityRevokedError:
                    log.error("audit ship aborted: identity revoked; loop exiting")
                    return
                except Exception as e:
                    log.error(
                        "audit flush failed unexpectedly: %s; continuing loop",
                        type(e).__name__,
                    )
                batch = []
                last_flush = now

    def _flush(self, batch: list[AuditEvent]) -> None:
        payload = {"events": [e.model_dump(mode="json") for e in batch]}
        backoff = _RETRY_INITIAL_BACKOFF_SECONDS
        for attempt in range(_RETRY_MAX_ATTEMPTS):
            try:
                res = self._post(payload, retry_on_401=True)
                if res.status_code == HTTP_ACCEPTED:
                    return
                if res.status_code in CLIENT_ERROR_RANGE:
                    problem = parse_problem_details(res)
                    if problem is not None:
                        log.error(
                            "audit ship rejected (%d, %s): %s",
                            res.status_code,
                            problem.type,
                            scrub_secrets(problem.detail or problem.title or ""),
                        )
                    else:
                        log.error("audit ship rejected (%d)", res.status_code)
                    return  # client error, do not retry
                log.warning("audit ship failed (%d), retry %d", res.status_code, attempt + 1)
            except httpx.HTTPError as e:
                log.warning(
                    "audit ship error: %s, retry %d", type(e).__name__, attempt + 1
                )
            if attempt < _RETRY_MAX_ATTEMPTS - 1:
                time.sleep(backoff)
                backoff *= _RETRY_BACKOFF_MULTIPLIER
        log.error("audit ship gave up after retries; dropped %d events", len(batch))

    def _post(self, payload: dict[str, object], *, retry_on_401: bool) -> httpx.Response:
        token = self._token_store.token()
        res = self._client.post(
            f"{self._api_url}{API_ROUTE_EVENTS}",
            json=payload,
            headers={HTTP_HEADER_AUTHORIZATION: f"{AUTH_BEARER_PREFIX}{token}"},
        )
        if res.status_code == HTTP_UNAUTHORIZED and retry_on_401:
            # Force a refresh and retry once with the new token. Refresh raising
            # IdentityRevokedError propagates up and aborts the flush.
            self._token_store.force_refresh()
            return self._post(payload, retry_on_401=False)
        return res
