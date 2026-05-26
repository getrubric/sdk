from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import httpx

from rubric._scrub import err_message, scrub_secrets
from rubric.constants import (
    API_ROUTE_BUNDLE,
    AUTH_BEARER_PREFIX,
    BUNDLE_QUERY_SINCE,
    HTTP_HEADER_AUTHORIZATION,
    HTTP_NO_CONTENT,
    HTTP_NOT_MODIFIED,
    HTTP_UNAUTHORIZED,
    validate_api_url,
)
from rubric.errors import parse_problem_details
from rubric.identity import IdentityRevokedError, TokenStore
from rubric.types import Bundle

log = logging.getLogger(__name__)

_DEFAULT_INTERVAL_SECONDS = 30.0
_DEFAULT_HTTP_CONNECT_TIMEOUT_SECONDS = 2.0
_DEFAULT_HTTP_READ_TIMEOUT_SECONDS = 10.0
_DEFAULT_HTTP_WRITE_TIMEOUT_SECONDS = 10.0
_DEFAULT_HTTP_POOL_TIMEOUT_SECONDS = 2.0
_DEFAULT_FIRST_PULL_TIMEOUT_SECONDS = 10.0
_DEFAULT_STOP_TIMEOUT_SECONDS = 5.0
_HASH_LOG_PREFIX_LENGTH = 12

# Clock-skew tolerance (milliseconds) when comparing `builtAt` between an
# incoming bundle and the cached one. The server's wall clock can drift a
# few seconds; we only reject incoming bundles whose `builtAt` is
# dramatically older than what we already have, which signals a rollback
# rather than a clock blip.
BUILT_AT_SKEW_TOLERANCE_MS = 5 * 60 * 1000


def _parse_built_at_ms(value: str) -> float | None:
    """Parse a `builtAt` string into epoch milliseconds, or None on failure."""
    try:
        # Accept ISO-8601 with `Z` suffix.
        normalized = value.replace("Z", "+00:00") if value.endswith("Z") else value
        dt = datetime.fromisoformat(normalized)
    except ValueError:
        try:
            dt = parsedate_to_datetime(value)
        except (TypeError, ValueError):
            return None
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp() * 1000.0


class BundlePoller:
    """Background thread that pulls policy bundles from the Rubric API.

    Polls every `interval_seconds`; uses the previous bundle's contentHash as
    an If-None-Match equivalent (?since=...) for cheap unchanged responses.
    """

    def __init__(
        self,
        api_url: str,
        token_store: TokenStore,
        on_update: Callable[[Bundle], None],
        interval_seconds: float = _DEFAULT_INTERVAL_SECONDS,
        client: httpx.Client | None = None,
    ) -> None:
        err = validate_api_url(api_url)
        if err is not None:
            raise ValueError(err)
        self._api_url = api_url.rstrip("/")
        self._token_store = token_store
        self._on_update = on_update
        self._interval = interval_seconds
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(
                connect=_DEFAULT_HTTP_CONNECT_TIMEOUT_SECONDS,
                read=_DEFAULT_HTTP_READ_TIMEOUT_SECONDS,
                write=_DEFAULT_HTTP_WRITE_TIMEOUT_SECONDS,
                pool=_DEFAULT_HTTP_POOL_TIMEOUT_SECONDS,
            ),
            # Don't honor HTTPS_PROXY/HTTP_PROXY env vars — a stray proxy
            # in the user's shell would otherwise see every bearer token.
            trust_env=False,
        )
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True, name="ag-bundle-poller")
        self._current_hash: str | None = None
        self._current_bundle: Bundle | None = None
        self._last_pull_at: datetime | None = None
        self._last_bundle_change_at: datetime | None = None
        self._last_rejected_bundle_at: datetime | None = None
        self._last_rejection_reason: str | None = None
        # Resolved once a bundle has been *successfully installed*, not on
        # mere attempt. `wait_for_first_pull` returns True only on success.
        self._first_pull_succeeded = threading.Event()
        # Resolved once the first attempt has completed (success or
        # failure), so callers that want a "we tried" signal can opt in.
        self._first_pull_attempted = threading.Event()

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=_DEFAULT_STOP_TIMEOUT_SECONDS)

    def wait_for_first_pull(self, timeout: float = _DEFAULT_FIRST_PULL_TIMEOUT_SECONDS) -> bool:
        """Block until the first bundle has been successfully installed.

        Returns True iff a bundle is in cache before the timeout elapses.
        Returns False if the first pull failed validation, hit a network
        error, or simply hasn't completed in time — callers must NOT treat
        a False as "ready".
        """
        return self._first_pull_succeeded.wait(timeout)

    def wait_for_first_attempt(self, timeout: float = _DEFAULT_FIRST_PULL_TIMEOUT_SECONDS) -> bool:
        """Block until the first pull attempt has completed (success or failure)."""
        return self._first_pull_attempted.wait(timeout)

    @property
    def current(self) -> Bundle | None:
        return self._current_bundle

    @property
    def last_pull_at(self) -> datetime | None:
        """Most recent successful HTTP response (200/304/204).

        Use this to detect a stuck poller. Combined with
        `last_bundle_change_at` to detect a "304-forever" condition.
        """
        return self._last_pull_at

    @property
    def last_bundle_change_at(self) -> datetime | None:
        """Most recent pull that actually swapped the cached bundle."""
        return self._last_bundle_change_at

    @property
    def last_rejected_bundle_at(self) -> datetime | None:
        """Most recent monotonicity rejection, or None if none."""
        return self._last_rejected_bundle_at

    @property
    def last_rejection_reason(self) -> str | None:
        """Human-readable reason for the most recent monotonicity rejection."""
        return self._last_rejection_reason

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._pull_once()
            except IdentityRevokedError:
                log.error("bundle pull aborted: identity revoked")
                self._first_pull_attempted.set()
                return
            except Exception as e:
                log.error("bundle pull failed: %s", type(e).__name__)
            finally:
                self._first_pull_attempted.set()
            self._stop.wait(self._interval)

    def _pull_once(self) -> None:
        params = {BUNDLE_QUERY_SINCE: self._current_hash} if self._current_hash else {}
        res = self._fetch(params, retry_on_401=True)
        if res.status_code in (HTTP_NOT_MODIFIED, HTTP_NO_CONTENT):
            # Still a successful pull — record so operators can see the
            # poller is alive even when the server reports no change.
            self._last_pull_at = datetime.now(timezone.utc)
            return
        if res.is_error:
            problem = parse_problem_details(res)
            if problem is not None:
                log.error(
                    "bundle pull rejected (%d, %s): %s",
                    res.status_code,
                    problem.type,
                    scrub_secrets(problem.detail or problem.title),
                )
            res.raise_for_status()

        bundle = Bundle.model_validate(res.json())

        # Record pull-success before evaluating monotonicity: the HTTP
        # round-trip succeeded, even if we reject the payload below.
        self._last_pull_at = datetime.now(timezone.utc)

        # Monotonicity check. Reject any incoming bundle whose version is
        # strictly less than what we already cached — a rollback would
        # otherwise unfreeze a previously frozen agent or shrink the
        # policy set silently. Also reject if `builtAt` is meaningfully
        # older than the cached bundle, with a 5-minute skew tolerance.
        cached = self._current_bundle
        if cached is not None:
            if bundle.bundleVersion < cached.bundleVersion:
                reason = (
                    f"rejected bundleVersion {bundle.bundleVersion} "
                    f"(cached {cached.bundleVersion})"
                )
                self._last_rejected_bundle_at = datetime.now(timezone.utc)
                self._last_rejection_reason = reason
                log.warning("bundle monotonicity violation: %s", reason)
                return
            incoming_built = _parse_built_at_ms(bundle.builtAt)
            cached_built = _parse_built_at_ms(cached.builtAt)
            if (
                incoming_built is not None
                and cached_built is not None
                and incoming_built < cached_built - BUILT_AT_SKEW_TOLERANCE_MS
            ):
                reason = (
                    f"rejected builtAt {bundle.builtAt} (cached {cached.builtAt}, "
                    f"beyond {BUILT_AT_SKEW_TOLERANCE_MS}ms skew tolerance)"
                )
                self._last_rejected_bundle_at = datetime.now(timezone.utc)
                self._last_rejection_reason = reason
                log.warning("bundle monotonicity violation: %s", reason)
                return

        if bundle.contentHash == self._current_hash:
            # Same hash — installation succeeded previously; mark ready.
            self._first_pull_succeeded.set()
            return
        self._current_hash = bundle.contentHash
        self._current_bundle = bundle
        self._last_bundle_change_at = datetime.now(timezone.utc)
        log.info(
            "bundle updated to v%d (%s)",
            bundle.bundleVersion,
            bundle.contentHash[:_HASH_LOG_PREFIX_LENGTH],
        )
        try:
            self._on_update(bundle)
        except Exception as e:
            # Don't let an on_update handler kill the poller, but do
            # surface a scrubbed reason for operators.
            log.error("bundle on_update handler failed: %s", err_message(e))
        # Mark ready only after the bundle is fully installed (cache
        # populated *and* on_update callback fired).
        self._first_pull_succeeded.set()

    def _fetch(self, params: dict[str, str], *, retry_on_401: bool) -> httpx.Response:
        token = self._token_store.token()
        res = self._client.get(
            f"{self._api_url}{API_ROUTE_BUNDLE}",
            params=params,
            headers={HTTP_HEADER_AUTHORIZATION: f"{AUTH_BEARER_PREFIX}{token}"},
        )
        if res.status_code == HTTP_UNAUTHORIZED and retry_on_401:
            self._token_store.force_refresh()
            return self._fetch(params, retry_on_401=False)
        return res
