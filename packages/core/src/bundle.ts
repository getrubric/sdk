// Policy bundle poller.
//
//   - Every `intervalMs` (default 30s), `GET /v1/bundle?since=<contentHash>`
//     using the previous bundle's contentHash as a cheap conditional.
//   - 304/204 → no change; sleep and try again.
//   - 401 → ask the TokenStore to forceRefresh and retry once. If that's
//     also rejected, the store transitions to dead and we exit the loop.
//   - Otherwise validate the body, swap the cached bundle, call onUpdate.
//
// `firstPullDone` resolves after the first iteration (success *or*
// failure) so callers can await the poller before serving traffic.

import { sleepOrAbort } from './_internal.js';
import {
  API_ROUTE_BUNDLE,
  AUTH_BEARER_PREFIX,
  BUNDLE_QUERY_SINCE,
  HTTP_HEADER_AUTHORIZATION,
  HTTP_NO_CONTENT,
  HTTP_NOT_MODIFIED,
  HTTP_UNAUTHORIZED,
  assertValidApiUrl,
} from './constants.js';
import { GovernanceError, IdentityRevokedError, parseProblemDetails } from './errors.js';
import { TokenStore } from './identity.js';
import { BundleSchema, type Bundle } from './types.js';

const DEFAULT_INTERVAL_MS = 30_000;
const DEFAULT_HTTP_TIMEOUT_MS = 10_000;
const DEFAULT_FIRST_PULL_TIMEOUT_MS = 10_000;

// Clock-skew tolerance when comparing `builtAt` between an incoming bundle
// and the cached one. The server's wall clock can legitimately drift a few
// seconds; we only reject incoming bundles whose `builtAt` is dramatically
// older than what we already have, which signals a rollback rather than a
// clock blip.
const BUILT_AT_SKEW_TOLERANCE_MS = 5 * 60_000;

export interface BundlePollerOptions {
  apiUrl: string;
  tokenStore: TokenStore;
  /**
   * Called whenever a new bundle (different contentHash) is received.
   * Awaited — if it throws, the error is logged via `onError` and the
   * next poll proceeds as normal.
   */
  onUpdate: (bundle: Bundle) => void | Promise<void>;
  /**
   * Called for any non-fatal pull error (network, 5xx, schema parse).
   * Defaults to a no-op so the daemon can attach its own pino logger
   * without dragging a logger dependency into @rubric-app/core.
   */
  onError?: (err: unknown) => void;
  intervalMs?: number;
  requestTimeoutMs?: number;
  fetch?: typeof globalThis.fetch;
}

/**
 * Background poller that pulls policy bundles from the Rubric API.
 *
 * Construct, call `start()`, then optionally `await firstPullDone(...)` to
 * gate request serving until the first bundle is in cache.
 */
export class BundlePoller {
  private readonly _apiUrl: string;
  private readonly _tokenStore: TokenStore;
  private readonly _onUpdate: (bundle: Bundle) => void | Promise<void>;
  private readonly _onError: (err: unknown) => void;
  private readonly _intervalMs: number;
  private readonly _requestTimeoutMs: number;
  private readonly _fetch: typeof globalThis.fetch;

  private _currentHash: string | null = null;
  private _currentBundle: Bundle | null = null;
  // Timestamp of the most recent successful pull. Used by callers
  // (the daemon /v1/status endpoint, `rubric doctor`) to detect a
  // stuck poller — a stale bundle is enforceable; a stuck poller
  // means we're not picking up org-side kill-switch flips.
  private _lastPullAt: Date | null = null;
  // Timestamp of the most recent pull that actually swapped the cached
  // bundle (contentHash changed). Distinct from `_lastPullAt`: a server
  // stuck returning 304 forever keeps `_lastPullAt` green while
  // `_lastBundleChangeAt` stays frozen — that gap is the signal
  // `rubric doctor` and `/v1/status` need to flag stale bundles.
  private _lastBundleChangeAt: Date | null = null;
  // Reasons we rejected an incoming pull as non-monotonic (older version
  // or older `builtAt`). Exposed so `rubric doctor` can surface "we're
  // seeing rollback attempts" without spamming `onError`.
  private _lastRejectedBundleAt: Date | null = null;
  private _lastRejectionReason: string | null = null;
  private _stopController: AbortController | null = null;
  private _loopPromise: Promise<void> | null = null;
  private _firstPullResolve: (() => void) | null = null;
  private readonly _firstPull: Promise<void>;

  constructor(options: BundlePollerOptions) {
    assertValidApiUrl(options.apiUrl);
    this._apiUrl = options.apiUrl.replace(/\/+$/, '');
    this._tokenStore = options.tokenStore;
    this._onUpdate = options.onUpdate;
    this._onError = options.onError ?? (() => {});
    this._intervalMs = options.intervalMs ?? DEFAULT_INTERVAL_MS;
    this._requestTimeoutMs = options.requestTimeoutMs ?? DEFAULT_HTTP_TIMEOUT_MS;
    this._fetch = options.fetch ?? globalThis.fetch.bind(globalThis);

    this._firstPull = new Promise<void>((resolve) => {
      this._firstPullResolve = resolve;
    });
  }

  // ---- Public read-only -----------------------------------------------------

  /** The most recently received bundle, or null if no successful pull yet. */
  get current(): Bundle | null {
    return this._currentBundle;
  }

  /**
   * Timestamp of the most recent successful pull (any HTTP status that
   * didn't throw — 200 + new bundle, 304/204 no-change, all count).
   * Null until the first successful pull.
   *
   * Use this to detect a stuck poller. Combined with `lastBundleChangeAt`
   * to detect a "304-forever" attack: if `lastPullAt` is recent but
   * `lastBundleChangeAt` is hours old, the server may be suppressing
   * legitimate bundle updates.
   */
  get lastPullAt(): Date | null {
    return this._lastPullAt;
  }

  /**
   * Timestamp of the most recent pull that actually changed the cached
   * bundle (i.e., the incoming `contentHash` differed from the previous
   * cache). Null until the first bundle is received. Stays frozen across
   * 304/204 responses and across 200 responses that repeat the same hash.
   *
   * Read by the daemon /v1/status endpoint and `rubric doctor` to flag
   * stale-bundle conditions.
   */
  get lastBundleChangeAt(): Date | null {
    return this._lastBundleChangeAt;
  }

  /**
   * Timestamp of the most recent pull whose payload we rejected on
   * monotonicity grounds (older `bundleVersion`, or `builtAt` more than
   * `BUILT_AT_SKEW_TOLERANCE_MS` older than the cached bundle). Null if
   * no rejection has happened on this poller.
   */
  get lastRejectedBundleAt(): Date | null {
    return this._lastRejectedBundleAt;
  }

  /**
   * Human-readable reason for the most recent monotonicity rejection,
   * or null if none. Pairs with `lastRejectedBundleAt`.
   */
  get lastRejectionReason(): string | null {
    return this._lastRejectionReason;
  }

  /**
   * Resolves after the first poll iteration completes — success *or*
   * failure. Callers gate request serving on this, then check
   * `current` to see whether the pull actually produced a bundle.
   *
   * Rejects only if the timeout elapses first.
   */
  firstPullDone(timeoutMs: number = DEFAULT_FIRST_PULL_TIMEOUT_MS): Promise<void> {
    return Promise.race([
      this._firstPull,
      new Promise<void>((_, reject) =>
        setTimeout(
          () => reject(new GovernanceError(`bundle first-pull timed out after ${timeoutMs}ms`)),
          timeoutMs,
        ).unref?.(),
      ),
    ]);
  }

  // ---- Lifecycle ------------------------------------------------------------

  /** Start the polling loop. Idempotent. */
  start(): void {
    if (this._stopController !== null) return;
    this._stopController = new AbortController();
    this._loopPromise = this._run(this._stopController.signal);
  }

  /** Stop the polling loop and wait for it to drain. Idempotent. */
  async stop(): Promise<void> {
    this._stopController?.abort();
    if (this._loopPromise) {
      await this._loopPromise.catch(() => {
        // Loop owns its errors — onError already fired for each.
      });
    }
    this._stopController = null;
    this._loopPromise = null;
  }

  // ---- Internals ------------------------------------------------------------

  private async _run(signal: AbortSignal): Promise<void> {
    while (!signal.aborted) {
      try {
        await this._pullOnce(signal);
      } catch (err: unknown) {
        if (err instanceof IdentityRevokedError) {
          // Revoked identity is terminal: stop the poller and trigger
          // the first-pull resolver so anyone awaiting it doesn't hang.
          this._resolveFirstPull();
          this._onError(err);
          return;
        }
        this._onError(err);
      } finally {
        this._resolveFirstPull();
      }
      if (await sleepOrAbort(this._intervalMs, signal)) return;
    }
  }

  private async _pullOnce(signal: AbortSignal): Promise<void> {
    const params = this._currentHash
      ? `?${BUNDLE_QUERY_SINCE}=${encodeURIComponent(this._currentHash)}`
      : '';
    const res = await this._fetchWithAuthRetry(`${API_ROUTE_BUNDLE}${params}`, signal);

    if (res.status === HTTP_NOT_MODIFIED || res.status === HTTP_NO_CONTENT) {
      // Still a successful pull — record the timestamp so `rubric doctor`
      // and the daemon /v1/status endpoint can see the poller is alive.
      this._lastPullAt = new Date();
      return;
    }
    if (!res.ok) {
      const problem = await parseProblemDetails(res.clone());
      throw new GovernanceError(
        `bundle pull failed (${res.status}): ${problem?.detail ?? problem?.title ?? res.statusText}`,
      );
    }

    const json: unknown = await res.json();
    const bundle = BundleSchema.parse(json);

    // Record the pull timestamp regardless of whether the bundle changed —
    // a successful HTTP response is what proves the poller is healthy.
    this._lastPullAt = new Date();

    // Monotonicity check. Reject any incoming bundle whose version is
    // strictly less than what we already cached — a rollback would
    // otherwise unfreeze a previously frozen agent or shrink the policy
    // set silently. Also reject if `builtAt` is meaningfully older than
    // the cached bundle's `builtAt`, with a 5-minute tolerance for
    // clock skew.
    const cached = this._currentBundle;
    if (cached !== null) {
      if (bundle.bundleVersion < cached.bundleVersion) {
        const reason = `rejected bundleVersion ${bundle.bundleVersion} (cached ${cached.bundleVersion})`;
        this._lastRejectedBundleAt = new Date();
        this._lastRejectionReason = reason;
        this._onError(new GovernanceError(`bundle monotonicity violation: ${reason}`));
        return;
      }
      const incomingBuiltAt = Date.parse(bundle.builtAt);
      const cachedBuiltAt = Date.parse(cached.builtAt);
      if (
        Number.isFinite(incomingBuiltAt) &&
        Number.isFinite(cachedBuiltAt) &&
        incomingBuiltAt < cachedBuiltAt - BUILT_AT_SKEW_TOLERANCE_MS
      ) {
        const reason = `rejected builtAt ${bundle.builtAt} (cached ${cached.builtAt}, beyond ${BUILT_AT_SKEW_TOLERANCE_MS}ms skew tolerance)`;
        this._lastRejectedBundleAt = new Date();
        this._lastRejectionReason = reason;
        this._onError(new GovernanceError(`bundle monotonicity violation: ${reason}`));
        return;
      }
    }

    // Server may legitimately return the same bundle if our `since=` was
    // ignored by some proxy; compare hashes and short-circuit to avoid a
    // spurious onUpdate notification.
    if (bundle.contentHash === this._currentHash) return;
    this._currentHash = bundle.contentHash;
    this._currentBundle = bundle;
    // Track content-change distinct from poll-success.
    this._lastBundleChangeAt = new Date();
    await this._onUpdate(bundle);
  }

  /**
   * `fetch` wrapper that retries once on 401 after asking the TokenStore
   * to refresh. A second 401 (or any other failure from forceRefresh)
   * surfaces as `IdentityRevokedError`, which the run-loop treats as
   * terminal.
   */
  private async _fetchWithAuthRetry(path: string, signal: AbortSignal): Promise<Response> {
    const res = await this._fetchOnce(path, signal);
    if (res.status !== HTTP_UNAUTHORIZED) return res;
    // First 401 — drain the body so the connection can be reused.
    await res.body?.cancel().catch(() => {});
    await this._tokenStore.forceRefresh();
    return this._fetchOnce(path, signal);
  }

  private _fetchOnce(path: string, signal: AbortSignal): Promise<Response> {
    const token = this._tokenStore.token();
    // Per-request timeout AND the loop's stop signal both need to abort
    // the fetch. `AbortSignal.any` (Node 20+) composes them.
    const timeout = AbortSignal.timeout(this._requestTimeoutMs);
    const composed = AbortSignal.any([signal, timeout]);
    return this._fetch(`${this._apiUrl}${path}`, {
      method: 'GET',
      headers: {
        [HTTP_HEADER_AUTHORIZATION]: `${AUTH_BEARER_PREFIX}${token}`,
      },
      signal: composed,
    });
  }

  private _resolveFirstPull(): void {
    if (this._firstPullResolve) {
      this._firstPullResolve();
      this._firstPullResolve = null;
    }
  }
}
