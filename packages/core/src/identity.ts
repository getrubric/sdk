// JWT-SVID token store + bootstrap flow.
//
//   1. `initialEnrollment(enrollmentToken, agentName)` exchanges the
//      enrollment token for a 60-minute JWT-SVID via
//      `POST /v1/identities/enroll`.
//   2. A background refresh task wakes `IDENTITY_REFRESH_LEAD_SECONDS`
//      before the JWT expires and calls `POST /v1/identities/refresh`.
//   3. On a 401 from any client, that client calls `forceRefresh()`; a
//      successful refresh returns the new token; a second 401 means the
//      identity is revoked, and the store enters a terminal `dead` state
//      that all callers observe via `IdentityRevokedError`.
//
// Concurrent `forceRefresh()` calls (e.g. the bundle poller and the
// audit sink both racing a 401 into the same store) are coalesced via
// an in-flight Promise so we never issue two refresh roundtrips at once.

import {
  API_ROUTE_IDENTITIES_ENROLL,
  API_ROUTE_IDENTITIES_REFRESH,
  AUTH_BEARER_PREFIX,
  CONTENT_TYPE_JSON,
  DEFAULT_API_URL,
  ENV_AGENT_NAME,
  ENV_API_URL,
  ENV_ENROLLMENT_TOKEN,
  HTTP_HEADER_AUTHORIZATION,
  HTTP_HEADER_CONTENT_TYPE,
  HTTP_UNAUTHORIZED,
  IDENTITY_REFRESH_LEAD_SECONDS,
  assertValidApiUrl,
} from './constants.js';
import { errMessage, safeText, scrubSecrets, sleepOrAbort } from './_internal.js';
import { ZodError } from 'zod';
import {
  GovernanceError,
  IdentityNotInitializedError,
  IdentityRevokedError,
  parseProblemDetails,
} from './errors.js';
import { SdkTokenResponseSchema, type SdkTokenResponse } from './types.js';

const DEFAULT_HTTP_TIMEOUT_MS = 10_000;
const REFRESH_BACKOFF_INITIAL_MS = 1_000;
const REFRESH_BACKOFF_MAX_MS = 30_000;
const MIN_REFRESH_INTERVAL_MS = 1_000;
// Fallback sleep when `parseIsoToEpoch` returns NaN / non-finite. Without
// this guard, `Math.max(1000, NaN) === NaN`, `setTimeout(_, NaN)` becomes 1ms,
// and the refresh loop hot-spins at ~1 kHz against the server.
const REFRESH_FALLBACK_SLEEP_MS = 30_000;

export interface TokenStoreOptions {
  /** Rubric API base URL. Trailing slash is trimmed. */
  apiUrl: string;
  /**
   * Override the fetch implementation. Defaults to the global `fetch`.
   * Useful for tests that want to inject a mock and unusual deployments
   * (proxied Node, custom keep-alive Agent) that need an undici Dispatcher.
   */
  fetch?: typeof globalThis.fetch;
  /** Per-request timeout in milliseconds. Default 10s. */
  requestTimeoutMs?: number;
  /**
   * Called when the refresh loop hits a recoverable anomaly (e.g. an
   * unparseable `expiresAt` from the server). No-op by default so
   * `@rubric-app/core` stays logger-free; the daemon wraps this and emits
   * a structured pino warning.
   */
  onWarn?: (msg: string) => void;
}

/**
 * Holds the current JWT-SVID and refreshes it before expiry.
 *
 * Created by `bootstrapTokenStore()`; not meant to be instantiated directly.
 */
export class TokenStore {
  private readonly _apiUrl: string;
  private readonly _fetch: typeof globalThis.fetch;
  private readonly _requestTimeoutMs: number;
  private readonly _onWarn: (msg: string) => void;

  private _token: string | null = null;
  private _expiresAtEpoch: number | null = null;
  private _agentId: string | null = null;
  private _identityId: string | null = null;
  private _dead = false;

  private _stopController: AbortController | null = null;
  private _loopPromise: Promise<void> | null = null;

  // Coalesces concurrent refresh requests. If the bundle poller and the
  // audit sink both 401 at the same time, they `await forceRefresh()` and
  // share a single in-flight request.
  private _refreshInFlight: Promise<void> | null = null;

  constructor(options: TokenStoreOptions) {
    assertValidApiUrl(options.apiUrl);
    this._apiUrl = options.apiUrl.replace(/\/+$/, '');
    this._fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    this._requestTimeoutMs = options.requestTimeoutMs ?? DEFAULT_HTTP_TIMEOUT_MS;
    this._onWarn = options.onWarn ?? ((): void => {});
  }

  // ---- Public read-only -----------------------------------------------------

  get agentId(): string {
    if (this._agentId === null) {
      throw new IdentityNotInitializedError('TokenStore has not been bootstrapped.');
    }
    return this._agentId;
  }

  get identityId(): string {
    if (this._identityId === null) {
      throw new IdentityNotInitializedError('TokenStore has not been bootstrapped.');
    }
    return this._identityId;
  }

  /** Current bearer JWT. Throws `IdentityRevokedError` if the store is dead. */
  token(): string {
    if (this._dead) {
      throw new IdentityRevokedError('Identity is no longer valid.');
    }
    if (this._token === null) {
      throw new IdentityNotInitializedError('Token store has no token.');
    }
    return this._token;
  }

  isDead(): boolean {
    return this._dead;
  }

  // ---- Lifecycle ------------------------------------------------------------

  /**
   * One-shot: present an enrollment token + agent name, get a JWT.
   *
   * Idempotent on `agentName` server-side — restarts return the same
   * identity row, fresh JWT each time.
   */
  async initialEnrollment(enrollmentToken: string, agentName: string): Promise<void> {
    const res = await this._request(API_ROUTE_IDENTITIES_ENROLL, {
      method: 'POST',
      headers: {
        [HTTP_HEADER_AUTHORIZATION]: `${AUTH_BEARER_PREFIX}${enrollmentToken}`,
        [HTTP_HEADER_CONTENT_TYPE]: CONTENT_TYPE_JSON,
      },
      body: JSON.stringify({ agentName }),
    });
    if (!res.ok) {
      const problem = await parseProblemDetails(res.clone());
      const detail = problem?.detail ?? problem?.title ?? (await safeText(res));
      // Scrub before interpolation — servers and dev-mode error
      // surfaces sometimes echo the request body, which would land our
      // enrollment-token JWT in any pino destination.
      throw new GovernanceError(
        `identity enrollment failed (${res.status}): ${scrubSecrets(detail)}`,
      );
    }
    const body = await this._parseTokenResponse(res, 'identity enrollment');
    this._applyTokenResponse(body);
  }

  /**
   * Start the background refresh loop. Idempotent — calling twice is a no-op.
   */
  startRefreshLoop(): void {
    if (this._stopController !== null) return;
    this._stopController = new AbortController();
    this._loopPromise = this._refreshLoop(this._stopController.signal);
  }

  /**
   * Stop the refresh loop and wait for it to drain. Idempotent.
   *
   * The await is bounded: the loop only awaits `sleepOrAbort(...)`
   * (instant resolve on abort) and pending HTTP requests inherit the
   * same abort signal, so `stop()` returns within ms in practice.
   */
  async stop(): Promise<void> {
    this._stopController?.abort();
    if (this._loopPromise) {
      await this._loopPromise.catch(() => {
        // Loop owns its errors; swallowed here so callers don't get
        // an abort-induced rejection back from `stop()`.
      });
    }
    this._stopController = null;
    this._loopPromise = null;
  }

  /**
   * Called by HTTP clients when a request returns 401.
   *
   * Throws `IdentityRevokedError` if the server says the identity is gone;
   * the store transitions to a terminal dead state and every subsequent
   * `token()` call will raise.
   */
  async forceRefresh(): Promise<void> {
    if (this._refreshInFlight) return this._refreshInFlight;
    const inflight = this._refreshOnce().catch((err: unknown) => {
      if (err instanceof IdentityRevokedError) {
        this._dead = true;
      }
      throw err;
    });
    this._refreshInFlight = inflight.finally(() => {
      this._refreshInFlight = null;
    });
    return this._refreshInFlight;
  }

  // ---- Internals ------------------------------------------------------------

  private async _refreshLoop(signal: AbortSignal): Promise<void> {
    let backoffMs = REFRESH_BACKOFF_INITIAL_MS;
    while (!signal.aborted) {
      if (this._dead) return;
      const exp = this._expiresAtEpoch;
      if (exp === null) return;

      const rawSleepMs = (exp - Date.now() / 1000 - IDENTITY_REFRESH_LEAD_SECONDS) * 1000;
      // A malformed `expiresAt` from the server makes `parseIsoToEpoch`
      // return NaN, which propagates through arithmetic so
      // `Math.max(1000, NaN) === NaN`, and `setTimeout(_, NaN)`
      // schedules at 1ms. That's a self-DoS against the server. Fall
      // back to a 30s sleep and warn so the operator can spot the bad
      // clock.
      let sleepMs: number;
      if (!Number.isFinite(rawSleepMs) || rawSleepMs < MIN_REFRESH_INTERVAL_MS) {
        if (!Number.isFinite(rawSleepMs)) {
          this._onWarn(
            `identity refresh: non-finite sleep computed (expiresAt unparseable); ` +
              `falling back to ${REFRESH_FALLBACK_SLEEP_MS}ms`,
          );
          sleepMs = REFRESH_FALLBACK_SLEEP_MS;
        } else {
          sleepMs = MIN_REFRESH_INTERVAL_MS;
        }
      } else {
        sleepMs = rawSleepMs;
      }
      const aborted = await sleepOrAbort(sleepMs, signal);
      if (aborted) return;

      try {
        await this._refreshOnce();
        backoffMs = REFRESH_BACKOFF_INITIAL_MS;
      } catch (err: unknown) {
        if (err instanceof IdentityRevokedError) {
          this._dead = true;
          // Deliberately no logger dep in core; the daemon wraps this
          // store and surfaces a structured pino event when the loop
          // returns.
          return;
        }
        const stopped = await sleepOrAbort(backoffMs, signal);
        if (stopped) return;
        backoffMs = Math.min(REFRESH_BACKOFF_MAX_MS, backoffMs * 2);
      }
    }
  }

  private async _refreshOnce(): Promise<void> {
    const current = this._token;
    if (current === null) {
      throw new GovernanceError('cannot refresh without a current token');
    }
    const res = await this._request(API_ROUTE_IDENTITIES_REFRESH, {
      method: 'POST',
      headers: {
        [HTTP_HEADER_AUTHORIZATION]: `${AUTH_BEARER_PREFIX}${current}`,
      },
    });
    if (res.status === HTTP_UNAUTHORIZED) {
      const problem = await parseProblemDetails(res.clone());
      const detail = problem?.detail ?? problem?.title ?? (await safeText(res));
      throw new IdentityRevokedError(scrubSecrets(detail || 'identity refresh rejected'));
    }
    if (!res.ok) {
      throw new GovernanceError(
        `refresh failed (${res.status}): ${scrubSecrets(await safeText(res))}`,
      );
    }
    const body = await this._parseTokenResponse(res, 'refresh');
    this._applyTokenResponse(body);
  }

  /**
   * Reads `res.json()` and runs `SdkTokenResponseSchema.parse(...)`. Wraps
   * `ZodError` so the `unrecognized_keys` / `received` fields — which a
   * buggy server might echo our just-issued JWT into — don't ride out
   * as a raw error message to pino.
   */
  private async _parseTokenResponse(res: Response, what: string): Promise<SdkTokenResponse> {
    const json = await res.json();
    try {
      return SdkTokenResponseSchema.parse(json);
    } catch (err: unknown) {
      if (err instanceof ZodError) {
        throw new GovernanceError(
          `${what}: malformed token response: ${scrubSecrets(err.message)}`,
        );
      }
      throw new GovernanceError(`${what}: malformed token response: ${scrubSecrets(errMessage(err))}`);
    }
  }

  private _applyTokenResponse(body: SdkTokenResponse): void {
    this._token = body.token;
    this._expiresAtEpoch = parseIsoToEpoch(body.expiresAt);
    // `agentId`/`identityId` are server-stable across refreshes — set on
    // enrollment, never reassigned. Refresh responses re-include them
    // (the response schema is shared); guarding here avoids a confusing
    // state where a misconfigured server could shift our identity mid-flight.
    if (this._agentId === null) this._agentId = body.agentId;
    if (this._identityId === null) this._identityId = body.identityId;
  }

  private async _request(path: string, init: RequestInit): Promise<Response> {
    const timeout = AbortSignal.timeout(this._requestTimeoutMs);
    return this._fetch(`${this._apiUrl}${path}`, { ...init, signal: timeout });
  }
}

// ---- Helpers ----------------------------------------------------------------

function parseIsoToEpoch(iso: string): number {
  // Returns NaN on unparseable input. Callers MUST guard with
  // `Number.isFinite` — `_refreshLoop` does so and falls back to
  // `REFRESH_FALLBACK_SLEEP_MS` rather than scheduling an immediate
  // refresh against a bad timestamp.
  return new Date(iso).getTime() / 1000;
}

// ---- Bootstrap convenience --------------------------------------------------

export interface BootstrapOptions {
  enrollmentToken?: string;
  agentName?: string;
  apiUrl?: string;
  fetch?: typeof globalThis.fetch;
  requestTimeoutMs?: number;
  onWarn?: (msg: string) => void;
}

/**
 * Resolve env-var fallbacks, perform initial enrollment, return a started
 * TokenStore.
 *
 * Pass `enrollmentToken` and `agentName`, or set `AG_ENROLLMENT_TOKEN` and
 * `AG_AGENT_NAME`. Idempotent on `agentName` — every cold boot returns the
 * same identity row with a fresh JWT.
 *
 * The returned store has its background refresh loop already running.
 */
export async function bootstrapTokenStore(options: BootstrapOptions = {}): Promise<TokenStore> {
  const apiUrl = options.apiUrl ?? process.env[ENV_API_URL] ?? DEFAULT_API_URL;
  const enrollmentToken = options.enrollmentToken ?? process.env[ENV_ENROLLMENT_TOKEN];
  const agentName = options.agentName ?? process.env[ENV_AGENT_NAME];

  if (!enrollmentToken) {
    throw new GovernanceError(`enrollmentToken is required (or set ${ENV_ENROLLMENT_TOKEN})`);
  }
  if (!agentName) {
    throw new GovernanceError(`agentName is required (or set ${ENV_AGENT_NAME})`);
  }

  const store = new TokenStore({
    apiUrl,
    ...(options.fetch !== undefined ? { fetch: options.fetch } : {}),
    ...(options.requestTimeoutMs !== undefined ? { requestTimeoutMs: options.requestTimeoutMs } : {}),
    ...(options.onWarn !== undefined ? { onWarn: options.onWarn } : {}),
  });
  await store.initialEnrollment(enrollmentToken, agentName);
  store.startRefreshLoop();
  return store;
}
