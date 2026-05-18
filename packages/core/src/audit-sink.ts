// Batched, fire-and-forget audit event shipper.
//
//   - `enqueue(event)` is sync, never blocks, never throws. Drops with
//     a counter increment when the in-memory queue is full (default 10k).
//   - A background loop wakes every ~500ms and flushes when either
//     `batch.length >= batchSize` or the flush interval has elapsed.
//   - Flush retries 5xx / network errors with exponential backoff
//     (0.5s × 2, 4 attempts). 4xx drops the batch with a logged reason
//     and bumps `dropped4xx`. 401 force-refreshes the TokenStore and
//     retries once; a second 401 surfaces as IdentityRevokedError, the
//     batch is dropped, and the loop exits.
//   - `stop(drainTimeoutMs)` flushes remaining batches synchronously up
//     to the deadline before returning.
//   - `getStats()` reports counters so the daemon's `/v1/status` can
//     surface silent server-side drops to operators.

import { randomUUID } from 'node:crypto';

import { errMessage, scrubSecrets, sleepOrAbort } from './_internal.js';
import { ZodError } from 'zod';
import {
  API_ROUTE_EVENTS,
  AUTH_BEARER_PREFIX,
  CONTENT_TYPE_JSON,
  HTTP_ACCEPTED,
  HTTP_HEADER_AUTHORIZATION,
  HTTP_HEADER_CONTENT_TYPE,
  HTTP_UNAUTHORIZED,
} from './constants.js';
import { GovernanceError, IdentityRevokedError, parseProblemDetails } from './errors.js';
import { TokenStore } from './identity.js';
import type { AuditEvent } from './types.js';

const DEFAULT_BATCH_SIZE = 100;
const DEFAULT_FLUSH_INTERVAL_MS = 5_000;
const DEFAULT_MAX_QUEUE = 10_000;
const DEFAULT_HTTP_TIMEOUT_MS = 10_000;
const DEFAULT_DRAIN_TIMEOUT_MS = 5_000;
// Tick of the background loop — the latency between when an event
// lands in the queue and when the loop notices it.
const POLL_TICK_MS = 500;
const RETRY_INITIAL_BACKOFF_MS = 500;
const RETRY_BACKOFF_MULTIPLIER = 2;
const RETRY_MAX_ATTEMPTS = 4;
const CLIENT_ERROR_MIN = 400;
const CLIENT_ERROR_MAX = 500;

export interface AuditSinkOptions {
  apiUrl: string;
  tokenStore: TokenStore;
  /**
   * Called for queue-full drops, ship failures, and identity revocation.
   * No-op by default so @rubric-app/core stays logger-free; the daemon wraps
   * this and emits a structured pino event.
   */
  onError?: (err: unknown) => void;
  batchSize?: number;
  flushIntervalMs?: number;
  maxQueue?: number;
  requestTimeoutMs?: number;
  fetch?: typeof globalThis.fetch;
}

/**
 * Observable counters for the audit pipeline. Surfaced by `AuditSink.getStats()`
 * and intended to be wired into the daemon's `/v1/status` endpoint so operators
 * can spot silent server-side suppression (4xx) or sustained 5xx drops without
 * tailing logs.
 */
export interface AuditSinkStats {
  /** Total events accepted by `enqueue()` (i.e. not dropped at the door for queue-full). */
  enqueued: number;
  /** Total events confirmed accepted by the server (HTTP 202). */
  sent: number;
  /** Events dropped after a 4xx — server rejected the batch, no retry. */
  dropped4xx: number;
  /** Events dropped after exhausting 5xx/network retries. */
  dropped5xx: number;
  /** Events dropped at the door because the queue was at `maxQueue`. */
  droppedQueueFull: number;
  /** Current in-memory queue depth (events buffered but not yet shipped). */
  queueDepth: number;
}

export class AuditSink {
  private readonly _apiUrl: string;
  private readonly _tokenStore: TokenStore;
  private readonly _onError: (err: unknown) => void;
  private readonly _batchSize: number;
  private readonly _flushIntervalMs: number;
  private readonly _maxQueue: number;
  private readonly _requestTimeoutMs: number;
  private readonly _fetch: typeof globalThis.fetch;

  private readonly _queue: AuditEvent[] = [];
  private _lastFlushMs = 0;
  private _stopController: AbortController | null = null;
  private _loopPromise: Promise<void> | null = null;

  // Counters — incremented at every event class so `/v1/status` can
  // surface server-side suppression and 5xx-exhaustion drops to operators.
  private _enqueued = 0;
  private _sent = 0;
  private _dropped4xx = 0;
  private _dropped5xx = 0;
  private _droppedQueueFull = 0;

  constructor(options: AuditSinkOptions) {
    this._apiUrl = options.apiUrl.replace(/\/+$/, '');
    this._tokenStore = options.tokenStore;
    this._onError = options.onError ?? (() => {});
    this._batchSize = options.batchSize ?? DEFAULT_BATCH_SIZE;
    this._flushIntervalMs = options.flushIntervalMs ?? DEFAULT_FLUSH_INTERVAL_MS;
    this._maxQueue = options.maxQueue ?? DEFAULT_MAX_QUEUE;
    this._requestTimeoutMs = options.requestTimeoutMs ?? DEFAULT_HTTP_TIMEOUT_MS;
    this._fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
  }

  // ---- Public ---------------------------------------------------------------

  /**
   * Queue an event for shipping. Never blocks, never throws.
   *
   * If the queue is at `maxQueue`, the event is dropped and `onError`
   * is called with a `GovernanceError` describing the drop. Drop-on-full
   * keeps the agent's hot path decoupled from server availability.
   */
  enqueue(event: AuditEvent): void {
    if (this._queue.length >= this._maxQueue) {
      this._droppedQueueFull++;
      this._onError(new GovernanceError('audit queue full; dropping event'));
      return;
    }
    // Stamp a stable per-event id at construction time so the server
    // can upsert on retries (a 5xx → 202 race would otherwise produce
    // duplicate rows). `crypto.randomUUID()` (UUIDv4); collision
    // probability across the ~10^4 lifetime queue is negligible. The
    // id rides as a metadata field so the wire schema can evolve a
    // top-level `eventId` independently.
    const eventId = randomUUID();
    const metadata = { ...(event.metadata ?? {}), eventId };
    const stamped: AuditEvent = { ...event, metadata };
    this._enqueued++;
    this._queue.push(stamped);
  }

  /** Number of events currently buffered. */
  get queueSize(): number {
    return this._queue.length;
  }

  /**
   * Snapshot of counters for the audit pipeline. Safe to call any
   * time; returns a fresh object so callers can JSON-serialize
   * without worrying about mutation. Adapters typically surface this
   * on their status endpoint — `dropped4xx > 0` is the
   * operator-visible alert for silent server-side suppression.
   */
  getStats(): AuditSinkStats {
    return {
      enqueued: this._enqueued,
      sent: this._sent,
      dropped4xx: this._dropped4xx,
      dropped5xx: this._dropped5xx,
      droppedQueueFull: this._droppedQueueFull,
      queueDepth: this._queue.length,
    };
  }

  /** Start the background flush loop. Idempotent. */
  start(): void {
    if (this._stopController !== null) return;
    this._stopController = new AbortController();
    this._lastFlushMs = Date.now();
    this._loopPromise = this._run(this._stopController.signal);
  }

  /**
   * Stop the flush loop and drain remaining events up to `drainTimeoutMs`.
   *
   * Drains serially in batches — once the deadline elapses or a flush
   * throws an identity-revoked error, remaining events are abandoned.
   */
  async stop(drainTimeoutMs: number = DEFAULT_DRAIN_TIMEOUT_MS): Promise<void> {
    this._stopController?.abort();
    if (this._loopPromise) {
      await this._loopPromise.catch(() => {});
    }
    const deadline = Date.now() + drainTimeoutMs;
    while (this._queue.length > 0 && Date.now() < deadline) {
      const batch = this._queue.splice(0, this._batchSize);
      try {
        await this._flush(batch);
      } catch (err: unknown) {
        this._onError(err);
        if (err instanceof IdentityRevokedError) break;
      }
    }
    if (this._queue.length > 0) {
      this._onError(
        new GovernanceError(
          `audit sink stopped with ${this._queue.length} undrained events`,
        ),
      );
    }
    this._stopController = null;
    this._loopPromise = null;
  }

  // ---- Internals ------------------------------------------------------------

  private async _run(signal: AbortSignal): Promise<void> {
    while (!signal.aborted) {
      const aborted = await sleepOrAbort(POLL_TICK_MS, signal);
      if (aborted) return;

      if (this._queue.length === 0) continue;

      const now = Date.now();
      const timeToFlush = now - this._lastFlushMs >= this._flushIntervalMs;
      const sizeToFlush = this._queue.length >= this._batchSize;
      if (!timeToFlush && !sizeToFlush) continue;

      const batch = this._queue.splice(0, this._batchSize);
      try {
        await this._flush(batch);
      } catch (err: unknown) {
        this._onError(err);
        if (err instanceof IdentityRevokedError) return;
      }
      this._lastFlushMs = Date.now();
    }
  }

  /**
   * Ship one batch. Returns normally on success or after a 4xx drop;
   * raises `IdentityRevokedError` when the TokenStore says the identity is
   * gone (caller should stop the loop). All other errors are reported via
   * `onError` and the batch is dropped after `RETRY_MAX_ATTEMPTS`.
   */
  private async _flush(batch: AuditEvent[]): Promise<void> {
    const payload = { events: batch };
    let backoffMs = RETRY_INITIAL_BACKOFF_MS;
    for (let attempt = 0; attempt < RETRY_MAX_ATTEMPTS; attempt++) {
      let res: Response;
      try {
        res = await this._postWithAuthRetry(payload);
      } catch (err: unknown) {
        if (err instanceof IdentityRevokedError) throw err;
        // A ZodError from somewhere in the auth-retry chain (today this is
        // `parseProblemDetails` → safe, but defense in depth) could echo
        // the request payload — which contains audit metadata that may be
        // sensitive. Scrub before re-raising as a GovernanceError.
        if (err instanceof ZodError) {
          this._onError(
            new GovernanceError(`audit ship parse error: ${scrubSecrets(err.message)}`),
          );
        } else {
          this._onError(
            new GovernanceError(`audit ship network error: ${scrubSecrets(errMessage(err))}`),
          );
        }
        await this._sleep(backoffMs);
        backoffMs *= RETRY_BACKOFF_MULTIPLIER;
        continue;
      }

      if (res.status === HTTP_ACCEPTED) {
        this._sent += batch.length;
        return;
      }

      if (res.status >= CLIENT_ERROR_MIN && res.status < CLIENT_ERROR_MAX) {
        // 4xx: drop. Don't retry — the server says the batch is malformed.
        // The server's problem-details body can include payload fragments
        // (e.g. zod's `unrecognized_keys` echoes input keys); pass the
        // detail through scrubSecrets so a stray `Bearer …` or JWT in the
        // request can't ride out into the daemon's pino log.
        const problem = await parseProblemDetails(res.clone());
        const detail = problem?.detail ?? problem?.title ?? res.statusText;
        this._dropped4xx += batch.length;
        this._onError(
          new GovernanceError(
            `audit ship rejected (${res.status}): ${scrubSecrets(detail)}`,
          ),
        );
        return;
      }

      // 5xx or other → retry with backoff.
      this._onError(
        new GovernanceError(`audit ship failed (${res.status}); retry ${attempt + 1}`),
      );
      await this._sleep(backoffMs);
      backoffMs *= RETRY_BACKOFF_MULTIPLIER;
    }
    this._dropped5xx += batch.length;
    this._onError(
      new GovernanceError(
        `audit ship gave up after ${RETRY_MAX_ATTEMPTS} attempts; dropped ${batch.length} events`,
      ),
    );
  }

  private async _postWithAuthRetry(payload: { events: AuditEvent[] }): Promise<Response> {
    const res = await this._postOnce(payload);
    if (res.status !== HTTP_UNAUTHORIZED) return res;
    // Drain the body so the connection can be reused, then force-refresh.
    await res.body?.cancel().catch(() => {});
    await this._tokenStore.forceRefresh();
    return this._postOnce(payload);
  }

  private _postOnce(payload: { events: AuditEvent[] }): Promise<Response> {
    const token = this._tokenStore.token();
    const timeout = AbortSignal.timeout(this._requestTimeoutMs);
    return this._fetch(`${this._apiUrl}${API_ROUTE_EVENTS}`, {
      method: 'POST',
      headers: {
        [HTTP_HEADER_AUTHORIZATION]: `${AUTH_BEARER_PREFIX}${token}`,
        [HTTP_HEADER_CONTENT_TYPE]: CONTENT_TYPE_JSON,
      },
      body: JSON.stringify(payload),
      signal: timeout,
    });
  }

  private _sleep(ms: number): Promise<void> {
    return new Promise((resolve) => {
      const t = setTimeout(resolve, ms);
      t.unref?.();
    });
  }
}
