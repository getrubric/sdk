// HTTP server hosting the Claude Code hook endpoint.
//
//   POST /v1/hook     — bearer-auth required; body is a Claude Code hook
//                       payload; response is the `HookResponse` shape.
//   POST /v1/shutdown — bearer-auth required; schedules graceful
//                       shutdown; returns 202 Accepted. Used by
//                       `rubric stop` to terminate the daemon over
//                       loopback HTTP rather than SIGTERM. Pidfile
//                       SIGTERM remains a fallback in the CLI.
//   GET  /v1/status   — bearer-auth required; daemon health + bundle
//                       metadata + audit counters.
//   GET  /healthz     — no auth; returns 200 + small JSON. Used by
//                       `rubric doctor` and external monitoring.
//
// Bound to `127.0.0.1` only by default; `startServer` rejects any other
// host that isn't on the loopback whitelist. If the requested port is
// already in use, the server falls back to OS-assigned by binding to
// port 0; the actual port is persisted to `daemon.port` so the CLI's
// `rubric start/stop/logs` can talk to whichever instance is running.

import * as http from 'node:http';

import { scrubSecrets } from '@rubric-app/core';

import type { Logger } from './logger.js';
import { checkBearer } from './auth.js';
import { handleHookPayload } from './handler.js';
import type { HandlerDeps } from './handler.js';
import { buildDaemonStatus, type DaemonStatusDeps } from './status.js';
import { HookPayloadSchema } from './types.js';

export const DEFAULT_DAEMON_HOST = '127.0.0.1';
export const DEFAULT_DAEMON_PORT = 47821;

// Host whitelist. The daemon is designed to serve callers on the same
// machine only; `startServer` refuses to bind anything outside this set.
const ALLOWED_HOSTS: ReadonlySet<string> = new Set(['127.0.0.1', '::1', 'localhost']);

// Cap the hook payload size. Claude Code's payloads are small (tool
// input + cwd + transcript_path); 1 MiB is generous and protects
// against accidental misuse. Anything over this is rejected with 413.
const MAX_PAYLOAD_BYTES = 1024 * 1024;

// HTTP slowloris guard. Defaults left to Node would let any local
// process tie up a connection by trickling header bytes — a stalled
// connection holds `server.close()` open until idle. The numbers here
// are tight but ample for a loopback caller; Claude Code's hook POST
// completes in milliseconds.
//
// Node enforces `headersTimeout` / `requestTimeout` via a periodic
// sweeper whose cadence is `connectionsCheckingInterval` (default 30s).
// With the timeouts below at 5–10 s, the default 30s sweep would let
// a stalled connection hang for up to 35–40s — close, but loose enough
// that graceful-shutdown drain can take the upper bound. We lower the
// sweep interval to 2s so the timeouts fire within ~2s of expiry.
const HEADERS_TIMEOUT_MS = 5_000;
const REQUEST_TIMEOUT_MS = 10_000;
const KEEP_ALIVE_TIMEOUT_MS = 5_000;
const CONNECTIONS_CHECKING_INTERVAL_MS = 2_000;

export interface StartServerOptions {
  /**
   * Bind host. Default `127.0.0.1`. Restricted to the loopback
   * whitelist (`127.0.0.1`, `::1`, `localhost`) — passing anything
   * else throws synchronously at startup.
   */
  host?: string;
  port?: number;
  daemonToken: string;
  logger: Logger;
  handlerDeps: HandlerDeps;
  /**
   * State sources for /v1/status. Optional — when omitted, the route
   * returns 503. Tests can leave this off; the real daemon always
   * wires it.
   */
  statusDeps?: DaemonStatusDeps;
  /**
   * Authenticated shutdown trigger. Optional — when omitted,
   * `POST /v1/shutdown` returns 503. The real daemon wires this to the
   * `runDaemon` shutdown path. Errors thrown by the callback are
   * logged; the 202 response has already been written by then.
   */
  onShutdownRequest?: () => Promise<void> | void;
  /**
   * Fire-and-forget callback invoked on each authenticated `/v1/hook`
   * request, before the decision is computed. The daemon wires this to a
   * poller self-heal: developer activity is the only time a stale bundle
   * has consequences, so it's the right moment to revive a stalled poller.
   * Must not block — it runs synchronously off the request path and any
   * throw is caught and logged, never surfaced to the caller.
   */
  onHookActivity?: () => void;
}

export interface RunningServer {
  /** Actual port bound — may differ from requested if fallback fired. */
  port: number;
  host: string;
  /**
   * Graceful close — closes idle connections immediately, then stops
   * accepting new connections and waits for in-flight requests to
   * complete.
   */
  close(): Promise<void>;
}

export async function startServer(options: StartServerOptions): Promise<RunningServer> {
  const host = options.host ?? DEFAULT_DAEMON_HOST;
  if (!ALLOWED_HOSTS.has(host)) {
    throw new Error(
      `startServer: refusing to bind '${host}'; only loopback hosts are allowed ` +
        `(${[...ALLOWED_HOSTS].join(', ')})`,
    );
  }
  const requestedPort = options.port ?? DEFAULT_DAEMON_PORT;

  const server = http.createServer((req, res) => {
    void handleRequest(req, res, options).catch((err: unknown) => {
      options.logger.error({ err }, 'unhandled request error');
      if (!res.writableEnded) {
        try {
          res.statusCode = 500;
          res.setHeader('content-type', 'application/json');
          res.end(JSON.stringify({ error: 'internal_error' }));
        } catch {
          /* socket already torn down */
        }
      }
    });
  });

  // Tighten HTTP timeouts so a single stalled connection can't pin
  // resources indefinitely. `headersTimeout` covers the slowloris case
  // (trickling header bytes); `requestTimeout` covers a stalled body;
  // `keepAliveTimeout` caps idle connections.
  // `connectionsCheckingInterval` controls how often Node sweeps for
  // timeout violations — see the constant comment above for why we
  // override the 30s default.
  server.headersTimeout = HEADERS_TIMEOUT_MS;
  server.requestTimeout = REQUEST_TIMEOUT_MS;
  server.keepAliveTimeout = KEEP_ALIVE_TIMEOUT_MS;
  // `connectionsCheckingInterval` lands in @types/node lazily; the
  // property is present on `http.Server` since Node 18.10. Assign
  // through a typed property to keep the rest of the call site clean.
  (server as http.Server & { connectionsCheckingInterval: number }).connectionsCheckingInterval =
    CONNECTIONS_CHECKING_INTERVAL_MS;

  // Try the requested port; if EADDRINUSE, fall back to OS-assigned (port 0).
  const port = await listenWithFallback(server, requestedPort, host, options.logger);

  return {
    port,
    host,
    close: () =>
      new Promise<void>((resolve, reject) => {
        // Drop idle keep-alive sockets so they don't hold close() open
        // for `keepAliveTimeout`. In-flight requests are still allowed
        // to finish — `closeIdleConnections` only touches sockets with
        // no active request.
        server.closeIdleConnections();
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}

async function listenWithFallback(
  server: http.Server,
  requestedPort: number,
  host: string,
  logger: Logger,
): Promise<number> {
  try {
    return await listenOnce(server, requestedPort, host);
  } catch (err: unknown) {
    if (isAddrInUse(err) && requestedPort !== 0) {
      logger.warn({ requestedPort }, 'requested port in use; falling back to OS-assigned');
      return listenOnce(server, 0, host);
    }
    throw err;
  }
}

function listenOnce(server: http.Server, port: number, host: string): Promise<number> {
  return new Promise<number>((resolve, reject) => {
    const onError = (err: unknown): void => {
      server.removeListener('listening', onListening);
      reject(err);
    };
    const onListening = (): void => {
      server.removeListener('error', onError);
      const addr = server.address();
      if (typeof addr !== 'object' || addr === null) {
        reject(new Error(`server.address() returned ${String(addr)}`));
        return;
      }
      resolve(addr.port);
    };
    server.once('error', onError);
    server.once('listening', onListening);
    server.listen(port, host);
  });
}

function isAddrInUse(err: unknown): boolean {
  return typeof err === 'object' && err !== null && (err as { code?: string }).code === 'EADDRINUSE';
}

// ---- Request handling ------------------------------------------------------

async function handleRequest(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  options: StartServerOptions,
): Promise<void> {
  if (req.method === 'GET' && req.url === '/healthz') {
    return respondJson(res, 200, { ok: true });
  }

  if (req.method === 'GET' && req.url === '/v1/status') {
    // Status requires bearer — leaks bundle/agent metadata.
    if (!checkBearer(req.headers['authorization'], options.daemonToken)) {
      return respondJson(res, 401, { error: 'unauthorized' });
    }
    if (!options.statusDeps) {
      return respondJson(res, 503, { error: 'status_unavailable' });
    }
    return respondJson(res, 200, buildDaemonStatus(options.statusDeps));
  }

  if (req.method === 'POST' && req.url === '/v1/shutdown') {
    // Authenticated graceful-shutdown trigger for `rubric stop`.
    // Uses the same bearer as `/v1/hook`. We respond 202 *before*
    // awaiting the shutdown so the caller doesn't hang on a long drain.
    if (!checkBearer(req.headers['authorization'], options.daemonToken)) {
      return respondJson(res, 401, { error: 'unauthorized' });
    }
    if (typeof options.onShutdownRequest !== 'function') {
      return respondJson(res, 503, { error: 'shutdown_unavailable' });
    }
    respondJson(res, 202, { accepted: true });
    // Schedule the shutdown after the response is flushed. `setImmediate`
    // lets the current tick (which is writing the 202) complete first.
    setImmediate(() => {
      void Promise.resolve(options.onShutdownRequest!()).catch((err: unknown) => {
        options.logger.error({ err }, 'shutdown handler rejected');
      });
    });
    return;
  }

  if (!(req.method === 'POST' && req.url === '/v1/hook')) {
    return respondJson(res, 404, { error: 'not_found' });
  }

  if (!checkBearer(req.headers['authorization'], options.daemonToken)) {
    // Generic 401 — no detail leak about whether the header was missing
    // vs. invalid vs. the wrong length.
    return respondJson(res, 401, { error: 'unauthorized' });
  }

  // Self-heal on developer activity. If the bundle poller has gone stale
  // (offline period, laptop sleep, a rejected identity), kick a revive now —
  // fire-and-forget so it never adds latency to the decision below, which
  // still uses the currently-cached bundle. The callback owns its cooldown.
  if (typeof options.onHookActivity === 'function') {
    try {
      options.onHookActivity();
    } catch (err: unknown) {
      options.logger.warn({ err }, 'onHookActivity threw; ignoring');
    }
  }

  const body = await readBody(req);
  if (body === null) {
    return respondJson(res, 413, { error: 'payload_too_large' });
  }

  let payload: unknown;
  try {
    payload = JSON.parse(body);
  } catch {
    return respondJson(res, 400, { error: 'invalid_json' });
  }

  const parsed = HookPayloadSchema.safeParse(payload);
  if (!parsed.success) {
    // zod issue paths and codes are safe; issue `message` and `received`
    // can reflect raw payload bytes — run them through scrubSecrets so
    // a misshapen request carrying a JWT doesn't leak it into pino.
    const issues = parsed.error.issues.map((iss) => ({
      ...iss,
      message: scrubSecrets(iss.message),
    }));
    options.logger.warn({ issues }, 'unrecognized Claude Code hook payload');
    return respondJson(res, 400, { error: 'invalid_payload' });
  }

  // The handler runs synchronously — evaluator.evaluate is CPU only,
  // audit.enqueue never blocks. No need to await here.
  const response = handleHookPayload(parsed.data, options.handlerDeps);
  // Per-call line is debug-only: at the default level the daemon records
  // no per-tool-call activity (tool name / decision) to disk.
  options.logger.debug(
    {
      event: parsed.data.hook_event_name,
      tool: 'tool_name' in parsed.data ? parsed.data.tool_name : undefined,
      decision: response.hookSpecificOutput?.permissionDecision,
    },
    'hook handled',
  );
  return respondJson(res, 200, response);
}

function readBody(req: http.IncomingMessage): Promise<string | null> {
  return new Promise((resolve, reject) => {
    let total = 0;
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > MAX_PAYLOAD_BYTES) {
        req.destroy();
        resolve(null);
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function respondJson(res: http.ServerResponse, status: number, body: unknown): void {
  res.statusCode = status;
  res.setHeader('content-type', 'application/json');
  res.end(JSON.stringify(body));
}
