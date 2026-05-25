// Daemon entry point: wires TokenStore + BundlePoller + Evaluator +
// AuditSink + HTTP server into a single long-lived process.
//
// Called by `rubric start --foreground` and by the platform service
// (launchd plist / systemd unit) — both ultimately invoke
// `node dist/cli/index.js daemon` which calls into here.

import * as fs from 'node:fs';

import {
  AuditSink,
  BundlePoller,
  Evaluator,
  GovernanceError,
  PolicyDocumentSchema,
  bootstrapTokenStore,
  errCode,
  scrubSecrets,
  type PolicyDocument,
  type TokenStore,
} from '@rubric-app/core';

import type { Paths } from '../config/paths.js';
import { DEFAULT_SAFETY_PACK, compileLocalBundle } from '../policies/default-pack.js';


import {
  installSignalHandlers,
  PidGuard,
  removePortFile,
  writePortFile,
} from './lifecycle.js';
import { createLogger, type Logger } from './logger.js';
import { NoopAuditSink } from './noop-audit.js';
import { startServer, type RunningServer } from './server.js';

const DEFAULT_FIRST_PULL_TIMEOUT_MS = 10_000;

// Required shape of the daemon token file. Mirrors `auth.checkBearer`'s
// own shape check; we validate at boot so a missing/corrupt token file
// fails fast rather than producing a daemon that 401s every request.
const HEX64_REGEX = /^[a-f0-9]{64}$/;

export interface DaemonConfig {
  /** 'solo' = local-only enforcement; 'connected' = enrolled against a tenant. */
  mode?: 'solo' | 'connected';
  /** Rubric API base URL. Connected mode only. */
  apiUrl?: string;
  /** Stable name for this agent in the dashboard. */
  agentName: string;
  /** Org-issued enrollment token. Stored at `paths.configFile`. Connected mode only. */
  enrollmentToken?: string;
  /** Requested daemon port. Falls back to OS-assigned if in use. */
  daemonPort?: number;
}

export interface RunDaemonOptions {
  config: DaemonConfig;
  paths: Paths;
  /** Override the log level (default 'info'). */
  logLevel?: 'trace' | 'debug' | 'info' | 'warn' | 'error' | 'fatal';
  /** If true, also tee logs to stderr — used by `rubric start --foreground`. */
  alsoStderr?: boolean;
  /** How long to wait for the first bundle before serving traffic. */
  firstBundleTimeoutMs?: number;
  /**
   * Local-dev escape hatch. When true, the daemon will bind the HTTP
   * server even if the first bundle pull never produced a bundle —
   * used by tests and by `rubric start --foreground --allow-cold-start`
   * during development against an offline Rubric API. In production
   * this flag is never set: we refuse to serve until the authoritative
   * policy set is in hand.
   */
  allowColdStart?: boolean;
}

/**
 * Start the daemon and return only when it's accepting hooks. Resolves
 * on graceful shutdown; rejects on a fatal startup error.
 *
 * Signal handlers (SIGTERM/SIGINT) are installed inside — invoking
 * code shouldn't install its own.
 */
export async function runDaemon(options: RunDaemonOptions): Promise<void> {
  const logger = createLogger({
    logFile: options.paths.logFile,
    level: options.logLevel ?? 'info',
    ...(options.alsoStderr ? { alsoStderr: options.alsoStderr } : {}),
  });
  logger.info({ paths: options.paths }, 'daemon starting');

  const daemonToken = loadDaemonToken(options.paths.daemonTokenFile);
  logger.info({ tokenFile: options.paths.daemonTokenFile }, 'daemon token loaded');

  const pidGuard = new PidGuard({ pidFile: options.paths.pidFile, logger });
  pidGuard.claim();

  // Solo mode: no identity, no control plane, no audit upload. Evaluate
  // locally against the baked-in/editable safety pack and serve hooks. The
  // connected path below is untouched.
  if (options.config.mode === 'solo') {
    return runSolo(options, logger, daemonToken, pidGuard);
  }

  // ---- Bring up the core stack --------------------------------------------
  // Order matters: identity must be live before the bundle poller and
  // audit sink can authenticate; bundle must seed the evaluator before
  // we accept hook requests (otherwise the first call falls through to
  // the empty-bundle `allow` path, which is permissive — we don't want
  // that on cold start, see plan §Failure-mode matrix).

  // Connected mode requires both (config validation guarantees it; narrow for
  // the type system and fail loud if a hand-edited config violates it).
  const { apiUrl, enrollmentToken } = options.config;
  if (apiUrl === undefined || enrollmentToken === undefined) {
    logger.fatal('connected mode requires apiUrl and enrollmentToken');
    pidGuard.release();
    throw new GovernanceError('connected mode requires apiUrl and enrollmentToken');
  }

  let tokenStore: TokenStore;
  try {
    tokenStore = await bootstrapTokenStore({
      apiUrl,
      agentName: options.config.agentName,
      enrollmentToken,
    });
  } catch (err: unknown) {
    logger.fatal({ err }, 'identity enrollment failed; daemon cannot start');
    pidGuard.release();
    throw err;
  }
  logger.info({ agentId: tokenStore.agentId }, 'identity enrolled');

  const evaluator = new Evaluator({
    onCompileError: ({ policyId, ruleId, pattern, cause }) =>
      logger.warn(
        { policyId, ruleId, pattern, err: cause },
        'policy regex failed to compile; rule treated as no-match',
      ),
  });

  const bundlePoller = new BundlePoller({
    apiUrl,
    tokenStore,
    onUpdate: (bundle) => {
      evaluator.updateBundle(bundle);
      logger.info(
        {
          bundleVersion: bundle.bundleVersion,
          contentHash: bundle.contentHash.slice(0, 12),
          policies: bundle.policies.length,
          frozenAgentIds: bundle.frozenAgentIds.length,
        },
        'bundle updated',
      );
    },
    onError: (err) => logger.warn({ err }, 'bundle pull failed'),
  });
  bundlePoller.start();

  // Refuse to bind `/v1/hook` until the first bundle pull has produced
  // an authoritative bundle. `firstPullDone` resolves on success OR
  // failure of the first poll; afterwards `current` is null iff the
  // pull failed (network error, 401 → IdentityRevoked, 5xx, schema
  // validation failure). Serving with no bundle would fail-open to an
  // empty policy set, so we fail-closed instead.
  //
  // The `--allow-cold-start` escape hatch exists for local dev and
  // tests against an offline Rubric API; production callers MUST NOT
  // set it.
  try {
    await bundlePoller.firstPullDone(
      options.firstBundleTimeoutMs ?? DEFAULT_FIRST_PULL_TIMEOUT_MS,
    );
  } catch (err: unknown) {
    if (!options.allowColdStart) {
      logger.fatal({ err }, 'first-pull timeout; refusing to serve without an authoritative bundle');
      await drainAndLog(
        logger,
        'startup-cleanup',
        Promise.allSettled([bundlePoller.stop(), tokenStore.stop()]),
      );
      pidGuard.release();
      throw err instanceof Error
        ? err
        : new GovernanceError('first-pull timeout; bundle never arrived');
    }
    logger.warn({ err }, 'cold-start allowed; first-pull timed out, serving with empty policy set');
  }
  if (bundlePoller.current === null && !options.allowColdStart) {
    logger.fatal(
      'first-pull completed but no bundle is loaded; refusing to serve without an authoritative bundle',
    );
    await drainAndLog(
      logger,
      'startup-cleanup',
      Promise.allSettled([bundlePoller.stop(), tokenStore.stop()]),
    );
    pidGuard.release();
    throw new GovernanceError(
      'daemon refusing to start: first bundle pull failed and --allow-cold-start was not set',
    );
  }

  const auditSink = new AuditSink({
    apiUrl,
    tokenStore,
    onError: (err) => logger.warn({ err }, 'audit sink error'),
  });
  auditSink.start();

  // ---- Poller self-heal on developer activity -----------------------------
  // Defense-in-depth beside the poller's own never-die loop. If the poll has
  // gone stale (a long offline period, a laptop sleep that drifted the timer,
  // or a rejected identity), the next Claude Code hook kicks a re-enroll +
  // poller restart. Fire-and-forget with a cooldown so a burst of tool calls
  // can't spawn overlapping revivals or hammer the control plane. Staleness
  // threshold matches `rubric doctor`'s bar so the two agree on "stuck".
  const REVIVE_STALE_AFTER_MS = 90_000;
  const REVIVE_COOLDOWN_MS = 30_000;
  let lastReviveAttempt = 0;
  let reviveInFlight = false;
  const maybeRevivePoller = (): void => {
    const lastPull = bundlePoller.lastPullAt;
    const stale = lastPull === null || Date.now() - lastPull.getTime() > REVIVE_STALE_AFTER_MS;
    if (!stale || reviveInFlight) return;
    if (Date.now() - lastReviveAttempt < REVIVE_COOLDOWN_MS) return;
    lastReviveAttempt = Date.now();
    reviveInFlight = true;
    void (async () => {
      try {
        logger.warn(
          { lastPullAt: lastPull, identityDead: tokenStore.isDead() },
          'bundle poller stale on hook activity; attempting self-heal',
        );
        // Re-enrollment is the load-bearing step: a stale/expired JWT can't
        // be refreshed, only re-enrolled. `start()` is idempotent and a
        // no-op while the never-die loop is still running.
        if (tokenStore.isDead()) {
          await tokenStore.reenroll();
          logger.info('identity re-enrolled during poller self-heal');
        }
        bundlePoller.start();
      } catch (err: unknown) {
        logger.warn({ err }, 'poller self-heal failed; will retry after cooldown');
      } finally {
        reviveInFlight = false;
      }
    })();
  };

  // ---- Bind the HTTP server -----------------------------------------------

  const startedAt = new Date();

  // The shutdown trigger handed to the server. We set this up *before*
  // startServer so the `POST /v1/shutdown` endpoint can resolve it
  // without a forward reference. The real shutdown function is defined
  // below; this indirection keeps both happy.
  let shutdownTrigger: (() => Promise<void>) | null = null;

  let server: RunningServer;
  try {
    server = await startServer({
      ...(options.config.daemonPort !== undefined ? { port: options.config.daemonPort } : {}),
      daemonToken,
      logger,
      onHookActivity: maybeRevivePoller,
      handlerDeps: {
        evaluator,
        audit: auditSink,
        agentId: tokenStore.agentId,
      },
      statusDeps: {
        bundlePoller,
        audit: auditSink,
        identity: { agentId: tokenStore.agentId },
        startedAt,
      },
      onShutdownRequest: async () => {
        // Invoked from `POST /v1/shutdown`. The server's response
        // (202) has already been written by the time we land here.
        if (shutdownTrigger === null) {
          logger.warn('shutdown requested before trigger was wired; ignoring');
          return;
        }
        await shutdownTrigger();
      },
    });
  } catch (err: unknown) {
    logger.fatal({ err }, 'failed to bind daemon HTTP server');
    // Log every rejection from the cleanup `allSettled` so component-stop
    // errors during startup cleanup don't get silently swallowed.
    await drainAndLog(
      logger,
      'startup-cleanup',
      Promise.allSettled([bundlePoller.stop(), auditSink.stop(), tokenStore.stop()]),
    );
    pidGuard.release();
    throw err;
  }
  writePortFile(options.paths.daemonPortFile, server.port);
  logger.info({ port: server.port, host: server.host }, 'daemon ready');

  // ---- Graceful shutdown ---------------------------------------------------

  const shutdown = async (): Promise<void> => {
    logger.info('shutting down');
    // Order: stop accepting new requests first; then drain the audit
    // sink so any tail events ship before identity is torn down;
    // poller can stop in parallel — it has no state to flush.
    await server.close().catch((err) => logger.warn({ err }, 'server.close failed'));
    // Log rejections from this `allSettled`. If `auditSink.stop()`
    // rejects mid-drain (e.g. IdentityRevokedError with undrained
    // events) we want a log line, not silence.
    await drainAndLog(
      logger,
      'shutdown',
      Promise.allSettled([bundlePoller.stop(), auditSink.stop()]),
    );
    await tokenStore.stop();
    removePortFile(options.paths.daemonPortFile);
    pidGuard.release();
    logger.info('shutdown complete');
  };

  // Return a Promise that resolves only when the daemon exits. The
  // install of signal handlers means we'll call shutdown then
  // `process.exit(0)` — this resolve is mostly for test harnesses
  // that drive shutdown programmatically.
  return new Promise<void>((resolve, reject) => {
    // Wire the shutdown trigger now that `shutdown` is in scope. Both
    // signal handlers and the `POST /v1/shutdown` endpoint resolve to
    // this same closure — we coalesce repeat triggers via
    // `shutdownInFlight`.
    let shutdownInFlight: Promise<void> | null = null;
    shutdownTrigger = (): Promise<void> => {
      if (shutdownInFlight !== null) return shutdownInFlight;
      shutdownInFlight = (async () => {
        try {
          await shutdown();
          resolve();
        } catch (err) {
          reject(err);
        }
      })();
      return shutdownInFlight;
    };

    installSignalHandlers({
      logger,
      onShutdown: shutdownTrigger,
    });
  });
}

/**
 * Solo-mode daemon: fully local enforcement. Skips enrollment, the bundle
 * poller, and the audit-upload sink. Loads the editable local policy pack
 * (falling back to the compiled-in default), feeds it to the Evaluator, and
 * serves the same hook server with a local audit sink. Nothing leaves the
 * machine.
 */
async function runSolo(
  options: RunDaemonOptions,
  logger: Logger,
  daemonToken: string,
  pidGuard: PidGuard,
): Promise<void> {
  const evaluator = new Evaluator({
    onCompileError: ({ policyId, ruleId, pattern, cause }) =>
      logger.warn({ policyId, ruleId, pattern, err: cause }, 'policy regex failed to compile'),
  });

  const pack = loadLocalPack(options.paths.policiesFile, logger);
  evaluator.updateBundle(compileLocalBundle(pack));
  logger.info({ policies: pack.length, source: options.paths.policiesFile }, 'solo policy pack loaded');

  const agentId = `solo:${options.config.agentName}`;
  // Solo records nothing: no local decision log, no telemetry.
  const audit = new NoopAuditSink();

  let shutdownTrigger: (() => Promise<void>) | null = null;
  let server: RunningServer;
  try {
    server = await startServer({
      ...(options.config.daemonPort !== undefined ? { port: options.config.daemonPort } : {}),
      daemonToken,
      logger,
      handlerDeps: { evaluator, audit, agentId },
      onShutdownRequest: async () => {
        if (shutdownTrigger === null) return;
        await shutdownTrigger();
      },
    });
  } catch (err: unknown) {
    logger.fatal({ err }, 'failed to bind daemon HTTP server');
    pidGuard.release();
    throw err;
  }
  writePortFile(options.paths.daemonPortFile, server.port);
  logger.info({ port: server.port, host: server.host, mode: 'solo' }, 'daemon ready');

  const shutdown = async (): Promise<void> => {
    logger.info('shutting down');
    await server.close().catch((err) => logger.warn({ err }, 'server.close failed'));
    removePortFile(options.paths.daemonPortFile);
    pidGuard.release();
    logger.info('shutdown complete');
  };

  return new Promise<void>((resolve, reject) => {
    let shutdownInFlight: Promise<void> | null = null;
    shutdownTrigger = (): Promise<void> => {
      if (shutdownInFlight !== null) return shutdownInFlight;
      shutdownInFlight = (async () => {
        try {
          await shutdown();
          resolve();
        } catch (err) {
          reject(err);
        }
      })();
      return shutdownInFlight;
    };
    installSignalHandlers({ logger, onShutdown: shutdownTrigger });
  });
}

/**
 * Read the editable local policy pack. Returns the compiled-in default pack on
 * a missing/invalid file — solo mode must NEVER fail closed (deny-all would
 * break the developer's Claude Code). File shape: `{ policies: [{ id, document }] }`.
 */
function loadLocalPack(
  policiesFile: string,
  logger: Logger,
): ReadonlyArray<{ id: string; document: PolicyDocument }> {
  let raw: string;
  try {
    raw = fs.readFileSync(policiesFile, 'utf8');
  } catch {
    return DEFAULT_SAFETY_PACK;
  }
  try {
    const parsed = JSON.parse(raw) as { policies?: unknown };
    const list = Array.isArray(parsed.policies) ? parsed.policies : [];
    const out: { id: string; document: PolicyDocument }[] = [];
    for (const item of list) {
      const entry = item as { id?: unknown; document?: unknown };
      if (typeof entry.id !== 'string') throw new Error('policy entry missing string id');
      out.push({ id: entry.id, document: PolicyDocumentSchema.parse(entry.document) });
    }
    if (out.length === 0) throw new Error('no policies in file');
    return out;
  } catch (err: unknown) {
    logger.warn({ err, policiesFile }, 'local policy file invalid; using baked-in default pack');
    return DEFAULT_SAFETY_PACK;
  }
}

// ---- Helpers ---------------------------------------------------------------

function loadDaemonToken(tokenFile: string): string {
  let raw: string;
  try {
    raw = fs.readFileSync(tokenFile, 'utf8');
  } catch (err: unknown) {
    if (errCode(err) === 'ENOENT') {
      throw new GovernanceError(
        `daemon token not found at ${tokenFile}; did you run 'rubric init'?`,
      );
    }
    throw err;
  }
  const token = raw.trim();
  // Belt-and-suspenders — explicitly refuse an empty token at boot
  // rather than letting `auth.checkBearer` see `expectedToken === ''`
  // at request time. The HEX64 regex below would catch this too, but a
  // pointed error message for the empty case helps the operator.
  if (token.length === 0) {
    throw new GovernanceError(
      `daemon token at ${tokenFile} is empty; run 'rubric init' to regenerate`,
    );
  }
  if (!HEX64_REGEX.test(token)) {
    throw new GovernanceError(
      `daemon token at ${tokenFile} is not a 64-char hex string (got ${token.length} chars)`,
    );
  }
  return token;
}

/**
 * Inspect every result of a `Promise.allSettled` and log each rejection
 * at error level. Used during startup cleanup and graceful shutdown so
 * component-stop errors don't get silently swallowed. Reasons are
 * scrubbed through `scrubSecrets` in case the underlying error message
 * carries an echo of a JWT / Bearer header / postgres URL.
 */
async function drainAndLog(
  logger: Logger,
  phase: string,
  pending: Promise<PromiseSettledResult<unknown>[]>,
): Promise<void> {
  const results = await pending;
  for (const [i, result] of results.entries()) {
    if (result.status === 'rejected') {
      const reason = result.reason;
      const message =
        reason instanceof Error
          ? scrubSecrets(reason.message)
          : scrubSecrets(String(reason));
      logger.error(
        {
          phase,
          index: i,
          reason: message,
          ...(reason instanceof Error ? { stack: scrubSecrets(reason.stack ?? '') } : {}),
        },
        'component cleanup failed',
      );
    }
  }
}
