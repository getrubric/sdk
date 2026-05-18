// `/v1/status` payload builder. Reads state from the live BundlePoller
// + AuditSink + TokenStore so the CLI's `rubric doctor` (and external
// monitoring) can inspect daemon health without instrumenting each
// module separately.
//
// The endpoint requires the daemon bearer token (same as /v1/hook)
// because it exposes the agent identity + bundle hash — fine to share
// across processes on the same machine, not fine for any random
// loopback caller. Healthz remains no-auth as the lighter probe.

import type { BundlePoller } from '@rubric-app/core';

const HASH_PREFIX_LENGTH = 12;

/**
 * Drop / ship counters reported by the AuditSink (`@rubric-app/core`
 * exports `AuditSink.getStats()` returning a structurally compatible
 * shape). Defining the type here rather than re-exporting from core
 * keeps the daemon's status payload stable across core SDK versions —
 * if core ever adds fields, we still emit only the ones we documented.
 */
export interface AuditSinkStats {
  /** Total events ever accepted into the in-memory queue. */
  readonly enqueued: number;
  /** Total events the server returned 202 for. */
  readonly sent: number;
  /** Events dropped after a 4xx response from the server. */
  readonly dropped4xx: number;
  /** Events dropped after exhausting 5xx retries. */
  readonly dropped5xx: number;
  /** Events dropped at the door because the queue was at `maxQueue`. */
  readonly droppedQueueFull?: number;
  /** Events currently buffered, awaiting flush. */
  readonly queueDepth: number;
}

export interface AuditSinkLike {
  /** Number of events currently queued, awaiting flush. */
  readonly queueSize: number;
  /**
   * Drop / ship counters. Provided by `@rubric-app/core`'s `AuditSink`.
   * Declared optional so the daemon's status builder can fall back
   * gracefully (`queueSize` + zeroed counters) against a minimal mock
   * AuditSink in tests.
   */
  getStats?(): AuditSinkStats;
}

export interface AgentIdSource {
  /** Daemon's enrolled agent id. */
  readonly agentId: string;
}

export interface DaemonStatusDeps {
  bundlePoller: BundlePoller;
  audit: AuditSinkLike;
  identity: AgentIdSource;
  /** Daemon process start time, for uptime reporting. */
  startedAt: Date;
}

export interface DaemonStatus {
  ok: boolean;
  agentId: string;
  uptimeSeconds: number;
  bundle: {
    bundleVersion: number | null;
    contentHash: string | null;
    builtAt: string | null;
    lastPullAt: string | null;
    policyCount: number;
    frozenAgentCount: number;
  };
  audit: {
    enqueued: number;
    sent: number;
    dropped4xx: number;
    dropped5xx: number;
    droppedQueueFull: number;
    queueDepth: number;
  };
}

export function buildDaemonStatus(deps: DaemonStatusDeps): DaemonStatus {
  const bundle = deps.bundlePoller.current;
  const lastPullAt = deps.bundlePoller.lastPullAt;
  const stats = readAuditStats(deps.audit);
  return {
    ok: bundle !== null && lastPullAt !== null,
    agentId: deps.identity.agentId,
    uptimeSeconds: Math.floor((Date.now() - deps.startedAt.getTime()) / 1000),
    bundle: {
      bundleVersion: bundle?.bundleVersion ?? null,
      // Truncate the hash so a leaked status response can't be replayed
      // as a `?since=` parameter — full hash isn't sensitive, but
      // there's no reason to expose more than necessary.
      contentHash: bundle ? bundle.contentHash.slice(0, HASH_PREFIX_LENGTH) : null,
      builtAt: bundle?.builtAt ?? null,
      lastPullAt: lastPullAt ? lastPullAt.toISOString() : null,
      policyCount: bundle?.policies.length ?? 0,
      frozenAgentCount: bundle?.frozenAgentIds.length ?? 0,
    },
    audit: {
      enqueued: stats.enqueued,
      sent: stats.sent,
      dropped4xx: stats.dropped4xx,
      dropped5xx: stats.dropped5xx,
      droppedQueueFull: stats.droppedQueueFull ?? 0,
      queueDepth: stats.queueDepth,
    },
  };
}

function readAuditStats(audit: AuditSinkLike): AuditSinkStats {
  if (typeof audit.getStats === 'function') {
    return audit.getStats();
  }
  return {
    enqueued: 0,
    sent: 0,
    dropped4xx: 0,
    dropped5xx: 0,
    queueDepth: audit.queueSize,
  };
}
