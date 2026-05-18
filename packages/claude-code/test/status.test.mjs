// Tests for buildDaemonStatus — pure function over poller/sink/identity
// proxies. We stub each upstream so we can drive every branch (no
// bundle, fresh bundle, stale bundle).

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { buildDaemonStatus } from '../dist/daemon/status.js';

const FAKE_BUNDLE = {
  bundleVersion: 7,
  contentHash: 'a'.repeat(64),
  builtAt: '2026-05-15T11:59:00.000Z',
  policies: [{}, {}, {}],
  frozenAgentIds: ['x', 'y'],
};

function poller({ current, lastPullAt } = {}) {
  return { current: current ?? null, lastPullAt: lastPullAt ?? null };
}
function sink({ queueSize } = {}) {
  return { queueSize: queueSize ?? 0 };
}
const IDENTITY = { agentId: 'agent-abc' };

test('buildDaemonStatus: no bundle yet → ok=false, null bundle fields', () => {
  const status = buildDaemonStatus({
    bundlePoller: poller(),
    audit: sink(),
    identity: IDENTITY,
    startedAt: new Date(Date.now() - 1500),
  });
  assert.equal(status.ok, false);
  assert.equal(status.agentId, 'agent-abc');
  assert.ok(status.uptimeSeconds >= 1);
  assert.equal(status.bundle.bundleVersion, null);
  assert.equal(status.bundle.contentHash, null);
  assert.equal(status.bundle.builtAt, null);
  assert.equal(status.bundle.lastPullAt, null);
  assert.equal(status.bundle.policyCount, 0);
  assert.equal(status.bundle.frozenAgentCount, 0);
});

test('buildDaemonStatus: bundle present → ok=true, hash truncated, counts populated', () => {
  const pulled = new Date('2026-05-15T12:00:00.000Z');
  const status = buildDaemonStatus({
    bundlePoller: poller({ current: FAKE_BUNDLE, lastPullAt: pulled }),
    audit: sink({ queueSize: 4 }),
    identity: IDENTITY,
    startedAt: new Date(Date.now() - 30_000),
  });
  assert.equal(status.ok, true);
  assert.equal(status.bundle.bundleVersion, 7);
  // Truncated to 12 chars.
  assert.equal(status.bundle.contentHash, 'aaaaaaaaaaaa');
  assert.equal(status.bundle.builtAt, '2026-05-15T11:59:00.000Z');
  assert.equal(status.bundle.lastPullAt, '2026-05-15T12:00:00.000Z');
  assert.equal(status.bundle.policyCount, 3);
  assert.equal(status.bundle.frozenAgentCount, 2);
  assert.equal(status.audit.queueDepth, 4);
});

test('buildDaemonStatus: surfaces AuditSink.getStats() when present', () => {
  const stats = {
    enqueued: 42,
    sent: 38,
    dropped4xx: 3,
    dropped5xx: 1,
    droppedQueueFull: 2,
    queueDepth: 0,
  };
  const status = buildDaemonStatus({
    bundlePoller: poller({
      current: FAKE_BUNDLE,
      lastPullAt: new Date('2026-05-15T12:00:00.000Z'),
    }),
    audit: { queueSize: 0, getStats: () => stats },
    identity: IDENTITY,
    startedAt: new Date(),
  });
  assert.deepEqual(status.audit, stats);
});

test('buildDaemonStatus: falls back to queueSize when getStats absent', () => {
  const status = buildDaemonStatus({
    bundlePoller: poller({
      current: FAKE_BUNDLE,
      lastPullAt: new Date('2026-05-15T12:00:00.000Z'),
    }),
    audit: sink({ queueSize: 7 }),
    identity: IDENTITY,
    startedAt: new Date(),
  });
  assert.equal(status.audit.queueDepth, 7);
  assert.equal(status.audit.enqueued, 0);
  assert.equal(status.audit.sent, 0);
  assert.equal(status.audit.dropped4xx, 0);
  assert.equal(status.audit.dropped5xx, 0);
  assert.equal(status.audit.droppedQueueFull, 0);
});

test('buildDaemonStatus: bundle but no lastPullAt → ok=false (defensive)', () => {
  // Shouldn't happen with the real BundlePoller (it sets both atomically),
  // but the schema permits the combination — assert we report the right
  // ok flag.
  const status = buildDaemonStatus({
    bundlePoller: poller({ current: FAKE_BUNDLE, lastPullAt: null }),
    audit: sink(),
    identity: IDENTITY,
    startedAt: new Date(),
  });
  assert.equal(status.ok, false);
});
