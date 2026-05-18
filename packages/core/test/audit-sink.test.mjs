// Tests for AuditSink:
//   - every enqueued event gets a UUID `eventId` stamped into metadata.
//   - getStats() counters increment correctly on each event class.
//   - 4xx error messages pass through scrubSecrets — a Bearer header in
//     the server's problem-details body does not ride out into onError.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { AuditSink, TokenStore } from '../dist/index.js';

const UUID_V4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function mkEvent(overrides = {}) {
  return {
    agentId: 'agent-test',
    sessionId: 'sess-test',
    ts: new Date().toISOString(),
    toolName: 'Bash',
    decision: 'allow',
    policyId: null,
    policyVersion: null,
    latencyMs: 1,
    ...overrides,
  };
}

// Minimal in-memory TokenStore stub. We construct a real TokenStore and
// fake out `token()` to avoid the enrollment flow.
function mkFakeTokenStore() {
  const store = new TokenStore({ apiUrl: 'http://test.invalid' });
  // Cheat past the IdentityNotInitialized guard. Internal-field
  // access is fine inside the package's own test suite.
  store._token = 'fake-jwt';
  store._agentId = 'agent-test';
  store._identityId = '00000000-0000-0000-0000-000000000000';
  store._expiresAtEpoch = Date.now() / 1000 + 3600;
  return store;
}

// ---- eventId stamping -----------------------------------------------------

test('enqueue stamps a UUID-shaped eventId into metadata', () => {
  const sink = new AuditSink({ apiUrl: 'http://test.invalid', tokenStore: mkFakeTokenStore() });
  sink.enqueue(mkEvent());
  // Pop via internal queue to verify the stamped shape.
  const queued = sink._queue[0];
  assert.ok(queued.metadata && typeof queued.metadata === 'object');
  assert.match(queued.metadata.eventId, UUID_V4_RE);
});

test('existing metadata is preserved alongside the eventId', () => {
  const sink = new AuditSink({ apiUrl: 'http://test.invalid', tokenStore: mkFakeTokenStore() });
  sink.enqueue(mkEvent({ metadata: { tool_input: { cmd: 'ls' }, custom: 42 } }));
  const queued = sink._queue[0];
  assert.deepEqual(queued.metadata.tool_input, { cmd: 'ls' });
  assert.equal(queued.metadata.custom, 42);
  assert.match(queued.metadata.eventId, UUID_V4_RE);
});

test('every enqueue gets a fresh eventId', () => {
  const sink = new AuditSink({ apiUrl: 'http://test.invalid', tokenStore: mkFakeTokenStore() });
  sink.enqueue(mkEvent());
  sink.enqueue(mkEvent());
  sink.enqueue(mkEvent());
  const ids = sink._queue.map((e) => e.metadata.eventId);
  assert.equal(new Set(ids).size, 3);
});

// ---- counters -------------------------------------------------------------

test('getStats initially zero with empty queue', () => {
  const sink = new AuditSink({ apiUrl: 'http://test.invalid', tokenStore: mkFakeTokenStore() });
  const s = sink.getStats();
  assert.equal(s.enqueued, 0);
  assert.equal(s.sent, 0);
  assert.equal(s.dropped4xx, 0);
  assert.equal(s.dropped5xx, 0);
  assert.equal(s.droppedQueueFull, 0);
  assert.equal(s.queueDepth, 0);
});

test('enqueued increments per call; queueDepth tracks live queue', () => {
  const sink = new AuditSink({ apiUrl: 'http://test.invalid', tokenStore: mkFakeTokenStore() });
  sink.enqueue(mkEvent());
  sink.enqueue(mkEvent());
  const s = sink.getStats();
  assert.equal(s.enqueued, 2);
  assert.equal(s.queueDepth, 2);
});

test('droppedQueueFull increments when queue at maxQueue', () => {
  const sink = new AuditSink({
    apiUrl: 'http://test.invalid',
    tokenStore: mkFakeTokenStore(),
    maxQueue: 2,
  });
  sink.enqueue(mkEvent());
  sink.enqueue(mkEvent());
  sink.enqueue(mkEvent()); // dropped
  sink.enqueue(mkEvent()); // dropped
  const s = sink.getStats();
  assert.equal(s.enqueued, 2);
  assert.equal(s.droppedQueueFull, 2);
});

test('4xx flush increments dropped4xx by batch size', async () => {
  // Fake fetch that returns 400 with a problem+json body.
  const fakeFetch = async () =>
    new Response(JSON.stringify({ type: 'about:blank', title: 'bad', status: 400 }), {
      status: 400,
      headers: { 'content-type': 'application/problem+json' },
    });
  const errors = [];
  const sink = new AuditSink({
    apiUrl: 'http://test.invalid',
    tokenStore: mkFakeTokenStore(),
    fetch: fakeFetch,
    onError: (e) => errors.push(e),
  });
  sink.enqueue(mkEvent());
  sink.enqueue(mkEvent());
  sink.enqueue(mkEvent());
  // Drive a flush directly.
  await sink._flush(sink._queue.splice(0, 100));
  const s = sink.getStats();
  assert.equal(s.dropped4xx, 3);
  assert.equal(s.sent, 0);
  assert.equal(errors.length, 1, 'one onError call for the 4xx drop');
});

test('sent counter increments by batch size on 202', async () => {
  const fakeFetch = async () => new Response('', { status: 202 });
  const sink = new AuditSink({
    apiUrl: 'http://test.invalid',
    tokenStore: mkFakeTokenStore(),
    fetch: fakeFetch,
  });
  sink.enqueue(mkEvent());
  sink.enqueue(mkEvent());
  await sink._flush(sink._queue.splice(0, 100));
  const s = sink.getStats();
  assert.equal(s.sent, 2);
  assert.equal(s.dropped4xx, 0);
});

// ---- 4xx error message is scrubbed ----------------------------------------

test('4xx problem detail with a Bearer token in it is scrubbed before onError', async () => {
  const leakingDetail =
    'request rejected; payload echo: Authorization: Bearer abcdef1234567890abcdef1234';
  const fakeFetch = async () =>
    new Response(
      JSON.stringify({
        type: 'about:blank',
        title: 'rejected',
        status: 400,
        detail: leakingDetail,
      }),
      { status: 400, headers: { 'content-type': 'application/problem+json' } },
    );
  const errors = [];
  const sink = new AuditSink({
    apiUrl: 'http://test.invalid',
    tokenStore: mkFakeTokenStore(),
    fetch: fakeFetch,
    onError: (e) => errors.push(e),
  });
  sink.enqueue(mkEvent());
  await sink._flush(sink._queue.splice(0, 100));
  assert.equal(errors.length, 1);
  const msg = errors[0].message;
  assert.ok(!msg.includes('abcdef1234567890abcdef1234'), `raw token leaked: ${msg}`);
  assert.match(msg, /Bearer <redacted>/);
});
