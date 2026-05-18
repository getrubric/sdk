// Tests for BundlePoller — bundle monotonicity rejection and the
// distinction between lastPullAt and lastBundleChangeAt.
//
// We exercise the poller end-to-end with an injected fetch stub. This is
// closer to integration than unit-style, but the poller's loop body is
// what we actually need to harden — testing _pullOnce in isolation would
// require either exposing it (we won't) or duplicating most of the loop
// in the test harness.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { BundlePoller } from '../dist/index.js';

const VALID_HASH_A = 'a'.repeat(64);
const VALID_HASH_B = 'b'.repeat(64);
const VALID_HASH_C = 'c'.repeat(64);

// A minimal valid PolicyDocument so the bundle passes zod parse.
const SAMPLE_POLICY = {
  apiVersion: 'agent-governance.io/v1',
  kind: 'Policy',
  metadata: { name: 'sample' },
  spec: {
    defaultEffect: 'deny',
    rules: [
      {
        id: 'r1',
        conditions: [{ field: 'tool_name', operator: 'eq', value: 'echo' }],
        effect: 'allow',
      },
    ],
  },
};

function mkBundleWire({
  bundleVersion,
  contentHash,
  builtAt = new Date().toISOString(),
  policies = [
    {
      policyId: '11111111-1111-1111-1111-111111111111',
      policyVersion: 1,
      document: SAMPLE_POLICY,
    },
  ],
  frozenAgentIds = [],
}) {
  return { bundleVersion, contentHash, builtAt, policies, frozenAgentIds };
}

// A simple JSON-returning Response-like object suitable for fetch stubbing.
function jsonResponse(body, init = {}) {
  return {
    ok: (init.status ?? 200) >= 200 && (init.status ?? 200) < 300,
    status: init.status ?? 200,
    statusText: init.statusText ?? 'OK',
    headers: new Map(),
    body: null,
    clone() {
      return jsonResponse(body, init);
    },
    json: async () => body,
    text: async () => JSON.stringify(body),
  };
}

// A no-op token store stub with the surface BundlePoller needs.
function stubTokenStore() {
  return {
    token: () => 'stub-token',
    async forceRefresh() {},
  };
}

// Drive the poller by directly invoking the fetch stub once via start()
// then stop()ping. We rely on `firstPullDone` to know the first iteration
// completed.
async function runOnePull(responses, opts = {}) {
  const calls = [];
  let i = 0;
  const fetchStub = async (url, init) => {
    calls.push({ url, init });
    if (i >= responses.length) {
      // Loop iterations beyond the first should not happen in these tests
      // because we stop() right after firstPullDone. Hand back a 304 just
      // in case timing introduces a second call.
      return jsonResponse(null, { status: 304 });
    }
    return responses[i++];
  };
  const events = { updates: [], errors: [] };
  const poller = new BundlePoller({
    apiUrl: 'http://localhost:9999',
    tokenStore: stubTokenStore(),
    onUpdate: (b) => {
      events.updates.push(b);
    },
    onError: (e) => {
      events.errors.push(e);
    },
    intervalMs: 1_000_000, // never tick a second iteration during the test
    fetch: fetchStub,
    ...opts,
  });
  poller.start();
  await poller.firstPullDone(5000);
  await poller.stop();
  return { poller, calls, events };
}

// ---- lastBundleChangeAt distinct from lastPullAt --------------------------

test('lastBundleChangeAt is set on first successful bundle pull', async () => {
  const wire = mkBundleWire({ bundleVersion: 1, contentHash: VALID_HASH_A });
  const { poller, events } = await runOnePull([jsonResponse(wire, { status: 200 })]);
  assert.equal(events.updates.length, 1);
  assert.ok(poller.lastPullAt instanceof Date);
  assert.ok(poller.lastBundleChangeAt instanceof Date);
  // Both timestamps are taken on the same pull and should be within a few ms.
  assert.ok(
    Math.abs(poller.lastPullAt.getTime() - poller.lastBundleChangeAt.getTime()) < 100,
  );
});

test('BundlePoller exposes lastPullAt and lastBundleChangeAt as getters', () => {
  // Surface check — the daemon's /v1/status endpoint reads both names.
  const poller = new BundlePoller({
    apiUrl: 'http://localhost:9999',
    tokenStore: stubTokenStore(),
    onUpdate: () => {},
    fetch: async () => jsonResponse(null, { status: 304 }),
  });
  assert.equal(poller.lastPullAt, null);
  assert.equal(poller.lastBundleChangeAt, null);
  assert.equal(poller.lastRejectedBundleAt, null);
  assert.equal(poller.lastRejectionReason, null);
});

// ---- bundle monotonicity --------------------------------------------------

test('poller rejects an incoming bundle with a lower bundleVersion', async () => {
  // Wire up two sequential responses on a single fetchStub via a closure
  // shared with two pollers — simpler to construct two pollers that share
  // state. Cleanest path: drive one poller with a fetch that returns
  // v2 first, then on the *second* `firstPullDone` we'd need a second tick.
  // We instead use one poller, accept the first bundle (v2), then drive a
  // manual second pull by toggling the response queue and waiting a tick.
  const responses = [
    jsonResponse(mkBundleWire({ bundleVersion: 2, contentHash: VALID_HASH_B }), { status: 200 }),
    jsonResponse(
      mkBundleWire({ bundleVersion: 1, contentHash: VALID_HASH_A }),
      { status: 200 },
    ),
  ];
  let i = 0;
  const fetchStub = async () =>
    i < responses.length ? responses[i++] : jsonResponse(null, { status: 304 });
  const events = { updates: [], errors: [] };
  const poller = new BundlePoller({
    apiUrl: 'http://localhost:9999',
    tokenStore: stubTokenStore(),
    onUpdate: (b) => events.updates.push(b),
    onError: (e) => events.errors.push(e),
    intervalMs: 10, // fast tick so the second pull happens promptly
    fetch: fetchStub,
  });
  poller.start();
  await poller.firstPullDone(5000);
  // Wait long enough for the second tick to land.
  await new Promise((r) => setTimeout(r, 80));
  await poller.stop();

  // Only the first bundle (v2) was accepted; the second (v1) was rejected.
  assert.equal(events.updates.length, 1);
  assert.equal(events.updates[0].bundleVersion, 2);
  assert.equal(poller.current.bundleVersion, 2);
  // The rejection surfaced via onError with a recognisable reason and
  // populated the lastRejection* fields.
  assert.ok(events.errors.length >= 1);
  assert.ok(poller.lastRejectedBundleAt instanceof Date);
  assert.match(poller.lastRejectionReason ?? '', /bundleVersion 1/);
});

test('poller rejects an incoming bundle with a much older builtAt', async () => {
  const now = Date.now();
  const cachedBuiltAt = new Date(now).toISOString();
  // 10 minutes earlier — well past the 5-minute skew tolerance.
  const olderBuiltAt = new Date(now - 10 * 60_000).toISOString();
  const responses = [
    jsonResponse(
      mkBundleWire({ bundleVersion: 1, contentHash: VALID_HASH_A, builtAt: cachedBuiltAt }),
      { status: 200 },
    ),
    jsonResponse(
      // Same bundleVersion, NEW contentHash so the dedupe doesn't swallow it,
      // but builtAt is from a previous era — a stale-bundle shape.
      mkBundleWire({ bundleVersion: 1, contentHash: VALID_HASH_C, builtAt: olderBuiltAt }),
      { status: 200 },
    ),
  ];
  let i = 0;
  const fetchStub = async () =>
    i < responses.length ? responses[i++] : jsonResponse(null, { status: 304 });
  const events = { updates: [], errors: [] };
  const poller = new BundlePoller({
    apiUrl: 'http://localhost:9999',
    tokenStore: stubTokenStore(),
    onUpdate: (b) => events.updates.push(b),
    onError: (e) => events.errors.push(e),
    intervalMs: 10,
    fetch: fetchStub,
  });
  poller.start();
  await poller.firstPullDone(5000);
  await new Promise((r) => setTimeout(r, 80));
  await poller.stop();

  assert.equal(events.updates.length, 1);
  assert.equal(poller.current.contentHash, VALID_HASH_A);
  assert.ok(poller.lastRejectedBundleAt instanceof Date);
  assert.match(poller.lastRejectionReason ?? '', /builtAt/);
});

test('poller accepts a newer bundleVersion even with the same contentHash treatment', async () => {
  // Sanity: monotonicity allows strictly-greater versions.
  const responses = [
    jsonResponse(mkBundleWire({ bundleVersion: 1, contentHash: VALID_HASH_A }), { status: 200 }),
    jsonResponse(mkBundleWire({ bundleVersion: 2, contentHash: VALID_HASH_B }), { status: 200 }),
  ];
  let i = 0;
  const fetchStub = async () =>
    i < responses.length ? responses[i++] : jsonResponse(null, { status: 304 });
  const events = { updates: [], errors: [] };
  const poller = new BundlePoller({
    apiUrl: 'http://localhost:9999',
    tokenStore: stubTokenStore(),
    onUpdate: (b) => events.updates.push(b),
    onError: (e) => events.errors.push(e),
    intervalMs: 10,
    fetch: fetchStub,
  });
  poller.start();
  await poller.firstPullDone(5000);
  await new Promise((r) => setTimeout(r, 80));
  await poller.stop();

  assert.equal(events.updates.length, 2);
  assert.equal(events.updates[1].bundleVersion, 2);
  assert.equal(poller.current.bundleVersion, 2);
  assert.equal(poller.lastRejectedBundleAt, null);
});
