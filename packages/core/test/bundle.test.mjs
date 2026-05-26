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
import { createPrivateKey, sign } from 'node:crypto';

import {
  BundlePoller,
  IdentityRevokedError,
  BUNDLE_SIGNATURE_ALG,
  BUNDLE_SIGNING_KEY_ID,
  canonicalBundleBytes,
} from '../dist/index.js';

// The Ed25519 PRIVATE key matching the PUBLIC key pinned in
// `BUNDLE_SIGNING_PUBLIC_KEY_SPKI_B64`. Tests sign bundles with it so the
// poller's verifier accepts them — exactly what the real API does. Base64
// PKCS8 DER. (Test-only; the real private key lives in the API's
// BUNDLE_SIGNING_PRIVATE_KEY env var.)
const SIGNING_PRIVATE_KEY_PKCS8_B64 =
  'MC4CAQAwBQYDK2VwBCIEILsn9FgVpUlNZXYoDx9jn8pnPdjDt3o/3c0lKF0aJJqK';

const TEST_PRIVATE_KEY = createPrivateKey({
  key: Buffer.from(SIGNING_PRIVATE_KEY_PKCS8_B64, 'base64'),
  format: 'der',
  type: 'pkcs8',
});

// Attach a valid signature to a content bundle, matching the server's signer.
function signContent(content) {
  const signature = sign(null, canonicalBundleBytes(content), TEST_PRIVATE_KEY).toString('base64');
  return {
    ...content,
    signature: { signatureAlg: BUNDLE_SIGNATURE_ALG, keyId: BUNDLE_SIGNING_KEY_ID, signature },
  };
}

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
  mcpAccess = { approvedServers: [], enforce: true },
}) {
  // Sign the FULLY-populated content (every field present) exactly as the
  // server does — the API's signer always emits a complete BundleContent, so
  // the wire bytes and the verifier's post-parse bytes agree byte-for-byte.
  return signContent({ bundleVersion, contentHash, builtAt, policies, frozenAgentIds, mcpAccess });
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
    apiUrl: 'https://api.rubric-app.com',
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
    apiUrl: 'https://api.rubric-app.com',
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
    apiUrl: 'https://api.rubric-app.com',
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
    apiUrl: 'https://api.rubric-app.com',
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
    apiUrl: 'https://api.rubric-app.com',
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

// ---- Regression: poller must not die on IdentityRevokedError --------------
// A revoked/stale identity once made `_run` terminate (it `return`ed on
// IdentityRevokedError), which silently stopped polling and left the daemon
// enforcing the last cached bundle. The loop must instead keep polling and
// recover once the identity is valid again. This test fails against the old
// terminal-`return` behavior.

test('regression: IdentityRevokedError does not terminate the poll loop', async () => {
  let tokenCalls = 0;
  // First poll throws IdentityRevokedError before any fetch — exactly like a
  // dead TokenStore whose `token()` raises. Subsequent polls have recovered.
  const recoveringTokenStore = {
    token() {
      tokenCalls += 1;
      if (tokenCalls === 1) throw new IdentityRevokedError('revoked once');
      return 'recovered-token';
    },
    async forceRefresh() {},
  };

  let fetchCalls = 0;
  // 304 keeps the body-parse path out of it; a successful pull is all we need
  // to prove the loop kept running after the revoked-identity throw.
  const fetchStub = async () => {
    fetchCalls += 1;
    return jsonResponse(null, { status: 304 });
  };

  const events = { errors: [] };
  const poller = new BundlePoller({
    apiUrl: 'http://localhost:9999',
    tokenStore: recoveringTokenStore,
    onUpdate: () => {},
    onError: (e) => events.errors.push(e),
    intervalMs: 10,
    fetch: fetchStub,
  });

  poller.start();
  // firstPullDone resolves after the first (throwing) iteration.
  await poller.firstPullDone(5000);
  // Wait for a later iteration to record a successful pull.
  const deadline = Date.now() + 2000;
  while (poller.lastPullAt === null && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 10));
  }
  await poller.stop();

  // The first iteration surfaced IdentityRevokedError via onError...
  assert.ok(
    events.errors.some((e) => e instanceof IdentityRevokedError),
    'IdentityRevokedError should surface via onError',
  );
  // ...but the loop kept going: it fetched and recorded a successful pull.
  assert.ok(fetchCalls >= 1, 'poller should fetch after recovering from the revoked-identity throw');
  assert.ok(poller.lastPullAt instanceof Date, 'a successful pull should follow recovery');
  assert.ok(tokenCalls >= 2, 'token() should be called again after the first throw');
});

// ---- Bundle signature verification ----------------------------------------

test('poller accepts a correctly-signed bundle', async () => {
  const wire = mkBundleWire({ bundleVersion: 1, contentHash: VALID_HASH_A });
  const { poller, events } = await runOnePull([jsonResponse(wire, { status: 200 })]);
  assert.equal(events.updates.length, 1);
  assert.equal(poller.current.bundleVersion, 1);
  assert.equal(poller.lastRejectedBundleAt, null);
  assert.equal(events.errors.length, 0);
});

test('poller rejects a bundle with no signature', async () => {
  // A well-formed bundle with NO signature envelope. It must not pass the
  // verify gate and must never become current.
  const content = {
    bundleVersion: 1,
    contentHash: VALID_HASH_A,
    builtAt: new Date().toISOString(),
    policies: [],
    frozenAgentIds: [],
  };
  const { poller, events } = await runOnePull([jsonResponse(content, { status: 200 })]);
  assert.equal(poller.current, null, 'unsigned bundle must not become current');
  assert.equal(events.updates.length, 0);
  assert.ok(events.errors.length >= 1, 'rejection should surface via onError');
});

test('poller rejects a bundle whose content was modified after signing', async () => {
  // Sign a benign deny-all bundle, then modify the bundle after signing so the
  // signature no longer matches the canonical bytes.
  const wire = mkBundleWire({ bundleVersion: 1, contentHash: VALID_HASH_A });
  const modified = {
    ...wire,
    frozenAgentIds: ['some-agent'], // mutate a signed field; signature is now stale
  };
  const { poller, events } = await runOnePull([jsonResponse(modified, { status: 200 })]);
  assert.equal(poller.current, null, 'modified bundle must not become current');
  assert.equal(events.updates.length, 0);
  assert.ok(events.errors.length >= 1);
  assert.ok(poller.lastRejectedBundleAt instanceof Date);
  assert.match(poller.lastRejectionReason ?? '', /signature/);
});

test('poller rejects a bundle signed by a non-pinned key', async () => {
  // Re-sign with a freshly generated, unpinned keypair — a server holding some
  // other private key. Verification against the pinned public key must fail.
  const { generateKeyPairSync } = await import('node:crypto');
  const { privateKey: wrongKey } = generateKeyPairSync('ed25519');
  const content = {
    bundleVersion: 1,
    contentHash: VALID_HASH_A,
    builtAt: new Date().toISOString(),
    policies: [],
    frozenAgentIds: [],
    mcpAccess: { approvedServers: [], enforce: true },
  };
  const signature = sign(null, canonicalBundleBytes(content), wrongKey).toString('base64');
  const wire = {
    ...content,
    signature: { signatureAlg: BUNDLE_SIGNATURE_ALG, keyId: BUNDLE_SIGNING_KEY_ID, signature },
  };
  const { poller, events } = await runOnePull([jsonResponse(wire, { status: 200 })]);
  assert.equal(poller.current, null);
  assert.equal(events.updates.length, 0);
  assert.match(poller.lastRejectionReason ?? '', /signature/);
});
