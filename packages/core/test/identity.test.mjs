// Tests for TokenStore:
//   - refresh loop with NaN/non-finite expiresAt does not hot-spin and
//     emits a warning.
//   - ZodError on a malformed token response is scrubbed before being
//     re-thrown as GovernanceError.
//   - HTTP error bodies are scrubbed before interpolation into the
//     GovernanceError message.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { TokenStore, GovernanceError, IdentityRevokedError } from '../dist/index.js';

// ---- NaN/non-finite sleep guard -------------------------------------------

test('refresh loop does not hot-spin on unparseable expiresAt and emits a warn', async () => {
  const warns = [];
  let refreshAttempts = 0;
  // fake fetch returns refresh OK with a deliberately bad expiresAt so
  // parseIsoToEpoch yields NaN.
  const fakeFetch = async () => {
    refreshAttempts++;
    return new Response(
      JSON.stringify({
        token: 'fresh-jwt',
        expiresAt: 'not-a-valid-iso-string',
        agentId: 'agent-test',
        identityId: '00000000-0000-0000-0000-000000000000',
      }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    );
  };
  const store = new TokenStore({
    apiUrl: 'http://test.invalid',
    fetch: fakeFetch,
    onWarn: (m) => warns.push(m),
  });
  // Seed the store as if it had been enrolled.
  store._token = 'initial-jwt';
  store._agentId = 'agent-test';
  store._identityId = '00000000-0000-0000-0000-000000000000';
  store._expiresAtEpoch = NaN; // <-- the trigger condition under test

  store.startRefreshLoop();
  // Sleep ~50ms — if the NaN guard is broken, setTimeout(_, NaN) fires every
  // 1ms and refreshAttempts would climb into the dozens.
  await new Promise((r) => setTimeout(r, 50));
  await store.stop();

  assert.ok(warns.length >= 1, 'expected at least one onWarn call for non-finite sleep');
  assert.match(warns[0], /non-finite|unparseable|expiresAt/i);
  // Without the guard, we'd see 30-50+ attempts. With the 30s fallback, zero.
  assert.ok(
    refreshAttempts < 3,
    `refresh hot-spun ${refreshAttempts} times in 50ms — NaN guard regressed`,
  );
});

// ---- ZodError on malformed token response is scrubbed --------------------

test('malformed token response with secret-shaped key is wrapped + scrubbed', async () => {
  // Server returns JSON that fails SdkTokenResponseSchema. zod's error
  // message includes the unrecognized key (and in some cases the value).
  // We embed an obvious Bearer to confirm it's redacted.
  const fakeFetch = async () =>
    new Response(
      JSON.stringify({
        token: 'eyJabc.eyJdef.signature_part_that_is_long_enough',
        // expiresAt missing → zod fails
        agentId: 'agent-test',
        identityId: '00000000-0000-0000-0000-000000000000',
        extra_field_with_secret: 'Bearer abcdef1234567890abcdef',
      }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    );
  const store = new TokenStore({ apiUrl: 'http://test.invalid', fetch: fakeFetch });

  await assert.rejects(
    () => store.initialEnrollment('enr_test', 'agent-test'),
    (err) => {
      assert.ok(err instanceof GovernanceError);
      assert.ok(!err.message.includes('eyJabc.eyJdef.signature_part_that_is_long_enough'));
      assert.ok(!err.message.includes('abcdef1234567890abcdef'));
      return true;
    },
  );
});

// ---- HTTP error body is scrubbed ------------------------------------------

test('5xx response body with embedded JWT is scrubbed in the thrown message', async () => {
  const leakingJwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4eHgifQ.abcdefghijklmnopqrstuvwxyz';
  const fakeFetch = async () =>
    new Response(`internal error; offending request body: ${leakingJwt}`, { status: 500 });
  const store = new TokenStore({ apiUrl: 'http://test.invalid', fetch: fakeFetch });

  await assert.rejects(
    () => store.initialEnrollment('enr_test', 'agent-test'),
    (err) => {
      assert.ok(err instanceof GovernanceError);
      assert.ok(
        !err.message.includes(leakingJwt),
        `JWT leaked into error message: ${err.message}`,
      );
      assert.match(err.message, /<redacted/);
      return true;
    },
  );
});

test('401 refresh failure with embedded token in problem detail is scrubbed', async () => {
  const leakingToken = 'a'.repeat(64);
  const fakeFetch = async () =>
    new Response(
      JSON.stringify({
        type: 'about:blank',
        title: 'unauthorized',
        status: 401,
        detail: `presented invalid token: ${leakingToken}`,
      }),
      { status: 401, headers: { 'content-type': 'application/problem+json' } },
    );
  const store = new TokenStore({ apiUrl: 'http://test.invalid', fetch: fakeFetch });
  store._token = 'old-jwt';

  await assert.rejects(
    () => store.forceRefresh(),
    (err) => {
      assert.ok(err instanceof IdentityRevokedError);
      assert.ok(!err.message.includes(leakingToken));
      return true;
    },
  );
});
