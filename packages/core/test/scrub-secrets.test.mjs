// Tests for `scrubSecrets` in `_internal.ts`. The helper is internal-only
// (not exported from `index.js`), so we import from the built `_internal.js`
// module directly. Each pattern gets a positive case (must redact) and a
// negative case (must NOT touch).

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { scrubSecrets } from '../dist/_internal.js';

// ---- JWT --------------------------------------------------------------------

test('JWT — three-part dotted token gets collapsed into <redacted:jwt>', () => {
  const jwt =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  const out = scrubSecrets(`refresh failed (500): ${jwt}`);
  assert.match(out, /<redacted:jwt>/);
  assert.ok(!out.includes(jwt), 'raw JWT must not appear in output');
});

test('JWT — multiple JWTs in one string each get redacted', () => {
  const j1 = 'eyJabc.eyJdef.sig1';
  const j2 = 'eyJghi.eyJjkl.sig2';
  const out = scrubSecrets(`first ${j1} and second ${j2}`);
  assert.ok(!out.includes(j1));
  assert.ok(!out.includes(j2));
});

test('JWT — negative: plain text without dot-triplet is untouched', () => {
  const s = 'hello world, no secret here';
  assert.equal(scrubSecrets(s), s);
});

// ---- Bearer headers ---------------------------------------------------------

test('Bearer — preserves literal `Bearer` prefix, redacts payload', () => {
  const s = 'Authorization: Bearer abcdef1234567890abcdef';
  const out = scrubSecrets(s);
  assert.match(out, /Bearer <redacted>/);
  assert.ok(!out.includes('abcdef1234567890abcdef'));
});

test('Bearer — short tokens (<16 chars) are NOT matched by the Bearer rule', () => {
  // The base64ish catch-all may still hit if ≥24 chars; this token is short.
  const s = 'Bearer short';
  const out = scrubSecrets(s);
  assert.ok(out.includes('Bearer'));
  // "short" is 5 chars, below the base64ish floor — should pass through.
  assert.ok(out.includes('short'));
});

// ---- 64-char hex (daemon token shape) ---------------------------------------

test('hex64 — exact 64 lowercase-hex string is redacted', () => {
  const tok = 'a'.repeat(64);
  const out = scrubSecrets(`daemon token: ${tok}`);
  assert.match(out, /<redacted:hex64>/);
  assert.ok(!out.includes(tok));
});

test('hex64 — 63-char hex is NOT redacted as hex64 (but may hit base64ish)', () => {
  const tok = 'a'.repeat(63);
  const out = scrubSecrets(`x: ${tok}`);
  // Below the 64 threshold for hex64; but ≥24 → base64ish catch-all fires.
  assert.ok(!out.includes(tok), '63-char run still hits base64ish catch-all');
  assert.match(out, /<redacted:blob>/);
});

test('hex64 — content-hash-shaped 64-hex inside a larger string', () => {
  const hash = 'deadbeef'.repeat(8); // 64 chars
  const out = scrubSecrets(`bundle contentHash=${hash} verified`);
  assert.ok(!out.includes(hash));
});

// ---- base64-ish blob --------------------------------------------------------

test('base64ish — ≥24 char run gets redacted', () => {
  const blob = 'A'.repeat(30);
  const out = scrubSecrets(`opaque: ${blob}`);
  assert.match(out, /<redacted:blob>/);
});

test('base64ish — 23-char run is below the floor and passes through', () => {
  const blob = 'A'.repeat(23);
  const out = scrubSecrets(`opaque: ${blob}`);
  assert.ok(out.includes(blob));
});

// ---- Provider-shape secrets -------------------------------------------------

test('provider — OpenAI sk- key redacted', () => {
  const k = 'sk-' + 'A'.repeat(40);
  const out = scrubSecrets(`key: ${k}`);
  assert.ok(!out.includes(k));
});

test('provider — GitHub ghp_ key redacted', () => {
  const k = 'ghp_' + 'B'.repeat(30);
  const out = scrubSecrets(`token: ${k}`);
  assert.ok(!out.includes(k));
});

test('provider — Slack xoxb-/xoxp- token redacted', () => {
  const k1 = 'xoxb-' + '1'.repeat(40);
  const k2 = 'xoxp-' + '2'.repeat(40);
  assert.ok(!scrubSecrets(k1).includes(k1));
  assert.ok(!scrubSecrets(k2).includes(k2));
});

test('provider — AWS AKIA key redacted', () => {
  const k = 'AKIA' + 'A'.repeat(16);
  const out = scrubSecrets(`aws: ${k}`);
  assert.ok(!out.includes(k));
});

test('provider — Rubric enr_ enrollment token redacted', () => {
  const k = 'enr_abc123_xyz-ABCDEF';
  const out = scrubSecrets(`enrollment: ${k}`);
  assert.ok(!out.includes(k));
});

test('provider — negative: words starting with sk- but with too few suffix chars', () => {
  // `sk-Aa` is 5 chars — needs ≥20 suffix to match. Pass-through.
  const s = 'sk-Aa is short';
  const out = scrubSecrets(s);
  assert.ok(out.includes('sk-Aa'));
});

// ---- Postgres URL with embedded credentials --------------------------------

test('postgres URL — embedded user:pass is redacted, scheme/host preserved', () => {
  const url = 'postgres://alice:s3cret@db.internal:5432/prod';
  const out = scrubSecrets(`could not connect: ${url}`);
  assert.ok(out.includes('postgres://<redacted>@'));
  assert.ok(!out.includes('alice:s3cret'));
});

test('postgresql:// scheme also handled', () => {
  const url = 'postgresql://bob:hunter2@host/db';
  const out = scrubSecrets(url);
  assert.match(out, /postgresql:\/\/<redacted>@/);
});

test('postgres URL — negative: no creds means no postgres-specific redaction', () => {
  // The host part is short enough to not trigger base64ish.
  const s = 'postgres://db.internal/prod';
  const out = scrubSecrets(s);
  assert.ok(out.includes('postgres://db.internal/prod'));
});

// ---- Idempotency / safety ---------------------------------------------------

test('empty string is returned unchanged', () => {
  assert.equal(scrubSecrets(''), '');
});

test('running scrubSecrets twice on its own output is stable', () => {
  const s = 'Bearer abcdef1234567890abcdef and ' + 'a'.repeat(64);
  const once = scrubSecrets(s);
  const twice = scrubSecrets(once);
  assert.equal(once, twice);
});

test('scrubSecrets does not crash on weird unicode', () => {
  const s = 'token=🔑 eyJabc.eyJdef.sig 🦀';
  const out = scrubSecrets(s);
  assert.match(out, /<redacted:jwt>/);
  // Emoji preserved.
  assert.ok(out.includes('🔑'));
  assert.ok(out.includes('🦀'));
});
