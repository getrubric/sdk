// Auth tests. Covers the hex64 shape check on both presented and
// expected tokens, the case-insensitive Bearer scheme, empty-token
// rejection, and the array-valued Authorization-header rejection.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { checkBearer } from '../dist/daemon/auth.js';

const TOKEN = '0123456789abcdef'.repeat(4); // 64 hex chars

test('checkBearer: missing header → false', () => {
  assert.equal(checkBearer(undefined, TOKEN), false);
});

test('checkBearer: array-valued header → false', () => {
  assert.equal(checkBearer([`Bearer ${TOKEN}`, `Bearer ${TOKEN}`], TOKEN), false);
});

test('checkBearer: empty expectedToken → false', () => {
  assert.equal(checkBearer(`Bearer ${TOKEN}`, ''), false);
});

test('checkBearer: malformed expectedToken (non-hex) → false', () => {
  assert.equal(checkBearer(`Bearer ${TOKEN}`, 'G'.repeat(64)), false);
});

test('checkBearer: case-insensitive Bearer scheme', () => {
  for (const scheme of ['Bearer ', 'bearer ', 'BEARER ', 'BeArEr\t']) {
    assert.equal(checkBearer(`${scheme}${TOKEN}`, TOKEN), true, `scheme: ${scheme}`);
  }
});

test('checkBearer: non-hex64 presented token → false', () => {
  for (const presented of ['', 'short', 'G'.repeat(64), TOKEN.toUpperCase(), TOKEN + 'x']) {
    assert.equal(checkBearer(`Bearer ${presented}`, TOKEN), false, `presented: ${presented}`);
  }
});

test('checkBearer: wrong-but-valid-shape token → false', () => {
  assert.equal(checkBearer(`Bearer ${'f'.repeat(64)}`, TOKEN), false);
});

test('checkBearer: correct token → true', () => {
  assert.equal(checkBearer(`Bearer ${TOKEN}`, TOKEN), true);
});

test('checkBearer: no scheme prefix → false', () => {
  assert.equal(checkBearer(TOKEN, TOKEN), false);
});
