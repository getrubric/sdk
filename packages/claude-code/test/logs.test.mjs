// Tests for the small pure helper in logs.ts. The streaming/filtering
// path is integration-test territory (needs a real file watch); cover
// here the bits a unit test can pin.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { parseDuration } from '../dist/cli/logs.js';

test('parseDuration: accepts s/m/h/d', () => {
  assert.equal(parseDuration('30s'), 30 * 1000);
  assert.equal(parseDuration('5m'), 5 * 60 * 1000);
  assert.equal(parseDuration('2h'), 2 * 3600 * 1000);
  assert.equal(parseDuration('1d'), 86_400 * 1000);
});

test('parseDuration: tolerates surrounding whitespace', () => {
  assert.equal(parseDuration('  10m  '), 10 * 60 * 1000);
});

test('parseDuration: rejects malformed inputs', () => {
  assert.throws(() => parseDuration(''), /invalid duration/);
  assert.throws(() => parseDuration('5'), /invalid duration/);
  assert.throws(() => parseDuration('5x'), /invalid duration/);
  assert.throws(() => parseDuration('forever'), /invalid duration/);
  assert.throws(() => parseDuration('-1m'), /invalid duration/);
});
