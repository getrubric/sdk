// API URL host + scheme enforcement. The SDK accepts only HTTPS URLs
// whose host is rubric-app.com or a subdomain of it.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { validateApiUrl } from '../dist/cli/_config.js';

test('validateApiUrl: accepts https://api.rubric-app.com', () => {
  assert.equal(validateApiUrl('https://api.rubric-app.com'), null);
});

test('validateApiUrl: accepts https://staging.rubric-app.com', () => {
  assert.equal(validateApiUrl('https://staging.rubric-app.com'), null);
});

test('validateApiUrl: accepts https://rubric-app.com (bare apex)', () => {
  assert.equal(validateApiUrl('https://rubric-app.com'), null);
});

test('validateApiUrl: accepts deep subdomain https://eu.api.rubric-app.com', () => {
  assert.equal(validateApiUrl('https://eu.api.rubric-app.com'), null);
});

// The other test files in this suite need to construct primitives against
// a local mock HTTP server, so the package.json test script sets
// RUBRIC_INTERNAL_ALLOW_LOOPBACK_FOR_TESTS=1. The next three tests verify
// the production behavior (no test-only loopback allowance), so we unset it
// for them.
function withoutLoopbackEscape(fn) {
  const before = process.env.RUBRIC_INTERNAL_ALLOW_LOOPBACK_FOR_TESTS;
  try {
    delete process.env.RUBRIC_INTERNAL_ALLOW_LOOPBACK_FOR_TESTS;
    fn();
  } finally {
    if (before !== undefined) process.env.RUBRIC_INTERNAL_ALLOW_LOOPBACK_FOR_TESTS = before;
  }
}

test('validateApiUrl: rejects http://localhost (production behavior)', () => {
  withoutLoopbackEscape(() => {
    const err = validateApiUrl('http://localhost:3001');
    assert.notEqual(err, null);
    assert.match(err, /must use https:\/\//);
  });
});

test('validateApiUrl: rejects http://127.0.0.1 (production behavior)', () => {
  withoutLoopbackEscape(() => {
    const err = validateApiUrl('http://127.0.0.1:3001');
    assert.notEqual(err, null);
    assert.match(err, /must use https:\/\//);
  });
});

test('validateApiUrl: rejects https://localhost (production behavior)', () => {
  withoutLoopbackEscape(() => {
    const err = validateApiUrl('https://localhost:3001');
    assert.notEqual(err, null);
    assert.match(err, /not a Rubric host/);
  });
});

test('test-only loopback allowance lets loopback through (internal test mode only)', () => {
  const before = process.env.RUBRIC_INTERNAL_ALLOW_LOOPBACK_FOR_TESTS;
  try {
    process.env.RUBRIC_INTERNAL_ALLOW_LOOPBACK_FOR_TESTS = '1';
    assert.equal(validateApiUrl('http://127.0.0.1:3001'), null);
    assert.equal(validateApiUrl('http://localhost:9999'), null);
  } finally {
    if (before === undefined) delete process.env.RUBRIC_INTERNAL_ALLOW_LOOPBACK_FOR_TESTS;
    else process.env.RUBRIC_INTERNAL_ALLOW_LOOPBACK_FOR_TESTS = before;
  }
});

test('validateApiUrl: rejects http://api.rubric-app.com (plaintext)', () => {
  const err = validateApiUrl('http://api.rubric-app.com');
  assert.notEqual(err, null);
  assert.match(err, /must use https:\/\//);
});

test('validateApiUrl: rejects third-party hosts', () => {
  const err = validateApiUrl('https://evil.example.com');
  assert.notEqual(err, null);
  assert.match(err, /not a Rubric host/);
});

test('validateApiUrl: rejects lookalike hosts (suffix-without-dot)', () => {
  // `lookalike-rubric-app.com` contains `rubric-app.com` as a suffix
  // but is NOT a subdomain. The dot prefix is load-bearing here.
  const err = validateApiUrl('https://lookalike-rubric-app.com');
  assert.notEqual(err, null);
  assert.match(err, /not a Rubric host/);
});

test('validateApiUrl: rejects garbage URLs', () => {
  assert.match(validateApiUrl('not-a-url'), /not a valid URL/);
});

test('validateApiUrl: rejects ftp://', () => {
  assert.match(validateApiUrl('ftp://rubric-app.com'), /must use https:\/\//);
});
