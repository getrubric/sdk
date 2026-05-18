// HTTPS enforcement for non-loopback API URLs.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { validateApiUrl } from '../dist/cli/_config.js';

test('validateApiUrl: accepts http://localhost (loopback)', () => {
  assert.equal(validateApiUrl('http://localhost:3001'), null);
});

test('validateApiUrl: accepts http://127.0.0.1 (loopback)', () => {
  assert.equal(validateApiUrl('http://127.0.0.1:3001'), null);
});

test('validateApiUrl: accepts http://[::1]/ (loopback)', () => {
  assert.equal(validateApiUrl('http://[::1]:3001'), null);
});

test('validateApiUrl: accepts https://api.rubric.io (TLS)', () => {
  assert.equal(validateApiUrl('https://api.rubric.io'), null);
});

test('validateApiUrl: rejects http://example.com (non-loopback http)', () => {
  const err = validateApiUrl('http://example.com');
  assert.notEqual(err, null);
  assert.match(err, /https:\/\/ required/);
  assert.match(err, /RUBRIC_INSECURE_HTTP/);
});

test('validateApiUrl: rejects http://attacker.example.com', () => {
  assert.notEqual(validateApiUrl('http://attacker.example.com'), null);
});

test('validateApiUrl: rejects garbage URLs', () => {
  assert.match(validateApiUrl('not-a-url'), /not a valid URL/);
  assert.match(validateApiUrl('ftp://example.com'), /http:\/\/ or https:\/\//);
});

test('validateApiUrl: RUBRIC_INSECURE_HTTP=1 lets non-loopback http through', () => {
  const before = process.env.RUBRIC_INSECURE_HTTP;
  try {
    process.env.RUBRIC_INSECURE_HTTP = '1';
    assert.equal(validateApiUrl('http://example.com'), null);
  } finally {
    if (before === undefined) delete process.env.RUBRIC_INSECURE_HTTP;
    else process.env.RUBRIC_INSECURE_HTTP = before;
  }
});

test('validateApiUrl: RUBRIC_INSECURE_HTTP=0 does not bypass', () => {
  const before = process.env.RUBRIC_INSECURE_HTTP;
  try {
    process.env.RUBRIC_INSECURE_HTTP = '0';
    assert.notEqual(validateApiUrl('http://example.com'), null);
  } finally {
    if (before === undefined) delete process.env.RUBRIC_INSECURE_HTTP;
    else process.env.RUBRIC_INSECURE_HTTP = before;
  }
});
