// Telemetry must be opt-out-able and strictly counts-only — never carry tool
// content.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import {
  Telemetry,
  loadOrCreateInstallId,
  telemetryEnabled,
} from '../dist/daemon/telemetry.js';

test('telemetryEnabled honors the config flag and RUBRIC_TELEMETRY=0', () => {
  delete process.env.RUBRIC_TELEMETRY;
  assert.equal(telemetryEnabled(), true);
  assert.equal(telemetryEnabled(false), false);
  process.env.RUBRIC_TELEMETRY = '0';
  assert.equal(telemetryEnabled(), false);
  assert.equal(telemetryEnabled(true), false);
  delete process.env.RUBRIC_TELEMETRY;
});

test('disabled telemetry never calls fetch', () => {
  const orig = globalThis.fetch;
  let called = false;
  globalThis.fetch = () => {
    called = true;
    return Promise.resolve(new Response(null, { status: 202 }));
  };
  try {
    new Telemetry({ installId: 'abcdef1234', enabled: false }).emit('block', { decision: 'deny' });
    assert.equal(called, false);
  } finally {
    globalThis.fetch = orig;
  }
});

test('emitted payload is counts-only — no tool content keys', async () => {
  const orig = globalThis.fetch;
  let captured;
  globalThis.fetch = (_url, init) => {
    captured = JSON.parse(init.body);
    return Promise.resolve(new Response(null, { status: 202 }));
  };
  try {
    new Telemetry({ installId: 'abcdef1234', enabled: true, apiUrl: 'https://example.test' }).emit(
      'block',
      { mode: 'solo', decision: 'deny', ruleId: 'deny-destructive-bash' },
    );
    // Give the fire-and-forget microtask a tick.
    await new Promise((r) => setTimeout(r, 5));
    const allowed = new Set(['installId', 'event', 'ts', 'mode', 'decision', 'ruleId', 'sdkVersion']);
    for (const key of Object.keys(captured)) {
      assert.ok(allowed.has(key), `unexpected telemetry key: ${key}`);
    }
    assert.equal(captured.event, 'block');
    assert.equal(captured.installId, 'abcdef1234');
  } finally {
    globalThis.fetch = orig;
  }
});

test('loadOrCreateInstallId creates then reuses a stable id', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rubric-tel-'));
  const file = path.join(dir, 'telemetry-id');
  const a = loadOrCreateInstallId(file);
  const b = loadOrCreateInstallId(file);
  assert.equal(a, b);
  assert.ok(a.length >= 8);
});
