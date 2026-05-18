// Server integration tests. Boots the real `node:http` server on an
// OS-assigned port, makes loopback POSTs, asserts on responses.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { startServer } from '../dist/daemon/server.js';

// Quiet pino — these tests don't care about log output.
const SILENT_LOGGER = {
  info() {},
  warn() {},
  error() {},
  fatal() {},
  debug() {},
  trace() {},
  child() {
    return SILENT_LOGGER;
  },
  level: 'silent',
};

const ALLOW_EVALUATOR = {
  evaluate() {
    return {
      decision: 'allow',
      matchedPolicyId: null,
      matchedPolicyVersion: null,
      matchedRuleId: null,
      latencyMs: 0.1,
    };
  },
};

function nullSink() {
  const events = [];
  return { enqueue: (e) => events.push(e), events };
}

const TOKEN = '0123456789abcdef'.repeat(4); // 64 hex chars
const FIXED_TS = '2026-05-15T12:00:00.000Z';

async function withServer(handlerDeps, fn) {
  const s = await startServer({
    port: 0,
    daemonToken: TOKEN,
    logger: SILENT_LOGGER,
    handlerDeps: { ...handlerDeps, now: () => FIXED_TS },
  });
  try {
    await fn(`http://127.0.0.1:${s.port}`);
  } finally {
    await s.close();
  }
}

test('GET /healthz returns 200 without auth', async () => {
  await withServer({ evaluator: ALLOW_EVALUATOR, audit: nullSink(), agentId: 'a' }, async (url) => {
    const res = await fetch(`${url}/healthz`);
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { ok: true });
  });
});

test('POST /v1/hook without auth → 401', async () => {
  await withServer({ evaluator: ALLOW_EVALUATOR, audit: nullSink(), agentId: 'a' }, async (url) => {
    const res = await fetch(`${url}/v1/hook`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        hook_event_name: 'PreToolUse',
        session_id: 's',
        tool_name: 'X',
        tool_input: {},
      }),
    });
    assert.equal(res.status, 401);
  });
});

test('POST /v1/hook with wrong bearer → 401', async () => {
  await withServer({ evaluator: ALLOW_EVALUATOR, audit: nullSink(), agentId: 'a' }, async (url) => {
    const res = await fetch(`${url}/v1/hook`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: 'Bearer ' + 'f'.repeat(64),
      },
      body: JSON.stringify({
        hook_event_name: 'PreToolUse',
        session_id: 's',
        tool_name: 'X',
        tool_input: {},
      }),
    });
    assert.equal(res.status, 401);
  });
});

test('POST /v1/hook with valid bearer + PreToolUse → 200 + permissionDecision', async () => {
  const sink = nullSink();
  await withServer({ evaluator: ALLOW_EVALUATOR, audit: sink, agentId: 'a' }, async (url) => {
    const res = await fetch(`${url}/v1/hook`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: 'Bearer ' + TOKEN,
      },
      body: JSON.stringify({
        hook_event_name: 'PreToolUse',
        session_id: 's',
        tool_name: 'Bash',
        tool_input: { command: 'ls' },
      }),
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.continue, true);
    assert.equal(body.hookSpecificOutput?.permissionDecision, 'allow');
    assert.equal(sink.events.length, 1);
  });
});

test('POST /v1/hook with malformed JSON → 400', async () => {
  await withServer({ evaluator: ALLOW_EVALUATOR, audit: nullSink(), agentId: 'a' }, async (url) => {
    const res = await fetch(`${url}/v1/hook`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer ' + TOKEN },
      body: '{not json',
    });
    assert.equal(res.status, 400);
  });
});

test('POST /v1/hook with valid auth but unknown event → 400', async () => {
  await withServer({ evaluator: ALLOW_EVALUATOR, audit: nullSink(), agentId: 'a' }, async (url) => {
    const res = await fetch(`${url}/v1/hook`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer ' + TOKEN },
      body: JSON.stringify({ hook_event_name: 'UnknownEvent', session_id: 's' }),
    });
    assert.equal(res.status, 400);
  });
});

test('unknown route → 404', async () => {
  await withServer({ evaluator: ALLOW_EVALUATOR, audit: nullSink(), agentId: 'a' }, async (url) => {
    const res = await fetch(`${url}/who-am-i`, {
      headers: { authorization: 'Bearer ' + TOKEN },
    });
    assert.equal(res.status, 404);
  });
});

// ---- Security regression tests --------------------------------------------

test('startServer refuses to bind a non-loopback host', async () => {
  await assert.rejects(
    () =>
      startServer({
        host: '0.0.0.0',
        port: 0,
        daemonToken: TOKEN,
        logger: SILENT_LOGGER,
        handlerDeps: { evaluator: ALLOW_EVALUATOR, audit: nullSink(), agentId: 'a' },
      }),
    /refusing to bind '0\.0\.0\.0'/,
  );
});

test('startServer accepts loopback hosts', async () => {
  for (const host of ['127.0.0.1', 'localhost']) {
    const s = await startServer({
      host,
      port: 0,
      daemonToken: TOKEN,
      logger: SILENT_LOGGER,
      handlerDeps: { evaluator: ALLOW_EVALUATOR, audit: nullSink(), agentId: 'a' },
    });
    await s.close();
  }
});

test('bearer scheme is case-insensitive (RFC 7235)', async () => {
  await withServer({ evaluator: ALLOW_EVALUATOR, audit: nullSink(), agentId: 'a' }, async (url) => {
    for (const scheme of ['bearer ', 'BEARER ', 'BeArEr\t']) {
      const res = await fetch(`${url}/v1/hook`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: scheme + TOKEN },
        body: JSON.stringify({
          hook_event_name: 'PreToolUse',
          session_id: 's',
          tool_name: 'X',
          tool_input: {},
        }),
      });
      assert.equal(res.status, 200, `scheme '${scheme}' should authenticate`);
    }
  });
});

test('non-hex64 presented bearer is rejected without timing leak', async () => {
  await withServer({ evaluator: ALLOW_EVALUATOR, audit: nullSink(), agentId: 'a' }, async (url) => {
    // Too short, non-hex, uppercase hex (token regex is lowercase only).
    for (const presented of ['', 'short', 'G'.repeat(64), TOKEN.toUpperCase()]) {
      const res = await fetch(`${url}/v1/hook`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: 'Bearer ' + presented,
        },
        body: '{}',
      });
      assert.equal(res.status, 401, `presented '${presented}' must 401`);
    }
  });
});

test('POST /v1/shutdown with valid bearer → 202 + invokes handler', async () => {
  let shutdownCalled = false;
  const s = await startServer({
    port: 0,
    daemonToken: TOKEN,
    logger: SILENT_LOGGER,
    handlerDeps: { evaluator: ALLOW_EVALUATOR, audit: nullSink(), agentId: 'a' },
    onShutdownRequest: () => {
      shutdownCalled = true;
    },
  });
  try {
    const res = await fetch(`http://127.0.0.1:${s.port}/v1/shutdown`, {
      method: 'POST',
      headers: { authorization: 'Bearer ' + TOKEN },
    });
    assert.equal(res.status, 202);
    const body = await res.json();
    assert.deepEqual(body, { accepted: true });
    // The handler is invoked on `setImmediate`; give the event loop a tick.
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));
    assert.equal(shutdownCalled, true);
  } finally {
    await s.close();
  }
});

test('POST /v1/shutdown without valid bearer → 401', async () => {
  await withServer(
    { evaluator: ALLOW_EVALUATOR, audit: nullSink(), agentId: 'a' },
    async (url) => {
      const res = await fetch(`${url}/v1/shutdown`, { method: 'POST' });
      assert.equal(res.status, 401);
    },
  );
});

test('POST /v1/shutdown when no handler wired → 503', async () => {
  await withServer(
    { evaluator: ALLOW_EVALUATOR, audit: nullSink(), agentId: 'a' },
    async (url) => {
      const res = await fetch(`${url}/v1/shutdown`, {
        method: 'POST',
        headers: { authorization: 'Bearer ' + TOKEN },
      });
      assert.equal(res.status, 503);
    },
  );
});

test('HTTP slowloris: stalled headers close within headersTimeout', async () => {
  const s = await startServer({
    port: 0,
    daemonToken: TOKEN,
    logger: SILENT_LOGGER,
    handlerDeps: { evaluator: ALLOW_EVALUATOR, audit: nullSink(), agentId: 'a' },
  });
  try {
    const net = await import('node:net');
    const sock = net.createConnection({ host: '127.0.0.1', port: s.port });
    await new Promise((res) => sock.once('connect', res));
    // Send only a partial request line and never finish headers.
    sock.write('POST /v1/hook HTTP/1.1\r\n');
    sock.write('Host: 127.0.0.1\r\n');
    // Wait for the server to close us or send a 408. The daemon sets
    // headersTimeout=5s and requestTimeout=10s; whichever fires first
    // tears the connection down. Default Node values (60s / 5min) would
    // still be pending at this assertion's deadline — the assertion is
    // really "the daemon does NOT use Node defaults". Allow up to 12s
    // for variance under load.
    const start = Date.now();
    const outcome = await new Promise((res) => {
      const timer = setTimeout(() => res({ kind: 'timeout' }), 12_000);
      let bytes = Buffer.alloc(0);
      sock.on('data', (c) => {
        bytes = Buffer.concat([bytes, c]);
      });
      sock.once('close', () => {
        clearTimeout(timer);
        res({ kind: 'closed', elapsedMs: Date.now() - start, bytes });
      });
      sock.once('error', () => {
        clearTimeout(timer);
        res({ kind: 'closed', elapsedMs: Date.now() - start, bytes });
      });
    });
    sock.destroy();
    assert.equal(
      outcome.kind,
      'closed',
      `server should close stalled connection (got ${outcome.kind})`,
    );
    // Should close well before the default Node timeout (~60s) — the
    // requestTimeout=10s upper bound is what we're really verifying.
    assert.ok(
      outcome.elapsedMs < 11_500,
      `close took ${outcome.elapsedMs}ms; expected < 11500 (requestTimeout=10000)`,
    );
  } finally {
    await s.close();
  }
});

// Note: a same-UID local process *cannot* drive an array-valued
// `Authorization` header through Node's HTTP parser — Node de-duplicates
// the Authorization header to the first value (RFC 7235 spec compliance).
// `checkBearer`'s `typeof !== 'string'` guard is defense-in-depth against
// future Node behavior changes and against direct in-process callers
// that build an `IncomingHttpHeaders`-shaped object themselves; the
// behavior is covered by the unit test in test/auth.test.mjs.
