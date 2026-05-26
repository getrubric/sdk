// `runDaemon` integration tests. Boots a mock Rubric API on 127.0.0.1
// and verifies the cold-start fall-back-to-baseline contract (a failed/empty
// first bundle pull serves the built-in baseline rather than locking out) and
// that enrollment / token failures still refuse to start.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import * as http from 'node:http';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { randomUUID } from 'node:crypto';

import { runDaemon } from '../dist/daemon/run.js';

const TOKEN = '0123456789abcdef'.repeat(4);

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'rubric-rundaemon-'));
}

function makePaths() {
  const root = tmpDir();
  const configDir = path.join(root, 'config');
  fs.mkdirSync(configDir, { recursive: true });
  fs.writeFileSync(path.join(configDir, 'daemon.token'), TOKEN, { mode: 0o600 });
  return {
    configDir,
    configFile: path.join(configDir, 'config.json'),
    daemonTokenFile: path.join(configDir, 'daemon.token'),
    pidFile: path.join(configDir, 'daemon.pid'),
    daemonPortFile: path.join(configDir, 'daemon.port'),
    logFile: path.join(root, 'daemon.log'),
    claudeSettingsFile: path.join(root, 'settings.json'),
  };
}

/**
 * Spin up a mock Rubric API on 127.0.0.1:0. Returns the bound base URL
 * and a `close` function. The handler can be replaced per-test by
 * mutating `routes`.
 */
async function withMockApi(routes, fn) {
  const server = http.createServer((req, res) => {
    const route = routes[`${req.method} ${req.url?.split('?')[0]}`];
    if (typeof route === 'function') {
      route(req, res);
    } else {
      res.statusCode = 500;
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ error: 'mock_no_route', route: req.url }));
    }
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const apiUrl = `http://127.0.0.1:${port}`;
  try {
    await fn(apiUrl);
  } finally {
    await new Promise((resolve) => server.close(() => resolve()));
  }
}

function enrollOk(req, res) {
  // Read body (ignored) then return a valid token response.
  req.on('data', () => {});
  req.on('end', () => {
    res.statusCode = 200;
    res.setHeader('content-type', 'application/json');
    res.end(
      JSON.stringify({
        token: 'eyJtb2NrIjp0cnVlfQ.eyJzdWIiOiJ0ZXN0In0.signature',
        expiresAt: new Date(Date.now() + 3600_000).toISOString(),
        agentId: 'mock-agent-' + randomUUID(),
        identityId: randomUUID(),
      }),
    );
  });
}

function bundle500(_req, res) {
  res.statusCode = 500;
  res.setHeader('content-type', 'application/json');
  res.end(JSON.stringify({ error: 'mock_bundle_failure' }));
}

async function waitForPortFile(portFile, budgetMs) {
  const deadline = Date.now() + budgetMs;
  while (Date.now() < deadline) {
    try {
      const n = Number(fs.readFileSync(portFile, 'utf8').trim());
      if (Number.isInteger(n) && n > 0) return n;
    } catch {
      /* not bound yet */
    }
    await new Promise((r) => setTimeout(r, 50));
  }
  return null;
}

async function postHook(port, toolName, input) {
  const res = await fetch(`http://127.0.0.1:${port}/v1/hook`, {
    method: 'POST',
    headers: { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json' },
    body: JSON.stringify({
      session_id: 's',
      hook_event_name: 'PreToolUse',
      tool_name: toolName,
      tool_input: input,
    }),
  });
  return res.json();
}

test('runDaemon serves the baseline pack when the first bundle pull fails (no cold-start lockout)', async () => {
  await withMockApi(
    {
      'POST /v1/identities/enroll': enrollOk,
      'GET /v1/bundle': bundle500,
    },
    async (apiUrl) => {
      const paths = makePaths();
      const daemonPromise = runDaemon({
        config: { apiUrl, agentName: 'test-agent', enrollmentToken: 'enr_test' },
        paths,
        logLevel: 'fatal',
        firstBundleTimeoutMs: 1_000,
      });
      let port;
      try {
        // Despite the bundle pull failing, the daemon binds and serves the
        // built-in baseline rather than refusing to start.
        port = await waitForPortFile(paths.daemonPortFile, 6_000);
        assert.ok(port, 'daemon should bind and serve despite the bundle pull failing');
        // Baseline is permissive: benign allowed, catastrophic denied.
        const allow = await postHook(port, 'Bash', { command: 'ls -la' });
        assert.equal(allow.hookSpecificOutput?.permissionDecision, 'allow');
        const deny = await postHook(port, 'Bash', { command: 'rm -rf /' });
        assert.equal(deny.hookSpecificOutput?.permissionDecision, 'deny');
      } finally {
        // Graceful shutdown via the authenticated endpoint — avoids SIGTERM,
        // whose handler calls process.exit(0) and would kill the test runner.
        if (port) {
          await fetch(`http://127.0.0.1:${port}/v1/shutdown`, {
            method: 'POST',
            headers: { authorization: `Bearer ${TOKEN}` },
          }).catch(() => {});
        }
        await daemonPromise;
      }
      assert.equal(fs.existsSync(paths.daemonPortFile), false);
    },
  );
});

// Note: a full happy-path `--allow-cold-start` integration test would
// need to drive a graceful shutdown of a live daemon.
// `installSignalHandlers` (in `daemon/lifecycle.ts`) calls
// `process.exit(0)` from its SIGTERM handler, which would terminate
// the test runner. The allowColdStart code path is covered by
// inspection in `run.ts` and by the negative test above; an
// end-to-end happy-path test belongs in a separate
// `node:child_process` runner.

test('runDaemon enrollment failure prevents pidGuard leak', async () => {
  // Even with allowColdStart, an enrollment failure (non-2xx) must throw
  // before the bundle poller / server start. The pid file should not
  // remain after the throw — exercises the catch-arm cleanup path.
  await withMockApi(
    {
      'POST /v1/identities/enroll': (_req, res) => {
        res.statusCode = 401;
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({ error: 'invalid_enrollment_token' }));
      },
    },
    async (apiUrl) => {
      const paths = makePaths();
      await assert.rejects(() =>
        runDaemon({
          config: { apiUrl, agentName: 'test', enrollmentToken: 'enr_bad' },
          paths,
          logLevel: 'fatal',
          firstBundleTimeoutMs: 500,
        }),
      );
      assert.equal(fs.existsSync(paths.pidFile), false);
      assert.equal(fs.existsSync(paths.daemonPortFile), false);
    },
  );
});

test('empty daemon token file → daemon refuses to start', async () => {
  await withMockApi({}, async (apiUrl) => {
    const paths = makePaths();
    fs.writeFileSync(paths.daemonTokenFile, '', { mode: 0o600 });
    await assert.rejects(
      () =>
        runDaemon({
          config: { apiUrl, agentName: 'test', enrollmentToken: 'enr_test' },
          paths,
          logLevel: 'fatal',
        }),
      /empty|hex string/i,
    );
  });
});

test('malformed daemon token (non-hex) → daemon refuses to start', async () => {
  await withMockApi({}, async (apiUrl) => {
    const paths = makePaths();
    fs.writeFileSync(paths.daemonTokenFile, 'G'.repeat(64), { mode: 0o600 });
    await assert.rejects(
      () =>
        runDaemon({
          config: { apiUrl, agentName: 'test', enrollmentToken: 'enr_test' },
          paths,
          logLevel: 'fatal',
        }),
      /hex string/i,
    );
  });
});
