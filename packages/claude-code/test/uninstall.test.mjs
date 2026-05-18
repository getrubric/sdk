// Tests for the uninstall flow:
//   - service unload happens BEFORE the daemon stop
//   - malformed settings.json gets backed up + reset (bearer scrubbed)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

// We need to mock service install/uninstall + runStop call order.
// The simplest way without a mocking library is to install our own
// module via `Module._cache` shims — overkill. Instead, we test the
// individual pieces:
//   * the malformed-settings-json handling is reachable as a unit
//     (file io + JSON parse fallback)
//   * the service-uninstall-before-stop order is documented in code
//     comments and verified by inspection.
//
// For the malformed-settings case, exercise the real `runUninstall`
// against a tmp HOME so it doesn't touch the developer's machine.

import { runUninstall } from '../dist/cli/uninstall.js';

function tmpHome() {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'rubric-uninstall-'));
  // Lay out the directories runUninstall expects.
  fs.mkdirSync(path.join(home, '.config', 'rubric'), { recursive: true });
  fs.mkdirSync(path.join(home, '.claude'), { recursive: true });
  return home;
}

test('runUninstall: malformed settings.json is backed up and reset', async (t) => {
  const home = tmpHome();
  const origHome = process.env.HOME;
  const origXdg = process.env.XDG_CONFIG_HOME;
  const origPlatform = process.platform;
  process.env.HOME = home;
  delete process.env.XDG_CONFIG_HOME;

  const settingsFile = path.join(home, '.claude', 'settings.json');
  const malformed =
    '{ "hooks": { "PreToolUse": [{"hooks":[{"type":"http",' +
    '"headers":{"Authorization":"Bearer abcdef0123456789' +
    // valid JSON up to here — chop trailing close braces to force a
    // parse failure.
    '";';
  fs.writeFileSync(settingsFile, malformed, 'utf8');

  t.after(() => {
    if (origHome === undefined) delete process.env.HOME;
    else process.env.HOME = origHome;
    if (origXdg !== undefined) process.env.XDG_CONFIG_HOME = origXdg;
    Object.defineProperty(process, 'platform', { value: origPlatform });
  });

  // Force unsupported platform so the service-uninstall paths are
  // no-ops (no launchd/systemd actually called from a test).
  Object.defineProperty(process, 'platform', { value: 'sunos' });

  // Suppress noisy output.
  const out = process.stdout.write.bind(process.stdout);
  const errOut = process.stderr.write.bind(process.stderr);
  process.stdout.write = () => true;
  process.stderr.write = () => true;
  try {
    await runUninstall({ keepDaemon: true });
  } finally {
    process.stdout.write = out;
    process.stderr.write = errOut;
  }

  // Original file must no longer carry the bearer token.
  const after = fs.readFileSync(settingsFile, 'utf8');
  assert.equal(after.includes('abcdef0123456789'), false);
  assert.equal(after.trim(), '{}');

  // A backup file must exist with the original content.
  const dir = fs.readdirSync(path.join(home, '.claude'));
  const backup = dir.find((f) => f.startsWith('settings.json.malformed-') && f.endsWith('.bak'));
  assert.ok(backup, `expected a backup file, got: ${dir.join(', ')}`);
  const backupContent = fs.readFileSync(path.join(home, '.claude', backup), 'utf8');
  assert.ok(backupContent.includes('abcdef0123456789'), 'backup must preserve original bearer');
});

test('runUninstall: removes the config dir even on the darwin/linux short-circuit', async (t) => {
  const home = tmpHome();
  const origHome = process.env.HOME;
  const origXdg = process.env.XDG_CONFIG_HOME;
  const origPlatform = process.platform;
  process.env.HOME = home;
  delete process.env.XDG_CONFIG_HOME;

  t.after(() => {
    if (origHome === undefined) delete process.env.HOME;
    else process.env.HOME = origHome;
    if (origXdg !== undefined) process.env.XDG_CONFIG_HOME = origXdg;
    Object.defineProperty(process, 'platform', { value: origPlatform });
  });
  Object.defineProperty(process, 'platform', { value: 'sunos' });

  // Pre-populate the config dir with the artifacts a real install
  // leaves behind. After uninstall they must all be gone — even when
  // keepDaemon means we don't try to talk to a running daemon at all.
  const cfgDir = path.join(home, '.config', 'rubric');
  fs.writeFileSync(path.join(cfgDir, 'daemon.token'), 'a'.repeat(64) + '\n', { mode: 0o600 });
  fs.writeFileSync(path.join(cfgDir, 'config.json'), '{}', { mode: 0o600 });
  fs.writeFileSync(path.join(cfgDir, 'daemon.pid'), '12345', { mode: 0o600 });

  const out = process.stdout.write.bind(process.stdout);
  const errOut = process.stderr.write.bind(process.stderr);
  process.stdout.write = () => true;
  process.stderr.write = () => true;
  try {
    await runUninstall({ keepDaemon: true });
  } finally {
    process.stdout.write = out;
    process.stderr.write = errOut;
  }

  assert.equal(fs.existsSync(cfgDir), false, 'config dir must be gone');
});

test('runUninstall: well-formed settings.json is cleaned of rubric hooks', async (t) => {
  const home = tmpHome();
  const origHome = process.env.HOME;
  const origXdg = process.env.XDG_CONFIG_HOME;
  const origPlatform = process.platform;
  process.env.HOME = home;
  delete process.env.XDG_CONFIG_HOME;

  t.after(() => {
    if (origHome === undefined) delete process.env.HOME;
    else process.env.HOME = origHome;
    if (origXdg !== undefined) process.env.XDG_CONFIG_HOME = origXdg;
    Object.defineProperty(process, 'platform', { value: origPlatform });
  });
  Object.defineProperty(process, 'platform', { value: 'sunos' });

  const settingsFile = path.join(home, '.claude', 'settings.json');
  fs.writeFileSync(
    settingsFile,
    JSON.stringify({
      hooks: {
        PreToolUse: [
          {
            matcher: '*',
            hooks: [
              {
                type: 'http',
                url: 'http://127.0.0.1:47821/v1/hook',
                headers: { Authorization: 'Bearer deadbeef' },
                timeout: 5,
              },
            ],
          },
        ],
        UserHook: [{ matcher: '*', hooks: [{ type: 'command', command: '/usr/bin/true' }] }],
      },
      userField: 'preserved',
    }, null, 2),
    'utf8',
  );

  const out = process.stdout.write.bind(process.stdout);
  const errOut = process.stderr.write.bind(process.stderr);
  process.stdout.write = () => true;
  process.stderr.write = () => true;
  try {
    await runUninstall({ keepDaemon: true });
  } finally {
    process.stdout.write = out;
    process.stderr.write = errOut;
  }

  const after = JSON.parse(fs.readFileSync(settingsFile, 'utf8'));
  assert.equal(after.userField, 'preserved', 'user field must survive');
  // No Rubric hook URL anywhere.
  assert.ok(!fs.readFileSync(settingsFile, 'utf8').includes('127.0.0.1:47821'));
  // User-authored hook survives.
  assert.ok(after.hooks?.UserHook);
});
