// Tests for the persisted-config helpers. Use a tmpdir so we don't
// touch the developer's real ~/.config/rubric/ if they happen to
// have one.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import {
  configExists,
  readConfig,
  readDaemonPid,
  readDaemonPort,
  writeConfig,
} from '../dist/cli/_config.js';

function tmpFile() {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'rubric-test-')), 'config.json');
}

test('writeConfig + readConfig round-trip', () => {
  const file = tmpFile();
  writeConfig(file, {
    apiUrl: 'https://api.rubric-app.com',
    agentName: 'claude-code-mac',
    enrollmentToken: 'enr_abc.def',
  });
  const back = readConfig(file);
  assert.equal(back.apiUrl, 'https://api.rubric-app.com');
  assert.equal(back.agentName, 'claude-code-mac');
  assert.equal(back.enrollmentToken, 'enr_abc.def');
});

test('writeConfig sets 0600 permissions on the config file', () => {
  const file = tmpFile();
  writeConfig(file, {
    apiUrl: 'https://api.rubric-app.com',
    agentName: 'a',
    enrollmentToken: 'enr_x',
  });
  const mode = fs.statSync(file).mode & 0o777;
  // The enrollment token is in this file; 0600 keeps it user-only on
  // systems where the home dir is otherwise group/other-readable.
  assert.equal(mode, 0o600);
});

test('readConfig throws clearly on a malformed file', () => {
  const file = tmpFile();
  fs.writeFileSync(file, '{ not json', 'utf8');
  assert.throws(() => readConfig(file), /not valid JSON/);
});

test('readConfig throws clearly on a schema-invalid file', () => {
  const file = tmpFile();
  fs.writeFileSync(file, JSON.stringify({ apiUrl: 'not-a-url' }), 'utf8');
  assert.throws(() => readConfig(file), /invalid/);
});

test('configExists is true after write, false otherwise', () => {
  const file = tmpFile();
  assert.equal(configExists(file), false);
  writeConfig(file, { apiUrl: 'https://api.rubric-app.com', agentName: 'a', enrollmentToken: 'enr_x' });
  assert.equal(configExists(file), true);
});

test('readDaemonPort accepts a valid port and rejects junk', () => {
  const file = tmpFile();
  fs.writeFileSync(file, '47821\n', 'utf8');
  assert.equal(readDaemonPort(file), 47821);
  fs.writeFileSync(file, 'not-a-port\n', 'utf8');
  assert.equal(readDaemonPort(file), null);
  fs.writeFileSync(file, '99999\n', 'utf8');
  assert.equal(readDaemonPort(file), null);
});

test('readDaemonPid returns the pid only when the process is alive', () => {
  const file = tmpFile();
  // Our own pid is always alive — should round-trip.
  fs.writeFileSync(file, String(process.pid), 'utf8');
  assert.equal(readDaemonPid(file), process.pid);

  // A pid that's definitely dead. We use a very high pid that almost
  // certainly doesn't exist; on Linux that's typically not assigned
  // until late in the run, and 2^22 is well beyond typical PID_MAX.
  fs.writeFileSync(file, '4194300', 'utf8');
  assert.equal(readDaemonPid(file), null);
});
