// systemd unit-file path validation must reject `$`, `;`, newlines,
// and other shell/unit metacharacters.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { buildSystemdService } from '../dist/config/services/systemd.js';

const FAKE_PATHS = {
  configDir: '/Users/x/.config/rubric',
  configFile: '/Users/x/.config/rubric/config.json',
  daemonTokenFile: '/Users/x/.config/rubric/daemon.token',
  pidFile: '/Users/x/.config/rubric/daemon.pid',
  daemonPortFile: '/Users/x/.config/rubric/daemon.port',
  logFile: '/Users/x/Library/Logs/rubric/claude-code.log',
  claudeSettingsFile: '/Users/x/.claude/settings.json',
};

function build(over) {
  return buildSystemdService({
    paths: FAKE_PATHS,
    nodeBinary: '/usr/local/bin/node',
    cliEntry: '/x/cli.js',
    home: '/home/x',
    ...over,
  });
}

test('buildSystemdService: rejects nodeBinary containing $', () => {
  assert.throws(
    () => build({ nodeBinary: '/usr/bin/$(whoami)' }),
    /disallowed character/,
  );
});

test('buildSystemdService: rejects cliEntry containing ;', () => {
  assert.throws(
    () => build({ cliEntry: '/x/cli.js;rm -rf /' }),
    /disallowed character/,
  );
});

test('buildSystemdService: rejects newline in path', () => {
  assert.throws(
    () => build({ nodeBinary: '/usr/bin/node\nExecStart=/bin/sh' }),
    /disallowed character/,
  );
});

test('buildSystemdService: rejects carriage return in path', () => {
  assert.throws(() => build({ cliEntry: '/x/cli\r.js' }), /disallowed character/);
});

test('buildSystemdService: rejects backtick in path', () => {
  assert.throws(
    () => build({ nodeBinary: '/usr/bin/`whoami`' }),
    /disallowed character/,
  );
});

test('buildSystemdService: rejects relative path (must be absolute)', () => {
  assert.throws(
    () => build({ nodeBinary: 'node' }),
    /must be an absolute path/,
  );
});

test('buildSystemdService: rejects empty string', () => {
  assert.throws(
    () => build({ nodeBinary: '' }),
    /must be a non-empty string/,
  );
});

test('buildSystemdService: still accepts plain absolute paths with spaces', () => {
  const spec = build({ nodeBinary: '/path with space/node' });
  // Spaces are escaped, not rejected.
  assert.match(spec.unitContent, /ExecStart=\/path\\ with\\ space\/node /);
});

test('buildSystemdService: doubles % to %% to avoid systemd specifier expansion', () => {
  // A path like /home/%u/node would otherwise have systemd expand %u to
  // the username. Our validator doesn't ban % (paths sometimes contain
  // legitimate %), so the escaper doubles it.
  const spec = build({ nodeBinary: '/u/%u/node' });
  assert.match(spec.unitContent, /\/u\/%%u\/node/);
});
