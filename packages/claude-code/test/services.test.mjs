// Tests for the service-file builders. The plist/unit content is the
// part we care about — the launchctl/systemctl shellouts are exercised
// via end-to-end install on a real machine, not in CI.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { buildLaunchdService, LAUNCHD_LABEL } from '../dist/config/services/launchd.js';
import { buildSystemdService, SYSTEMD_UNIT_NAME } from '../dist/config/services/systemd.js';
import { installService, uninstallService } from '../dist/config/services/index.js';

const FAKE_PATHS = {
  configDir: '/Users/x/.config/rubric',
  configFile: '/Users/x/.config/rubric/config.json',
  daemonTokenFile: '/Users/x/.config/rubric/daemon.token',
  pidFile: '/Users/x/.config/rubric/daemon.pid',
  daemonPortFile: '/Users/x/.config/rubric/daemon.port',
  logFile: '/Users/x/Library/Logs/rubric/claude-code.log',
  claudeSettingsFile: '/Users/x/.claude/settings.json',
};

// ---- launchd ---------------------------------------------------------------

test('buildLaunchdService: produces valid plist with the right label and paths', () => {
  const spec = buildLaunchdService({
    paths: FAKE_PATHS,
    nodeBinary: '/usr/local/bin/node',
    cliEntry: '/Users/x/n/rubric/dist/cli/index.js',
    home: '/Users/x',
  });
  assert.equal(spec.label, LAUNCHD_LABEL);
  assert.equal(spec.plistPath, '/Users/x/Library/LaunchAgents/dev.rubric.claude-code.plist');
  // Plist must start with the XML declaration and DOCTYPE.
  assert.ok(spec.plistContent.startsWith('<?xml version="1.0" encoding="UTF-8"?>'));
  assert.ok(spec.plistContent.includes('<!DOCTYPE plist'));
  // Label, program args, KeepAlive, RunAtLoad, log paths all present.
  assert.ok(spec.plistContent.includes('<string>dev.rubric.claude-code</string>'));
  assert.ok(spec.plistContent.includes('<string>/usr/local/bin/node</string>'));
  assert.ok(spec.plistContent.includes('<string>/Users/x/n/rubric/dist/cli/index.js</string>'));
  assert.ok(spec.plistContent.includes('<string>daemon</string>'));
  assert.ok(spec.plistContent.includes('<key>KeepAlive</key>\n    <true/>'));
  assert.ok(spec.plistContent.includes('<key>RunAtLoad</key>\n    <true/>'));
  assert.ok(spec.plistContent.includes(FAKE_PATHS.logFile));
});

test('buildLaunchdService: XML-escapes special characters in paths', () => {
  // Paths with quotes / ampersands shouldn't break the plist. (We don't
  // expect this in practice but defense-in-depth is cheap.)
  const spec = buildLaunchdService({
    paths: FAKE_PATHS,
    nodeBinary: '/path/with "quote"/node',
    cliEntry: '/path/with & ampersand/index.js',
    home: '/Users/x',
  });
  assert.ok(spec.plistContent.includes('&quot;quote&quot;'));
  assert.ok(spec.plistContent.includes('&amp;'));
  // And nothing un-escaped slipped through.
  assert.ok(!spec.plistContent.includes('"quote"'));
});

// ---- systemd ---------------------------------------------------------------

test('buildSystemdService: produces unit with Restart=always and the right ExecStart', () => {
  const spec = buildSystemdService({
    paths: FAKE_PATHS,
    nodeBinary: '/usr/local/bin/node',
    cliEntry: '/home/x/n/rubric/dist/cli/index.js',
    home: '/home/x',
  });
  assert.equal(spec.unitName, SYSTEMD_UNIT_NAME);
  assert.ok(spec.unitContent.includes('[Unit]'));
  assert.ok(spec.unitContent.includes('[Service]'));
  assert.ok(spec.unitContent.includes('[Install]'));
  // Crash restart.
  assert.ok(spec.unitContent.includes('Restart=always'));
  assert.ok(spec.unitContent.includes('RestartSec=2'));
  // The ExecStart line wires node + cliEntry + 'daemon'.
  assert.match(
    spec.unitContent,
    /ExecStart=\/usr\/local\/bin\/node \/home\/x\/n\/rubric\/dist\/cli\/index\.js daemon/,
  );
  // Logs are forwarded to the file the daemon also writes.
  assert.ok(spec.unitContent.includes(`StandardOutput=append:${FAKE_PATHS.logFile}`));
  assert.ok(spec.unitContent.includes(`StandardError=append:${FAKE_PATHS.logFile}`));
  // Restart storm guard.
  assert.ok(spec.unitContent.includes('StartLimitBurst=5'));
});

test('buildSystemdService: respects XDG_CONFIG_HOME for the unit path', () => {
  const xdg = process.env.XDG_CONFIG_HOME;
  try {
    process.env.XDG_CONFIG_HOME = '/custom/xdg';
    const spec = buildSystemdService({
      paths: FAKE_PATHS,
      nodeBinary: '/usr/bin/node',
      cliEntry: '/x/cli.js',
      home: '/home/x',
    });
    assert.equal(spec.unitPath, '/custom/xdg/systemd/user/rubric-claude-code.service');
  } finally {
    if (xdg === undefined) delete process.env.XDG_CONFIG_HOME;
    else process.env.XDG_CONFIG_HOME = xdg;
  }
});

test('buildSystemdService: escapes spaces in paths for the ExecStart line', () => {
  const spec = buildSystemdService({
    paths: FAKE_PATHS,
    nodeBinary: '/path with space/node',
    cliEntry: '/x/cli.js',
    home: '/home/x',
  });
  // systemd EXEC line escapes spaces with backslash, NOT shell-quote.
  assert.ok(
    spec.unitContent.includes('ExecStart=/path\\ with\\ space/node /x/cli.js daemon'),
    `got: ${spec.unitContent.match(/ExecStart=.*/)?.[0]}`,
  );
});

// ---- Dispatcher ------------------------------------------------------------

test('installService on unsupported platform returns a graceful result', async () => {
  const result = await installService({
    paths: FAKE_PATHS,
    nodeBinary: '/x',
    cliEntry: '/y',
    platform: 'win32',
    home: '/Users/x',
  });
  assert.equal(result.platform, 'unsupported');
  assert.equal(result.loaded, false);
  assert.match(result.message, /no service manager/);
});

test('uninstallService on unsupported platform returns a graceful result', async () => {
  const result = await uninstallService({
    paths: FAKE_PATHS,
    platform: 'win32',
    home: '/Users/x',
  });
  assert.equal(result.platform, 'unsupported');
  assert.match(result.message, /no service manager/);
});
