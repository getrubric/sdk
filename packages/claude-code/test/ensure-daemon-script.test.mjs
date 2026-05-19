// Tests for the ensure-daemon shell script renderer. We don't shell out
// to actually execute it (that would require launchctl/systemctl in CI)
// — we just verify the rendered text contains the load-bearing pieces.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  renderEnsureDaemonScript,
  LAUNCHD_LABEL,
  SYSTEMD_UNIT,
} from '../dist/config/ensure-daemon-script.js';

test('renders with the configured host and port in the healthz URL', () => {
  const out = renderEnsureDaemonScript({ daemonHost: '127.0.0.1', daemonPort: 47821 });
  assert.match(out, /HEALTHZ="http:\/\/127\.0\.0\.1:47821\/healthz"/);
});

test('renders with a custom host/port if a non-default install ever needs one', () => {
  const out = renderEnsureDaemonScript({ daemonHost: '127.0.0.1', daemonPort: 9999 });
  assert.match(out, /HEALTHZ="http:\/\/127\.0\.0\.1:9999\/healthz"/);
});

test('exits 0 in both the fast path and the slow path', () => {
  const out = renderEnsureDaemonScript({ daemonHost: '127.0.0.1', daemonPort: 47821 });
  // Three exit 0s: fast-path hit, poll-success, and the terminal fall-through.
  const exits = out.match(/exit 0/g) ?? [];
  assert.ok(exits.length >= 3, `expected ≥3 exit 0 statements, got ${exits.length}`);
});

test('kicks the launchd label on Darwin', () => {
  const out = renderEnsureDaemonScript({ daemonHost: '127.0.0.1', daemonPort: 47821 });
  assert.match(out, new RegExp(`launchctl kickstart -k "gui/\\$\\(id -u\\)/${LAUNCHD_LABEL}"`));
});

test('restarts the systemd-user unit on Linux', () => {
  const out = renderEnsureDaemonScript({ daemonHost: '127.0.0.1', daemonPort: 47821 });
  assert.match(out, new RegExp(`systemctl --user restart ${SYSTEMD_UNIT}`));
});

test('begins with a POSIX shebang so it works whether sh is bash or dash', () => {
  const out = renderEnsureDaemonScript({ daemonHost: '127.0.0.1', daemonPort: 47821 });
  assert.ok(out.startsWith('#!/usr/bin/env sh\n'), 'expected POSIX sh shebang');
});

test('bounds the poll loop so a stuck service-manager kick cannot hang the hook', () => {
  const out = renderEnsureDaemonScript({ daemonHost: '127.0.0.1', daemonPort: 47821 });
  assert.match(out, /while \[ "\$i" -lt \d+ \]/);
});
