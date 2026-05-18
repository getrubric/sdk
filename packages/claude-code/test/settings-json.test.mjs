// Tests for the settings.json patcher. The properties we care about:
//   1. apply preserves all user-authored fields
//   2. apply is idempotent
//   3. remove is the exact inverse of apply on an empty starting object
//   4. apply + remove on a user-modified file leaves the user's fields untouched
//   5. the inlined token is what Claude Code actually receives in headers
//   6. legacy env entries from older installs get scrubbed on every apply

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { applyRubricHooks, removeRubricHooks } from '../dist/config/settings-json.js';

const TOK = 'a'.repeat(64);
const TOK2 = 'b'.repeat(64);
const RUBRIC_URL = 'http://127.0.0.1:47821/v1/hook';

test('apply requires a 64-char hex daemonToken', () => {
  assert.throws(() => applyRubricHooks({}, { daemonToken: '' }), /64-char hex/);
  assert.throws(() => applyRubricHooks({}, { daemonToken: 'short' }), /64-char hex/);
  // No daemonToken at all → throws.
  assert.throws(() => applyRubricHooks({}, {}), /64-char hex/);
});

test('apply on empty object writes 3 hook events with inlined bearer', () => {
  const out = applyRubricHooks({}, { daemonToken: TOK });
  // No env section — we don't use env-var indirection anymore.
  assert.equal(out.env, undefined);
  for (const evt of ['PreToolUse', 'PostToolUse', 'SessionStart']) {
    const groups = out.hooks[evt];
    assert.equal(groups.length, 1);
    assert.equal(groups[0].matcher, '*');
    const h = groups[0].hooks[0];
    assert.equal(h.type, 'http');
    assert.equal(h.url, RUBRIC_URL);
    // The actual token literal, NOT a $VAR reference.
    assert.equal(h.headers.Authorization, `Bearer ${TOK}`);
    assert.equal(h.headers['Content-Type'], 'application/json');
  }
});

test('apply preserves user-authored top-level keys', () => {
  const input = {
    theme: 'dark',
    permissions: { allow: ['Bash'] },
    customKey: { nested: true },
  };
  const out = applyRubricHooks(input, { daemonToken: TOK });
  assert.equal(out.theme, 'dark');
  assert.deepEqual(out.permissions, { allow: ['Bash'] });
  assert.deepEqual(out.customKey, { nested: true });
});

test('apply preserves user-authored env vars without adding any of ours', () => {
  const input = { env: { MY_VAR: 'x', ANOTHER: 'y' } };
  const out = applyRubricHooks(input, { daemonToken: TOK });
  assert.equal(out.env.MY_VAR, 'x');
  assert.equal(out.env.ANOTHER, 'y');
  // We never write our own env entry now — the token is inlined in headers.
  assert.equal(out.env.RUBRIC_DAEMON_TOKEN, undefined);
});

test('apply heals broken legacy env entries from older installs', () => {
  // Earlier patcher versions wrote this — Claude Code never honored the
  // ${file:...} syntax so the hooks 401'd silently. A re-apply scrubs
  // the legacy entry.
  const input = {
    env: {
      RUBRIC_DAEMON_TOKEN: '${file:~/.config/rubric/daemon.token}',
      USER_VAR: 'keep',
    },
  };
  const out = applyRubricHooks(input, { daemonToken: TOK });
  assert.equal(out.env.RUBRIC_DAEMON_TOKEN, undefined);
  assert.equal(out.env.USER_VAR, 'keep');
});

test('apply removes the env block entirely when only the legacy key was in it', () => {
  const input = { env: { RUBRIC_DAEMON_TOKEN: '${file:...}' } };
  const out = applyRubricHooks(input, { daemonToken: TOK });
  assert.equal(out.env, undefined);
});

test('apply preserves user-authored hook entries for the same event', () => {
  const input = {
    hooks: {
      PreToolUse: [
        { matcher: 'Bash', hooks: [{ type: 'command', command: 'echo before-rubric' }] },
      ],
    },
  };
  const out = applyRubricHooks(input, { daemonToken: TOK });
  const userGroup = out.hooks.PreToolUse.find((g) => g.matcher === 'Bash');
  assert.ok(userGroup, 'user’s Bash matcher must still be present');
  const rubricGroup = out.hooks.PreToolUse.find((g) =>
    g.hooks.some((h) => h.url === RUBRIC_URL),
  );
  assert.ok(rubricGroup, 'Rubric’s group must be added');
});

test('apply is idempotent — running twice produces the same output as once', () => {
  const input = { theme: 'dark' };
  const once = applyRubricHooks(input, { daemonToken: TOK });
  const twice = applyRubricHooks(once, { daemonToken: TOK });
  assert.deepEqual(twice, once);
  for (const evt of ['PreToolUse', 'PostToolUse', 'SessionStart']) {
    const rubricCount = twice.hooks[evt]
      .flatMap((g) => g.hooks)
      .filter((h) => h.url === RUBRIC_URL).length;
    assert.equal(rubricCount, 1, `${evt} should have exactly one Rubric entry`);
  }
});

test('apply with a rotated token replaces the old bearer cleanly', () => {
  const first = applyRubricHooks({}, { daemonToken: TOK });
  const rotated = applyRubricHooks(first, { daemonToken: TOK2 });
  for (const evt of ['PreToolUse', 'PostToolUse', 'SessionStart']) {
    assert.equal(rotated.hooks[evt].length, 1);
    assert.equal(rotated.hooks[evt][0].hooks[0].headers.Authorization, `Bearer ${TOK2}`);
  }
});

test('remove is the inverse of apply on an empty starting object', () => {
  const applied = applyRubricHooks({}, { daemonToken: TOK });
  const removed = removeRubricHooks(applied);
  assert.deepEqual(removed, {});
});

test('remove preserves user-authored fields and user hook entries', () => {
  const input = {
    theme: 'dark',
    env: { MY_VAR: 'x' },
    hooks: {
      PreToolUse: [
        { matcher: 'Bash', hooks: [{ type: 'command', command: 'echo user-hook' }] },
      ],
    },
  };
  const applied = applyRubricHooks(input, { daemonToken: TOK });
  const removed = removeRubricHooks(applied);
  assert.equal(removed.theme, 'dark');
  assert.deepEqual(removed.env, { MY_VAR: 'x' });
  assert.equal(removed.hooks.PreToolUse.length, 1);
  assert.equal(removed.hooks.PreToolUse[0].matcher, 'Bash');
  assert.equal(removed.hooks.PostToolUse, undefined);
  assert.equal(removed.hooks.SessionStart, undefined);
});

test('remove also scrubs the legacy env entry (heals older installs on uninstall)', () => {
  const input = {
    env: { RUBRIC_DAEMON_TOKEN: '${file:...}', USER_VAR: 'keep' },
    hooks: {
      PreToolUse: [
        { matcher: '*', hooks: [{ type: 'http', url: RUBRIC_URL, headers: {}, timeout: 5 }] },
      ],
    },
  };
  const removed = removeRubricHooks(input);
  assert.equal(removed.env.RUBRIC_DAEMON_TOKEN, undefined);
  assert.equal(removed.env.USER_VAR, 'keep');
  assert.equal(removed.hooks, undefined);
});

test('remove on a settings.json that never had Rubric is a no-op', () => {
  const input = { theme: 'dark', env: { MY_VAR: 'x' } };
  assert.deepEqual(removeRubricHooks(input), input);
});

test('apply does not mutate its input', () => {
  const input = { theme: 'dark', env: { X: '1' } };
  const snapshot = JSON.stringify(input);
  applyRubricHooks(input, { daemonToken: TOK });
  assert.equal(JSON.stringify(input), snapshot);
});

test('apply gracefully handles a non-object input', () => {
  assert.deepEqual(applyRubricHooks(null, { daemonToken: TOK }), applyRubricHooks({}, { daemonToken: TOK }));
  assert.deepEqual(applyRubricHooks(undefined, { daemonToken: TOK }), applyRubricHooks({}, { daemonToken: TOK }));
  assert.deepEqual(applyRubricHooks([], { daemonToken: TOK }), applyRubricHooks({}, { daemonToken: TOK }));
});
