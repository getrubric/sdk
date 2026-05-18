// Tests for the writeFileSecure / readFileSecure helpers.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import {
  writeFileSecure,
  readFileSecure,
  ensureDirMode,
} from '../dist/config/fs-secure.js';

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'rubric-fssec-'));
}

// ---- explicit chmod after overwrite ---------------------------------------

test('writeFileSecure: chmods 0600 even when overwriting an existing 0644 file', () => {
  const dir = tmpDir();
  const file = path.join(dir, 'secret');
  // Pre-create at 0644 — the same scenario `~/.claude/settings.json`
  // sees when Claude Code created it on a prior run.
  fs.writeFileSync(file, 'old', { mode: 0o644 });
  fs.chmodSync(file, 0o644);
  assert.equal(fs.lstatSync(file).mode & 0o777, 0o644);

  writeFileSecure(file, 'new contents', { mode: 0o600 });

  // `fs.writeFileSync(p, c, { mode: 0o600 })` would leave this at 0644
  // because the mode flag only applies on create. writeFileSecure
  // chmods explicitly after every write.
  assert.equal(fs.lstatSync(file).mode & 0o777, 0o600);
  assert.equal(fs.readFileSync(file, 'utf8'), 'new contents');
});

test('writeFileSecure: chmods 0600 in atomic mode too', () => {
  const dir = tmpDir();
  const file = path.join(dir, 'settings.json');
  fs.writeFileSync(file, '{}', { mode: 0o644 });
  fs.chmodSync(file, 0o644);

  writeFileSecure(file, '{"hooks":{}}', { mode: 0o600, atomic: true });

  assert.equal(fs.lstatSync(file).mode & 0o777, 0o600);
  assert.equal(fs.readFileSync(file, 'utf8'), '{"hooks":{}}');
});

// ---- refuse symlink targets -----------------------------------------------

test('writeFileSecure: refuses to follow a symlink at the destination', () => {
  const dir = tmpDir();
  const target = path.join(dir, 'victim');
  fs.writeFileSync(target, 'victim contents', { mode: 0o600 });
  const link = path.join(dir, 'daemon.token');
  fs.symlinkSync(target, link);

  assert.throws(
    () => writeFileSecure(link, 'replacement', { mode: 0o600 }),
    /refuses to follow symlink/,
  );
  // The link target must not have been overwritten.
  assert.equal(fs.readFileSync(target, 'utf8'), 'victim contents');
});

test('writeFileSecure: refuses to follow a symlink in atomic mode', () => {
  const dir = tmpDir();
  const target = path.join(dir, 'pre-existing.plist');
  fs.writeFileSync(target, 'pre-existing plist', { mode: 0o644 });
  const link = path.join(dir, 'rubric.plist');
  fs.symlinkSync(target, link);

  assert.throws(
    () => writeFileSecure(link, 'rubric content', { mode: 0o644, atomic: true }),
    /refuses to follow symlink/,
  );
  assert.equal(fs.readFileSync(target, 'utf8'), 'pre-existing plist');
});

test('writeFileSecure: succeeds on a fresh path', () => {
  const dir = tmpDir();
  const file = path.join(dir, 'fresh');
  writeFileSecure(file, 'hello', { mode: 0o600 });
  assert.equal(fs.readFileSync(file, 'utf8'), 'hello');
  assert.equal(fs.lstatSync(file).mode & 0o777, 0o600);
});

test('writeFileSecure: atomic write succeeds on fresh path and cleans up tmp', () => {
  const dir = tmpDir();
  const file = path.join(dir, 'settings.json');
  writeFileSecure(file, '{}', { mode: 0o600, atomic: true });
  assert.equal(fs.readFileSync(file, 'utf8'), '{}');
  // Tmp file should be gone after rename.
  assert.equal(fs.existsSync(`${file}.tmp`), false);
});

// ---- readFileSecure -------------------------------------------------------

test('readFileSecure: returns file contents when not a symlink', () => {
  const dir = tmpDir();
  const file = path.join(dir, 'daemon.pid');
  fs.writeFileSync(file, '12345\n', { mode: 0o600 });
  assert.equal(readFileSecure(file), '12345\n');
});

test('readFileSecure: refuses to follow a symlink', () => {
  const dir = tmpDir();
  const target = path.join(dir, 'sensitive');
  fs.writeFileSync(target, 'secret\n', { mode: 0o600 });
  const link = path.join(dir, 'daemon.pid');
  fs.symlinkSync(target, link);
  assert.throws(() => readFileSecure(link), /refuses to follow symlink/);
});

test('readFileSecure: surfaces ENOENT for missing files', () => {
  assert.throws(() => readFileSecure('/no/such/path'), (err) => {
    return err.code === 'ENOENT';
  });
});

// ---- ensureDirMode --------------------------------------------------------

test('ensureDirMode: chmods an existing wider-mode directory back to 0700', () => {
  const dir = tmpDir();
  // mkdtemp gives us a 0700 dir already on macOS; widen it to simulate
  // the case where ~/.config/rubric/ pre-exists at 0755.
  fs.chmodSync(dir, 0o755);
  assert.equal(fs.lstatSync(dir).mode & 0o777, 0o755);

  ensureDirMode(dir, 0o700);

  assert.equal(fs.lstatSync(dir).mode & 0o777, 0o700);
});

test('ensureDirMode: leaves a correctly-permissioned directory alone', () => {
  const dir = tmpDir();
  fs.chmodSync(dir, 0o700);
  ensureDirMode(dir, 0o700);
  assert.equal(fs.lstatSync(dir).mode & 0o777, 0o700);
});

test('ensureDirMode: refuses to chmod a symlink', () => {
  const dir = tmpDir();
  const target = path.join(dir, 'realdir');
  fs.mkdirSync(target, { mode: 0o755 });
  const link = path.join(dir, 'configdir');
  fs.symlinkSync(target, link);
  assert.throws(() => ensureDirMode(link, 0o700), /refuses to chmod symlink/);
});
