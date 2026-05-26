// Integration tests for the shadow-git snapshot/restore mechanism.
// These shell out to real `git`, so they're skipped if git is unavailable.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import {
  lastUserPrompt,
  listSnapshots,
  resolveProjectRoot,
  restore,
  shadowGitDir,
  snapshot,
} from '../dist/seatbelt/shadow.js';

const gitAvailable = spawnSync('git', ['--version']).status === 0;

function makeRepo() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rubric-seatbelt-'));
  const init = spawnSync('git', ['init', '-q'], { cwd: root });
  assert.equal(init.status, 0, 'git init failed');
  return root;
}

function makePaths() {
  const seatbeltDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rubric-shadow-'));
  return { seatbeltDir };
}

test('snapshot then restore brings back deleted files and removes new ones', { skip: !gitAvailable }, () => {
  const root = makeRepo();
  const paths = makePaths();

  fs.writeFileSync(path.join(root, 'a.txt'), 'original-a');

  const made = snapshot({ paths, projectRoot: root, command: 'git reset --hard HEAD', sessionId: 's1' });
  assert.equal(made, true, 'snapshot should succeed');

  // Shadow repo lives under our seatbelt dir, not the project's real .git.
  assert.ok(fs.existsSync(shadowGitDir(paths, root)), 'shadow git dir should exist');
  assert.ok(!fs.existsSync(path.join(shadowGitDir(paths, root), '..', '..', '.git')));

  const snaps = listSnapshots({ paths, projectRoot: root });
  assert.equal(snaps.length, 1);
  assert.equal(snaps[0].command, 'git reset --hard HEAD');

  // Simulate the destructive aftermath: delete a.txt, create b.txt.
  fs.rmSync(path.join(root, 'a.txt'));
  fs.writeFileSync(path.join(root, 'b.txt'), 'agent-created');

  restore({ paths, projectRoot: root, sha: snaps[0].sha });

  assert.equal(fs.readFileSync(path.join(root, 'a.txt'), 'utf8'), 'original-a', 'a.txt restored');
  assert.ok(!fs.existsSync(path.join(root, 'b.txt')), 'b.txt (created after snapshot) removed');

  // Restore is reversible: a redo snapshot of the pre-restore state was added.
  const after = listSnapshots({ paths, projectRoot: root });
  assert.ok(after.length >= 2, 'a redo snapshot should have been created');
  assert.match(after[0].command, /pre-restore/);
});

test('snapshot/restore works when the seatbelt dir lives inside the work-tree', { skip: !gitAvailable }, () => {
  // Regression: a dotfiles repo rooted at $HOME puts ~/.config/rubric/seatbelt
  // inside the work-tree. The shadow repo must exclude its own storage or
  // `reset --hard` corrupts it ("unable to read sha1 file of …/index.lock").
  const root = makeRepo();
  const paths = { seatbeltDir: path.join(root, '.config', 'rubric', 'seatbelt') };

  fs.writeFileSync(path.join(root, 'precious.txt'), 'v1');
  assert.equal(snapshot({ paths, projectRoot: root, command: 'git reset --hard', sessionId: 's' }), true);

  fs.writeFileSync(path.join(root, 'precious.txt'), 'v2-clobbered');
  const snaps = listSnapshots({ paths, projectRoot: root });
  assert.equal(snaps.length, 1);
  restore({ paths, projectRoot: root, sha: snaps[0].sha });

  assert.equal(fs.readFileSync(path.join(root, 'precious.txt'), 'utf8'), 'v1');
  // The shadow repo's own storage survived intact.
  assert.ok(fs.existsSync(shadowGitDir(paths, root)));
});

test('listSnapshots returns [] when no shadow repo exists', { skip: !gitAvailable }, () => {
  const root = makeRepo();
  const paths = makePaths();
  assert.deepEqual(listSnapshots({ paths, projectRoot: root }), []);
});

test('resolveProjectRoot walks up to the .git directory', { skip: !gitAvailable }, () => {
  const root = makeRepo();
  const nested = path.join(root, 'src', 'deep');
  fs.mkdirSync(nested, { recursive: true });
  // realpath both sides — macOS /tmp is a symlink to /private/tmp.
  assert.equal(fs.realpathSync(resolveProjectRoot(nested)), fs.realpathSync(root));
});

test('lastUserPrompt recovers the last human prompt from a transcript', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rubric-transcript-'));
  const file = path.join(dir, 't.jsonl');
  const lines = [
    JSON.stringify({ type: 'user', isMeta: true, message: { role: 'user', content: '<system reminder>' } }),
    JSON.stringify({ type: 'user', message: { role: 'user', content: 'refactor the auth module to use JWT' } }),
    JSON.stringify({ type: 'assistant', message: { role: 'assistant', content: [{ type: 'text', text: 'on it' }] } }),
    // A tool result rides as a user-role turn — must NOT be picked as the prompt.
    JSON.stringify({ type: 'user', message: { role: 'user', content: [{ type: 'tool_result', content: 'ok' }] } }),
  ];
  fs.writeFileSync(file, lines.join('\n') + '\n');
  assert.equal(lastUserPrompt(file), 'refactor the auth module to use JWT');
});

test('lastUserPrompt returns "" for a missing transcript', () => {
  assert.equal(lastUserPrompt('/no/such/transcript.jsonl'), '');
});

test('snapshot labels the commit with the prompt from the transcript', { skip: !gitAvailable }, () => {
  const root = makeRepo();
  const paths = makePaths();
  const transcript = path.join(root, 'transcript.jsonl');
  fs.writeFileSync(
    transcript,
    JSON.stringify({ type: 'user', message: { role: 'user', content: 'wipe the build and start over' } }) + '\n',
  );
  fs.writeFileSync(path.join(root, 'x.txt'), '1');
  snapshot({ paths, projectRoot: root, command: 'git clean -fd', sessionId: 's', transcriptPath: transcript });
  const [snap] = listSnapshots({ paths, projectRoot: root });
  assert.equal(snap.command, 'git clean -fd');
  assert.equal(snap.prompt, 'wipe the build and start over');
});

test('shadowGitDir is symlink-stable: a path and a symlink to it map to one shadow', () => {
  // Regression: the daemon snapshots from the hook's cwd (may be /tmp/x) while
  // `rubric undo` resolves process.cwd() (/private/tmp/x on macOS). If
  // shadowGitDir hashed the textual path they'd split into two shadows and
  // undo would find nothing. Hashing the realpath keeps them unified.
  const real = fs.mkdtempSync(path.join(os.tmpdir(), 'rubric-real-'));
  const aliasParent = fs.mkdtempSync(path.join(os.tmpdir(), 'rubric-alias-'));
  const alias = path.join(aliasParent, 'link');
  fs.symlinkSync(real, alias);
  const paths = { seatbeltDir: '/x/seatbelt' };
  assert.equal(shadowGitDir(paths, alias), shadowGitDir(paths, real));
});

test('resolveProjectRoot returns null outside any repo', () => {
  const lone = fs.mkdtempSync(path.join(os.tmpdir(), 'rubric-norepo-'));
  // os.tmpdir() itself is not a git repo, so walking up finds nothing.
  assert.equal(resolveProjectRoot(lone), null);
});
