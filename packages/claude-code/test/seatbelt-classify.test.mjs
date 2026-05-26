// Unit tests for the seatbelt command classifier.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { isDestructiveGit } from '../dist/seatbelt/classify.js';

test('destructive git commands are flagged', () => {
  const destructive = [
    'git reset --hard HEAD~1',
    'git reset --hard',
    'git reset --merge origin/main',
    'git checkout -- .',
    'git checkout -- src/index.ts',
    'git checkout .',
    'git restore src/app.ts',
    'git clean -fd',
    'git clean -f',
    'git clean -fdx',
    'git clean --force',
    'git stash drop',
    'git stash clear',
    'git rebase main',
    'git rebase -i HEAD~3',
    'git branch -D feature',
    'cd /tmp && git reset --hard HEAD',
  ];
  for (const cmd of destructive) {
    assert.equal(isDestructiveGit(cmd), true, `expected destructive: ${cmd}`);
  }
});

test('destructive git survives the global-option block and flag reordering', () => {
  const commands = [
    'git -C /path reset --hard', // -C <dir> global option before subcommand
    'git -c core.x=y reset --hard', // -c <k=v> global option before subcommand
    'git --git-dir=/r/.git checkout -- .', // attached global option
    'git --work-tree=/r checkout -- .',
    'git clean -d -f', // force split into its own token, reordered
    'git clean -f -d',
    'git checkout -f', // force discards the worktree
    'git checkout --force',
    'git checkout HEAD~1 -- file', // ref before the pathspec separator
    'git restore --staged --worktree file', // --worktree discards despite --staged
    'GIT_DIR=/r/.git git reset --hard', // leading env-assignment
    'git -C /path clean -d -f',
  ];
  for (const cmd of commands) {
    assert.equal(isDestructiveGit(cmd), true, `expected destructive: ${cmd}`);
  }
});

test('safe / non-discarding commands are not flagged', () => {
  const safe = [
    'git status',
    'git log --oneline',
    'git commit -m "wip"',
    'git add -A',
    'git restore --staged src/app.ts', // unstaging only, not a worktree discard
    'git rebase --abort',
    'git rebase --continue',
    'git reset --soft HEAD~1', // soft reset keeps the worktree
    'git checkout main', // switching branches, not discarding paths
    'git branch -d merged-branch', // safe delete (lowercase d, no --force)
    'ls -la',
    'rm -rf /tmp/scratch',
    'git -C /path status', // global option before a safe subcommand
    'git --git-dir=/r/.git log', // attached global option, safe subcommand
    'git -c core.pager=cat diff', // -c <k=v> then safe subcommand
    'git restore --staged src/app.ts', // unstaging only (no --worktree)
    'git checkout -b new-feature', // creating/switching branch, not discarding
    'cd /tmp/.git/checkout && ls', // path containing "git checkout", not a git cmd
    'echo git reset --hard', // mentions the command but does not run git
  ];
  for (const cmd of safe) {
    assert.equal(isDestructiveGit(cmd), false, `expected safe: ${cmd}`);
  }
});

test('empty input is not flagged', () => {
  assert.equal(isDestructiveGit(''), false);
});
