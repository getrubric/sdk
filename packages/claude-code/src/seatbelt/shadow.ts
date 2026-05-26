// Shadow-git mechanism for the seatbelt.
//
// Per project root we keep a hidden "shadow" git repo whose GIT_DIR lives
// under `~/.config/rubric/seatbelt/<hash>/git` but whose work-tree is the
// developer's actual project. Snapshots commit the working tree into this
// shadow repo *without the real `.git` ever knowing* — the dotfiles "bare
// repo + --work-tree" trick. `rubric undo` restores from it.
//
// Every git invocation is a `spawnSync` (synchronous so the PreToolUse hook
// can snapshot before the tool runs) with a timeout. Snapshotting is
// best-effort: any failure (git missing, not a repo, timeout) is swallowed —
// the seatbelt is a safety net, never a gate on the developer's command.

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';

import type { Paths } from '../config/paths.js';

const GIT_TIMEOUT_MS = 15_000;

// Identity stamped on shadow commits. Never the developer's git identity —
// these commits live only in the shadow repo and shouldn't borrow their name.
const SHADOW_AUTHOR = ['-c', 'user.email=seatbelt@rubric.local', '-c', 'user.name=Rubric Seatbelt'];

// Directories we never want bloating the shadow repo even if they're not in
// the project's own .gitignore (the project's .gitignore is still honored on
// top of these). Written to a per-shadow excludes file wired via
// core.excludesFile.
const DEFAULT_EXCLUDES = [
  '.git/',
  'node_modules/',
  'dist/',
  'build/',
  '.next/',
  '.rubric/',
  'target/',
  'vendor/',
  '*.log',
];

// Marker subject line on every snapshot commit. The triggering command and
// session id ride in the body as `cmd:` / `session:` lines.
const SNAPSHOT_SUBJECT = 'rubric-snapshot';

export interface Snapshot {
  /** Full commit sha in the shadow repo. */
  sha: string;
  /** First 8 chars — what `rubric undo --list` prints and `--to` accepts. */
  shortSha: string;
  /** Committer date, ISO 8601. */
  date: string;
  /** The destructive command that triggered this snapshot (best-effort). */
  command: string;
  /** The user prompt the agent was acting on, read from the transcript (best-effort, may be ''). */
  prompt: string;
}

// Read at most this much of the transcript tail when recovering the last
// prompt — bounds the cost of the synchronous read on the snapshot path.
const TRANSCRIPT_TAIL_BYTES = 256 * 1024;

/**
 * Walk up from `cwd` looking for a `.git` entry; return the directory that
 * contains it (the project root), or null if none is found before `/`.
 * `.git` may be a directory (normal repo) or a file (worktree/submodule) —
 * either counts.
 */
export function resolveProjectRoot(cwd: string): string | null {
  let dir = path.resolve(cwd);
  // Bounded walk: stop at the filesystem root (parent === self).
  for (;;) {
    if (fs.existsSync(path.join(dir, '.git'))) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

/** GIT_DIR of the shadow repo for a given project root. */
export function shadowGitDir(paths: Paths, projectRoot: string): string {
  // Hash the *realpath* so the daemon (which snapshots from the hook's cwd)
  // and `rubric undo` (which resolves from process.cwd()) land on the same
  // shadow repo even when they reach the project through different symlinks —
  // e.g. macOS `/tmp` → `/private/tmp`. Hashing the textual `path.resolve`
  // would split those into two shadows and lose the undo history.
  const hash = createHash('sha256').update(realOrSelf(projectRoot)).digest('hex').slice(0, 12);
  return path.join(paths.seatbeltDir, hash, 'git');
}

/** Path to the per-shadow excludes file (sibling of the GIT_DIR). */
function excludesFile(gitDir: string): string {
  return path.join(path.dirname(gitDir), 'excludes');
}

interface GitResult {
  status: number | null;
  stdout: string;
  stderr: string;
  error?: Error;
}

/**
 * Run git against the shadow repo with the work-tree pointed at the real
 * project. The `--git-dir`/`--work-tree` flags take precedence over any
 * inherited GIT_* env vars, but we scrub those vars anyway so a daemon
 * launched inside someone's repo can't leak its GIT_DIR into our calls.
 */
function runGit(gitDir: string, workTree: string, args: string[]): GitResult {
  const env = { ...process.env };
  delete env['GIT_DIR'];
  delete env['GIT_WORK_TREE'];
  delete env['GIT_INDEX_FILE'];
  const res = spawnSync(
    'git',
    ['--git-dir', gitDir, '--work-tree', workTree, ...args],
    { encoding: 'utf8', timeout: GIT_TIMEOUT_MS, env, maxBuffer: 64 * 1024 * 1024 },
  );
  return {
    status: res.status,
    stdout: res.stdout ?? '',
    stderr: res.stderr ?? '',
    ...(res.error ? { error: res.error } : {}),
  };
}

function isInitialized(gitDir: string): boolean {
  return fs.existsSync(path.join(gitDir, 'HEAD'));
}

/**
 * Build the excludes-file contents for a shadow repo. Always includes the
 * defaults; additionally, if the shadow repo's own storage lives *inside* the
 * work-tree (e.g. a dotfiles repo rooted at `$HOME`, where
 * `~/.config/rubric/seatbelt` is under the work-tree), excludes that path so a
 * snapshot never captures — and a restore never corrupts — the shadow repo's
 * own files.
 */
function buildExcludes(gitDir: string, workTree: string): string {
  const lines = [...DEFAULT_EXCLUDES];
  // The seatbelt root is two levels up from the GIT_DIR (`<seatbelt>/<hash>/git`).
  const seatbeltRoot = path.dirname(path.dirname(gitDir));
  // Compare via realpath: on macOS the config dir and the work-tree can reach
  // the same files through different symlinks (`/var` vs `/private/var`), and
  // a textual relative path would then be wrongly `..`-prefixed and skip the
  // exclude. realpathSync may fail if a path doesn't exist yet — fall back.
  const rel = path.relative(realOrSelf(workTree), realOrSelf(seatbeltRoot));
  if (rel && !rel.startsWith('..') && !path.isAbsolute(rel)) {
    // gitignore-style, anchored to the work-tree root.
    lines.push(`/${rel.split(path.sep).join('/')}/`);
  }
  return lines.join('\n') + '\n';
}

function realOrSelf(p: string): string {
  try {
    return fs.realpathSync(p);
  } catch {
    return path.resolve(p);
  }
}

/** Initialize the shadow repo (idempotent) and wire its excludes file. */
function ensureInitialized(gitDir: string, workTree: string): void {
  if (isInitialized(gitDir)) return;
  fs.mkdirSync(path.dirname(gitDir), { recursive: true });
  const init = runGit(gitDir, workTree, ['init', '-q']);
  if (init.status !== 0) {
    throw new Error(`shadow git init failed: ${init.stderr.trim() || init.error?.message || 'unknown'}`);
  }
  const excludes = excludesFile(gitDir);
  fs.writeFileSync(excludes, buildExcludes(gitDir, workTree), { mode: 0o600 });
  runGit(gitDir, workTree, ['config', 'core.excludesFile', excludes]);
  // The shadow index/objects are ours alone; never sign these commits.
  runGit(gitDir, workTree, ['config', 'commit.gpgsign', 'false']);
}

function buildMessage(command: string, sessionId: string, prompt: string): string {
  // Strip newlines and cap each field so the commit message stays sane even
  // if the agent ran a heredoc / very long one-liner or the prompt is huge.
  const oneLine = command.replace(/\s+/g, ' ').trim().slice(0, 500);
  let msg = `${SNAPSHOT_SUBJECT}\n\ncmd: ${oneLine}\nsession: ${sessionId}`;
  const cleanPrompt = prompt.replace(/\s+/g, ' ').trim().slice(0, 200);
  if (cleanPrompt) msg += `\nprompt: ${cleanPrompt}`;
  return msg;
}

/**
 * Recover the most recent *human* user prompt from a Claude Code transcript
 * (JSONL). Reads only the tail of the file and scans backwards for the last
 * user-role text message that isn't a tool result or meta-injected message.
 * Best-effort: returns '' on any failure or unknown shape.
 */
export function lastUserPrompt(transcriptPath: string): string {
  try {
    const stat = fs.statSync(transcriptPath);
    const start = Math.max(0, stat.size - TRANSCRIPT_TAIL_BYTES);
    const len = stat.size - start;
    if (len <= 0) return '';
    const buf = Buffer.alloc(len);
    const fd = fs.openSync(transcriptPath, 'r');
    try {
      fs.readSync(fd, buf, 0, len, start);
    } finally {
      fs.closeSync(fd);
    }
    const lines = buf.toString('utf8').split('\n');
    for (let i = lines.length - 1; i >= 0; i--) {
      const line = lines[i]?.trim();
      if (!line) continue;
      let obj: unknown;
      try {
        obj = JSON.parse(line);
      } catch {
        // A truncated first line (we started mid-file) or non-JSON — skip.
        continue;
      }
      const text = extractUserText(obj);
      if (text) return text;
    }
  } catch {
    /* best-effort — prompt labeling is a nicety, never load-bearing */
  }
  return '';
}

/** Pull human-typed text out of one transcript entry, or '' if it isn't one. */
function extractUserText(entry: unknown): string {
  if (typeof entry !== 'object' || entry === null) return '';
  const e = entry as Record<string, unknown>;
  // Skip system-injected ("meta") user turns — they aren't human prompts.
  if (e['isMeta'] === true || e['type'] !== 'user') return '';
  const message = e['message'];
  if (typeof message !== 'object' || message === null) return '';
  const content = (message as Record<string, unknown>)['content'];
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) {
    // A turn carrying a tool_result is a tool response, not a human prompt.
    if (content.some((b) => (b as Record<string, unknown>)?.['type'] === 'tool_result')) {
      return '';
    }
    const texts = content
      .filter((b) => (b as Record<string, unknown>)?.['type'] === 'text')
      .map((b) => (b as Record<string, unknown>)['text'])
      .filter((t): t is string => typeof t === 'string');
    if (texts.length > 0) return texts.join(' ');
  }
  return '';
}

export interface SnapshotArgs {
  paths: Paths;
  projectRoot: string;
  command: string;
  sessionId: string;
  /** Claude Code transcript path; if given, the last user prompt labels the snapshot. */
  transcriptPath?: string;
  /** Best-effort warning sink (daemon logger). Optional. */
  onWarn?: (message: string) => void;
}

/**
 * Snapshot the project's working tree into the shadow repo. Best-effort:
 * returns true if a commit was created, false (with an optional warning) on
 * any failure. Never throws — callers can ignore the result.
 */
export function snapshot(args: SnapshotArgs): boolean {
  const { paths, projectRoot, command, sessionId, transcriptPath, onWarn } = args;
  const gitDir = shadowGitDir(paths, projectRoot);
  const prompt = transcriptPath ? lastUserPrompt(transcriptPath) : '';
  try {
    ensureInitialized(gitDir, projectRoot);
    // Stage everything in the work-tree (honoring .gitignore + our excludes).
    const add = runGit(gitDir, projectRoot, ['add', '-A']);
    if (add.status !== 0) {
      onWarn?.(`seatbelt: git add failed: ${add.stderr.trim() || add.error?.message || 'unknown'}`);
      return false;
    }
    // `--allow-empty` so a snapshot is recorded even when nothing changed
    // since the last one (gives `undo` a stable point to land on).
    const commit = runGit(gitDir, projectRoot, [
      ...SHADOW_AUTHOR,
      'commit',
      '--allow-empty',
      '--no-verify',
      '-q',
      '-m',
      buildMessage(command, sessionId, prompt),
    ]);
    if (commit.status !== 0) {
      onWarn?.(`seatbelt: git commit failed: ${commit.stderr.trim() || commit.error?.message || 'unknown'}`);
      return false;
    }
    return true;
  } catch (err: unknown) {
    onWarn?.(`seatbelt: snapshot failed: ${(err as Error).message}`);
    return false;
  }
}

export interface ListArgs {
  paths: Paths;
  projectRoot: string;
}

// Record/field separators: \x1e between commits, \x1f between fields. Chosen
// so multi-line commit bodies can't break the parse.
const RS = '\x1e';
const FS = '\x1f';

/**
 * List snapshots newest-first by reading the shadow repo's `git log`.
 * Returns [] if no shadow repo exists yet (nothing snapshotted). Throws only
 * on an unexpected git failure against an existing repo.
 */
export function listSnapshots(args: ListArgs): Snapshot[] {
  const gitDir = shadowGitDir(args.paths, args.projectRoot);
  if (!isInitialized(gitDir)) return [];
  const log = runGit(gitDir, args.projectRoot, [
    'log',
    `--format=%H${FS}%cI${FS}%B${RS}`,
  ]);
  if (log.status !== 0) {
    // A fresh repo with zero commits exits non-zero ("does not have any
    // commits yet") — treat as empty, not an error.
    if (/does not have any commits|bad default revision/i.test(log.stderr)) return [];
    throw new Error(`shadow git log failed: ${log.stderr.trim() || 'unknown'}`);
  }
  const out: Snapshot[] = [];
  for (const record of log.stdout.split(RS)) {
    const trimmed = record.replace(/^\s+/, '');
    if (!trimmed) continue;
    const [sha, date, body = ''] = trimmed.split(FS);
    if (!sha || !date) continue;
    const cmdMatch = body.match(/^cmd:\s*(.*)$/m);
    const promptMatch = body.match(/^prompt:\s*(.*)$/m);
    out.push({
      sha,
      shortSha: sha.slice(0, 8),
      date,
      command: cmdMatch?.[1]?.trim() ?? '(unknown)',
      prompt: promptMatch?.[1]?.trim() ?? '',
    });
  }
  return out;
}

export interface RestoreArgs {
  paths: Paths;
  projectRoot: string;
  /** Full or unambiguous-prefix sha of the snapshot to restore. */
  sha: string;
  sessionId?: string;
}

/**
 * Restore the working tree to a snapshot. First takes a fresh "redo"
 * snapshot of the current state (so the restore is itself reversible), then
 * makes the work-tree exactly match `sha` — restoring modified/deleted files
 * and removing files created after the snapshot. Throws on failure.
 *
 * Mechanics: `reset --hard <sha>` rewrites the work-tree to match the
 * snapshot, then `reset --soft <tip>` moves the branch ref back to the tip so
 * the snapshot history (including the redo point) stays intact and visible to
 * `--list`. Untracked-in-shadow files (excludes, node_modules, …) are left
 * untouched throughout.
 */
export function restore(args: RestoreArgs): void {
  const { paths, projectRoot, sha } = args;
  const gitDir = shadowGitDir(paths, projectRoot);
  if (!isInitialized(gitDir)) {
    throw new Error('no seatbelt snapshots exist for this project');
  }

  // Capture the current tip before we add the redo snapshot, so we can move
  // the branch ref back to it afterwards.
  const tipBefore = runGit(gitDir, projectRoot, ['rev-parse', 'HEAD']);
  if (tipBefore.status !== 0) {
    throw new Error('shadow repo has no commits to restore from');
  }

  // Redo point: snapshot the current (pre-restore) state.
  const redoOk = snapshot({
    paths,
    projectRoot,
    command: 'rubric undo (pre-restore safety snapshot)',
    sessionId: args.sessionId ?? 'rubric-undo',
  });
  const tip = redoOk
    ? runGit(gitDir, projectRoot, ['rev-parse', 'HEAD']).stdout.trim()
    : tipBefore.stdout.trim();

  // Make the work-tree match the target snapshot.
  const hard = runGit(gitDir, projectRoot, ['reset', '--hard', sha]);
  if (hard.status !== 0) {
    throw new Error(`restore failed: ${hard.stderr.trim() || 'unknown'}`);
  }
  // Move the branch ref back to the tip so history stays append-only and the
  // redo snapshot remains reachable; the work-tree (already restored) is left
  // as-is by --soft.
  const soft = runGit(gitDir, projectRoot, ['reset', '--soft', tip]);
  if (soft.status !== 0) {
    // Work-tree is already restored; failing to re-point the ref only loses
    // the redo point's reachability. Surface it but don't undo the restore.
    throw new Error(
      `restore succeeded but failed to re-point shadow history: ${soft.stderr.trim() || 'unknown'}`,
    );
  }
}
