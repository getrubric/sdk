// `rubric undo` — restore the working tree from a seatbelt snapshot.
//
// Operates directly on the per-project shadow repo (no daemon round-trip):
// undo is a local-filesystem op, so it works offline and even if the daemon
// is stopped. Default restores the most recent snapshot; `--list` shows them;
// `--to <sha>` restores a specific one.

import { defaultPaths } from '../config/paths.js';
import {
  listSnapshots,
  resolveProjectRoot,
  restore,
  type Snapshot,
} from '../seatbelt/shadow.js';

import { dim, fail, header, info, ok, warn } from './_format.js';

export interface UndoOptions {
  /** Just print the available snapshots and exit. */
  list?: boolean;
  /** Restore this specific snapshot (full or 8-char short sha). */
  to?: string;
}

export async function runUndo(options: UndoOptions = {}): Promise<void> {
  const paths = defaultPaths();
  const projectRoot = resolveProjectRoot(process.cwd());
  if (projectRoot === null) {
    process.stderr.write(
      `${fail('not inside a git project — the seatbelt only snapshots git working trees')}\n`,
    );
    process.exit(1);
  }

  let snapshots: Snapshot[];
  try {
    snapshots = listSnapshots({ paths, projectRoot });
  } catch (err: unknown) {
    process.stderr.write(`${fail((err as Error).message)}\n`);
    process.exit(1);
  }

  if (snapshots.length === 0) {
    process.stdout.write(
      `${info('No seatbelt snapshots yet for this project.')}\n` +
        `  ${dim('Snapshots are taken automatically before destructive git commands (reset --hard, clean -fd, …).')}\n`,
    );
    return;
  }

  if (options.list) {
    printList(snapshots);
    return;
  }

  // Pick the target: --to <sha> (prefix match) or the most recent.
  let target: Snapshot | undefined;
  if (options.to) {
    target = snapshots.find((s) => s.sha === options.to || s.shortSha === options.to || s.sha.startsWith(options.to as string));
    if (!target) {
      process.stderr.write(
        `${fail(`no snapshot matches "${options.to}"`)}\n  ${dim('run `rubric undo --list` to see available snapshots')}\n`,
      );
      process.exit(1);
    }
  } else {
    target = snapshots[0];
  }
  if (!target) {
    // Unreachable (we returned early on an empty list), but narrows the type.
    process.stderr.write(`${fail('no snapshot to restore')}\n`);
    process.exit(1);
  }

  process.stdout.write(
    `${warn('Stop your Claude Code session first if it is still running, so it does not race the restore.')}\n`,
  );
  try {
    restore({ paths, projectRoot, sha: target.sha });
  } catch (err: unknown) {
    process.stderr.write(`${fail((err as Error).message)}\n`);
    process.exit(1);
  }

  process.stdout.write(
    `${ok(`restored working tree to snapshot ${dim(target.shortSha)} (${timeAgo(target.date)})`)}\n` +
      (target.prompt ? `  ${dim(`task: ${target.prompt}`)}\n` : '') +
      `  ${dim(`taken before: ${target.command}`)}\n` +
      `  ${dim('a redo snapshot of the prior state was saved — `rubric undo --list` shows it.')}\n`,
  );
}

function printList(snapshots: Snapshot[]): void {
  process.stdout.write(`${header('Seatbelt snapshots')} ${dim('(newest first)')}\n\n`);
  for (const s of snapshots) {
    // Lead with the task (the prompt the agent was working on) when we have
    // it — that's what tells the user *which* point they want — then the
    // triggering command on a dimmed continuation line.
    if (s.prompt) {
      process.stdout.write(
        `  ${s.shortSha}  ${dim(timeAgo(s.date).padEnd(10))}  ${s.prompt}\n` +
          `            ${dim(`↳ ${s.command}`)}\n`,
      );
    } else {
      process.stdout.write(
        `  ${s.shortSha}  ${dim(timeAgo(s.date).padEnd(10))}  ${dim(s.command)}\n`,
      );
    }
  }
  process.stdout.write(
    `\n  ${dim('restore the latest: `rubric undo`   ·   a specific one: `rubric undo --to <sha>`')}\n`,
  );
}

/** Compact relative time ("3m ago", "2h ago") from an ISO timestamp. */
function timeAgo(iso: string): string {
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return iso;
  const secs = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.round(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.round(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  return `${days}d ago`;
}
