// Daemon logger setup. Thin wrapper over pino so the rest of the
// daemon imports a typed `createLogger` instead of instantiating pino
// in five places.

import * as fs from 'node:fs';
import * as path from 'node:path';

import pino, { type Logger } from 'pino';

export interface CreateLoggerOptions {
  /** Absolute path the log is written to. Parent directory is created. */
  logFile: string;
  /** Default 'info'. */
  level?: pino.LevelWithSilent;
  /** If true, also write to stderr (useful for `rubric start --foreground`). */
  alsoStderr?: boolean;
}

/**
 * Open the daemon's log file (creating its parent directory) and
 * return a pino logger writing to it. The destination is opened with
 * `O_APPEND` so concurrent daemon instances during start/stop races
 * don't truncate each other's output.
 */
export function createLogger(options: CreateLoggerOptions): Logger {
  fs.mkdirSync(path.dirname(options.logFile), { recursive: true });

  // pino's `destination(...)` opens the log file with the process
  // default umask (commonly 0022 → 0644). The daemon log can contain
  // session ids, decision metadata, and echoes of payload fragments,
  // so we want 0600. The sequence:
  //
  //   1. Create the file ourselves with `O_APPEND|O_CREAT` at mode 0600.
  //      `openSync(path, 'a', 0o600)` is equivalent. If it already
  //      exists, its mode is preserved by `open(2)` (no-op for the mode
  //      arg) so we follow with an explicit `chmodSync` to tighten
  //      previously-loose files.
  //   2. Hand the open path to pino. pino will reopen it in append mode
  //      and inherit the existing 0600 perms.
  try {
    const fd = fs.openSync(options.logFile, 'a', 0o600);
    fs.closeSync(fd);
    fs.chmodSync(options.logFile, 0o600);
  } catch {
    /* best-effort: an unusual filesystem that doesn't honor POSIX
       modes shouldn't take the daemon down. The logger will still
       open; we treat this as a soft failure. */
  }

  const fileDest = pino.destination({
    dest: options.logFile,
    sync: false,
    append: true,
    mkdir: true,
  });

  // `pino` accepts a single destination or a multistream array. We use
  // a multistream only when also writing to stderr, to keep the common
  // case zero-overhead.
  const destination = options.alsoStderr
    ? pino.multistream([{ stream: fileDest }, { stream: process.stderr }])
    : fileDest;

  return pino(
    {
      level: options.level ?? 'info',
      base: { pid: process.pid, hostname: undefined },
      timestamp: pino.stdTimeFunctions.isoTime,
    },
    destination,
  );
}

export type { Logger };
