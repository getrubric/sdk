// Daemon lifecycle: pidfile + port file + SIGTERM/SIGINT handlers.
//
// The pidfile guards against running two daemons against the same
// config dir (which would race on the daemon token and on settings.json
// patches). On `rubric start` the CLI checks this file before
// spawning; this module ensures it's removed on graceful shutdown so
// stale pidfiles don't permanently block a restart.

import * as fs from 'node:fs';

import { errCode } from '@rubric/core';

import { readFileSecure, writeFileSecure } from '../config/fs-secure.js';

import type { Logger } from './logger.js';

export interface PidGuardOptions {
  pidFile: string;
  logger: Logger;
}

export class PidGuard {
  private readonly _pidFile: string;
  private readonly _logger: Logger;
  private _claimed = false;

  constructor(options: PidGuardOptions) {
    this._pidFile = options.pidFile;
    this._logger = options.logger;
  }

  /**
   * Write pid to the pidfile. Throws if another live daemon is already
   * claimed.
   */
  claim(): void {
    if (existingDaemonAlive(this._pidFile)) {
      throw new Error(
        `daemon already running (see ${this._pidFile}); use 'rubric stop' first`,
      );
    }
    // Refuse symlinked pidfile destinations, chmod after write so 0600
    // sticks on overwrite. Write fresh — overwrites any stale pidfile
    // from a crashed daemon.
    writeFileSecure(this._pidFile, String(process.pid), { mode: 0o600 });
    this._claimed = true;
    this._logger.info({ pid: process.pid, pidFile: this._pidFile }, 'pidfile claimed');
  }

  release(): void {
    if (!this._claimed) return;
    try {
      fs.unlinkSync(this._pidFile);
    } catch (err: unknown) {
      // Already gone — fine. Any other error is logged but not fatal.
      if (errCode(err) !== 'ENOENT') {
        this._logger.warn({ err }, 'failed to remove pidfile');
      }
    }
    this._claimed = false;
  }
}

/**
 * Returns true if the pidfile names a process that's still alive.
 * `kill(pid, 0)` is the POSIX "is this pid valid?" probe — it doesn't
 * send a signal, only checks reachability.
 */
function existingDaemonAlive(pidFile: string): boolean {
  let raw: string;
  try {
    // Refuse symlinked pidfiles (O_NOFOLLOW + lstat pre-check).
    // A symlink to `/var/log/auth.log` would otherwise feed the first
    // line of that file into Number() — at best garbage, at worst a
    // valid PID that's not ours.
    raw = readFileSecure(pidFile);
  } catch (err: unknown) {
    if (errCode(err) === 'ENOENT') return false;
    throw err;
  }
  const pid = Number(raw.trim());
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err: unknown) {
    // ESRCH = no such process → not alive, definitely safe to claim.
    // EPERM = pid exists but we can't signal it. Treating EPERM as
    //   "alive" means a pidfile pointing at PID 1 (or any kernel/root
    //   process from a stale pidfile) permanently jams daemon start.
    //   We instead treat EPERM as "not our daemon — the pidfile is
    //   stale" and let the daemon proceed to overwrite it. The
    //   overwrite itself is safe (writeFileSecure refuses symlinks and
    //   chmods 0600); the worst case is we run alongside the
    //   pre-existing thing, which by definition isn't us anyway.
    return false;
  }
}

/**
 * Atomically write the daemon's bound port to disk so the CLI can find
 * a running daemon even when the OS-assigned fallback was used.
 */
export function writePortFile(portFile: string, port: number): void {
  // writeFileSecure with atomic:true does the same write-rename, but
  // additionally refuses symlink destinations and explicitly chmods to
  // 0600 after rename. (Port itself isn't a secret, but the temp file
  // and the consistency guarantees match the rest of configDir.)
  writeFileSecure(portFile, String(port), { mode: 0o600, atomic: true });
}

export function removePortFile(portFile: string): void {
  try {
    fs.unlinkSync(portFile);
  } catch (err: unknown) {
    if (errCode(err) !== 'ENOENT') throw err;
  }
}

export interface SignalHandlerOptions {
  logger: Logger;
  onShutdown: () => Promise<void>;
}

/**
 * Wire SIGTERM/SIGINT to a single-shot graceful shutdown. A second
 * signal force-exits so a hung shutdown can still be killed with two
 * Ctrl-Cs.
 */
export function installSignalHandlers(options: SignalHandlerOptions): void {
  let shuttingDown = false;
  const onSignal = (sig: NodeJS.Signals): void => {
    if (shuttingDown) {
      options.logger.warn({ sig }, 'second signal received; forcing exit');
      process.exit(1);
    }
    shuttingDown = true;
    options.logger.info({ sig }, 'shutdown signal received');
    options.onShutdown().then(
      () => process.exit(0),
      (err: unknown) => {
        options.logger.error({ err }, 'shutdown failed');
        process.exit(1);
      },
    );
  };
  process.once('SIGTERM', onSignal);
  process.once('SIGINT', onSignal);
}
