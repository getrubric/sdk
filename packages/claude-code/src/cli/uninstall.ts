// `rubric uninstall` — reverse what `rubric init` did.
//
// Order matters here. With launchd's `KeepAlive=true` (or systemd's
// `Restart=always`), the service manager respawns the daemon in the
// window between SIGTERM and service-disable, and the new daemon
// would outlive uninstall holding the bearer + port. So:
//
//   1. `uninstallService` — boot the unit out of launchd / disable in
//      systemd. The service manager stops respawning.
//   2. `runStop` — terminate any straggler daemon that was still
//      running when (1) ran.
//   3. Remove config dir + scrub settings.json.
//   4. Optionally remove the log file (--purge).

import * as fs from 'node:fs';

import { errCode } from '@rubric/core';

import { writeFileSecure } from '../config/fs-secure.js';
import { defaultPaths } from '../config/paths.js';

import { uninstallService } from '../config/services/index.js';
import { removeRubricHooks } from '../config/settings-json.js';
import { dim, info, ok, warn } from './_format.js';
import { runStop } from './stop.js';

export interface UninstallOptions {
  /** Also remove the log file (default: leave it for postmortem). */
  purge?: boolean;
  /** Don't touch the daemon — just remove files. */
  keepDaemon?: boolean;
}

export async function runUninstall(options: UninstallOptions = {}): Promise<void> {
  const paths = defaultPaths();

  if (!options.keepDaemon) {
    // Unload the service FIRST so the supervisor stops respawning.
    // Then runStop terminates any straggler. The reverse order (stop →
    // unload) lets launchd KeepAlive=true respawn the daemon in the gap.
    const svc = await uninstallService({ paths });
    if (svc.platform !== 'unsupported') {
      process.stdout.write(`${ok(`unloaded ${svc.platform} service`)}  ${dim(svc.message)}\n`);
    }

    // `runStop --force` here: the daemon may have already been killed
    // by `launchctl bootout` / `systemctl --now disable`, so the
    // authenticated shutdown path will likely time out. Force fallback
    // is OK because we just disabled the service manager — there's
    // nothing to race with.
    await runStop({ force: true }).catch(() => {
      /* stop already reported its error */
    });
  }

  // ---- Unpatch settings.json ----------------------------------------------
  // If the file is malformed JSON we back it up and write a minimal
  // valid settings ({}) so the bearer token never lingers on disk
  // after uninstall.
  await unpatchSettings(paths.claudeSettingsFile);

  // ---- Remove config dir --------------------------------------------------
  try {
    fs.rmSync(paths.configDir, { recursive: true, force: true });
    process.stdout.write(`${ok(`removed ${dim(paths.configDir)}`)}\n`);
  } catch (err: unknown) {
    process.stderr.write(
      `${warn(`could not remove ${paths.configDir}: ${(err as Error).message}`)}\n`,
    );
  }

  // ---- Optionally purge logs ---------------------------------------------
  if (options.purge) {
    try {
      fs.unlinkSync(paths.logFile);
      process.stdout.write(`${ok(`removed ${dim(paths.logFile)}`)}\n`);
    } catch (err: unknown) {
      if (errCode(err) !== 'ENOENT') {
        process.stderr.write(`${warn(`could not remove ${paths.logFile}`)}\n`);
      }
    }
  } else {
    process.stdout.write(`${info(`log file preserved at ${dim(paths.logFile)} (use --purge to remove)`)}\n`);
  }
}

async function unpatchSettings(settingsFile: string): Promise<void> {
  let raw: string;
  try {
    raw = fs.readFileSync(settingsFile, 'utf8');
  } catch (err: unknown) {
    if (errCode(err) === 'ENOENT') {
      process.stdout.write(`${info(`${settingsFile} not present; skipping`)}\n`);
      return;
    }
    process.stderr.write(
      `${warn(`could not read ${settingsFile}: ${(err as Error).message}`)}\n`,
    );
    return;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (parseErr: unknown) {
    // Rather than leaving the bearer token in a malformed file,
    // archive the malformed content and write a minimal valid
    // settings. The user can re-add their own hooks from the backup
    // afterward.
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupPath = `${settingsFile}.malformed-${stamp}.bak`;
    try {
      fs.writeFileSync(backupPath, raw, { encoding: 'utf8', mode: 0o600 });
      fs.chmodSync(backupPath, 0o600);
    } catch (backupErr: unknown) {
      // If we can't even back it up, refuse to clobber — the bearer
      // is then still on disk, but at least we haven't silently
      // destroyed the user's content.
      process.stderr.write(
        `${warn(
          `${settingsFile} is malformed JSON (${(parseErr as Error).message}) and ` +
            `the backup write also failed (${(backupErr as Error).message}); ` +
            `not modifying. The daemon bearer token may still be in this file — ` +
            `edit it by hand to remove.`,
        )}\n`,
      );
      return;
    }
    // Write an empty object, atomically so a SIGKILL never leaves the
    // file in a worse shape than we found it.
    writeFileSecure(settingsFile, '{}\n', { mode: 0o600, atomic: true });
    process.stderr.write(
      `${warn(
        `${settingsFile} was malformed JSON; backed up to ${dim(backupPath)} ` +
          `and reset to '{}' so the daemon bearer token doesn't linger on disk.`,
      )}\n`,
    );
    return;
  }

  const cleaned = removeRubricHooks(parsed);
  // Atomic write-rename, refuse symlinks, explicit chmod after write
  // so 0600 sticks (the user may have had this file at 0644 before init).
  writeFileSecure(settingsFile, JSON.stringify(cleaned, null, 2) + '\n', {
    mode: 0o600,
    atomic: true,
  });
  process.stdout.write(`${ok(`cleaned ${dim(settingsFile)}`)}\n`);
}
