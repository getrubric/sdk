// Secure file-writing helper for secret-bearing files (daemon.token,
// config.json, daemon.pid, ~/.claude/settings.json, launchd plist,
// systemd unit).
//
// Guarantees:
//   - mode sticks on overwrite (explicit chmod after every write).
//   - symlink destinations are refused via `lstat` pre-check + `O_NOFOLLOW`.
//   - atomic mode writes to `<path>.tmp` then renames over destination,
//     so a SIGKILL mid-write never leaves a half-written file.
//
// Behavior:
//   1. `lstat(path)` — if exists and is a symlink → throw.
//   2. If exists and is a regular file owned by another UID → throw.
//   3. Open destination with `O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW`
//      (or `O_EXCL` instead of `O_TRUNC` when `atomic` since we're
//      writing to a temp path that should never pre-exist).
//   4. Write content, `fsync`, close.
//   5. Explicit `fs.chmodSync(path, opts.mode)` regardless of whether
//      the file pre-existed.
//   6. If `atomic: true`: write+chmod the `.tmp` file, then `renameSync`
//      over destination. `rename(2)` is atomic on POSIX within the same
//      filesystem; consumers see either the old or the new content,
//      never a half-written file.

import * as fs from 'node:fs';

import { errCode } from '@rubric/core';

export interface WriteFileSecureOptions {
  /** Final file mode (e.g. 0o600). Always applied via explicit chmod. */
  mode: number;
  /**
   * Write to `<path>.tmp` then rename over `path`. Use for files that
   * other processes may read concurrently (settings.json, port file).
   */
  atomic?: boolean;
}

/**
 * Write a file with strict ownership / symlink / mode guarantees.
 * Throws on any condition that could cause a secret to leak or land
 * in the wrong place.
 */
export function writeFileSecure(
  filePath: string,
  content: string | Buffer,
  opts: WriteFileSecureOptions,
): void {
  if (opts.atomic) {
    const tmpPath = `${filePath}.tmp`;
    // Clean up a stale tmp from a prior crashed write before checking.
    // We still refuse if the stale tmp is a symlink.
    try {
      const tmpStat = fs.lstatSync(tmpPath);
      if (tmpStat.isSymbolicLink()) {
        throw new Error(
          `writeFileSecure: refuses to follow symlink at temp path ${tmpPath}`,
        );
      }
      // Best-effort unlink; if it fails the O_EXCL open below will
      // surface a clearer error.
      fs.unlinkSync(tmpPath);
    } catch (err: unknown) {
      const code = errCode(err);
      const message = err instanceof Error ? err.message : '';
      if (code !== 'ENOENT' && !message.startsWith('writeFileSecure:')) {
        // Pass through unexpected lstat errors; ENOENT is fine.
        throw err;
      }
      if (message.startsWith('writeFileSecure:')) throw err;
    }
    writeOnce(tmpPath, content, opts.mode, /* exclusive */ true);
    // Renames over a symlinked destination would replace the target;
    // check before we rename. Also covers the case where destination
    // is a symlink to a regular file we don't want to overwrite.
    assertNotSymlink(filePath);
    fs.renameSync(tmpPath, filePath);
    // rename(2) preserves the source's mode (already chmod'd above)
    // but be explicit so the final state is observable from the call
    // site without inspecting the helper.
    fs.chmodSync(filePath, opts.mode);
    return;
  }

  assertSafeDestination(filePath);
  writeOnce(filePath, content, opts.mode, /* exclusive */ false);
}

/**
 * Open `path` with `O_RDONLY | O_NOFOLLOW`, read it, and return the
 * contents as a UTF-8 string. Refuses symlinked sources — used for
 * reading the pidfile and the daemon token where a symlinked file
 * could redirect us into another user's file.
 */
export function readFileSecure(filePath: string): string {
  // lstat first so we can produce a clear "symlink refused" error
  // rather than the more cryptic ELOOP / ENOTDIR that O_NOFOLLOW
  // surfaces.
  const st = fs.lstatSync(filePath);
  if (st.isSymbolicLink()) {
    throw new Error(`readFileSecure: refuses to follow symlink at ${filePath}`);
  }
  const fd = fs.openSync(filePath, fs.constants.O_RDONLY | O_NOFOLLOW());
  try {
    // fs.readFileSync accepts a numeric fd. Every file we read this way
    // is small (pidfile ~6 bytes, token 65 bytes).
    return fs.readFileSync(fd, { encoding: 'utf8' });
  } finally {
    fs.closeSync(fd);
  }
}

// ---- Internals ------------------------------------------------------------

function writeOnce(
  filePath: string,
  content: string | Buffer,
  mode: number,
  exclusive: boolean,
): void {
  // O_NOFOLLOW: if the path is a symlink, fail with ELOOP rather than
  //   following the link and writing to its target.
  // O_EXCL  (atomic temp path): fail if the file already exists.
  // O_TRUNC (in-place write):   start from a clean file.
  const baseFlags = fs.constants.O_WRONLY | fs.constants.O_CREAT | O_NOFOLLOW();
  const flags = baseFlags | (exclusive ? fs.constants.O_EXCL : fs.constants.O_TRUNC);
  // Pass the desired mode to open(2) as well; this covers the
  // create-from-fresh case where the file didn't exist. The explicit
  // chmodSync below covers the overwrite case.
  const fd = fs.openSync(filePath, flags, mode);
  try {
    if (typeof content === 'string') {
      fs.writeSync(fd, content, 0, 'utf8');
    } else {
      fs.writeSync(fd, content, 0, content.length, 0);
    }
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  // ALWAYS chmod after — `fs.writeFileSync(..., { mode })` and
  // even `open(..., O_CREAT, mode)` only apply `mode` on create. The
  // overwrite path silently keeps the prior (likely 0644) mode.
  fs.chmodSync(filePath, mode);
}

function assertSafeDestination(filePath: string): void {
  let st: fs.Stats | null = null;
  try {
    st = fs.lstatSync(filePath);
  } catch (err: unknown) {
    if (errCode(err) === 'ENOENT') return;
    throw err;
  }
  if (st.isSymbolicLink()) {
    throw new Error(`writeFileSecure: refuses to follow symlink at ${filePath}`);
  }
  if (!st.isFile()) {
    throw new Error(
      `writeFileSecure: refuses to write to non-regular file at ${filePath}`,
    );
  }
  // Ownership check — if a path we expect to own is owned by a
  // different UID we should refuse. (On systems without geteuid the
  // check is skipped: best-effort defense.)
  const myUid = process.geteuid?.();
  if (typeof myUid === 'number' && st.uid !== myUid) {
    throw new Error(
      `writeFileSecure: refuses to overwrite ${filePath}: owned by uid ${st.uid}, ` +
        `not ${myUid}`,
    );
  }
}

function assertNotSymlink(filePath: string): void {
  try {
    const st = fs.lstatSync(filePath);
    if (st.isSymbolicLink()) {
      throw new Error(`writeFileSecure: refuses to follow symlink at ${filePath}`);
    }
  } catch (err: unknown) {
    if (errCode(err) === 'ENOENT') return;
    throw err;
  }
}

/**
 * `O_NOFOLLOW` constant. Defined on every POSIX Node platform we
 * support (darwin, linux); Windows wouldn't expose it but the daemon
 * isn't supported there either (see paths.ts).
 */
function O_NOFOLLOW(): number {
  // Some Node versions don't expose `O_NOFOLLOW` on the
  // `fs.constants` type even though the value is defined; the cast
  // is a runtime no-op.
  const c = fs.constants as unknown as { O_NOFOLLOW?: number };
  if (typeof c.O_NOFOLLOW === 'number') return c.O_NOFOLLOW;
  // POSIX standard value on Linux is 0x20000; on macOS/BSD it's 0x100.
  // We refuse to silently degrade — if the constant isn't there, the
  // platform isn't one we support for the secure-write path.
  throw new Error(
    'writeFileSecure: O_NOFOLLOW not exposed by node:fs.constants on this platform',
  );
}

/**
 * After a `mkdirSync(..., { mode: 0o700 })`, ensure the directory's
 * actual mode is `0o700` even if it pre-existed at a wider mode.
 */
export function ensureDirMode(dir: string, mode: number): void {
  let st: fs.Stats;
  try {
    st = fs.lstatSync(dir);
  } catch {
    return; // directory doesn't exist (mkdir failed earlier) — bail
  }
  if (st.isSymbolicLink()) {
    throw new Error(`ensureDirMode: refuses to chmod symlink at ${dir}`);
  }
  if (!st.isDirectory()) {
    throw new Error(`ensureDirMode: not a directory at ${dir}`);
  }
  if ((st.mode & 0o777) !== (mode & 0o777)) {
    fs.chmodSync(dir, mode);
  }
}
