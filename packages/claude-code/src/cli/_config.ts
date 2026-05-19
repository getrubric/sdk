// Persistent config (`~/.config/rubric/config.json`) — read/write helpers.
//
// One file holds everything `rubric daemon` needs to bootstrap:
//   - apiUrl, agentName, enrollmentToken (passed to bootstrapTokenStore)
//   - daemonPort  (optional — defaults to 47821, falls back to OS-assigned)
//
// All values are validated with zod on read so a manually-edited file
// surfaces a clear error rather than crashing the daemon at runtime.

import * as fs from 'node:fs';
import * as path from 'node:path';

import { errCode, validateApiUrl } from '@rubric-app/core';
import { z } from 'zod';

import { readFileSecure, writeFileSecure } from '../config/fs-secure.js';

// Re-export so existing imports from `../cli/_config` keep working.
export { validateApiUrl };

export const PersistedConfigSchema = z.object({
  apiUrl: z
    .string()
    .url()
    .refine(
      (v) => validateApiUrl(v) === null,
      (v) => ({ message: validateApiUrl(v) ?? 'invalid' }),
    ),
  agentName: z.string().min(1).max(128),
  // Enrollment is idempotent on agentName; we keep the token so the
  // daemon can re-enroll on every cold boot (matches Python SDK).
  enrollmentToken: z.string().min(1),
  daemonPort: z.number().int().min(1).max(65535).optional(),
});
export type PersistedConfig = z.infer<typeof PersistedConfigSchema>;

export function readConfig(configFile: string): PersistedConfig {
  let raw: string;
  try {
    raw = fs.readFileSync(configFile, 'utf8');
  } catch (err: unknown) {
    if (errCode(err) === 'ENOENT') {
      throw new Error(`config not found at ${configFile}; run 'rubric init' first`);
    }
    throw err;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err: unknown) {
    throw new Error(`config at ${configFile} is not valid JSON: ${(err as Error).message}`);
  }
  const result = PersistedConfigSchema.safeParse(parsed);
  if (!result.success) {
    throw new Error(
      `config at ${configFile} is invalid: ${result.error.issues
        .map((i) => `${i.path.join('.')}: ${i.message}`)
        .join('; ')}`,
    );
  }
  return result.data;
}

export function writeConfig(configFile: string, value: PersistedConfig): void {
  // Validate on the way out so we never write a malformed file.
  const validated = PersistedConfigSchema.parse(value);
  fs.mkdirSync(path.dirname(configFile), { recursive: true });
  // Refuse symlink targets, chmod after write so 0600 sticks on
  // overwrite, atomic write-rename so a SIGKILL never leaves a
  // half-written file with the enrollment token on disk.
  writeFileSecure(configFile, JSON.stringify(validated, null, 2) + '\n', {
    mode: 0o600,
    atomic: true,
  });
}

export function configExists(configFile: string): boolean {
  try {
    fs.accessSync(configFile, fs.constants.R_OK);
    return true;
  } catch {
    return false;
  }
}

export function readDaemonPort(portFile: string): number | null {
  let raw: string;
  try {
    raw = fs.readFileSync(portFile, 'utf8');
  } catch (err: unknown) {
    if (errCode(err) === 'ENOENT') return null;
    throw err;
  }
  const n = Number(raw.trim());
  if (!Number.isInteger(n) || n <= 0 || n > 65535) return null;
  return n;
}

export function readDaemonPid(pidFile: string): number | null {
  let raw: string;
  try {
    // Refuse symlinked pidfiles. A symlink to e.g. /var/log/auth.log
    // would leak the first line into Number() parsing — at best
    // garbage, at worst nudges `rubric stop` toward SIGTERMing an
    // unrelated PID.
    raw = readFileSecure(pidFile);
  } catch (err: unknown) {
    if (errCode(err) === 'ENOENT') return null;
    throw err;
  }
  const n = Number(raw.trim());
  if (!Number.isInteger(n) || n <= 0) return null;
  // Verify the pid is alive — pidfile may be stale.
  try {
    process.kill(n, 0);
    return n;
  } catch (err: unknown) {
    // ESRCH = no such process — stale pidfile, return null so callers
    //   treat it as "no daemon running".
    // EPERM = pid exists but we can't signal it. We refuse to claim
    //   this as "our daemon": EPERM on a pid we should own means the
    //   pidfile points at *not* our daemon (PID 1, a kernel process,
    //   another user's process, etc.). Returning null here means
    //   `rubric stop` and `rubric doctor` treat the pid as absent
    //   rather than silently SIGTERMing whatever it points to.
    return null;
  }
}
