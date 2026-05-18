// Bearer-token check for the loopback daemon.
//
// A 32-byte hex token stored in a 0600 file gates the daemon's
// endpoints. Only processes with read access to the user's
// `~/.config/rubric/` can issue requests.
//
// The token is inlined into Claude Code's `settings.json` so it never
// rides in environment variables or process trees.

import { timingSafeEqual } from 'node:crypto';

// Bearer scheme is case-insensitive per RFC 7235 §2.1. Accept any
// case (`Bearer `, `bearer `, `BEARER\t`) followed by ≥1 whitespace
// character. Anchored at the start of the header value.
const BEARER_SCHEME_REGEX = /^Bearer\s+/i;

// Both presented and expected tokens MUST match this shape — the
// daemon writes 64 hex chars at init, and `loadDaemonToken` in run.ts
// validates the file contents identically. Rejecting any other shape
// at this layer is belt-and-suspenders: it makes the `timingSafeEqual`
// branch unreachable for malformed input, and removes the need for a
// separate length check.
const HEX64_REGEX = /^[a-f0-9]{64}$/;

/**
 * Constant-time compare of an incoming Authorization header against the
 * daemon token. Returns false on any malformed input — never throws,
 * never short-circuits in a length-dependent way.
 *
 * The `authHeader` parameter accepts `string | string[] | undefined` to
 * match Node's IncomingHttpHeaders shape for headers that may be sent
 * multiple times. Array-valued (duplicated) headers are rejected.
 */
export function checkBearer(
  authHeader: string | string[] | undefined,
  expectedToken: string,
): boolean {
  // Reject duplicate / array-valued Authorization headers.
  if (typeof authHeader !== 'string') return false;
  // Belt-and-suspenders against a misconfigured / empty token file. The
  // boot-time check in `run.ts:loadDaemonToken` should make this branch
  // unreachable, but if it ever isn't, an empty `expectedToken` would
  // make every "Bearer " request succeed via timingSafeEqual([], []).
  if (!HEX64_REGEX.test(expectedToken)) return false;
  const match = BEARER_SCHEME_REGEX.exec(authHeader);
  if (match === null) return false;
  const presented = authHeader.slice(match[0].length);
  // Shape-check the presented token against the expected shape before
  // we hand bytes to `timingSafeEqual`. Cheap, and removes the need for
  // a separate length check — equal length is implied by both matching
  // `^[a-f0-9]{64}$`.
  if (!HEX64_REGEX.test(presented)) return false;
  try {
    return timingSafeEqual(Buffer.from(presented, 'utf8'), Buffer.from(expectedToken, 'utf8'));
  } catch {
    return false;
  }
}
