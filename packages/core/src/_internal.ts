// Internal helpers shared across `@rubric/core` modules. The
// underscore-prefixed filename signals that callers consume these at
// their own risk — the surface is exported from `index.ts` as a
// convenience for the official adapter packages but is not covered by
// the public semver contract.

/**
 * Resolves when either `ms` milliseconds have passed or the signal aborts.
 * Returns true if aborted, false if the timer fired normally.
 *
 * The timer is `.unref()`d so a long sleep won't keep the Node process
 * alive on its own — long-running modules (identity refresh, bundle poll,
 * audit flush) are kept up by the daemon's HTTP server or by application
 * code, not by their internal timers.
 */
export function sleepOrAbort(ms: number, signal: AbortSignal): Promise<boolean> {
  if (signal.aborted) return Promise.resolve(true);
  return new Promise<boolean>((resolve) => {
    const onAbort = (): void => {
      clearTimeout(timer);
      signal.removeEventListener('abort', onAbort);
      resolve(true);
    };
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', onAbort);
      resolve(false);
    }, ms);
    timer.unref?.();
    signal.addEventListener('abort', onAbort, { once: true });
  });
}

/**
 * Best-effort read of `response.text()`.
 *
 * On success, returns the body text (subject to caller-side scrubbing — see
 * `scrubSecrets`). On a read failure (network reset mid-stream, decompression
 * error, etc.) returns a sentinel `<body unreadable: …>` string so that
 * downstream error messages aren't blind. Never throws.
 *
 * Callers that interpolate this into log lines or `Error` messages SHOULD
 * pass the result through `scrubSecrets` first.
 */
export async function safeText(res: Response): Promise<string> {
  try {
    return await res.text();
  } catch (err: unknown) {
    const code = err instanceof Error && 'code' in err ? String((err as { code: unknown }).code) : 'unknown';
    return `<body unreadable: ${code}>`;
  }
}

/**
 * Extracts a human-readable message from an `unknown` thrown value without
 * relying on an unsafe `as Error` cast. Use this anywhere we catch `err: unknown`
 * and want to interpolate `err.message` into an error message or log line.
 */
export function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * Extracts `err.code` from `unknown` thrown values — typically a
 * `NodeJS.ErrnoException` carrying a code like `'ENOENT'` or `'EPERM'`.
 * Returns `null` when the value isn't an `Error` or has no string-valued
 * `code`. Use this instead of `(err as NodeJS.ErrnoException).code`.
 */
export function errCode(err: unknown): string | null {
  if (err instanceof Error && 'code' in err) {
    const code = (err as { code: unknown }).code;
    return typeof code === 'string' ? code : null;
  }
  return null;
}

// ---- scrubSecrets ----------------------------------------------------------
//
// Patterns are intentionally conservative — false-positive redactions are
// cheap (you just lose a chunk of an error message), false-negatives (a real
// secret leaking into a pino log file or a daemon error message) are not.
//
// Order matters in a few places: JWT must run before generic base64-ish so
// the dot-separated triplet is collapsed into one `<redacted>` token rather
// than three. `Bearer` must run before generic base64-ish so the literal
// `Bearer ` prefix is preserved in the redacted output (helpful for ops).
// `postgres://` must run before generic base64-ish so the URL shape is
// recognizable in the redacted output.
//
// All patterns are anchored with `\b` where the surrounding character class
// allows; we deliberately do NOT anchor on `^…$` because the input is
// typically an error message with secrets embedded mid-string.
const PROVIDER_PATTERNS: readonly RegExp[] = [
  /sk-[A-Za-z0-9]{20,}/g,
  /ghp_[A-Za-z0-9]{20,}/g,
  /xox[bpas]-[A-Za-z0-9-]{20,}/g,
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\benr_[A-Za-z0-9_-]+/g,
];

const JWT_PATTERN = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g;
const BEARER_PATTERN = /Bearer\s+[A-Za-z0-9._\-=+/]{16,}/g;
const HEX64_PATTERN = /\b[a-f0-9]{64}\b/g;
const POSTGRES_URL_PATTERN = /postgres(?:ql)?:\/\/[^@\s]+:[^@\s]+@/g;
// Catches generic base64url / base64-ish blobs. Kept last because the more
// specific patterns above produce more useful redactions.
const BASE64ISH_PATTERN = /\b[A-Za-z0-9+/_-]{24,}={0,2}\b/g;

/**
 * Replace likely secrets in `s` with `<redacted>` (or a shape-preserving
 * equivalent). Designed for interpolation into error messages and log lines.
 *
 * **Patterns covered (in priority order):**
 *  - JWT triplets — `eyJ…\.eyJ…\.…`
 *  - `Authorization: Bearer …` headers — preserves the literal `Bearer` prefix
 *  - Postgres URLs with embedded credentials — `postgres(ql)?://user:pw@host`
 *    → `postgres(ql)?://<redacted>@host`
 *  - Provider-shape API keys: `sk-…`, `ghp_…`, `xox[bpas]-…`, AWS `AKIA…`,
 *    Rubric enrollment tokens `enr_…`
 *  - Daemon-shape 64-char hex tokens — `\b[a-f0-9]{64}\b`
 *  - Generic base64url-ish blobs of ≥ 24 chars (last-resort catch-all)
 *
 * **Not idempotent on edge cases:** running the output back through
 * `scrubSecrets` is safe and a no-op, but the regex over-redacts long
 * hexadecimal hashes (e.g. SHA-256 content hashes) — that's an intentional
 * trade-off, content hashes in error strings are not load-bearing.
 *
 * Intended consumers:
 *   - Identity / bundle / audit-sink — wrap every `safeText(res)`
 *     interpolation into a `GovernanceError` message.
 *   - Adapter daemons — wrap any log line that includes raw
 *     tool-input or tool-response payloads.
 *
 * @param s Any string. Non-string inputs should be `String()`-coerced by the caller.
 * @returns A copy of `s` with each matched pattern replaced. Returns `s`
 *          unchanged if no patterns matched.
 */
export function scrubSecrets(s: string): string {
  if (s.length === 0) return s;
  let out = s;
  out = out.replace(JWT_PATTERN, '<redacted:jwt>');
  out = out.replace(BEARER_PATTERN, 'Bearer <redacted>');
  out = out.replace(POSTGRES_URL_PATTERN, (m) => {
    // Preserve the scheme so the shape is recognizable in logs.
    const scheme = m.startsWith('postgresql') ? 'postgresql' : 'postgres';
    return `${scheme}://<redacted>@`;
  });
  for (const pattern of PROVIDER_PATTERNS) {
    out = out.replace(pattern, '<redacted:secret>');
  }
  out = out.replace(HEX64_PATTERN, '<redacted:hex64>');
  out = out.replace(BASE64ISH_PATTERN, '<redacted:blob>');
  return out;
}
