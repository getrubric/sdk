import { spawn } from 'node:child_process';

/**
 * Best-effort "open this URL in the user's browser". Returns true if we
 * managed to spawn an opener, false otherwise — callers always print the URL
 * as a fallback regardless, so a failure here is non-fatal (headless servers,
 * SSH sessions, locked-down environments).
 */
export function tryOpenBrowser(url: string): boolean {
  const cmd =
    process.platform === 'darwin'
      ? 'open'
      : process.platform === 'win32'
        ? 'cmd'
        : 'xdg-open';
  const args = process.platform === 'win32' ? ['/c', 'start', '', url] : [url];
  try {
    const child = spawn(cmd, args, { stdio: 'ignore', detached: true });
    child.on('error', () => {
      /* opener missing (e.g. no xdg-open) — fallback URL was already printed */
    });
    child.unref();
    return true;
  } catch {
    return false;
  }
}
