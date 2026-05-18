// `rubric stop` — graceful shutdown of the daemon.
//
// Flow:
//   1. Read daemon-token and daemon-port. POST /v1/shutdown with the
//      bearer. Authenticated shutdown = proof the pid is actually our
//      daemon (only our daemon has the matching token).
//   2. On 202: wait up to 5s for the process to exit (poll
//      `kill(pid, 0)` purely as a liveness probe; not for identity).
//   3. On 401 or connection refused: the daemon at that pid is not
//      ours. Refuse to SIGTERM. `--force` bypasses this guard for the
//      legacy "kill any pidfile" behavior, which we leave available
//      for edge cases (stuck pre-1.0 daemon that doesn't speak
//      /v1/shutdown, etc.).
//   4. After exit, the daemon's own signal handler removes the
//      pidfile; we don't unlink it here.

import { errCode } from '@rubric-app/core';

import { defaultPaths } from '../config/paths.js';
import { readFileSecure } from '../config/fs-secure.js';

import { readDaemonPid, readDaemonPort } from './_config.js';
import { dim, fail, info, ok, warn } from './_format.js';

const SHUTDOWN_WAIT_MS = 6_000;
const POLL_INTERVAL_MS = 100;
const SHUTDOWN_REQUEST_TIMEOUT_MS = 2_000;

export interface StopOptions {
  /**
   * Fall back to raw SIGTERM against the pidfile when the daemon
   * doesn't respond to authenticated shutdown (401, network error, or
   * /v1/shutdown not implemented). Off by default — without it,
   * `rubric stop` refuses to signal a pid we can't prove is ours.
   */
  force?: boolean;
}

export async function runStop(options: StopOptions = {}): Promise<void> {
  const paths = defaultPaths();
  const pid = readDaemonPid(paths.pidFile);
  if (pid === null) {
    process.stdout.write(`${info('no daemon running')}\n`);
    return;
  }

  // ---- Try the authenticated shutdown path first --------------------------
  const port = readDaemonPort(paths.daemonPortFile);
  let token: string | null = null;
  try {
    token = readFileSecure(paths.daemonTokenFile).trim();
  } catch {
    /* token may be missing on a partial install — handled below */
  }

  let httpShutdownOk = false;
  if (port !== null && token !== null && /^[a-f0-9]{64}$/.test(token)) {
    try {
      const res = await fetch(`http://127.0.0.1:${port}/v1/shutdown`, {
        method: 'POST',
        headers: { authorization: `Bearer ${token}` },
        signal: AbortSignal.timeout(SHUTDOWN_REQUEST_TIMEOUT_MS),
      });
      if (res.status === 202) {
        process.stdout.write(
          `${info(`requested shutdown of pid ${pid}; waiting up to ${SHUTDOWN_WAIT_MS / 1000}s…`)}\n`,
        );
        httpShutdownOk = true;
      } else if (res.status === 401) {
        // The daemon answered but rejected our bearer — the pid in
        // daemon.pid points at *something*, but not the daemon we
        // enrolled. Refuse to SIGTERM by default.
        if (!options.force) {
          process.stderr.write(
            `${fail(
              `pid ${pid} responded but rejected our token; not signaling. ` +
                `Re-run 'rubric init' or use 'rubric stop --force' to SIGTERM anyway.`,
            )}\n`,
          );
          process.exit(1);
        }
        process.stderr.write(
          `${warn(`pid ${pid} rejected our token; --force given, falling back to SIGTERM`)}\n`,
        );
      } else {
        // Some other status — old daemon, broken proxy, etc.
        if (!options.force) {
          process.stderr.write(
            `${fail(
              `pid ${pid} returned HTTP ${res.status} from /v1/shutdown; not signaling. ` +
                `Use 'rubric stop --force' to SIGTERM by pidfile.`,
            )}\n`,
          );
          process.exit(1);
        }
        process.stderr.write(
          `${warn(`pid ${pid} returned HTTP ${res.status}; --force given, falling back to SIGTERM`)}\n`,
        );
      }
    } catch (err: unknown) {
      // Connection refused / timeout: either the daemon's HTTP server
      // is down (but the process is still there) or the pid in
      // daemon.pid points at a totally unrelated process. Refuse to
      // signal without --force.
      if (!options.force) {
        process.stderr.write(
          `${fail(
            `could not reach daemon shutdown endpoint on :${port}: ${(err as Error).message}. ` +
              `Refusing to SIGTERM pid ${pid} without identity proof. ` +
              `Use 'rubric stop --force' to bypass (only if you trust the pidfile).`,
          )}\n`,
        );
        process.exit(1);
      }
      process.stderr.write(
        `${warn(
          `daemon shutdown endpoint unreachable: ${(err as Error).message}; --force given, falling back to SIGTERM`,
        )}\n`,
      );
    }
  } else if (!options.force) {
    process.stderr.write(
      `${fail(
        `cannot authenticate shutdown (missing port or token). ` +
          `Use 'rubric stop --force' to SIGTERM by pidfile, ` +
          `or 're-run rubric init' to repair the install.`,
      )}\n`,
    );
    process.exit(1);
  }

  // ---- Fallback / post-202 wait: deliver SIGTERM if requested ------------
  if (!httpShutdownOk && options.force) {
    try {
      process.kill(pid, 'SIGTERM');
    } catch (err: unknown) {
      if (errCode(err) === 'ESRCH') {
        process.stdout.write(`${info(`pid ${pid} not found — stale pidfile`)}\n`);
        return;
      }
      process.stderr.write(`${fail(`could not signal pid ${pid}: ${(err as Error).message}`)}\n`);
      process.exit(1);
    }
    process.stdout.write(
      `${info(`sent SIGTERM to pid ${pid} (--force); waiting up to ${SHUTDOWN_WAIT_MS / 1000}s…`)}\n`,
    );
  }

  // ---- Wait for exit -----------------------------------------------------
  const deadline = Date.now() + SHUTDOWN_WAIT_MS;
  while (Date.now() < deadline) {
    try {
      process.kill(pid, 0);
    } catch {
      process.stdout.write(`${ok(`daemon stopped ${dim(`(pid ${pid})`)}`)}\n`);
      return;
    }
    await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
  }
  process.stderr.write(
    `${fail(`pid ${pid} still alive after ${SHUTDOWN_WAIT_MS / 1000}s — send SIGKILL manually if needed`)}\n`,
  );
  process.exit(1);
}
