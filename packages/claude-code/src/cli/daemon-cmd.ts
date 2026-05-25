// `rubric daemon` — runs the long-lived daemon. Calls `runDaemon()`
// with the persisted config. Used by:
//   - `rubric init` (spawn detached)
//   - launchd plist / systemd unit
//   - operators running it directly with --foreground for debugging
//
// This is the *only* call site for `runDaemon()` with persisted state
// — it owns the config-file-to-daemon-args translation.

import { runDaemon } from '../daemon/index.js';
import { defaultPaths } from '../config/paths.js';

import { readConfig } from './_config.js';
import { fatal } from './_format.js';

export interface DaemonCmdOptions {
  /** Tee logs to stderr so they're visible when run interactively. */
  foreground?: boolean;
  /** Override the log level. */
  logLevel?: 'trace' | 'debug' | 'info' | 'warn' | 'error' | 'fatal';
}

export async function runDaemonCmd(options: DaemonCmdOptions = {}): Promise<void> {
  const paths = defaultPaths();
  let config: ReturnType<typeof readConfig>;
  try {
    config = readConfig(paths.configFile);
  } catch (err: unknown) {
    fatal((err as Error).message);
  }
  // runDaemon's Promise resolves on graceful shutdown — it installs
  // SIGTERM/SIGINT handlers internally, so we just await it.
  await runDaemon({
    config: {
      mode: config.mode,
      ...(config.apiUrl !== undefined ? { apiUrl: config.apiUrl } : {}),
      agentName: config.agentName,
      ...(config.enrollmentToken !== undefined ? { enrollmentToken: config.enrollmentToken } : {}),
      ...(config.daemonPort !== undefined ? { daemonPort: config.daemonPort } : {}),
      ...(config.telemetry !== undefined ? { telemetry: config.telemetry } : {}),
    },
    paths,
    ...(options.logLevel ? { logLevel: options.logLevel } : {}),
    ...(options.foreground ? { alsoStderr: true } : {}),
  });
}
