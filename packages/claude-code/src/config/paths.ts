// Platform-aware default paths for the Rubric Claude Code adapter.
//
// All paths are resolved relative to `os.homedir()`. The CLI and daemon
// both consume `defaultPaths()`; tests pass a `Paths` literal so the
// effective layout is always explicit.

import * as os from 'node:os';
import * as path from 'node:path';

export interface Paths {
  /** `~/.config/rubric/` — config, enrollment token, daemon.token. */
  configDir: string;
  /** JSON file with { apiUrl, agentName, enrollmentToken, daemonPort? }. */
  configFile: string;
  /** 32-byte hex string, 0600. The hooks send this as the bearer to the daemon. */
  daemonTokenFile: string;
  /** Process ID of the running daemon. Removed on graceful shutdown. */
  pidFile: string;
  /** Captured at startup — the port the daemon actually bound to. */
  daemonPortFile: string;
  /** pino destination. macOS conventionally uses `~/Library/Logs/`; Linux uses `$XDG_STATE_HOME` or `~/.local/state/`. */
  logFile: string;
  /** `~/.claude/settings.json` — Claude Code's user settings. */
  claudeSettingsFile: string;
  /**
   * Shell script the Claude Code hook invokes before each Rubric http
   * hook. Curls the daemon's `/healthz` and, on miss, kicks the
   * service via the platform's service manager so a downed daemon
   * self-heals before the http hook fires.
   */
  ensureDaemonScriptFile: string;
  /** Solo mode: the editable local policy pack the daemon enforces. */
  policiesFile: string;
  /** Random anonymous install id for opt-out telemetry (not a user id). */
  telemetryIdFile: string;
}

/**
 * Resolve the conventional paths for the current user + platform.
 *
 * `XDG_CONFIG_HOME` / `XDG_STATE_HOME` are honored if set so the daemon
 * fits into a non-default XDG layout without surprise. Windows isn't
 * supported in MVP (see plan, Non-goals).
 */
export function defaultPaths(home: string = os.homedir(), platform: NodeJS.Platform = process.platform): Paths {
  const xdgConfigHome = process.env['XDG_CONFIG_HOME'] || path.join(home, '.config');
  const configDir = path.join(xdgConfigHome, 'rubric');

  let logBase: string;
  if (platform === 'darwin') {
    logBase = path.join(home, 'Library', 'Logs', 'rubric');
  } else {
    const xdgStateHome = process.env['XDG_STATE_HOME'] || path.join(home, '.local', 'state');
    logBase = path.join(xdgStateHome, 'rubric');
  }

  return {
    configDir,
    configFile: path.join(configDir, 'config.json'),
    daemonTokenFile: path.join(configDir, 'daemon.token'),
    pidFile: path.join(configDir, 'daemon.pid'),
    daemonPortFile: path.join(configDir, 'daemon.port'),
    logFile: path.join(logBase, 'claude-code.log'),
    claudeSettingsFile: path.join(home, '.claude', 'settings.json'),
    ensureDaemonScriptFile: path.join(configDir, 'ensure-daemon.sh'),
    policiesFile: path.join(configDir, 'policies.json'),
    telemetryIdFile: path.join(configDir, 'telemetry-id'),
  };
}
