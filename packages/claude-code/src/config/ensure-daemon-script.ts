// Writer for `~/.config/rubric/ensure-daemon.sh`.
//
// The shell script runs before every Rubric Claude Code hook. It
// curls the daemon's `/healthz` endpoint; on a miss it kicks the
// platform's service manager (launchd on macOS, systemd-user on Linux)
// and polls for the daemon to come back up. The script always exits 0
// so a failure here falls through to the http hook, which is what
// surfaces real errors to Claude Code.

import * as fs from 'node:fs';
import * as path from 'node:path';

import { writeFileSecure } from './fs-secure.js';

export const LAUNCHD_LABEL = 'dev.rubric.claude-code';
export const SYSTEMD_UNIT = 'rubric-claude-code';

const HEALTHZ_FAST_TIMEOUT_S = 0.25;
const HEALTHZ_POLL_TIMEOUT_S = 0.1;
// 50 * 0.1s = ~5s, which covers a cold start (Node init + first bundle pull
// takes ~3s in practice). The script's overall wall time is bounded by
// `ENSURE_DAEMON_TIMEOUT_S` in settings-json.ts — that timeout is set
// above this budget so the script can finish its own poll loop.
const POLL_TICKS = 50;
// Don't enter the slow path more than once per ATTEMPT_COOLDOWN_S. With
// the cooldown, a broken install fails fast on every subsequent tool
// call instead of burning the full poll budget on each one — the user
// sees Claude Code's "hook failed" error sooner and can fix it.
const ATTEMPT_COOLDOWN_S = 30;

export interface EnsureDaemonScriptOptions {
  /** Host the daemon binds to. Almost always `127.0.0.1`. */
  daemonHost: string;
  /** Port the daemon binds to. Default install uses `47821`. */
  daemonPort: number;
}

/**
 * Render the ensure-daemon shell script for the given daemon endpoint.
 * Exported for tests so the rendered output can be asserted against
 * directly without having to write to disk.
 */
export function renderEnsureDaemonScript(options: EnsureDaemonScriptOptions): string {
  const { daemonHost, daemonPort } = options;
  return `#!/usr/bin/env sh
# Auto-revive the Rubric daemon if /healthz isn't responding. Generated
# by \`rubric init\` — do not edit; re-running init overwrites this file.
#
# Exits 0 unconditionally so a failed revive falls through to the http
# hook that follows, which is what surfaces a real error to Claude Code.

set -u

HEALTHZ="http://${daemonHost}:${daemonPort}/healthz"
ATTEMPT_FILE="\${TMPDIR:-/tmp}/rubric-ensure-daemon.last-attempt.$(id -u)"
COOLDOWN=${ATTEMPT_COOLDOWN_S}

# Fast path: daemon is up.
if curl -fsS -m ${HEALTHZ_FAST_TIMEOUT_S} "$HEALTHZ" >/dev/null 2>&1; then
  exit 0
fi

# Throttle the slow path so a broken install doesn't burn the full poll
# budget on every tool call — without this, a misconfigured daemon would
# make every Claude Code action wait ~5s before failing through.
NOW=$(date +%s)
LAST=0
if [ -f "$ATTEMPT_FILE" ]; then
  LAST=$(cat "$ATTEMPT_FILE" 2>/dev/null || echo 0)
fi
if [ "$((NOW - LAST))" -lt "$COOLDOWN" ]; then
  exit 0
fi
echo "$NOW" > "$ATTEMPT_FILE" 2>/dev/null || true

# Slow path: ask the platform service manager to bring the daemon up.
# bootstrap covers the case where the service was \`launchctl bootout\`-ed
# or never loaded (fresh reboot before the LaunchAgent loads). kickstart
# covers the case where the service is loaded but the process is hung.
# Both no-op when the precondition isn't met, so running them back-to-back
# is safe.
case "$(uname -s)" in
  Darwin)
    PLIST="$HOME/Library/LaunchAgents/${LAUNCHD_LABEL}.plist"
    # Probe whether launchd already knows about the service. kickstart only
    # works on loaded services; bootstrap only works on unloaded ones. Run
    # the right one for the current state instead of trying both — bootstrap
    # after bootstrap fails with "I/O error" on macOS until launchd's
    # internal cleanup catches up, which can drop the service entirely.
    if launchctl print "gui/$(id -u)/${LAUNCHD_LABEL}" >/dev/null 2>&1; then
      launchctl kickstart -k "gui/$(id -u)/${LAUNCHD_LABEL}" >/dev/null 2>&1 || true
    elif [ -f "$PLIST" ]; then
      launchctl bootstrap "gui/$(id -u)" "$PLIST" >/dev/null 2>&1 || true
    fi
    ;;
  Linux)
    systemctl --user restart ${SYSTEMD_UNIT} >/dev/null 2>&1 \\
      || systemctl --user start ${SYSTEMD_UNIT} >/dev/null 2>&1 \\
      || true
    ;;
esac

# Poll for the daemon to come back up. Bounded so the hook can't hang.
i=0
while [ "$i" -lt ${POLL_TICKS} ]; do
  if curl -fsS -m ${HEALTHZ_POLL_TIMEOUT_S} "$HEALTHZ" >/dev/null 2>&1; then
    exit 0
  fi
  sleep 0.1
  i=$((i + 1))
done

exit 0
`;
}

/**
 * Write the ensure-daemon script to disk at `scriptPath`. Mode is
 * `0755` (executable; the hook spawns it directly). Parent directory
 * is created if missing.
 */
export function writeEnsureDaemonScript(
  scriptPath: string,
  options: EnsureDaemonScriptOptions,
): void {
  fs.mkdirSync(path.dirname(scriptPath), { recursive: true, mode: 0o700 });
  const body = renderEnsureDaemonScript(options);
  writeFileSecure(scriptPath, body, { mode: 0o755, atomic: true });
}
