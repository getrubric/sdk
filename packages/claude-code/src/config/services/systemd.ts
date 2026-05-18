// Linux systemd --user unit for the Rubric daemon.
//
// Lives in `~/.config/systemd/user/rubric-claude-code.service` and is
// enabled with `systemctl --user enable --now`. Restart=always covers
// crashes; WantedBy=default.target means the service starts on user
// login (the systemd --user equivalent of launchd RunAtLoad).
//
// Note: systemd --user requires `loginctl enable-linger $USER` to keep
// services running after logout. Init mentions this in its closing
// message if it's not already set.

import * as fs from 'node:fs';
import * as path from 'node:path';

import { errCode } from '@rubric-app/core';

import { writeFileSecure } from '../fs-secure.js';
import type { Paths } from '../paths.js';

export const SYSTEMD_UNIT_NAME = 'rubric-claude-code.service';

export interface SystemdServiceSpec {
  unitPath: string;
  unitName: string;
  unitContent: string;
}

export interface BuildSystemdOptions {
  paths: Paths;
  /** Absolute path to the node binary that will run the daemon. */
  nodeBinary: string;
  /** Absolute path to dist/cli/index.js — the rubric CLI entry. */
  cliEntry: string;
  /** Home dir, used to resolve the user systemd unit location. */
  home: string;
}

export function buildSystemdService(options: BuildSystemdOptions): SystemdServiceSpec {
  const xdgConfigHome = process.env['XDG_CONFIG_HOME'] || path.join(options.home, '.config');
  const unitPath = path.join(xdgConfigHome, 'systemd', 'user', SYSTEMD_UNIT_NAME);

  // Validate paths *before* interpolating them into the unit file.
  // Current callers (`installService`) only pass `process.execPath`
  // and an SDK-resolved CLI entry — both safe — but any future caller
  // that feeds user-controlled paths in would otherwise risk an
  // `ExecStart=` injection.
  assertSafeUnitPath(options.nodeBinary, 'nodeBinary');
  assertSafeUnitPath(options.cliEntry, 'cliEntry');
  assertSafeUnitPath(options.paths.logFile, 'paths.logFile');

  // INI / systemd-unit format. Each `Append:` directive needs the log
  // dir to exist; we let the daemon's createLogger() handle that on
  // first run rather than pre-creating it here.
  const unitContent = `[Unit]
Description=Rubric Claude Code daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${systemdExecEscape(options.nodeBinary)} ${systemdExecEscape(options.cliEntry)} daemon
Restart=always
RestartSec=2
# Forward daemon stdout/stderr to its log file. The daemon also writes
# directly to ${options.paths.logFile} via pino — these two paths are
# the same so the log is the single source of truth.
StandardOutput=append:${systemdValueEscape(options.paths.logFile)}
StandardError=append:${systemdValueEscape(options.paths.logFile)}
# Avoid restart storms if config is broken; 5 restarts in 60s → give up.
StartLimitIntervalSec=60
StartLimitBurst=5

[Install]
WantedBy=default.target
`;

  return { unitPath, unitName: SYSTEMD_UNIT_NAME, unitContent };
}

export async function installSystemdService(
  spec: SystemdServiceSpec,
  exec: ExecCommand = defaultExec,
): Promise<{ spec: SystemdServiceSpec; loaded: boolean; message: string }> {
  fs.mkdirSync(path.dirname(spec.unitPath), { recursive: true });
  // writeFileSecure refuses pre-created symlinks at the unit path.
  // 0644 is intentional — systemd needs to read the unit; the file
  // contains no secrets (the bearer is in ~/.config/rubric/, mode 0600).
  writeFileSecure(spec.unitPath, spec.unitContent, { mode: 0o644 });

  const reload = await exec('systemctl', ['--user', 'daemon-reload']);
  if (reload.code !== 0) {
    return {
      spec,
      loaded: false,
      message: `wrote unit but systemctl daemon-reload failed: ${reload.stderr.trim()}`,
    };
  }
  const enable = await exec('systemctl', ['--user', 'enable', '--now', spec.unitName]);
  if (enable.code !== 0) {
    return {
      spec,
      loaded: false,
      message: `wrote unit but systemctl enable --now failed: ${enable.stderr.trim()}`,
    };
  }
  return { spec, loaded: true, message: 'enabled via systemctl --user enable --now' };
}

export async function uninstallSystemdService(
  unitPath: string,
  unitName: string = SYSTEMD_UNIT_NAME,
  exec: ExecCommand = defaultExec,
): Promise<{ removed: boolean; message: string }> {
  // Best-effort disable. Errors are expected if the unit isn't loaded.
  await exec('systemctl', ['--user', 'disable', '--now', unitName]);
  try {
    fs.unlinkSync(unitPath);
    await exec('systemctl', ['--user', 'daemon-reload']);
    return { removed: true, message: `removed ${unitPath}` };
  } catch (err: unknown) {
    if (errCode(err) === 'ENOENT') {
      return { removed: false, message: 'no unit file found to remove' };
    }
    throw err;
  }
}

// ---- Shared exec helper ----------------------------------------------------

export interface ExecResult {
  code: number;
  stdout: string;
  stderr: string;
}
export type ExecCommand = (cmd: string, args: string[]) => Promise<ExecResult>;

async function defaultExec(cmd: string, args: string[]): Promise<ExecResult> {
  const { spawn } = await import('node:child_process');
  return new Promise((resolve) => {
    let stdout = '';
    let stderr = '';
    const child = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    child.stdout.on('data', (d) => (stdout += d.toString('utf8')));
    child.stderr.on('data', (d) => (stderr += d.toString('utf8')));
    child.on('error', (err) => resolve({ code: -1, stdout, stderr: stderr + String(err) }));
    child.on('exit', (code) => resolve({ code: code ?? -1, stdout, stderr }));
  });
}

/**
 * Validate path inputs that flow into the unit file against a strict
 * allow-list. Must be:
 *   - absolute (`/...`),
 *   - non-empty,
 *   - free of shell/unit metacharacters that could break out of the
 *     `ExecStart=` token or inject additional directives.
 *
 * Rejected characters: NUL, newline, carriage return, `$`, `;`, `|`,
 * `&`, `` ` ``, `<`, `>`, `(`, `)`, `*`, `?`, `[`, `]`, `{`, `}`,
 * `'`, `"`, `\\`. Combined with `systemdExecEscape` below, this is
 * defense-in-depth: even a path that slipped past validation couldn't
 * terminate the line (newlines are forbidden) or inject a specifier
 * (`%` is escape-doubled by `systemdValueEscape`).
 *
 * Throws — refusing to write a unit file with invalid inputs is the
 * correct behavior at install time.
 */
function assertSafeUnitPath(p: string, label: string): void {
  if (typeof p !== 'string' || p.length === 0) {
    throw new Error(`systemd unit: ${label} must be a non-empty string`);
  }
  if (!p.startsWith('/')) {
    throw new Error(`systemd unit: ${label} must be an absolute path (got ${p})`);
  }
  // Disallow control characters and shell/unit metacharacters. Spaces
  // are allowed (and escaped); everything else dangerous is not.
  // eslint-disable-next-line no-control-regex
  const banned = /[\x00-\x1f\x7f$;|&`<>()*?[\]{}'"\\]/;
  if (banned.test(p)) {
    throw new Error(
      `systemd unit: ${label} contains a disallowed character; ` +
        `paths must be plain ASCII without shell/unit metacharacters`,
    );
  }
}

/**
 * Escape a value used inside an `ExecStart=` (or similar) line in a
 * systemd unit file. systemd's parser splits on unescaped whitespace,
 * so spaces in absolute paths need a backslash; backslashes and
 * quotes need backslash-escaping too. `%` is the systemd specifier
 * sigil (e.g. `%h` for $HOME) and must be doubled (`%%`) to disable
 * expansion. `$` carries no shell meaning inside `ExecStart=` (no
 * shell is involved) but we escape it anyway to keep the value
 * literal.
 *
 * Inputs are pre-validated by `assertSafeUnitPath`; this escape exists
 * defense-in-depth in case validation is relaxed later.
 */
function systemdExecEscape(s: string): string {
  return s
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\$/g, '\\$')
    .replace(/%/g, '%%')
    .replace(/(\s)/g, '\\$1');
}

/**
 * Like `systemdExecEscape`, but for value positions (e.g.
 * `StandardOutput=append:<value>`) where whitespace is allowed
 * literally. Still escapes specifier sigils and control characters.
 */
function systemdValueEscape(s: string): string {
  return s.replace(/%/g, '%%');
}

