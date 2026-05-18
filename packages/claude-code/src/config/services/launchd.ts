// macOS launchd LaunchAgent for the Rubric daemon.
//
// LaunchAgents live in `~/Library/LaunchAgents/`. We use the `dev.rubric.`
// reverse-DNS prefix to keep the namespace unique and human-discoverable
// via `launchctl list | grep rubric`.
//
// KeepAlive=true gives us automatic restart on crash, satisfying plan
// acceptance criterion #5 ("30-min API outage: enforcement continues on
// cached bundle…"): if the daemon panics on a transient malformed bundle,
// launchd brings it back within a second; the audit sink's persistent
// drop-on-full queue + bundle poller's hash cache keep the cached
// policy live across the bounce.

import * as fs from 'node:fs';
import * as path from 'node:path';

import { errCode } from '@rubric/core';

import { writeFileSecure } from '../fs-secure.js';
import type { Paths } from '../paths.js';

export const LAUNCHD_LABEL = 'dev.rubric.claude-code';

export interface LaunchdServiceSpec {
  /** Path the plist file is written to. */
  plistPath: string;
  /** Reverse-DNS label that identifies the service to launchctl. */
  label: string;
  /** XML content of the plist. */
  plistContent: string;
}

export interface BuildLaunchdOptions {
  paths: Paths;
  /** Absolute path to the node binary that will run the daemon. */
  nodeBinary: string;
  /** Absolute path to dist/cli/index.js — the rubric CLI entry. */
  cliEntry: string;
  /** Home dir, used to resolve the LaunchAgents location. */
  home: string;
}

export function buildLaunchdService(options: BuildLaunchdOptions): LaunchdServiceSpec {
  const label = LAUNCHD_LABEL;
  const plistPath = path.join(options.home, 'Library', 'LaunchAgents', `${label}.plist`);

  // Plist is XML — we hand-build it rather than pull in a `plist` lib for
  // a single static-shape file. Indentation matches Apple's convention.
  const plistContent = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${xmlEscape(label)}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${xmlEscape(options.nodeBinary)}</string>
        <string>${xmlEscape(options.cliEntry)}</string>
        <string>daemon</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ProcessType</key>
    <string>Background</string>
    <key>StandardOutPath</key>
    <string>${xmlEscape(options.paths.logFile)}</string>
    <key>StandardErrorPath</key>
    <string>${xmlEscape(options.paths.logFile)}</string>
    <!--
        We don't set EnvironmentVariables — the daemon reads
        ${xmlEscape(options.paths.configFile)} directly. Keeping env
        out of the plist means the enrollment token never sits in
        launchctl's env table.
    -->
</dict>
</plist>
`;

  return { plistPath, label, plistContent };
}

/**
 * Write the plist to disk and (best-effort) ask launchctl to load it.
 * Returns the spec so callers can report what they did.
 *
 * Loading uses `launchctl bootstrap` which is the modern API; falling
 * back to `launchctl load` for older macOS where bootstrap isn't there.
 * Errors from launchctl don't throw — we report them via the returned
 * `loadResult` so init can degrade gracefully (file is on disk, user
 * can `launchctl load` manually).
 */
export async function installLaunchdService(
  spec: LaunchdServiceSpec,
  exec: ExecCommand = defaultExec,
): Promise<{ spec: LaunchdServiceSpec; loaded: boolean; message: string }> {
  fs.mkdirSync(path.dirname(spec.plistPath), { recursive: true });
  // writeFileSecure refuses pre-created symlinks at the plist path.
  // The plist itself is non-secret (0644 — launchd needs to read it),
  // but symlink refusal prevents redirection to an unrelated plist.
  writeFileSecure(spec.plistPath, spec.plistContent, { mode: 0o644 });

  // `launchctl bootstrap gui/$UID <path>` is the modern way; the older
  // `launchctl load` works on every supported macOS but is deprecated.
  // Try bootstrap first; on any failure fall back to load.
  const uid = process.getuid?.() ?? 0;
  const bootstrap = await exec('launchctl', ['bootstrap', `gui/${uid}`, spec.plistPath]);
  if (bootstrap.code === 0) {
    return { spec, loaded: true, message: `loaded via launchctl bootstrap gui/${uid}` };
  }
  const load = await exec('launchctl', ['load', spec.plistPath]);
  if (load.code === 0) {
    return { spec, loaded: true, message: 'loaded via launchctl load' };
  }
  return {
    spec,
    loaded: false,
    message: `wrote plist but launchctl rejected it: ${load.stderr.trim() || bootstrap.stderr.trim()}`,
  };
}

export async function uninstallLaunchdService(
  plistPath: string,
  label: string = LAUNCHD_LABEL,
  exec: ExecCommand = defaultExec,
): Promise<{ removed: boolean; message: string }> {
  const uid = process.getuid?.() ?? 0;
  // Best-effort unload. Ignore errors — the plist file removal below is
  // what really matters, and bootout/unload error on an already-unloaded
  // service.
  await exec('launchctl', ['bootout', `gui/${uid}/${label}`]);
  await exec('launchctl', ['unload', plistPath]);
  try {
    fs.unlinkSync(plistPath);
    return { removed: true, message: `removed ${plistPath}` };
  } catch (err: unknown) {
    if (errCode(err) === 'ENOENT') {
      return { removed: false, message: 'no plist found to remove' };
    }
    throw err;
  }
}

// ---- exec wrapper ---------------------------------------------------------
// Pulled into a typedef so tests can inject a fake without monkey-patching
// child_process.

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

function xmlEscape(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
