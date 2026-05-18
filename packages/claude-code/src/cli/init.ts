// `rubric init` — interactive enrollment + filesystem setup + daemon start.
//
// Steps, in order:
//   1. Prompt for apiUrl / agentName / enrollmentToken (skip prompts for
//      values supplied via CLI flags or env vars).
//   2. Test-enroll once (POST /v1/identities/enroll) so we fail loudly
//      *before* writing any config if the inputs are wrong.
//   3. Generate a 32-byte daemon token, write `config.json` (0600),
//      `daemon.token` (0600) into ~/.config/rubric/.
//   4. Patch ~/.claude/settings.json with our hook block (preserves user
//      content, idempotent — see settings-json.ts).
//   5. Spawn `rubric daemon` detached so it survives this process exit.

import { spawn } from 'node:child_process';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import { hostname } from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import { bootstrapTokenStore, DEFAULT_API_URL, errCode } from '@rubric-app/core';
import prompts from 'prompts';

import { ensureDirMode, writeFileSecure } from '../config/fs-secure.js';
import { defaultPaths, type Paths } from '../config/paths.js';
import { installService } from '../config/services/index.js';
import { applyRubricHooks } from '../config/settings-json.js';

import {
  configExists,
  readConfig,
  validateApiUrl,
  writeConfig,
  type PersistedConfig,
} from './_config.js';
import { dim, fail, header, info, ok, warn } from './_format.js';

export interface InitOptions {
  apiUrl?: string;
  agentName?: string;
  enrollmentToken?: string;
  /** Skip starting the daemon at the end of init. */
  noStart?: boolean;
  /** Don't touch ~/.claude/settings.json. Useful for managed-settings setups. */
  noSettingsPatch?: boolean;
  /** Re-run init even if config already exists. */
  force?: boolean;
}

export async function runInit(options: InitOptions = {}): Promise<void> {
  const paths = defaultPaths();
  process.stdout.write(`${header('Rubric Claude Code adapter — init')}\n\n`);

  if (configExists(paths.configFile) && !options.force) {
    process.stdout.write(
      `${info(`existing config found at ${dim(paths.configFile)}`)}\n` +
        `  Re-run with ${dim('--force')} to overwrite, or 'rubric doctor' to inspect.\n`,
    );
    return;
  }

  const config = await collectConfig(options, paths);

  // Validate the resolved API URL regardless of source (prompt
  // captures interactive entry but --api-url / RUBRIC_API_URL bypass
  // the prompt entirely). Throw before any HTTP roundtrip.
  {
    const err = validateApiUrl(config.apiUrl);
    if (err !== null) {
      process.stderr.write(`${fail(`invalid API URL: ${err}`)}\n`);
      process.exit(1);
    }
  }

  // ---- Test-enroll BEFORE writing anything --------------------------------
  // This is the slow part of init (HTTP roundtrip) but it's also the only
  // step that can fail in a way the user didn't anticipate. Front-load it
  // so a wrong token doesn't leave a half-finished install.
  process.stdout.write(`${info('verifying enrollment token…')}\n`);
  let agentId: string;
  try {
    const store = await bootstrapTokenStore({
      apiUrl: config.apiUrl,
      agentName: config.agentName,
      enrollmentToken: config.enrollmentToken,
    });
    agentId = store.agentId;
    await store.stop(); // stop refresh loop; daemon will re-enroll on its own.
  } catch (err: unknown) {
    process.stderr.write(
      `${fail(`enrollment failed: ${(err as Error).message}`)}\n` +
        `\nCheck that:\n` +
        `  - the API URL is reachable (curl ${config.apiUrl}/health)\n` +
        `  - the enrollment token is current and not already used past its cap\n` +
        `  - the agentName is unique within your org\n`,
    );
    process.exit(1);
  }
  process.stdout.write(`${ok(`enrolled as ${dim(agentId)}`)}\n`);

  // ---- Write config files --------------------------------------------------
  // mkdirSync with `mode` only applies to the *new* directory; if
  // configDir already exists at 0755 (e.g. left behind by a previous
  // tool), it stays 0755. `ensureDirMode` fixes that.
  fs.mkdirSync(paths.configDir, { recursive: true, mode: 0o700 });
  ensureDirMode(paths.configDir, 0o700);
  writeConfig(paths.configFile, config);
  process.stdout.write(`${ok(`wrote ${dim(paths.configFile)}`)}\n`);

  const daemonToken = crypto.randomBytes(32).toString('hex');
  // writeFileSecure refuses symlinks (O_NOFOLLOW + lstat pre-check)
  // and explicitly chmods after write so 0600 sticks on overwrite.
  writeFileSecure(paths.daemonTokenFile, daemonToken + '\n', { mode: 0o600 });
  process.stdout.write(`${ok(`wrote ${dim(paths.daemonTokenFile)} (0600)`)}\n`);

  // ---- Patch ~/.claude/settings.json --------------------------------------
  if (!options.noSettingsPatch) {
    patchClaudeSettings(paths.claudeSettingsFile, daemonToken);
    process.stdout.write(`${ok(`patched ${dim(paths.claudeSettingsFile)}`)}\n`);
  } else {
    process.stdout.write(`${info(`skipped settings.json patch (--no-settings-patch)`)}\n`);
  }

  // ---- Install service (launchd / systemd) — fall back to detached spawn -
  if (!options.noStart) {
    const cliEntry = resolveCliEntry();
    const result = await installService({
      paths,
      nodeBinary: process.execPath,
      cliEntry,
    });
    if (result.platform === 'unsupported') {
      // Unknown platform → detached child. Survives terminal close, not reboot.
      spawnDetachedDaemon();
      process.stdout.write(
        `${warn(`no service manager for ${process.platform}; spawning detached daemon`)}\n` +
          `${ok(`daemon spawned`)}  ${dim(`(pid in ${paths.pidFile})`)}\n`,
      );
    } else if (result.loaded) {
      process.stdout.write(
        `${ok(`installed ${result.platform} service`)}  ${dim(result.message)}\n`,
      );
      if (result.platform === 'systemd') {
        process.stdout.write(
          `${dim('  tip: run `loginctl enable-linger $USER` if you want the daemon to keep running after logout')}\n`,
        );
      }
    } else {
      // File was written but the service manager rejected loading — fall back.
      process.stdout.write(`${warn(result.message)}\n`);
      spawnDetachedDaemon();
      process.stdout.write(
        `${ok(`daemon spawned as fallback`)}  ${dim(`(pid in ${paths.pidFile})`)}\n` +
          `${dim('  load the service manually once the issue is fixed; see ' + (result.filePath ?? ''))}\n`,
      );
    }
    process.stdout.write(`\n${info('next:')} ${dim('rubric doctor')}  to confirm everything is wired up\n`);
  } else {
    process.stdout.write(
      `${info('init complete — daemon not started (--no-start)')}\n` +
        `  Start it manually with ${dim('rubric daemon')} or via your service supervisor.\n`,
    );
  }
}

// ---- Helpers ---------------------------------------------------------------

async function collectConfig(options: InitOptions, paths: Paths): Promise<PersistedConfig> {
  // Reuse existing answers as defaults when forcing a re-run.
  let existing: Partial<PersistedConfig> = {};
  if (configExists(paths.configFile)) {
    try {
      existing = readConfig(paths.configFile);
    } catch (err: unknown) {
      process.stderr.write(
        `${warn(`existing config at ${paths.configFile} is unreadable; re-prompting (${(err as Error).message})`)}\n`,
      );
    }
  }

  // The SDK only operates against the hosted Rubric API — there is no
  // self-hosted path. `apiUrl` is therefore NOT prompted for; it
  // resolves from (in priority order):
  //   1. `--api-url` flag
  //   2. `RUBRIC_API_URL` env var (escape hatch for staging / dev)
  //   3. previously-persisted `~/.config/rubric/config.json`
  //   4. `DEFAULT_API_URL` constant (production)
  // The URL validator still runs to refuse plaintext http:// for any
  // non-loopback override.
  const apiUrl: string =
    options.apiUrl ??
    process.env['RUBRIC_API_URL'] ??
    existing.apiUrl ??
    DEFAULT_API_URL;

  const agentName =
    options.agentName ?? process.env['RUBRIC_AGENT_NAME'] ?? existing.agentName ?? undefined;
  const enrollmentToken =
    options.enrollmentToken ?? process.env['RUBRIC_ENROLLMENT_TOKEN'] ?? undefined;

  const questions: prompts.PromptObject[] = [];
  if (!agentName) {
    questions.push({
      type: 'text',
      name: 'agentName',
      message: 'Agent name (shown in the dashboard)',
      initial: `claude-code-${shortHostname()}`,
      validate: (v: string) => (v.trim().length > 0 ? true : 'cannot be empty'),
    });
  }
  if (!enrollmentToken) {
    questions.push({
      type: 'password',
      name: 'enrollmentToken',
      message: 'Enrollment token (paste from the dashboard)',
      validate: (v: string) =>
        v.startsWith('enr_') ? true : 'expected to start with "enr_"',
    });
  }

  const responses = await prompts(questions, {
    onCancel: () => {
      process.stderr.write(`${fail('init cancelled')}\n`);
      process.exit(1);
    },
  });

  return {
    apiUrl,
    agentName: (agentName ?? responses['agentName']) as string,
    enrollmentToken: (enrollmentToken ?? responses['enrollmentToken']) as string,
  };
}

function patchClaudeSettings(settingsFile: string, daemonToken: string): void {
  fs.mkdirSync(path.dirname(settingsFile), { recursive: true });
  let existing: unknown = {};
  try {
    existing = JSON.parse(fs.readFileSync(settingsFile, 'utf8'));
  } catch (err: unknown) {
    if (errCode(err) !== 'ENOENT') {
      // Malformed JSON — bail rather than risk overwriting valid content.
      throw new Error(
        `${settingsFile} exists but is not valid JSON; refusing to patch. ` +
          `Fix the file (or move it aside) and re-run init.`,
      );
    }
  }
  const patched = applyRubricHooks(existing, { daemonToken });
  // writeFileSecure does an explicit chmod after write (so 0600 sticks
  // on overwrite of a pre-existing 0644 file), refuses symlink targets
  // via O_NOFOLLOW, and `atomic: true` write-renames a temp file so a
  // SIGKILL mid-write never leaves a half-written file briefly
  // containing the bearer token on disk.
  writeFileSecure(settingsFile, JSON.stringify(patched, null, 2) + '\n', {
    mode: 0o600,
    atomic: true,
  });
}

function spawnDetachedDaemon(): void {
  // Fallback for platforms without a known service manager (BSD, alpine
  // without systemd, etc.). Survives terminal close but not reboot —
  // the user runs `rubric init` again after a reboot in that scenario.
  const cliEntry = resolveCliEntry();
  // Filter env so the enrollment token (used only for the one-shot
  // test-enroll above) doesn't ride into the long-lived daemon's
  // environment. The daemon reads it from config.json.
  // Also strip RUBRIC_DAEMON_TOKEN defensively; the daemon reads the
  // token from daemon.token directly.
  const env: NodeJS.ProcessEnv = { ...process.env };
  delete env['RUBRIC_ENROLLMENT_TOKEN'];
  delete env['RUBRIC_DAEMON_TOKEN'];
  const child = spawn(process.execPath, [cliEntry, 'daemon'], {
    detached: true,
    stdio: 'ignore',
    env,
  });
  child.unref();
}

function resolveCliEntry(): string {
  // process.argv[1] is set when the entry was invoked via the bin
  // shebang; it's the cleanest absolute path. Fallback: derive from
  // import.meta.url of this module — we're at dist/cli/init.js, so the
  // sibling index.js is the entry.
  if (process.argv[1] && path.isAbsolute(process.argv[1])) {
    return process.argv[1];
  }
  const here = fileURLToPath(import.meta.url);
  return path.join(path.dirname(here), 'index.js');
}

function shortHostname(): string {
  try {
    return hostname().split('.')[0]!.toLowerCase();
  } catch {
    return 'host';
  }
}
