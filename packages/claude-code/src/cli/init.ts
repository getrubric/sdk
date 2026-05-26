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
import { installService, kickstartService } from '../config/services/index.js';
import { applyRubricHooks } from '../config/settings-json.js';
import { writeEnsureDaemonScript } from '../config/ensure-daemon-script.js';
import { DEFAULT_DAEMON_HOST, DEFAULT_DAEMON_PORT } from '../daemon/server.js';
import { DEFAULT_SAFETY_PACK } from '../policies/default-pack.js';

import {
  configExists,
  readConfig,
  validateApiUrl,
  writeConfig,
  type PersistedConfig,
} from './_config.js';
import { dim, fail, header, info, ok, warn } from './_format.js';

export type InitMode = 'solo' | 'connected';

export interface InitOptions {
  /** Skip the picker: 'solo' (no account) or 'connected' (enroll). */
  mode?: InitMode;
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
  process.stdout.write(`${header('Rubric — guardrails for Claude Code')}\n\n`);

  if (configExists(paths.configFile) && !options.force) {
    process.stdout.write(
      `${info(`existing config found at ${dim(paths.configFile)}`)}\n` +
        `  Re-run with ${dim('--force')} to overwrite, or 'rubric doctor' to inspect.\n`,
    );
    return;
  }

  const choice = await chooseMode(options);
  if (choice === 'solo') {
    await runSoloInit(paths, options);
    return;
  }
  // Both 'create' (new personal workspace) and 'connected' (join an existing
  // team workspace) end at the same connected enrollment over the existing
  // enrollment-token flow. They differ only in intro: 'create' opens sign-up
  // first to mint a workspace + token, then continues straight into enrollment
  // in the same session.
  if (choice === 'create') {
    openSignupForAccount();
  }
  await runConnectedInit(paths, options);
}

/**
 * Decide how to onboard. Explicit flags / env (CI, scripting) skip the picker;
 * an interactive TTY shows the three-way choice; a non-TTY with no signal is an
 * error rather than a hung prompt.
 */
async function chooseMode(options: InitOptions): Promise<'solo' | 'connected' | 'create'> {
  if (options.mode === 'solo') return 'solo';
  if (
    options.mode === 'connected' ||
    options.enrollmentToken ||
    process.env['RUBRIC_ENROLLMENT_TOKEN']
  ) {
    return 'connected';
  }
  if (!process.stdin.isTTY) {
    process.stderr.write(
      `${fail('non-interactive shell: pass --mode solo or --enrollment-token <token>')}\n`,
    );
    process.exit(1);
  }
  const { choice } = await prompts(
    {
      type: 'select',
      name: 'choice',
      message: 'How do you want to run Rubric?',
      choices: [
        {
          title: 'Create a Rubric account (recommended)',
          description: 'Your own cloud workspace — audit history, analytics, synced guardrails.',
          value: 'create',
        },
        {
          title: 'Join my team’s workspace',
          description: 'Connect to your organization’s existing Rubric workspace.',
          value: 'connected',
        },
        {
          title: 'Just protect this machine — no account',
          description: 'Local guardrails only. Nothing leaves your machine.',
          value: 'solo',
        },
      ],
      initial: 0,
    },
    {
      onCancel: () => {
        process.stderr.write(`${fail('init cancelled')}\n`);
        process.exit(1);
      },
    },
  );
  return choice as 'solo' | 'connected' | 'create';
}

/** Solo onboarding: no account, local default pack, nothing leaves the machine. */
async function runSoloInit(paths: Paths, options: InitOptions): Promise<void> {
  const agentName =
    options.agentName ?? process.env['RUBRIC_AGENT_NAME'] ?? `claude-code-${shortHostname()}`;

  fs.mkdirSync(paths.configDir, { recursive: true, mode: 0o700 });
  ensureDirMode(paths.configDir, 0o700);
  writeConfig(paths.configFile, { mode: 'solo', agentName });
  process.stdout.write(`${ok(`wrote ${dim(paths.configFile)}`)}\n`);

  // Materialize the editable default safety pack the daemon enforces.
  writeFileSecure(
    paths.policiesFile,
    JSON.stringify({ policies: DEFAULT_SAFETY_PACK }, null, 2) + '\n',
    { mode: 0o644 },
  );
  process.stdout.write(`${ok(`installed default safety pack → ${dim(paths.policiesFile)}`)}\n`);

  await finishInstall(paths, options);

  if (!options.noStart) {
    process.stdout.write(
      `\n${ok('Rubric is guarding Claude Code.')} Dangerous actions (destructive shell, secret files, internal fetches) are blocked; everything else runs free.\n` +
        `  ${dim('Nothing leaves your machine — Rubric records nothing.')} Edit ${dim(paths.policiesFile)} to tune the rules.\n` +
        `  Run ${dim('rubric login')} anytime to sync, audit, and share with your team.\n` +
        manageTip(),
    );
  }
}

/** Connected onboarding: enroll into an existing org with a dashboard token. */
async function runConnectedInit(paths: Paths, options: InitOptions): Promise<void> {
  const config = await collectConfig(options, paths);
  const apiUrl = config.apiUrl ?? DEFAULT_API_URL;
  const enrollmentToken = config.enrollmentToken;

  const urlErr = validateApiUrl(apiUrl);
  if (urlErr !== null) {
    process.stderr.write(`${fail(`invalid API URL: ${urlErr}`)}\n`);
    process.exit(1);
  }
  if (!enrollmentToken) {
    process.stderr.write(`${fail('an enrollment token is required to join a workspace')}\n`);
    process.exit(1);
  }

  // ---- Test-enroll BEFORE writing anything --------------------------------
  process.stdout.write(`${info('verifying enrollment token…')}\n`);
  let agentId: string;
  try {
    const store = await bootstrapTokenStore({ apiUrl, agentName: config.agentName, enrollmentToken });
    agentId = store.agentId;
    await store.stop();
  } catch (err: unknown) {
    process.stderr.write(
      `${fail(`enrollment failed: ${(err as Error).message}`)}\n` +
        `\nCheck that:\n` +
        `  - the API URL is reachable (curl ${apiUrl}/health)\n` +
        `  - the enrollment token is current and not already used past its cap\n` +
        `  - the agentName is unique within your org\n`,
    );
    process.exit(1);
  }
  process.stdout.write(`${ok(`enrolled as ${dim(agentId)}`)}\n`);

  fs.mkdirSync(paths.configDir, { recursive: true, mode: 0o700 });
  ensureDirMode(paths.configDir, 0o700);
  writeConfig(paths.configFile, config);
  process.stdout.write(`${ok(`wrote ${dim(paths.configFile)}`)}\n`);

  await finishInstall(paths, options);

  if (!options.noStart) {
    process.stdout.write(
      `\n${info('next:')} ${dim('rubric doctor')}  to confirm everything is wired up\n` + manageTip(),
    );
  }
}

/**
 * Tip shown after install: the `rubric` management command (doctor, status,
 * logs, uninstall) is only on PATH after a global install. `npx` runs the
 * package transiently and leaves no `rubric` binary, so point users at the
 * global install if they used it.
 */
function manageTip(): string {
  return (
    `  ${dim('Note:')} the ${dim('rubric')} command (doctor, status, logs, uninstall) needs a global install — ` +
    `if you used ${dim('npx')}, run ${dim('npm i -g @rubric-app/claude-code')}.\n`
  );
}

/**
 * Shared install tail for both modes: daemon token, ensure-daemon script,
 * Claude Code settings patch (same hook for solo + connected), and starting
 * the daemon via the platform service (with token-rotation kickstart +
 * health wait) or a detached spawn. Each caller writes its own config first.
 */
async function finishInstall(paths: Paths, options: InitOptions): Promise<void> {
  const daemonToken = crypto.randomBytes(32).toString('hex');
  writeFileSecure(paths.daemonTokenFile, daemonToken + '\n', { mode: 0o600 });
  process.stdout.write(`${ok(`wrote ${dim(paths.daemonTokenFile)} (0600)`)}\n`);

  writeEnsureDaemonScript(paths.ensureDaemonScriptFile, {
    daemonHost: DEFAULT_DAEMON_HOST,
    daemonPort: DEFAULT_DAEMON_PORT,
  });
  process.stdout.write(`${ok(`wrote ${dim(paths.ensureDaemonScriptFile)} (0755)`)}\n`);

  if (!options.noSettingsPatch) {
    patchClaudeSettings(paths.claudeSettingsFile, daemonToken, paths.ensureDaemonScriptFile);
    process.stdout.write(`${ok(`patched ${dim(paths.claudeSettingsFile)}`)}\n`);
  } else {
    process.stdout.write(`${info(`skipped settings.json patch (--no-settings-patch)`)}\n`);
  }

  if (options.noStart) {
    process.stdout.write(
      `${info('daemon not started (--no-start)')} — start it with ${dim('rubric daemon')}.\n`,
    );
    return;
  }

  const cliEntry = resolveCliEntry();
  const result = await installService({ paths, nodeBinary: process.execPath, cliEntry });
  if (result.platform === 'unsupported') {
    spawnDetachedDaemon();
    process.stdout.write(
      `${warn(`no service manager for ${process.platform}; spawning detached daemon`)}\n` +
        `${ok('daemon spawned')}  ${dim(`(pid in ${paths.pidFile})`)}\n`,
    );
  } else if (result.loaded) {
    process.stdout.write(`${ok(`installed ${result.platform} service`)}  ${dim(result.message)}\n`);
    const kick = await kickstartService();
    if (kick.kicked) {
      process.stdout.write(`${ok('restarted daemon')}  ${dim(kick.message)}\n`);
      const ready = await waitForDaemonHealth(DEFAULT_DAEMON_HOST, DEFAULT_DAEMON_PORT);
      if (!ready) {
        process.stdout.write(
          `${warn('daemon did not come up within 10s — run `rubric doctor` to inspect')}\n`,
        );
      }
    } else {
      process.stdout.write(
        `${warn(`daemon may need a manual restart to pick up the new token: ${kick.message}`)}\n`,
      );
    }
    if (result.platform === 'systemd') {
      process.stdout.write(
        `${dim('  tip: run `loginctl enable-linger $USER` if you want the daemon to keep running after logout')}\n`,
      );
    }
  } else {
    process.stdout.write(`${warn(result.message)}\n`);
    spawnDetachedDaemon();
    process.stdout.write(
      `${ok('daemon spawned as fallback')}  ${dim(`(pid in ${paths.pidFile})`)}\n` +
        `${dim('  load the service manually once the issue is fixed; see ' + (result.filePath ?? ''))}\n`,
    );
  }
}

function openSignupForAccount(): void {
  // The seamless `rubric login` browser handshake isn't built; bridge through
  // web sign-up over the existing enrollment-token path. Open the browser, then
  // fall straight into the enrollment-token prompt (runConnectedInit) so the
  // whole thing completes in one session rather than re-running with a flag.
  const signupUrl = 'https://app.rubric-app.com/sign-up';
  tryOpenBrowser(signupUrl);
  process.stdout.write(
    `${info('Create your personal Rubric workspace:')} ${dim(signupUrl)}\n` +
      `  (opening your browser…)  Once you're in, copy your enrollment token from\n` +
      `  ${dim('Settings → Agents → New enrollment token')} and paste it below.\n\n`,
  );
}

/** Best-effort: open a URL in the user's default browser. Never throws. */
function tryOpenBrowser(url: string): void {
  const cmd =
    process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'start' : 'xdg-open';
  try {
    spawn(cmd, [url], { stdio: 'ignore', detached: true }).unref();
  } catch {
    /* best effort — the URL is printed above regardless */
  }
}

// ---- Helpers ---------------------------------------------------------------

/** Connected-mode config collection (apiUrl + agentName + enrollment token). */
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
    options.enrollmentToken ??
    process.env['RUBRIC_ENROLLMENT_TOKEN'] ??
    existing.enrollmentToken ??
    undefined;

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
    mode: 'connected',
    apiUrl,
    agentName: (agentName ?? responses['agentName']) as string,
    enrollmentToken: (enrollmentToken ?? responses['enrollmentToken']) as string,
  };
}

function patchClaudeSettings(
  settingsFile: string,
  daemonToken: string,
  ensureDaemonScriptPath: string,
): void {
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
  const patched = applyRubricHooks(existing, {
    daemonToken,
    ensureDaemonScriptPath,
  });
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

/**
 * Poll the daemon's `/healthz` until it returns 200 or the budget runs
 * out. Used by `init` so it doesn't return until the daemon it just
 * restarted is actually serving — saves the user from a transient
 * red-check on the immediately-following `rubric doctor`.
 */
async function waitForDaemonHealth(
  host: string,
  port: number,
  budgetMs: number = 10_000,
  tickMs: number = 200,
): Promise<boolean> {
  const deadline = Date.now() + budgetMs;
  const url = `http://${host}:${port}/healthz`;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(tickMs) });
      if (res.status === 200) return true;
    } catch {
      // connection refused / timeout — daemon still coming up.
    }
    await new Promise((resolve) => setTimeout(resolve, tickMs));
  }
  return false;
}

function shortHostname(): string {
  try {
    return hostname().split('.')[0]!.toLowerCase();
  } catch {
    return 'host';
  }
}
