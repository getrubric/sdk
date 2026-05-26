#!/usr/bin/env node
// `rubric` — Claude Code adapter CLI.
//
// All subcommands are async. We catch at the top level and exit 1
// on uncaught throws so commander doesn't print a confusing Node
// stack trace for ordinary user errors.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import { Command } from 'commander';

import { fail } from './_format.js';

const program = new Command();
program
  .name('rubric')
  .description('Rubric Claude Code adapter — gate Claude Code tool calls via Rubric policies.')
  .version(readVersion());

program
  .command('init', { isDefault: true })
  .description('Set up Rubric for Claude Code (interactive picker: solo / account / team).')
  .option('--mode <mode>', 'skip the picker: "solo" (no account) or "connected" (enroll)')
  .option('--api-url <url>', 'Rubric API base URL (skip prompt)')
  .option('--agent-name <name>', 'agent name in the dashboard (skip prompt)')
  .option('--enrollment-token <token>', 'enrollment token from the dashboard (skip prompt)')
  .option('--no-start', 'do not spawn the daemon at the end of init')
  .option('--no-settings-patch', 'do not patch ~/.claude/settings.json')
  .option('--force', 're-run init even if config already exists')
  .action(async (opts) => {
    const { runInit } = await import('./init.js');
    // Commander maps `--no-start` → opts.start=false (not opts.noStart);
    // normalize the negated flags into InitOptions explicitly.
    await runInit({
      ...(opts.mode ? { mode: opts.mode } : {}),
      ...(opts.apiUrl ? { apiUrl: opts.apiUrl } : {}),
      ...(opts.agentName ? { agentName: opts.agentName } : {}),
      ...(opts.enrollmentToken ? { enrollmentToken: opts.enrollmentToken } : {}),
      noStart: opts.start === false,
      noSettingsPatch: opts.settingsPatch === false,
      force: Boolean(opts.force),
    });
  });

program
  .command('login')
  .description('Connect this machine to a Rubric workspace via the browser (one-step).')
  .option('--api-url <url>', 'Rubric API base URL (skip prompt)')
  .option('--agent-name <name>', 'agent name in the dashboard (skip prompt)')
  .option('--no-start', 'do not spawn the daemon at the end of login')
  .option('--no-settings-patch', 'do not patch ~/.claude/settings.json')
  .action(async (opts) => {
    const { runLogin } = await import('./login.js');
    await runLogin({
      ...(opts.apiUrl ? { apiUrl: opts.apiUrl } : {}),
      ...(opts.agentName ? { agentName: opts.agentName } : {}),
      noStart: opts.start === false,
      noSettingsPatch: opts.settingsPatch === false,
    });
  });

program
  .command('doctor')
  .description('Run sanity checks against the local install.')
  .action(async () => {
    const { runDoctor } = await import('./doctor.js');
    await runDoctor();
  });

program
  .command('status')
  .description('Show concise overview of the local install.')
  .action(async () => {
    const { runStatus } = await import('./status.js');
    await runStatus();
  });

program
  .command('stop')
  .description('Request graceful shutdown of the daemon and wait for exit.')
  .option(
    '--force',
    'fall back to raw SIGTERM against the pidfile if the daemon does not respond to authenticated shutdown',
  )
  .action(async (opts) => {
    const { runStop } = await import('./stop.js');
    await runStop(opts);
  });

program
  .command('uninstall')
  .description('Reverse `rubric init` — stop daemon, unpatch settings.json, remove config.')
  .option('--purge', 'also remove the log file')
  .option('--keep-daemon', 'do not stop the daemon (useful in scripts)')
  .action(async (opts) => {
    const { runUninstall } = await import('./uninstall.js');
    await runUninstall(opts);
  });

program
  .command('undo')
  .description('Restore the working tree from a seatbelt snapshot taken before a destructive git command.')
  .option('--list', 'list available snapshots instead of restoring')
  .option('--to <sha>', 'restore a specific snapshot (full or short sha from --list)')
  .action(async (opts) => {
    const { runUndo } = await import('./undo.js');
    await runUndo({
      list: Boolean(opts.list),
      ...(opts.to ? { to: opts.to } : {}),
    });
  });

program
  .command('logs')
  .description('Pretty-print the daemon log with optional filters.')
  .option('--decision <kind>', 'show only PreToolUse decisions of this kind (allow | deny | ask)')
  .option('--tool <name>', 'show only events with this tool name (e.g. Bash, Read)')
  .option('--since <duration>', 'show only events newer than this (30s | 5m | 2h | 1d)')
  .option('-f, --follow', 'keep tailing as new lines arrive (Ctrl-C to exit)')
  .action(async (opts) => {
    const { runLogs } = await import('./logs.js');
    await runLogs(opts);
  });

const mcp = program.command('mcp').description('Manage this agent’s MCP server access.');
mcp
  .command('request')
  .argument('<server>', 'MCP server name (the `<server>` in mcp__<server>__tool)')
  .requiredOption('--reason <reason>', 'why this agent needs access (recorded for the approver)')
  .description('Request admin approval for this agent to use an MCP server.')
  .action(async (server: string, opts: { reason?: string }) => {
    const { runMcpRequest } = await import('./mcp.js');
    await runMcpRequest(server, opts);
  });

// `rubric daemon` is hidden from --help: it's invoked by `rubric init`
// (spawn detached) and by launchd/systemd, not typed by humans.
program
  .command('daemon', { hidden: true })
  .description('Run the long-lived daemon (used by the service manager).')
  .option('--foreground', 'tee logs to stderr (use when running interactively)')
  .option('--log-level <level>', 'trace | debug | info | warn | error | fatal')
  .action(async (opts) => {
    const { runDaemonCmd } = await import('./daemon-cmd.js');
    await runDaemonCmd(opts);
  });

program.parseAsync(process.argv).catch((err: unknown) => {
  process.stderr.write(`${fail((err as Error).message ?? String(err))}\n`);
  process.exit(1);
});

function readVersion(): string {
  // Read from the package.json that sits two directories up from this
  // file in the published layout: `dist/cli/index.js` → `dist/cli` →
  // `dist` → package root. In dev (`src/cli/index.ts`) the same walk
  // lands on the same package.json, so this works in both contexts.
  try {
    const here = fileURLToPath(import.meta.url);
    const pkgPath = path.resolve(path.dirname(here), '..', '..', 'package.json');
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8')) as { version?: unknown };
    if (typeof pkg.version === 'string') return pkg.version;
  } catch {
    /* fall through — version is informational, not load-bearing */
  }
  return 'unknown';
}
