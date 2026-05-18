// `rubric status` — concise overview of the local install.

import { defaultPaths } from '../config/paths.js';

import { configExists, readDaemonPid, readDaemonPort } from './_config.js';
import { dim, header, info } from './_format.js';

export async function runStatus(): Promise<void> {
  const paths = defaultPaths();
  process.stdout.write(`${header('Rubric Claude Code adapter status')}\n\n`);

  process.stdout.write(`config:        ${configExists(paths.configFile) ? paths.configFile : dim('missing')}\n`);

  const pid = readDaemonPid(paths.pidFile);
  process.stdout.write(`daemon pid:    ${pid ?? dim('not running')}\n`);

  const port = readDaemonPort(paths.daemonPortFile);
  process.stdout.write(`daemon port:   ${port ?? dim('unknown')}\n`);

  if (pid !== null && port !== null) {
    try {
      const res = await fetch(`http://127.0.0.1:${port}/healthz`, {
        signal: AbortSignal.timeout(500),
      });
      process.stdout.write(`healthz:       ${res.status === 200 ? 'ok' : `HTTP ${res.status}`}\n`);
    } catch (err: unknown) {
      process.stdout.write(`healthz:       ${dim((err as Error).message)}\n`);
    }
  } else {
    process.stdout.write(`${info("daemon not running — start with 'rubric daemon &' (or 'rubric init')")}\n`);
  }

  process.stdout.write(`log file:      ${paths.logFile}\n`);
}
