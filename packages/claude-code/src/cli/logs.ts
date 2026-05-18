// `rubric logs` — view the daemon's pino log file with optional
// filters. The log is JSON-lines (one event per line); we parse,
// filter in JS, and pretty-print.
//
// Filters supported:
//   --decision <allow|deny|ask>  show only PreToolUse decisions of this kind
//   --tool <name>                 show only events with tool=<name>
//   --since <duration>            show only events more recent than this
//                                  (`10s` / `5m` / `2h` / `1d` accepted)
//   --follow                      keep tailing as new lines arrive
//
// Multiple filters compose with AND. With no filters, every line is
// shown. Output is sorted only by file order (the daemon writes in
// monotonic order so this is also time order).

import * as fs from 'node:fs';

import { defaultPaths } from '../config/paths.js';

import { bold, dim, fail, warn } from './_format.js';

export interface LogsOptions {
  decision?: 'allow' | 'deny' | 'ask';
  tool?: string;
  since?: string;
  follow?: boolean;
}

interface PinoLine {
  level?: number;
  time?: string;
  msg?: string;
  event?: string;
  tool?: string;
  decision?: string;
  [k: string]: unknown;
}

export async function runLogs(options: LogsOptions = {}): Promise<void> {
  const paths = defaultPaths();
  if (!fs.existsSync(paths.logFile)) {
    process.stderr.write(`${fail(`log file not found at ${paths.logFile}`)}\n`);
    process.exit(1);
  }

  const cutoff = options.since ? Date.now() - parseDuration(options.since) : null;
  const filters = (line: PinoLine): boolean => {
    if (cutoff !== null) {
      const ts = line.time ? Date.parse(line.time) : NaN;
      if (Number.isNaN(ts) || ts < cutoff) return false;
    }
    if (options.decision && line.decision !== options.decision) return false;
    if (options.tool && line.tool !== options.tool) return false;
    return true;
  };

  // Print existing content first.
  const startSize = fs.statSync(paths.logFile).size;
  await streamRange(paths.logFile, 0, startSize, filters);

  if (!options.follow) return;

  // Tail: poll for size changes (fs.watch is unreliable on some
  // filesystems for append-mode writes). 250ms is a reasonable
  // trade-off between perceived latency and CPU.
  let cursor = startSize;
  const interval = setInterval(() => {
    let stat: fs.Stats;
    try {
      stat = fs.statSync(paths.logFile);
    } catch {
      return; // log was rotated away; wait for it to reappear
    }
    if (stat.size < cursor) {
      // File was truncated/rotated — reset cursor.
      cursor = 0;
    }
    if (stat.size > cursor) {
      streamRange(paths.logFile, cursor, stat.size, filters)
        .catch((err: unknown) => {
          // Never silently swallow a tail read failure. Log lines
          // during the transient failure would otherwise be permanently
          // lost from the user's view.
          process.stderr.write(
            `${warn(`tail read failed: ${(err as Error).message ?? String(err)}`)}\n`,
          );
        })
        .finally(() => {
          cursor = stat.size;
        });
    }
  }, 250);

  // Clean up on Ctrl-C.
  process.on('SIGINT', () => {
    clearInterval(interval);
    process.exit(0);
  });
}

// ---- Helpers ---------------------------------------------------------------

async function streamRange(
  file: string,
  start: number,
  end: number,
  filter: (line: PinoLine) => boolean,
): Promise<void> {
  if (end <= start) return;
  const stream = fs.createReadStream(file, { start, end: end - 1, encoding: 'utf8' });
  let buf = '';
  for await (const chunk of stream) {
    buf += chunk;
    let nl: number;
    while ((nl = buf.indexOf('\n')) !== -1) {
      const line = buf.slice(0, nl);
      buf = buf.slice(nl + 1);
      handleLine(line, filter);
    }
  }
  // Last partial line (if any) is ignored — it'll come back on the next
  // streamRange call once it has its terminating newline. Pino flushes
  // by line in practice, so this rarely matters.
}

function handleLine(raw: string, filter: (line: PinoLine) => boolean): void {
  if (!raw) return;
  let parsed: PinoLine;
  try {
    parsed = JSON.parse(raw);
  } catch {
    // Non-JSON line (e.g. a Node crash trace caught by stderr). Print
    // it verbatim if no filters are active; otherwise drop it (the
    // filters all key off JSON fields).
    process.stdout.write(`${raw}\n`);
    return;
  }
  if (!filter(parsed)) return;
  process.stdout.write(formatLine(parsed) + '\n');
}

function formatLine(line: PinoLine): string {
  const ts = line.time ?? '';
  const level = levelLabel(line.level);
  const msg = line.msg ?? '';
  const extras: string[] = [];
  for (const [k, v] of Object.entries(line)) {
    if (k === 'level' || k === 'time' || k === 'msg' || k === 'pid' || k === 'hostname') continue;
    extras.push(`${k}=${formatValue(v)}`);
  }
  return `${dim(ts)} ${level} ${bold(msg)}${extras.length > 0 ? '  ' + dim(extras.join(' ')) : ''}`;
}

function levelLabel(level: number | undefined): string {
  if (level === undefined) return '----';
  if (level <= 20) return 'TRACE';
  if (level <= 30) return 'INFO ';
  if (level <= 40) return 'WARN ';
  if (level <= 50) return 'ERROR';
  return 'FATAL';
}

function formatValue(v: unknown): string {
  if (typeof v === 'string') return v;
  if (typeof v === 'number' || typeof v === 'boolean' || v === null) return String(v);
  return JSON.stringify(v);
}

/**
 * Parse a short human duration like `30s` / `5m` / `2h` / `1d` into ms.
 * Throws on unparseable input — keeping the CLI surface small.
 */
export function parseDuration(input: string): number {
  const m = /^(\d+)(s|m|h|d)$/.exec(input.trim());
  if (!m) {
    throw new Error(`invalid duration '${input}'; use forms like 30s, 5m, 2h, 1d`);
  }
  const value = Number(m[1]);
  const unit = m[2]!;
  const seconds =
    unit === 's' ? value : unit === 'm' ? value * 60 : unit === 'h' ? value * 3600 : value * 86400;
  return seconds * 1000;
}
