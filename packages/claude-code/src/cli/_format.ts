// Output helpers — terminal coloring + status markers.
//
// Honors `NO_COLOR` and `--no-color` (commander handles --no-color
// itself; we check the env). All functions write to stdout/stderr;
// no global state.

import pc from 'picocolors';

const isTTY = process.stdout.isTTY && !process.env['NO_COLOR'];

export function dim(s: string): string {
  return isTTY ? pc.dim(s) : s;
}

export function bold(s: string): string {
  return isTTY ? pc.bold(s) : s;
}

export function ok(s: string): string {
  return isTTY ? pc.green('✓') + ' ' + s : '[ok] ' + s;
}

export function fail(s: string): string {
  return isTTY ? pc.red('✗') + ' ' + s : '[fail] ' + s;
}

export function warn(s: string): string {
  return isTTY ? pc.yellow('!') + ' ' + s : '[warn] ' + s;
}

export function info(s: string): string {
  return isTTY ? pc.cyan('•') + ' ' + s : '[info] ' + s;
}

export function header(s: string): string {
  return bold(s);
}

/**
 * Print a fatal error and exit non-zero. Always writes to stderr.
 * Use this only at command-top-level; deeper code should throw and let
 * the CLI entry point format the message.
 */
export function fatal(message: string): never {
  process.stderr.write(`${fail(message)}\n`);
  process.exit(1);
}
