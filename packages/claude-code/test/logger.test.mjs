// Logger tests. Covers the log-file mode tightening — pino's default
// destination opens the log file with the process umask, which on most
// systems is 0022 (yielding 0644). We chmod to 0600 immediately after
// open so a same-UID local process can't observe session metadata or
// any payload-fragment echoes.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { createLogger } from '../dist/daemon/logger.js';

function tmpLogFile() {
  return path.join(
    fs.mkdtempSync(path.join(os.tmpdir(), 'rubric-logger-test-')),
    'daemon.log',
  );
}

test('createLogger chmods the log file to 0600', () => {
  const logFile = tmpLogFile();
  const logger = createLogger({ logFile, level: 'info' });
  logger.info('hello');
  // Flush pino's async destination by giving the event loop a tick.
  // pino opens the destination with `sync: false`; the file exists
  // synchronously after `pino.destination` returns regardless of
  // whether any write has flushed.
  const stat = fs.statSync(logFile);
  // Mask off file-type bits, keep permission bits.
  const mode = stat.mode & 0o777;
  assert.equal(mode, 0o600, `expected mode 0600, got 0${mode.toString(8)}`);
});
