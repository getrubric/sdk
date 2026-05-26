// Tests for SessionStart MCP-server discovery from `.mcp.json`. We use a temp
// project dir so the assertions are deterministic regardless of whatever
// `~/.claude.json` happens to exist on the test machine — we only assert on
// the uniquely-named servers we write into the project file.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { discoverMcpServers } from '../dist/daemon/mcp-config.js';

function tmpProject(mcpJson) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rubric-mcp-'));
  fs.writeFileSync(path.join(dir, '.mcp.json'), JSON.stringify(mcpJson));
  return dir;
}

test('discoverMcpServers: stdio + remote entries are parsed with inferred transport', () => {
  const dir = tmpProject({
    mcpServers: {
      tstStdio: { command: 'npx', args: ['-y', 'pkg'] },
      tstRemote: { url: 'https://mcp.example.com', type: 'sse' },
      tstHttp: { url: 'https://mcp2.example.com' },
    },
  });
  const found = discoverMcpServers(dir);
  const byName = Object.fromEntries(found.map((s) => [s.name, s]));

  assert.equal(byName.tstStdio.transport, 'stdio');
  assert.equal(byName.tstStdio.command, 'npx');
  assert.equal(byName.tstRemote.transport, 'sse');
  assert.equal(byName.tstRemote.url, 'https://mcp.example.com');
  assert.equal(byName.tstHttp.transport, 'http'); // url present, no type → http
});

test('discoverMcpServers: missing/garbage file yields [] (no throw)', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rubric-mcp-empty-'));
  // No .mcp.json written. Result is whatever ~/.claude.json yields, but must
  // not throw and must be an array.
  assert.ok(Array.isArray(discoverMcpServers(dir)));

  fs.writeFileSync(path.join(dir, '.mcp.json'), '{ not json');
  assert.ok(Array.isArray(discoverMcpServers(dir)));
});
