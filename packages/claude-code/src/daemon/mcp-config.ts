// Best-effort discovery of the MCP servers configured for a Claude Code
// session. Read at SessionStart so a server appears in the Rubric catalog
// (and a pending grant is created) before any of its tools are called.
//
// Sources, merged by server name (project file wins on conflict):
//   - `<cwd>/.mcp.json`        — project-scoped servers (if cwd is known)
//   - `~/.claude.json`         — user-scoped servers (top-level `mcpServers`)
//
// Both files use the standard MCP shape:
//   { "mcpServers": { "<name>": { "command": "npx", "args": [...] }
//                                | { "url": "https://…", "type": "sse" } } }
//
// Everything here is wrapped so a missing/garbage file yields `[]` rather
// than throwing — tool-name discovery remains the guaranteed fallback.

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import type { ReportedMcpServer } from './types.js';

interface RawServerEntry {
  command?: unknown;
  url?: unknown;
  type?: unknown;
}

function parseServerMap(value: unknown): ReportedMcpServer[] {
  if (!value || typeof value !== 'object') return [];
  const map = (value as { mcpServers?: unknown }).mcpServers;
  if (!map || typeof map !== 'object') return [];

  const out: ReportedMcpServer[] = [];
  for (const [name, raw] of Object.entries(map as Record<string, unknown>)) {
    if (!name || !raw || typeof raw !== 'object') continue;
    const entry = raw as RawServerEntry;
    const command = typeof entry.command === 'string' ? entry.command : undefined;
    const url = typeof entry.url === 'string' ? entry.url : undefined;
    const declaredType = typeof entry.type === 'string' ? entry.type : undefined;
    const transport = url ? (declaredType ?? 'http') : command ? 'stdio' : declaredType;
    out.push({
      name,
      ...(transport ? { transport } : {}),
      ...(command ? { command } : {}),
      ...(url ? { url } : {}),
    });
  }
  return out;
}

function readJsonFile(file: string): unknown {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}

/**
 * Discover configured MCP servers for a session. `cwd` is the session's
 * working directory (from the hook payload) used to locate the project
 * `.mcp.json`; omit it to read only the user-scoped config.
 */
export function discoverMcpServers(cwd?: string): ReportedMcpServer[] {
  const byName = new Map<string, ReportedMcpServer>();

  // User-scoped first; project-scoped overrides on name collision.
  for (const s of parseServerMap(readJsonFile(path.join(os.homedir(), '.claude.json')))) {
    byName.set(s.name, s);
  }
  if (cwd) {
    for (const s of parseServerMap(readJsonFile(path.join(cwd, '.mcp.json')))) {
      byName.set(s.name, s);
    }
  }
  return [...byName.values()];
}
