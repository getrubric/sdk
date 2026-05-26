// `rubric mcp request <server> --reason "…"` — ask an admin to approve this
// agent's access to an MCP server. The developer's reasoning is captured and
// stored on the request; an admin approves it in the Rubric dashboard (or, for
// auto-approve servers, it's granted immediately). Until then, calls to that
// server's `mcp__<server>__*` tools are denied at the daemon.

import { bootstrapTokenStore } from '@rubric-app/core';

import { defaultPaths } from '../config/paths.js';
import { readConfig } from './_config.js';
import { dim, info, ok } from './_format.js';

// Mirror of `API_ROUTES.mcp` + the SDK request sub-route from
// packages/shared/src/constants.ts. The claude-code package can't import the
// shared workspace package (it ships to npm), so the route is duplicated here.
const MCP_REQUEST_ROUTE = '/v1/mcp/requests';

const AUTH_BEARER_PREFIX = 'Bearer ';
const REQUEST_TIMEOUT_MS = 10_000;

interface RequestResult {
  status: string;
  server: string;
  grantId: string;
}

export interface McpRequestOptions {
  reason?: string;
}

export async function runMcpRequest(server: string, opts: McpRequestOptions): Promise<void> {
  const reason = (opts.reason ?? '').trim();
  if (!reason) {
    throw new Error('a reason is required: rubric mcp request <server> --reason "<why you need it>"');
  }

  const paths = defaultPaths();
  const config = readConfig(paths.configFile);
  if (config.mode === 'solo' || !config.apiUrl || !config.enrollmentToken) {
    throw new Error(
      'MCP requests need a connected account — run `rubric login` (or `rubric init` and join a workspace) first.',
    );
  }
  const apiUrl = config.apiUrl.replace(/\/+$/, '');

  const store = await bootstrapTokenStore({
    apiUrl,
    agentName: config.agentName,
    enrollmentToken: config.enrollmentToken,
  });

  try {
    const res = await fetch(`${apiUrl}${MCP_REQUEST_ROUTE}`, {
      method: 'POST',
      headers: {
        authorization: `${AUTH_BEARER_PREFIX}${store.token()}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({ server, reason }),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });

    if (!res.ok) {
      const detail = await res.text().catch(() => '');
      throw new Error(`request failed (HTTP ${res.status})${detail ? `: ${detail}` : ''}`);
    }

    const body = (await res.json()) as RequestResult;
    if (body.status === 'approved') {
      process.stdout.write(
        `${ok(`Access to "${body.server}" approved (auto-approve).`)}\n` +
          `${dim('  The daemon picks up the new bundle on its next poll (≤30s); then re-run your command.')}\n`,
      );
    } else {
      process.stdout.write(
        `${info(`Request submitted for "${body.server}" — pending admin approval.`)}\n` +
          `${dim('  An admin reviews it in the Rubric dashboard under MCP servers.')}\n`,
      );
    }
  } finally {
    await store.stop();
  }
}
