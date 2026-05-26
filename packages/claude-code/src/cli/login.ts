// `rubric login` — OAuth 2.0 Device Authorization Grant (RFC 8628).
//
// Flow: POST /v1/cli/auth/start → open the browser to the verification URL →
// poll /v1/cli/auth/poll until the user approves in the dashboard → enroll
// with the minted enrollment token via the existing identity path → write a
// connected config → (on "create") auto-publish the local safety pack so the
// fresh workspace's bundle isn't empty.

import * as fs from 'node:fs';
import * as os from 'node:os';

import { bootstrapTokenStore, DEFAULT_API_URL } from '@rubric-app/core';

import { ensureDirMode } from '../config/fs-secure.js';
import { defaultPaths, type Paths } from '../config/paths.js';
import { DEFAULT_SAFETY_PACK } from '../policies/default-pack.js';
import { writeConfig } from './_config.js';
import { tryOpenBrowser } from './_browser.js';
import { dim, fail, header, info, ok, warn } from './_format.js';
import { finishInstall, type InitOptions } from './init.js';

export interface LoginOptions extends InitOptions {
  /** Disambiguates the dashboard approval screen. */
  intent?: 'create' | 'join';
}

// Route paths are hardcoded (not imported from the dashboard's shared package)
// so the published SDK stays decoupled from the monorepo contract package.
const ROUTE_START = '/v1/cli/auth/start';
const ROUTE_POLL = '/v1/cli/auth/poll';
const ROUTE_POLICIES_IMPORT = '/v1/policies/import';
const HTTP_TIMEOUT_MS = 15_000;

interface StartResponse {
  deviceCode: string;
  userCode: string;
  verificationUri: string;
  interval: number;
  expiresIn: number;
}

type PollResponse =
  | { status: 'authorization_pending' }
  | { status: 'slow_down'; interval: number }
  | { status: 'expired' }
  | { status: 'denied' }
  | {
      status: 'approved';
      apiUrl: string;
      org: { id: string; name: string; slug: string };
      enrollmentToken: string;
      agentName: string;
      created: boolean;
    };

export async function runLogin(options: LoginOptions = {}): Promise<void> {
  const paths = defaultPaths();
  process.stdout.write(`${header('Rubric — connect to your workspace')}\n\n`);

  const apiUrl =
    options.apiUrl ?? process.env['RUBRIC_API_URL'] ?? DEFAULT_API_URL;
  const intent = options.intent ?? null;

  // ---- start ---------------------------------------------------------------
  const start = await postJson<StartResponse>(`${apiUrl}${ROUTE_START}`, {
    ...(intent ? { intent } : {}),
    clientInfo: { hostname: os.hostname(), platform: process.platform },
  });

  const opened = tryOpenBrowser(start.verificationUri);
  process.stdout.write(
    `${info('Approve this connection in your browser:')}\n` +
      `  ${dim(start.verificationUri)}\n` +
      (opened ? '' : `  ${warn('(open the link above manually)')}\n`) +
      `  Code: ${dim(start.userCode)}\n\n` +
      `${info('Waiting for approval…')} ${dim('(Ctrl-C to cancel)')}\n`,
  );

  // ---- poll ----------------------------------------------------------------
  let intervalMs = start.interval * 1000;
  const deadline = Date.now() + start.expiresIn * 1000;
  let approved: Extract<PollResponse, { status: 'approved' }> | null = null;

  while (Date.now() < deadline) {
    await sleep(intervalMs);
    const poll = await postJson<PollResponse>(`${apiUrl}${ROUTE_POLL}`, {
      deviceCode: start.deviceCode,
    });
    if (poll.status === 'authorization_pending') continue;
    if (poll.status === 'slow_down') {
      intervalMs = poll.interval * 1000;
      continue;
    }
    if (poll.status === 'expired') {
      process.stderr.write(`${fail('login request expired — run `rubric login` again')}\n`);
      process.exit(1);
    }
    if (poll.status === 'denied') {
      process.stderr.write(`${fail('login was denied in the browser')}\n`);
      process.exit(1);
    }
    approved = poll;
    break;
  }
  if (!approved) {
    process.stderr.write(`${fail('login timed out waiting for approval')}\n`);
    process.exit(1);
  }

  // ---- enroll (reuse the existing identity path) ---------------------------
  const resolvedApiUrl = approved.apiUrl || apiUrl;
  process.stdout.write(`${ok(`approved — connecting as ${dim(approved.agentName)}`)}\n`);
  let agentId: string;
  try {
    const store = await bootstrapTokenStore({
      apiUrl: resolvedApiUrl,
      agentName: approved.agentName,
      enrollmentToken: approved.enrollmentToken,
    });
    agentId = store.agentId;
    await store.stop();
  } catch (err: unknown) {
    process.stderr.write(`${fail(`enrollment failed: ${(err as Error).message}`)}\n`);
    process.exit(1);
  }

  fs.mkdirSync(paths.configDir, { recursive: true, mode: 0o700 });
  ensureDirMode(paths.configDir, 0o700);
  writeConfig(paths.configFile, {
    mode: 'connected',
    apiUrl: resolvedApiUrl,
    agentName: approved.agentName,
    enrollmentToken: approved.enrollmentToken,
  });
  process.stdout.write(`${ok(`connected to ${dim(approved.org.name)} as ${dim(agentId)}`)}\n`);

  // ---- auto-publish local pack (new workspace only) ------------------------
  // Done BEFORE starting the daemon so the connected bundle is populated when
  // the daemon's first poll lands — otherwise a brand-new org's empty bundle
  // would fail closed. Driven by what the server actually did (`created`), not
  // the client's intent, so creating a workspace from a bare `rubric login`
  // still seeds the pack.
  if (approved.created) {
    await importLocalPack(resolvedApiUrl, approved.enrollmentToken, paths);
  }

  await finishInstall(paths, options);

  if (!options.noStart) {
    process.stdout.write(
      `\n${ok('Connected.')} Your guardrails now sync from the dashboard; every tool call is audited.\n` +
        `  Manage policies at ${dim(approved.org.slug)} in the Rubric dashboard.\n`,
    );
  }
}

/** Publish the local safety pack into the freshly-connected workspace. Reads
 *  the editable `policies.json` if present, else falls back to the built-in
 *  default pack — either way the new org gets enforceable policies. */
async function importLocalPack(
  apiUrl: string,
  enrollmentToken: string,
  paths: Paths,
): Promise<void> {
  let documents: unknown[];
  try {
    const raw = fs.readFileSync(paths.policiesFile, 'utf8');
    const parsed = JSON.parse(raw) as { policies?: Array<{ document?: unknown }> };
    documents = (parsed.policies ?? []).map((p) => p.document).filter(Boolean);
    if (documents.length === 0) documents = DEFAULT_SAFETY_PACK.map((p) => p.document);
  } catch {
    documents = DEFAULT_SAFETY_PACK.map((p) => p.document);
  }

  try {
    await postJson(
      `${apiUrl}${ROUTE_POLICIES_IMPORT}`,
      { policies: documents },
      { Authorization: `Bearer ${enrollmentToken}` },
    );
    process.stdout.write(`${ok(`published ${documents.length} local policies to the dashboard`)}\n`);
  } catch (err: unknown) {
    // Non-fatal: the user is connected; they can publish from the dashboard.
    process.stdout.write(
      `${warn(`could not auto-publish local policies: ${(err as Error).message}`)}\n`,
    );
  }
}

// ---- helpers ---------------------------------------------------------------

async function postJson<T>(
  url: string,
  body: unknown,
  headers: Record<string, string> = {},
): Promise<T> {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
  });
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const problem = (await res.json()) as { detail?: string; title?: string };
      detail = problem.detail ?? problem.title ?? detail;
    } catch {
      /* non-JSON error body */
    }
    throw new Error(detail);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
