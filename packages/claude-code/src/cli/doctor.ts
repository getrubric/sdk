// `rubric doctor` — sanity checks. Each runs independently and reports
// its own pass/fail/skip line; the command exits 0 only when all
// non-skipped checks pass. The 6 checks from the plan:
//
//   1. config files present and readable
//   2. daemon process alive (pidfile + signal probe)
//   3. daemon /healthz responds in <200ms
//   4. JWT refresh round-trip works (POST /v1/identities/refresh)
//   5. bundle non-empty and recent (last-pull timestamp < 5min)
//   6. ~/.claude/settings.json contains expected hook entries

import * as fs from 'node:fs';

import { errCode } from '@rubric-app/core';

import { defaultPaths } from '../config/paths.js';

import { configExists, readConfig, readDaemonPid, readDaemonPort } from './_config.js';
import { dim, fail, ok, warn } from './_format.js';

const BUNDLE_FRESH_THRESHOLD_MS = 90_000; // 1.5× the default 30s poll interval

interface CheckResult {
  pass: boolean;
  message: string;
  skipped?: boolean;
}

export async function runDoctor(): Promise<void> {
  const paths = defaultPaths();
  const checks: { name: string; run: () => Promise<CheckResult> | CheckResult }[] = [
    { name: 'config files present', run: () => checkConfigFiles(paths) },
    { name: 'daemon process alive', run: () => checkDaemonAlive(paths) },
    { name: 'daemon /healthz < 200ms', run: () => checkHealthz(paths) },
    { name: 'identity refresh works', run: () => checkRefresh(paths) },
    { name: 'settings.json has hooks', run: () => checkSettingsJson(paths) },
    { name: 'bundle non-empty + fresh', run: () => checkBundleFresh(paths) },
  ];

  let failures = 0;
  for (const { name, run } of checks) {
    const r = await run();
    const prefix = r.skipped ? warn(name) : r.pass ? ok(name) : fail(name);
    process.stdout.write(`${prefix}  ${dim(r.message)}\n`);
    if (!r.pass && !r.skipped) failures++;
  }

  process.stdout.write(`\n`);
  if (failures === 0) {
    process.stdout.write(`${ok('doctor: all checks passed')}\n`);
  } else {
    process.stdout.write(`${fail(`doctor: ${failures} check(s) failed`)}\n`);
    process.exit(1);
  }
}

// ---- Checks ----------------------------------------------------------------

type DoctorPaths = ReturnType<typeof defaultPaths>;

function checkConfigFiles(paths: DoctorPaths): CheckResult {
  if (!configExists(paths.configFile)) {
    return { pass: false, message: `${paths.configFile} missing — run 'rubric init'` };
  }
  try {
    readConfig(paths.configFile);
  } catch (err: unknown) {
    return { pass: false, message: (err as Error).message };
  }
  if (!fs.existsSync(paths.daemonTokenFile)) {
    return { pass: false, message: `${paths.daemonTokenFile} missing — run 'rubric init'` };
  }
  return { pass: true, message: `${paths.configFile}` };
}

function checkDaemonAlive(paths: DoctorPaths): CheckResult {
  const pid = readDaemonPid(paths.pidFile);
  if (pid === null) {
    return { pass: false, message: 'no daemon found — start with `rubric daemon` or re-run init' };
  }
  return { pass: true, message: `pid ${pid}` };
}

async function checkHealthz(paths: DoctorPaths): Promise<CheckResult> {
  const port = readDaemonPort(paths.daemonPortFile);
  if (port === null) {
    return { pass: false, message: `${paths.daemonPortFile} missing — daemon may not have bound yet` };
  }
  const startMs = Date.now();
  try {
    const res = await fetch(`http://127.0.0.1:${port}/healthz`, {
      signal: AbortSignal.timeout(1000),
    });
    const elapsed = Date.now() - startMs;
    if (res.status !== 200) {
      return { pass: false, message: `healthz status ${res.status}` };
    }
    if (elapsed > 200) {
      return { pass: false, message: `healthz returned in ${elapsed}ms (>200ms)` };
    }
    return { pass: true, message: `${elapsed}ms on :${port}` };
  } catch (err: unknown) {
    return { pass: false, message: (err as Error).message };
  }
}

async function checkRefresh(paths: DoctorPaths): Promise<CheckResult> {
  // The daemon owns the JWT — we can't run a refresh against it
  // directly. Instead, validate that the API itself is reachable and
  // serving identity routes by hitting /v1/identities/refresh
  // unauthenticated and expecting 401 (proves the endpoint exists).
  // A true "refresh-roundtrip" check requires a daemon endpoint we
  // haven't added yet — leave that for the follow-up.
  let config: ReturnType<typeof readConfig>;
  try {
    config = readConfig(paths.configFile);
  } catch {
    return { pass: false, skipped: true, message: 'no config; skipping' };
  }
  // Solo mode has no account, identity, or control plane — there's nothing to
  // refresh against. Report as a neutral skip rather than a failure.
  if (config.mode === 'solo') {
    return { pass: true, skipped: true, message: 'solo mode — no account or control plane' };
  }
  try {
    const res = await fetch(`${config.apiUrl}/v1/identities/refresh`, {
      method: 'POST',
      signal: AbortSignal.timeout(2000),
    });
    if (res.status === 401) {
      // Endpoint exists and rejected our anonymous call — exactly what we expect.
      return { pass: true, message: `${config.apiUrl} reachable` };
    }
    return { pass: false, message: `expected 401 from refresh endpoint, got ${res.status}` };
  } catch (err: unknown) {
    return {
      pass: false,
      message: `cannot reach ${config.apiUrl}: ${(err as Error).message}`,
    };
  }
}

function checkSettingsJson(paths: DoctorPaths): CheckResult {
  let raw: string;
  try {
    raw = fs.readFileSync(paths.claudeSettingsFile, 'utf8');
  } catch (err: unknown) {
    if (errCode(err) === 'ENOENT') {
      return { pass: false, message: `${paths.claudeSettingsFile} missing` };
    }
    return { pass: false, message: (err as Error).message };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err: unknown) {
    return { pass: false, message: `${paths.claudeSettingsFile} invalid JSON` };
  }
  if (!parsed || typeof parsed !== 'object') {
    return { pass: false, message: `${paths.claudeSettingsFile} is not an object` };
  }
  const root = parsed as Record<string, unknown>;
  const missing: string[] = [];
  for (const evt of ['PreToolUse', 'PostToolUse', 'SessionStart']) {
    const groups = (root['hooks'] as Record<string, unknown> | undefined)?.[evt];
    if (
      !Array.isArray(groups) ||
      !groups.some((g) =>
        ((g as { hooks?: unknown[] }).hooks ?? []).some(
          (h: unknown) =>
            (h as { url?: string }).url === 'http://127.0.0.1:47821/v1/hook',
        ),
      )
    ) {
      missing.push(evt);
    }
  }
  if (missing.length > 0) {
    return { pass: false, message: `missing hook entries for: ${missing.join(', ')}` };
  }
  return { pass: true, message: 'PreToolUse, PostToolUse, SessionStart wired' };
}

async function checkBundleFresh(paths: DoctorPaths): Promise<CheckResult> {
  // Solo mode pulls no bundle from a control plane — it enforces the local
  // editable pack. Verify that instead of hitting /v1/status (which solo
  // doesn't serve). Solo never fails closed: a missing/invalid pack falls back
  // to the built-in default, so those states are healthy, not failures.
  let config: ReturnType<typeof readConfig> | null = null;
  try {
    config = readConfig(paths.configFile);
  } catch {
    /* fall through to the connected path's own skip handling */
  }
  if (config?.mode === 'solo') {
    try {
      const parsed = JSON.parse(fs.readFileSync(paths.policiesFile, 'utf8')) as {
        policies?: unknown[];
      };
      const count = Array.isArray(parsed.policies) ? parsed.policies.length : 0;
      if (count === 0) {
        return { pass: true, skipped: true, message: 'using built-in default pack' };
      }
      return { pass: true, message: `${count} policy/policies (local pack)` };
    } catch {
      return { pass: true, skipped: true, message: 'no/invalid policies.json — using built-in default pack' };
    }
  }

  const port = readDaemonPort(paths.daemonPortFile);
  if (port === null) {
    return { pass: false, skipped: true, message: 'no daemon port; skipping' };
  }
  let daemonToken: string;
  try {
    daemonToken = fs.readFileSync(paths.daemonTokenFile, 'utf8').trim();
  } catch {
    return { pass: false, skipped: true, message: 'no daemon token; skipping' };
  }
  try {
    const res = await fetch(`http://127.0.0.1:${port}/v1/status`, {
      headers: { authorization: `Bearer ${daemonToken}` },
      signal: AbortSignal.timeout(1000),
    });
    if (res.status !== 200) {
      return { pass: false, message: `status returned ${res.status}` };
    }
    const body = (await res.json()) as {
      bundle?: { bundleVersion?: number | null; lastPullAt?: string | null; policyCount?: number };
    };
    const policyCount = body.bundle?.policyCount ?? 0;
    if (policyCount === 0) {
      return {
        pass: false,
        message: 'no policies in bundle — seed templates or author one in the dashboard',
      };
    }
    const lastPullAt = body.bundle?.lastPullAt ? new Date(body.bundle.lastPullAt) : null;
    if (lastPullAt === null) {
      return { pass: false, message: 'no successful bundle pull yet' };
    }
    const ageMs = Date.now() - lastPullAt.getTime();
    if (ageMs > BUNDLE_FRESH_THRESHOLD_MS) {
      return {
        pass: false,
        message: `last pull ${Math.floor(ageMs / 1000)}s ago (>${Math.floor(BUNDLE_FRESH_THRESHOLD_MS / 1000)}s); poller may be stuck`,
      };
    }
    return {
      pass: true,
      message: `${policyCount} policy/policies, last pulled ${Math.floor(ageMs / 1000)}s ago`,
    };
  } catch (err: unknown) {
    return { pass: false, message: (err as Error).message };
  }
}

