// Anonymous, opt-out, counts-only telemetry for solo installs.
//
// Sends: which lifecycle event fired (install / daemon_start / session /
// block) plus low-cardinality dimensions (mode, decision, policy rule id).
// NEVER sends: tool names, inputs, file paths, commands, URLs, or anything
// that identifies a user. Opt out with RUBRIC_TELEMETRY=0 or
// `"telemetry": false` in config.json. Fire-and-forget: failures are
// swallowed and never affect enforcement.

import { randomBytes } from 'node:crypto';
import * as fs from 'node:fs';

import { DEFAULT_API_URL } from '@rubric-app/core';

const TELEMETRY_ROUTE = '/v1/telemetry';
const TELEMETRY_TIMEOUT_MS = 3000;

export type TelemetryEventName = 'install' | 'daemon_start' | 'session' | 'block';

export interface TelemetryDimensions {
  mode?: 'solo' | 'connected';
  decision?: 'allow' | 'deny' | 'ask';
  ruleId?: string;
}

export interface TelemetryOptions {
  installId: string;
  enabled: boolean;
  apiUrl?: string;
  sdkVersion?: string;
}

export class Telemetry {
  private readonly base: string;

  constructor(private readonly opts: TelemetryOptions) {
    this.base = (opts.apiUrl ?? DEFAULT_API_URL).replace(/\/+$/, '');
  }

  emit(event: TelemetryEventName, dims: TelemetryDimensions = {}): void {
    if (!this.opts.enabled) return;
    const body = {
      installId: this.opts.installId,
      event,
      ts: new Date().toISOString(),
      ...(this.opts.sdkVersion ? { sdkVersion: this.opts.sdkVersion } : {}),
      ...(dims.mode ? { mode: dims.mode } : {}),
      ...(dims.decision ? { decision: dims.decision } : {}),
      ...(dims.ruleId ? { ruleId: dims.ruleId } : {}),
    };
    void fetch(`${this.base}${TELEMETRY_ROUTE}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(TELEMETRY_TIMEOUT_MS),
    }).catch(() => {
      // Swallowed by design — telemetry must never affect the daemon.
    });
  }
}

/** Telemetry is on unless RUBRIC_TELEMETRY=0 or the config flag is false. */
export function telemetryEnabled(configFlag?: boolean): boolean {
  if (process.env['RUBRIC_TELEMETRY'] === '0') return false;
  if (configFlag === false) return false;
  return true;
}

/** Load (or lazily create) the random anonymous install id. */
export function loadOrCreateInstallId(file: string): string {
  try {
    const existing = fs.readFileSync(file, 'utf8').trim();
    if (existing.length >= 8) return existing;
  } catch {
    /* fall through to create */
  }
  const id = randomBytes(16).toString('hex');
  try {
    fs.writeFileSync(file, id + '\n', { mode: 0o600 });
  } catch {
    /* best-effort — telemetry id is not load-bearing */
  }
  return id;
}

/** One-line opt-out notice shown after install. */
export const TELEMETRY_NOTICE =
  'Anonymous, counts-only usage telemetry is on (no code, commands, or paths ever sent). Opt out: RUBRIC_TELEMETRY=0';
