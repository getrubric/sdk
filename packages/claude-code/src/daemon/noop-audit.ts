// Solo-mode audit sink: a no-op. Solo enforcement is fully local and
// records nothing — no decision log on disk, no telemetry, nothing leaves
// (or is written on) the machine. The daemon still composes an
// `AuditEnqueuer` so the shared hook handler is mode-agnostic; in solo it
// simply drops every event.

import type { AuditEvent } from '@rubric-app/core';

import type { AuditEnqueuer } from './handler.js';

export class NoopAuditSink implements AuditEnqueuer {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  enqueue(_event: AuditEvent): void {
    // Intentionally empty — solo mode persists and emits nothing.
  }
}
