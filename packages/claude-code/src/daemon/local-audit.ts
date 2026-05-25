// Solo-mode audit sink: there's no control plane to ship to, so every
// decision is written to the local daemon log instead. Keeps the
// `AuditEnqueuer` contract the handler depends on, and means
// `rubric logs --decision deny` surfaces solo decisions with no extra work.
// Nothing leaves the machine.

import type { AuditEvent } from '@rubric-app/core';

import type { AuditEnqueuer } from './handler.js';
import type { Logger } from './logger.js';
import type { Telemetry } from './telemetry.js';

const SESSION_START_TOOL = '__session_start__';

export class LocalAuditSink implements AuditEnqueuer {
  constructor(
    private readonly logger: Logger,
    private readonly telemetry?: Telemetry,
  ) {}

  enqueue(event: AuditEvent): void {
    this.logger.info(
      {
        audit: {
          ts: event.ts,
          toolName: event.toolName,
          decision: event.decision,
          sessionId: event.sessionId,
          ...(event.metadata ? { metadata: event.metadata } : {}),
        },
      },
      'solo decision',
    );

    // Counts-only telemetry — no tool name/content, just the lifecycle signal.
    if (this.telemetry) {
      if (event.toolName === SESSION_START_TOOL) {
        this.telemetry.emit('session', { mode: 'solo' });
      } else if (event.decision === 'deny' || event.decision === 'ask') {
        const ruleId =
          typeof event.metadata?.matchedRuleId === 'string'
            ? event.metadata.matchedRuleId
            : undefined;
        this.telemetry.emit('block', {
          mode: 'solo',
          decision: event.decision,
          ...(ruleId ? { ruleId } : {}),
        });
      }
    }
  }
}
