// Routes Claude Code hook payloads by event name and returns the
// JSON response Claude Code expects.
//
//   PreToolUse  → evaluator.evaluate() → hookSpecificOutput with
//                 permissionDecision + audit-event enqueue
//   PostToolUse → audit-event only, { continue: true }
//   SessionStart → audit-event only, { continue: true }
//
// The handler is a pure function over its dependencies — the daemon
// composes Evaluator + AuditSink + TokenStore externally and passes
// them in. That keeps unit tests trivial.

import { scrubSecrets, type AuditEvent, type Evaluator } from '@rubric-app/core';

import { toEvaluationRequest } from './translate.js';
import {
  HOOK_EVENT_POST_TOOL_USE,
  HOOK_EVENT_PRE_TOOL_USE,
  HOOK_EVENT_SESSION_START,
  type HookPayload,
  type HookResponse,
} from './types.js';

// Framework identifier stamped on every audit event so the dashboard
// can attribute calls to the Claude Code adapter.
const FRAMEWORK_CLAUDE_CODE = 'claude-code';

// `scrubSecrets` is imported from `@rubric-app/core`. Audit metadata
// redactions match the strings the core SDK redacts on its way out of
// `safeText()` — single source of truth.

/**
 * Walk an arbitrary JSON-shaped value and apply `scrubSecrets` to every
 * string leaf. Used to sanitize `tool_input` and `tool_response` before
 * they land in audit metadata or log lines — Claude Code's Bash tool in
 * particular tends to carry inline secrets (`psql "postgres://user:pw@..."`,
 * `curl -H "Authorization: Bearer $TOKEN"`).
 *
 * Cycle-safe via a `WeakSet`; recursion depth is bounded by the input —
 * tool_input is zod-validated at the server entry, and the 1 MiB payload
 * cap puts a hard ceiling on nesting in practice.
 */
export function scrubDeep(v: unknown, seen: WeakSet<object> = new WeakSet()): unknown {
  if (typeof v === 'string') return scrubSecrets(v);
  if (v === null || typeof v !== 'object') return v;
  if (seen.has(v)) return '<redacted:cycle>';
  seen.add(v);
  if (Array.isArray(v)) {
    return v.map((item) => scrubDeep(item, seen));
  }
  const out: Record<string, unknown> = {};
  for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
    out[k] = scrubDeep(val, seen);
  }
  return out;
}

/** Minimal interface the handler needs from an AuditSink. */
export interface AuditEnqueuer {
  enqueue(event: AuditEvent): void;
}

export interface HandlerDeps {
  evaluator: Evaluator;
  audit: AuditEnqueuer;
  /** Rubric-side agent id from the enrolled identity. */
  agentId: string;
  /** Claude Code's own version string, if known. Stamped on audit events. */
  agentVersion?: string;
  /**
   * Returns a stable iso timestamp for the event. Pulled out as an
   * option so tests can inject deterministic timestamps.
   */
  now?: () => string;
}

export function handleHookPayload(payload: HookPayload, deps: HandlerDeps): HookResponse {
  const now = deps.now ?? (() => new Date().toISOString());

  switch (payload.hook_event_name) {
    case HOOK_EVENT_PRE_TOOL_USE: {
      const request = toEvaluationRequest(payload, deps.agentId);
      const result = deps.evaluator.evaluate(request);

      const event: AuditEvent = {
        agentId: deps.agentId,
        sessionId: payload.session_id,
        ts: now(),
        toolName: payload.tool_name,
        decision: result.decision,
        policyId: result.matchedPolicyId ?? null,
        policyVersion: result.matchedPolicyVersion ?? null,
        latencyMs: result.latencyMs,
        metadata: {
          hook: HOOK_EVENT_PRE_TOOL_USE,
          // `tool_input` is scrubbed for inline secrets (JWTs, Bearer
          // headers, postgres URLs with creds, provider-shape API keys)
          // before being forwarded into audit metadata. Audit rows are
          // stored in plaintext server-side; we don't want a Bash
          // command line with `AWS_SECRET_ACCESS_KEY=…` riding through
          // unredacted.
          tool_input: scrubDeep(payload.tool_input),
          ...(result.matchedRuleId ? { matchedRuleId: result.matchedRuleId } : {}),
          ...(result.code ? { code: result.code } : {}),
          ...(result.reason ? { reason: result.reason } : {}),
        },
        framework: FRAMEWORK_CLAUDE_CODE,
        ...(deps.agentVersion ? { version: deps.agentVersion } : {}),
      };
      deps.audit.enqueue(event);

      return {
        continue: true,
        hookSpecificOutput: {
          hookEventName: HOOK_EVENT_PRE_TOOL_USE,
          permissionDecision: result.decision,
          // Surface a reason on deny (why it was blocked) and on ask (why
          // Claude Code is prompting). Allows don't need one.
          ...(result.decision === 'deny' || result.decision === 'ask'
            ? { permissionDecisionReason: buildDecisionReason(result.decision, result) }
            : {}),
        },
      };
    }

    case HOOK_EVENT_POST_TOOL_USE: {
      // PostToolUse is observation-only — the tool already ran.
      // We still ship an audit event so the dashboard sees the call's
      // outcome and any tool_response payload.
      const event: AuditEvent = {
        agentId: deps.agentId,
        sessionId: payload.session_id,
        ts: now(),
        toolName: payload.tool_name,
        // PostToolUse has no decision per se; we tag it as 'allow' so
        // the events row is well-formed and use the metadata.hook
        // discriminator to distinguish pre/post in the dashboard.
        decision: 'allow',
        policyId: null,
        policyVersion: null,
        latencyMs: 0,
        metadata: {
          hook: HOOK_EVENT_POST_TOOL_USE,
          tool_input: scrubDeep(payload.tool_input),
          ...(payload.tool_response !== undefined
            ? { tool_response: scrubDeep(payload.tool_response) }
            : {}),
        },
        framework: FRAMEWORK_CLAUDE_CODE,
        ...(deps.agentVersion ? { version: deps.agentVersion } : {}),
      };
      deps.audit.enqueue(event);
      return { continue: true };
    }

    case HOOK_EVENT_SESSION_START: {
      const event: AuditEvent = {
        agentId: deps.agentId,
        sessionId: payload.session_id,
        ts: now(),
        // `__session_start__` is a sentinel toolName — the dashboard
        // filters it out of tool-call charts but keeps it for session
        // attribution. Picking an underscore-bracketed string avoids
        // colliding with any real tool name.
        toolName: '__session_start__',
        decision: 'allow',
        policyId: null,
        policyVersion: null,
        latencyMs: 0,
        metadata: {
          hook: HOOK_EVENT_SESSION_START,
          ...(payload.source ? { source: payload.source } : {}),
        },
        framework: FRAMEWORK_CLAUDE_CODE,
        ...(deps.agentVersion ? { version: deps.agentVersion } : {}),
      };
      deps.audit.enqueue(event);
      return { continue: true };
    }

    default:
      // Exhaustiveness check — adding a fourth hook event without
      // updating this switch is a compile-time error. The runtime
      // throw is unreachable today (zod discriminatedUnion enforces
      // the shape upstream) but documents intent.
      return assertNever(payload);
  }
}

// ---- Helpers ---------------------------------------------------------------

function assertNever(x: never): never {
  throw new Error(`handleHookPayload: non-exhaustive switch on ${JSON.stringify(x)}`);
}

/**
 * Human-readable deny reason for the developer to see in their Claude
 * Code terminal. Prefer the policy's explicit reason if present (set
 * by the kill-switch path), otherwise reconstruct a useful sentence.
 */
function buildDecisionReason(
  decision: 'deny' | 'ask',
  result: {
    reason?: string;
    matchedPolicyId?: string | null;
    matchedRuleId?: string | null;
    code?: string;
  },
): string {
  if (result.reason) return result.reason;
  const policy = result.matchedPolicyId ? `policy ${result.matchedPolicyId}` : 'a policy';
  const rule = result.matchedRuleId ? ` (rule ${result.matchedRuleId})` : '';
  return decision === 'ask'
    ? `Rubric flagged this call for your approval: ${policy}${rule} matched.`
    : `Rubric denied this call: ${policy}${rule} matched.`;
}
