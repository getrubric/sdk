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

import { isDestructiveGit } from '../seatbelt/classify.js';
import { rubricMark } from './art.js';
import { toEvaluationRequest } from './translate.js';
import {
  HOOK_EVENT_POST_TOOL_USE,
  HOOK_EVENT_PRE_TOOL_USE,
  HOOK_EVENT_SESSION_START,
  type HookPayload,
  type HookResponse,
  type ReportedMcpServer,
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
  /**
   * Discovers configured MCP servers at SessionStart (best-effort), so
   * Rubric's catalog learns about a server before its tools are called.
   * Injected by the daemon in connected mode; omitted in solo (records
   * nothing) and in unit tests (no discovery then).
   */
  discoverMcpServers?: (cwd?: string) => ReportedMcpServer[];
  /**
   * Git seatbelt: snapshot the working tree before a destructive git command
   * runs. Injected by the daemon (closes over `paths` + shadow-repo helpers)
   * and gated on the seatbelt config flag; omitted in unit tests unless they
   * pass a spy. Best-effort — the implementation never throws, but the
   * handler calls it inside a try/catch anyway so the decision path is never
   * affected by a snapshot failure.
   */
  snapshot?: (args: {
    cwd: string;
    command: string;
    sessionId: string;
    /** Claude Code transcript path, used to label the snapshot with the prompt. */
    transcriptPath?: string;
  }) => void;
  /**
   * Reports whether a seatbelt snapshot was just taken for this session +
   * command (set by the daemon alongside `snapshot`). Used on PostToolUse to
   * nudge the user — only when a snapshot actually happened, so we never claim
   * "we saved you" when nothing was captured (e.g. outside a git repo).
   */
  wasJustSnapshotted?: (sessionId: string, command: string) => boolean;
}

/** User-facing nudge surfaced after a destructive git command that we snapshotted. */
const SEATBELT_NUDGE =
  'Rubric snapshotted your working tree before that git command. ' +
  'Run `rubric undo` to restore it (or `rubric undo --list` to pick a point).';

/** Extract the Bash `command` string from a tool_input, or '' if absent. */
function bashCommand(toolInput: Record<string, unknown>): string {
  return typeof toolInput['command'] === 'string' ? (toolInput['command'] as string) : '';
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

      // Git seatbelt: if this is an allowed-or-asked Bash command that
      // discards work, snapshot the working tree *now* — before Claude Code
      // executes it. The PreToolUse hook is synchronous, so the snapshot
      // completes first. We skip `deny` (the command never runs) and require
      // a cwd (the project root resolves from it). Best-effort and isolated:
      // a snapshot failure must never change the decision we already made.
      if (
        deps.snapshot &&
        payload.tool_name === 'Bash' &&
        result.decision !== 'deny' &&
        typeof payload.cwd === 'string' &&
        payload.cwd.length > 0
      ) {
        const command = bashCommand(payload.tool_input);
        if (isDestructiveGit(command)) {
          try {
            deps.snapshot({
              cwd: payload.cwd,
              command,
              sessionId: payload.session_id,
              ...(payload.transcript_path ? { transcriptPath: payload.transcript_path } : {}),
            });
          } catch {
            // Swallow — seatbelt is a net, never a gate.
          }
        }
      }

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

      // Seatbelt nudge: if PreToolUse snapshotted before this exact command,
      // tell the user (in their terminal) that they can undo it. Gated on a
      // real snapshot having been taken so the message is never a false claim.
      if (
        deps.wasJustSnapshotted &&
        payload.tool_name === 'Bash' &&
        deps.wasJustSnapshotted(payload.session_id, bashCommand(payload.tool_input))
      ) {
        return { continue: true, systemMessage: SEATBELT_NUDGE };
      }
      return { continue: true };
    }

    case HOOK_EVENT_SESSION_START: {
      // Discover configured MCP servers (payload-reported ∪ file-discovered),
      // deduped by name. The control plane upserts these into the catalog and
      // opens pending grants — richer + earlier than tool-name discovery.
      const mcpServers = mergeReportedServers(
        payload.mcp_servers ?? [],
        deps.discoverMcpServers?.(payload.cwd) ?? [],
      );

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
          ...(mcpServers.length > 0 ? { mcpServers } : {}),
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

/** Union two reported-server lists, deduping by name (first wins). */
function mergeReportedServers(
  a: ReportedMcpServer[],
  b: ReportedMcpServer[],
): ReportedMcpServer[] {
  const byName = new Map<string, ReportedMcpServer>();
  for (const s of [...a, ...b]) {
    if (!byName.has(s.name)) byName.set(s.name, s);
  }
  return [...byName.values()];
}

/**
 * Human-readable reason shown in the developer's Claude Code terminal on
 * `ask` (why approval is being requested) and `deny` (why it was blocked).
 *
 * Composes the Rubric mark, a one-line headline that names the matched
 * policy, and a plain-language explanation drawn from the matched rule's
 * description. For denies with no matched policy (kill-switch, empty
 * bundle, MCP gate, compile error, timeout) the evaluator's own `reason`
 * is the explanation.
 */
function buildDecisionReason(
  decision: 'deny' | 'ask',
  result: {
    reason?: string;
    matchedPolicyName?: string | null;
    matchedRuleDescription?: string | null;
  },
): string {
  let headline: string;
  let explanation: string;

  if (result.matchedPolicyName) {
    headline =
      decision === 'ask'
        ? `Rubric requires approval from policy "${result.matchedPolicyName}".`
        : `Rubric blocked this action per policy "${result.matchedPolicyName}".`;
    explanation = result.matchedRuleDescription ?? '';
  } else {
    headline =
      decision === 'ask'
        ? 'Rubric requires your approval to run this.'
        : 'Rubric blocked this action.';
    explanation = result.reason ?? '';
  }

  const lines = [rubricMark(), '', headline];
  if (explanation) lines.push(explanation);
  return lines.join('\n');
}
