// Claude Code hook payload schemas.
//
// Claude Code sends hook events as JSON POSTs to whatever URL is
// configured in `~/.claude/settings.json`. We validate just enough to
// route by `hook_event_name` and extract the fields the evaluator
// needs (`tool_name`, `tool_input`). Everything else is permissively
// accepted via `.passthrough()` so future Claude Code schema changes
// don't break the daemon — only the translator might need an update.
//
// Spec: https://docs.claude.com/en/docs/claude-code/hooks-reference

import { z } from 'zod';

// ---- Event names -----------------------------------------------------------

export const HOOK_EVENT_PRE_TOOL_USE = 'PreToolUse' as const;
export const HOOK_EVENT_POST_TOOL_USE = 'PostToolUse' as const;
export const HOOK_EVENT_SESSION_START = 'SessionStart' as const;

export const HookEventNameSchema = z.union([
  z.literal(HOOK_EVENT_PRE_TOOL_USE),
  z.literal(HOOK_EVENT_POST_TOOL_USE),
  z.literal(HOOK_EVENT_SESSION_START),
]);
export type HookEventName = z.infer<typeof HookEventNameSchema>;

// ---- Common payload shape --------------------------------------------------

const HookPayloadBaseSchema = z
  .object({
    session_id: z.string().min(1),
    transcript_path: z.string().optional(),
    cwd: z.string().optional(),
    hook_event_name: HookEventNameSchema,
  })
  .passthrough();

export const PreToolUsePayloadSchema = HookPayloadBaseSchema.extend({
  hook_event_name: z.literal(HOOK_EVENT_PRE_TOOL_USE),
  tool_name: z.string().min(1),
  // `tool_input` is whatever the tool's input schema is on the Claude
  // Code side; we don't try to know all of them. Permissive object.
  tool_input: z.record(z.string(), z.unknown()).default({}),
});
export type PreToolUsePayload = z.infer<typeof PreToolUsePayloadSchema>;

export const PostToolUsePayloadSchema = HookPayloadBaseSchema.extend({
  hook_event_name: z.literal(HOOK_EVENT_POST_TOOL_USE),
  tool_name: z.string().min(1),
  tool_input: z.record(z.string(), z.unknown()).default({}),
  tool_response: z.unknown().optional(),
});
export type PostToolUsePayload = z.infer<typeof PostToolUsePayloadSchema>;

// A configured MCP server reported to Rubric for discovery. Future Claude
// Code versions may include these on the SessionStart payload directly; until
// then the daemon discovers them from `.mcp.json` / `~/.claude.json`.
export const ReportedMcpServerSchema = z.object({
  name: z.string().min(1),
  transport: z.string().optional(),
  command: z.string().optional(),
  url: z.string().optional(),
  tools: z.array(z.string()).optional(),
});
export type ReportedMcpServer = z.infer<typeof ReportedMcpServerSchema>;

export const SessionStartPayloadSchema = HookPayloadBaseSchema.extend({
  hook_event_name: z.literal(HOOK_EVENT_SESSION_START),
  source: z.string().optional(),
  mcp_servers: z.array(ReportedMcpServerSchema).optional(),
});
export type SessionStartPayload = z.infer<typeof SessionStartPayloadSchema>;

export const HookPayloadSchema = z.discriminatedUnion('hook_event_name', [
  PreToolUsePayloadSchema,
  PostToolUsePayloadSchema,
  SessionStartPayloadSchema,
]);
export type HookPayload = z.infer<typeof HookPayloadSchema>;

// ---- Response shape Claude Code expects ------------------------------------

// Spec: PreToolUse responses can include `hookSpecificOutput` with
// `permissionDecision: "allow" | "deny" | "ask"` and an optional
// `permissionDecisionReason`. Other events return `{ continue: true }`.

export type PermissionDecision = 'allow' | 'deny' | 'ask';

export interface HookResponse {
  continue: boolean;
  /**
   * Universal hook-output field: a warning message Claude Code shows to the
   * *user* (not fed to Claude). The seatbelt uses it on PostToolUse to tell
   * the developer a snapshot was taken and `rubric undo` can restore it.
   */
  systemMessage?: string;
  /** Top-level `decision` is the legacy field; new field is `permissionDecision`. */
  hookSpecificOutput?: {
    hookEventName: HookEventName;
    permissionDecision?: PermissionDecision;
    permissionDecisionReason?: string;
  };
}
