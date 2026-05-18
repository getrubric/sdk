// Translate Claude Code hook payloads to the shape the @rubric-app/core
// evaluator expects.
//
// Why this layer exists: the evaluator uses dot-pathed field names like
// `input.command`, `input.file_path`, `input.url`. Claude Code's
// payload nests those under `tool_input.*`. Lifting them into `input.*`
// at the translator means policies authored once work *across* SDKs —
// the Python SDK puts function args under `input.*` from the
// EvaluationMetadata model; this adapter does the same shape for
// Claude Code calls.
//
// Keep this file the *only* place that knows about the Claude Code
// payload format. Schema drift on Claude's side touches only here.

import type { EvaluationRequest } from '@rubric-app/core';

import type { PreToolUsePayload, PostToolUsePayload } from './types.js';

/**
 * Build an `EvaluationRequest` from a `PreToolUse` (or `PostToolUse`)
 * payload. `agent_id` is supplied by the daemon (TokenStore.agentId) —
 * we don't bake it in here because the translator is a pure function.
 */
export function toEvaluationRequest(
  payload: PreToolUsePayload | PostToolUsePayload,
  agentId: string,
): EvaluationRequest {
  return {
    tool_name: payload.tool_name,
    agent_id: agentId,
    // Forward `tool_input` under `input.*` so dot-pathed conditions
    // (`input.command`, `input.file_path`, ...) reach the right field.
    input: payload.tool_input,
    // Surface the session id + cwd as top-level keys so policies can
    // discriminate on them (`{ field: "session_id", ... }`) without
    // diving into `input.*`. Cheap and uniform across hooks.
    session_id: payload.session_id,
    cwd: payload.cwd,
  };
}
