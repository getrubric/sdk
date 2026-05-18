// Public daemon surface. Consumed by `cli/` and by tests.

export { runDaemon } from './run.js';
export type { DaemonConfig, RunDaemonOptions } from './run.js';

export { startServer, DEFAULT_DAEMON_HOST, DEFAULT_DAEMON_PORT } from './server.js';
export type { StartServerOptions, RunningServer } from './server.js';

export { handleHookPayload } from './handler.js';
export type { HandlerDeps, AuditEnqueuer } from './handler.js';

export { buildDaemonStatus } from './status.js';
export type { DaemonStatus, DaemonStatusDeps, AuditSinkLike, AgentIdSource } from './status.js';

export { toEvaluationRequest } from './translate.js';

export { checkBearer } from './auth.js';

export {
  HOOK_EVENT_PRE_TOOL_USE,
  HOOK_EVENT_POST_TOOL_USE,
  HOOK_EVENT_SESSION_START,
  HookPayloadSchema,
  PreToolUsePayloadSchema,
  PostToolUsePayloadSchema,
  SessionStartPayloadSchema,
  HookEventNameSchema,
} from './types.js';
export type {
  HookEventName,
  HookPayload,
  PreToolUsePayload,
  PostToolUsePayload,
  SessionStartPayload,
  HookResponse,
  PermissionDecision,
} from './types.js';
