// Wire-level constants for the Rubric API protocol.

// ---- HTTP routes -----------------------------------------------------------

export const API_ROUTE_IDENTITIES_ENROLL = '/v1/identities/enroll';
export const API_ROUTE_IDENTITIES_REFRESH = '/v1/identities/refresh';
export const API_ROUTE_BUNDLE = '/v1/bundle';
export const API_ROUTE_EVENTS = '/v1/events';

// ---- HTTP headers / content types -----------------------------------------

export const HTTP_HEADER_AUTHORIZATION = 'authorization';
export const HTTP_HEADER_CONTENT_TYPE = 'content-type';

export const CONTENT_TYPE_JSON = 'application/json';
export const CONTENT_TYPE_PROBLEM_JSON = 'application/problem+json';

export const AUTH_BEARER_PREFIX = 'Bearer ';

// ---- HTTP status codes -----------------------------------------------------

export const HTTP_NO_CONTENT = 204;
export const HTTP_NOT_MODIFIED = 304;
export const HTTP_UNAUTHORIZED = 401;
export const HTTP_ACCEPTED = 202;

// ---- Bundle poll -----------------------------------------------------------

export const BUNDLE_QUERY_SINCE = 'since';

// ---- Policy doc constants --------------------------------------------------

export const POLICY_API_VERSION = 'agent-governance.io/v1';
export const POLICY_KIND = 'Policy';

export const POLICY_CONDITION_OPERATOR_VALUES = [
  'eq',
  'neq',
  'in',
  'not_in',
  'contains',
  'starts_with',
  'ends_with',
  'matches',
] as const;
export type PolicyConditionOperator = (typeof POLICY_CONDITION_OPERATOR_VALUES)[number];

// 'ask' = defer to the human (Claude Code surfaces an approval prompt). The
// control-plane `decision` enum stays allow|deny for now, so this is a
// deliberate SDK-side superset used by the evaluator + permissive packs.
export const DECISION_VALUES = ['allow', 'deny', 'ask'] as const;
export type Decision = (typeof DECISION_VALUES)[number];
export const DECISION_ALLOW: Decision = 'allow';
export const DECISION_DENY: Decision = 'deny';
export const DECISION_ASK: Decision = 'ask';

// ---- SDK env vars ----------------------------------------------------------

export const ENV_ENROLLMENT_TOKEN = 'AG_ENROLLMENT_TOKEN';
export const ENV_AGENT_NAME = 'AG_AGENT_NAME';
export const ENV_API_URL = 'AG_API_URL';
export const DEFAULT_API_URL = 'https://api.rubric-app.com';

// ---- API URL validation ----------------------------------------------------

/**
 * The Rubric API is hosted on the `rubric-app.com` domain. The SDK
 * refuses to send bearer-bearing traffic anywhere else. This rules out
 * localhost, IP literals, third-party hosts, and `http://` of any kind.
 */
export const ALLOWED_HOST_EXACT = 'rubric-app.com';
export const ALLOWED_HOST_SUFFIX = '.rubric-app.com';

// Internal: the SDK's own integration tests need to run against a local
// mock HTTP server. This env var allows http://127.0.0.1 / http://localhost
// as an API URL ONLY when set. It is intentionally undocumented and is
// never set in production builds — package.json test scripts set it at
// invocation time. Never set this yourself.
const TEST_LOOPBACK_ESCAPE_ENV = 'RUBRIC_INTERNAL_ALLOW_LOOPBACK_FOR_TESTS';
const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1', '[::1]']);

/**
 * Validate an API URL. Returns `null` on accept, or a human-readable
 * error string. The SDK accepts only `https://` URLs whose host is
 * `rubric-app.com` or a subdomain of it (e.g. `api.rubric-app.com`,
 * `staging.rubric-app.com`). The platform is hosted; there is no
 * localhost or self-hosted path.
 */
export function validateApiUrl(input: string): string | null {
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    return `not a valid URL: ${input}`;
  }
  const host = url.hostname.toLowerCase();
  if (
    process.env[TEST_LOOPBACK_ESCAPE_ENV] === '1' &&
    LOOPBACK_HOSTS.has(host) &&
    (url.protocol === 'http:' || url.protocol === 'https:')
  ) {
    return null;
  }
  if (url.protocol !== 'https:') {
    return `must use https:// (got ${url.protocol})`;
  }
  if (host !== ALLOWED_HOST_EXACT && !host.endsWith(ALLOWED_HOST_SUFFIX)) {
    return (
      `host '${host}' is not a Rubric host; ` +
      `the API URL must be on ${ALLOWED_HOST_EXACT} ` +
      `(e.g. https://api.${ALLOWED_HOST_EXACT})`
    );
  }
  return null;
}

/** Throw a `TypeError` if the URL fails `validateApiUrl`. */
export function assertValidApiUrl(input: string): void {
  const err = validateApiUrl(input);
  if (err !== null) {
    throw new TypeError(`invalid Rubric API URL: ${err}`);
  }
}

// ---- Identity timing -------------------------------------------------------

// Server-side TTL is 60 min; refresh fires this far before `expiresAt`.
export const IDENTITY_REFRESH_LEAD_SECONDS = 600;

// ---- Kill-switch (frozen agent) deny semantics -----------------------------
// Stable strings the dashboard renders alongside denies — adapters
// pass these verbatim so the audit trail looks the same regardless of
// which framework reported the event.

export const DENY_REASON_AGENT_FROZEN = 'agent frozen by operator';
export const RESULT_CODE_AGENT_FROZEN = 'AGENT_FROZEN';

// ---- MCP server gating -----------------------------------------------------
// Default-deny enforcement of the per-agent MCP allow-list carried in the
// bundle (`mcpAccess`). When the control plane ships a bundle with
// `mcpAccess.enforce = true`, a call to an `mcp__<server>__*` tool whose
// server isn't approved fails closed before policy evaluation.

export const MCP_TOOL_NAME_PREFIX = 'mcp__';
export const MCP_TOOL_NAME_DELIMITER = '__';
export const RESULT_CODE_MCP_NOT_APPROVED = 'MCP_SERVER_NOT_APPROVED';

/** Split `mcp__<server>__<tool>` → `{ server, tool }`; null if not MCP. */
export function parseMcpServer(toolName: string): { server: string; tool: string } | null {
  if (!toolName.startsWith(MCP_TOOL_NAME_PREFIX)) return null;
  const rest = toolName.slice(MCP_TOOL_NAME_PREFIX.length);
  const idx = rest.indexOf(MCP_TOOL_NAME_DELIMITER);
  if (idx <= 0) return null; // server segment must be non-empty
  return { server: rest.slice(0, idx), tool: rest.slice(idx + MCP_TOOL_NAME_DELIMITER.length) };
}

export function denyReasonMcpNotApproved(server: string): string {
  return `MCP server "${server}" is not approved for this agent. Request access in your Rubric dashboard.`;
}
