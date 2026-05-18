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

export const DECISION_VALUES = ['allow', 'deny'] as const;
export type Decision = (typeof DECISION_VALUES)[number];
export const DECISION_ALLOW: Decision = 'allow';
export const DECISION_DENY: Decision = 'deny';

// ---- SDK env vars ----------------------------------------------------------

export const ENV_ENROLLMENT_TOKEN = 'AG_ENROLLMENT_TOKEN';
export const ENV_AGENT_NAME = 'AG_AGENT_NAME';
export const ENV_API_URL = 'AG_API_URL';
export const DEFAULT_API_URL = 'https://api.rubric-app.com';

// ---- Identity timing -------------------------------------------------------

// Server-side TTL is 60 min; refresh fires this far before `expiresAt`.
export const IDENTITY_REFRESH_LEAD_SECONDS = 600;

// ---- Kill-switch (frozen agent) deny semantics -----------------------------
// Stable strings the dashboard renders alongside denies — adapters
// pass these verbatim so the audit trail looks the same regardless of
// which framework reported the event.

export const DENY_REASON_AGENT_FROZEN = 'agent frozen by operator';
export const RESULT_CODE_AGENT_FROZEN = 'AGENT_FROZEN';
