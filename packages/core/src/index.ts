// `@rubric-app/core` — public API.
//
// Framework-neutral runtime for Rubric SDK adapters. Four building
// blocks compose to form a complete adapter:
//
//   identity   → JWT-SVID enrollment + proactive refresh
//   bundle     → 30-second policy bundle polling with rollback rejection
//   audit-sink → batched, retried shipping of audit events
//   evaluator  → tool-call evaluation against the active bundle

export {
  bootstrapTokenStore,
  TokenStore,
  type BootstrapOptions,
  type TokenStoreOptions,
} from './identity.js';

export { BundlePoller, type BundlePollerOptions } from './bundle.js';

export { verifyBundleSignature } from './bundle-signature.js';

export {
  AuditSink,
  type AuditSinkOptions,
  type AuditSinkStats,
} from './audit-sink.js';

export {
  Evaluator,
  RESULT_CODE_EVAL_TIMEOUT,
  RESULT_CODE_NO_POLICIES,
  RESULT_CODE_POLICY_COMPILE_ERROR,
  type EvaluationRequest,
  type EvaluationResult,
  type EvaluatorOptions,
} from './evaluator.js';

// Internal helpers exposed for the daemon's audit/log scrubbing path.
// The `_internal` underscore signals "consume at your own risk" — these
// are stable in practice but not covered by the public semver contract.
export { scrubSecrets, errMessage, errCode } from './_internal.js';

export {
  GovernanceError,
  GovernanceProblemError,
  IdentityNotInitializedError,
  IdentityRevokedError,
  ProblemDetailsSchema,
  parseProblemDetails,
  type ProblemDetails,
} from './errors.js';

export {
  AuditEventSchema,
  BundleContentSchema,
  BundlePolicyEntrySchema,
  BundleSchema,
  BundleSignatureSchema,
  DecisionSchema,
  PolicyConditionOperatorSchema,
  PolicyConditionSchema,
  PolicyDocumentSchema,
  PolicyEffectSchema,
  PolicyRuleSchema,
  SdkTokenResponseSchema,
  canonicalBundleBytes,
  type AuditEvent,
  type Bundle,
  type BundleContent,
  type BundlePolicyEntry,
  type BundleSignature,
  type PolicyCondition,
  type PolicyDocument,
  type PolicyRule,
  type SdkTokenResponse,
} from './types.js';

export {
  ALLOWED_HOST_EXACT,
  ALLOWED_HOST_SUFFIX,
  BUNDLE_SIGNATURE_ALG,
  BUNDLE_SIGNING_KEY_ID,
  BUNDLE_SIGNING_PUBLIC_KEY_SPKI_B64,
  DECISION_ALLOW,
  DECISION_DENY,
  DECISION_VALUES,
  DEFAULT_API_URL,
  DENY_REASON_AGENT_FROZEN,
  POLICY_CONDITION_OPERATOR_VALUES,
  RESULT_CODE_AGENT_FROZEN,
  assertValidApiUrl,
  validateApiUrl,
  type Decision,
  type PolicyConditionOperator,
} from './constants.js';
