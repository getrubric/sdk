// Wire schemas for the Rubric API. These mirror the shapes the server
// emits and validates against; any drift surfaces as a zod parse error
// at the SDK boundary rather than crashing deeper in the evaluator or
// audit loop.

import { z } from 'zod';

import {
  BUNDLE_SIGNATURE_ALG,
  DECISION_VALUES,
  POLICY_API_VERSION,
  POLICY_CONDITION_OPERATOR_VALUES,
  POLICY_KIND,
} from './constants.js';

// ---- Identity --------------------------------------------------------------

/**
 * Wire format the SDK receives on `/v1/identities/enroll` and
 * `/v1/identities/refresh`.
 */
export const SdkTokenResponseSchema = z.object({
  token: z.string(),
  expiresAt: z.string().datetime(),
  agentId: z.string(),
  identityId: z.string().uuid(),
});
export type SdkTokenResponse = z.infer<typeof SdkTokenResponseSchema>;

// ---- Policy document -------------------------------------------------------
// The bundle poller validates incoming bundles against these schemas so
// a malformed or version-skewed server response surfaces a clear error
// at the SDK boundary, not deep inside the evaluator.

export const PolicyEffectSchema = z.enum(DECISION_VALUES);
export const PolicyConditionOperatorSchema = z.enum(POLICY_CONDITION_OPERATOR_VALUES);

// Bundle size caps. Prevents a runaway server response from shipping a
// multi-million-rule bundle that hangs every tool-call evaluation.
// Paired with the per-evaluation wall-clock budget in
// `evaluator.evaluate()`.
export const POLICY_MAX_RULES_PER_DOCUMENT = 1000;
export const POLICY_MAX_CONDITIONS_PER_RULE = 50;

// Reject policy `field` paths that would walk into Object.prototype slots.
// Defense-in-depth — JSON.parse doesn't pollute the prototype itself, but a
// pattern like `field: "__proto__.toString"` would still resolve into the
// prototype chain via `resolveField`. Schema-side rejection means a bad bundle
// fails the zod parse rather than silently misbehaving downstream.
const FORBIDDEN_FIELD_PARTS = new Set(['__proto__', 'constructor', 'prototype']);

export const PolicyConditionSchema = z.object({
  field: z
    .string()
    .min(1)
    .refine(
      (s) => s.split('.').every((part) => !FORBIDDEN_FIELD_PARTS.has(part)),
      {
        message:
          'field must not contain `__proto__`, `constructor`, or `prototype` parts',
      },
    ),
  operator: PolicyConditionOperatorSchema,
  value: z.union([
    z.string(),
    z.number(),
    z.boolean(),
    z.array(z.string()),
    z.array(z.number()),
  ]),
});
export type PolicyCondition = z.infer<typeof PolicyConditionSchema>;

export const PolicyRuleSchema = z.object({
  id: z.string().min(1),
  description: z.string().optional(),
  conditions: z.array(PolicyConditionSchema).min(1).max(POLICY_MAX_CONDITIONS_PER_RULE),
  effect: PolicyEffectSchema,
});
export type PolicyRule = z.infer<typeof PolicyRuleSchema>;

export const PolicyDocumentSchema = z.object({
  apiVersion: z.literal(POLICY_API_VERSION),
  kind: z.literal(POLICY_KIND),
  metadata: z.object({
    name: z.string().min(1).max(128),
    description: z.string().max(1024).optional(),
    labels: z.record(z.string(), z.string()).optional(),
  }),
  spec: z.object({
    // Required — no default. A policy that omits `defaultEffect` is a server
    // bug or a manual edit gone wrong; failing the zod parse is strictly
    // safer than silently treating "missing" as "allow".
    defaultEffect: PolicyEffectSchema,
    rules: z.array(PolicyRuleSchema).min(1).max(POLICY_MAX_RULES_PER_DOCUMENT),
  }),
});
export type PolicyDocument = z.infer<typeof PolicyDocumentSchema>;

// ---- Bundle ----------------------------------------------------------------

export const BundlePolicyEntrySchema = z.object({
  policyId: z.string().uuid(),
  policyVersion: z.number().int().nonnegative(),
  document: PolicyDocumentSchema,
});
export type BundlePolicyEntry = z.infer<typeof BundlePolicyEntrySchema>;

// Per-agent MCP allow-list carried in the bundle. Default-deny when
// `enforce` is true: an `mcp__<server>__*` call whose server slug isn't in
// `approvedServers` is blocked by the evaluator. Older control planes may omit
// the whole object — `.default()` keeps such bundles valid, and an absent
// `enforce` defaults true so connected bundles default to deny.
export const BundleMcpAccessSchema = z.object({
  approvedServers: z.array(z.string().min(1)).default([]),
  enforce: z.boolean().default(true),
});
export type BundleMcpAccess = z.infer<typeof BundleMcpAccessSchema>;

// Signature envelope. `signature` is a base64 Ed25519 detached signature
// over the canonical serialization of the bundle's *content* fields (see
// `canonicalBundleBytes`). `contentHash` stays a plain integrity checksum; the
// signature is what proves the bundle came from the control plane. MUST stay
// in sync with the server's `BundleSignatureSchema` in
// `@agent-governance/shared`.
export const BundleSignatureSchema = z.object({
  signatureAlg: z.literal(BUNDLE_SIGNATURE_ALG),
  keyId: z.string().min(1),
  signature: z.string().min(1),
});
export type BundleSignature = z.infer<typeof BundleSignatureSchema>;

// Content fields — everything the signature commits to.
export const BundleContentSchema = z.object({
  bundleVersion: z.number().int().nonnegative(),
  contentHash: z.string().regex(/^[a-f0-9]{64}$/),
  builtAt: z.string().datetime(),
  policies: z.array(BundlePolicyEntrySchema),
  frozenAgentIds: z.array(z.string().min(1).max(128)).default([]),
  mcpAccess: BundleMcpAccessSchema.default({ approvedServers: [], enforce: true }),
});
export type BundleContent = z.infer<typeof BundleContentSchema>;

// `signature` is optional at the schema level so the locally-trusted offline
// baseline pack (compiled in-process, never fetched, so it has no signature)
// still parses. Network-pulled bundles are checked by `verifyBundleSignature`
// in `bundle.ts`'s `_pullOnce`, which drops any bundle whose signature is
// missing or doesn't verify.
export const BundleSchema = BundleContentSchema.extend({
  signature: BundleSignatureSchema.optional(),
});
export type Bundle = z.infer<typeof BundleSchema>;

/**
 * Deterministic byte serialization of a bundle's content for signature
 * verification. MUST stay byte-for-byte identical to the server's
 * `canonicalBundleBytes` (`@agent-governance/shared`): keys emitted in a fixed
 * (sorted) order recursively, excluding the `signature` envelope.
 */
export function canonicalBundleBytes(content: BundleContent): Buffer {
  return Buffer.from(stableStringify(content), 'utf8');
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(',')}]`;
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  const parts = keys.map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`);
  return `{${parts.join(',')}}`;
}

// ---- Audit event -----------------------------------------------------------
// Outgoing events are NOT validated against this schema on the hot
// path — the caller built them in-process, so it would be a CPU spend
// with no enforcement value, and the server rejects malformed batches
// with 4xx (which the sink drops with a logged reason and visible
// counter). The schema is exported so SDK consumers can typecheck
// their own event constructors.

export const DecisionSchema = z.enum(DECISION_VALUES);

export const AuditEventSchema = z.object({
  agentId: z.string().min(1).max(128),
  sessionId: z.string().min(1).max(128),
  ts: z.string().datetime(),
  toolName: z.string().min(1).max(256),
  decision: DecisionSchema,
  policyId: z.string().uuid().nullable(),
  policyVersion: z.number().int().nonnegative().nullable(),
  latencyMs: z.number().nonnegative(),
  metadata: z.record(z.string(), z.unknown()).nullable().optional(),
  framework: z.string().min(1).max(64).nullable().optional(),
  version: z.string().min(1).max(64).nullable().optional(),
  traceId: z.string().uuid().nullable().optional(),
  tracePosition: z.number().int().nonnegative().nullable().optional(),
});
export type AuditEvent = z.infer<typeof AuditEventSchema>;
