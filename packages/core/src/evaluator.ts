// Local policy evaluator.
//
// Algorithm:
//
//   1. If the bundle lists `request.agent_id` in `frozenAgentIds`, return
//      `deny / AGENT_FROZEN` before any rule fires — kill-switch.
//   2. If the bundle is null or has no policies, default to deny with
//      `deny / NO_POLICIES`. The daemon also gates `/v1/hook` on a
//      successful first bundle pull, but the evaluator itself refuses
//      to be permissive without an authoritative bundle as defense in
//      depth.
//   3. For every (policy, rule) pair, evaluate the rule's conditions
//      (logical AND across conditions). On a match:
//        - record the policy/rule as the current "matched" rule
//        - if the rule's effect is `deny`, return immediately
//        - else (allow) continue scanning — later matches overwrite earlier
//      The algorithm is "first-deny-wins; otherwise last-allow-wins".
//   4. If no rule matched, fall through to the *first* policy's
//      `spec.defaultEffect`.
//
// `matches` conditions are evaluated under `re2`, a non-backtracking
// regex engine, so match time stays linear in the input length regardless
// of the pattern. The cost is that re2 doesn't support lookaround or
// backreferences; patterns using those fail to compile. We treat compile
// failure as a deny: any policy containing an uncompileable pattern is
// marked "errored" and every evaluation that touches it returns
// `deny / POLICY_COMPILE_ERROR`. Regex patterns are pre-compiled in
// `updateBundle()` rather than at evaluation time so the native binding
// cost is paid once per bundle, not once per tool call.

import RE2 from 're2';

import {
  DECISION_ALLOW,
  DECISION_ASK,
  DECISION_DENY,
  DENY_REASON_AGENT_FROZEN,
  RESULT_CODE_AGENT_FROZEN,
  RESULT_CODE_MCP_NOT_APPROVED,
  denyReasonMcpNotApproved,
  parseMcpServer,
  type Decision,
} from './constants.js';
import type { Bundle, PolicyCondition } from './types.js';

const NANOS_PER_MS = 1_000_000;

// Per-evaluation wall-clock budget. A pathologically large bundle (rules ×
// conditions × regex tests) that slips past the schema's static caps would
// otherwise pin the event loop for every tool-call. 50ms is well above the
// p99 of a healthy 1000-rule bundle (~1-2ms locally) and well below user-
// perceivable hook latency.
const EVAL_WALL_CLOCK_BUDGET_MS = 50;

// Stable result codes surfaced via `EvaluationResult.code`. Kept here so
// callers (daemon, audit sink) can branch on them without importing constants.
export const RESULT_CODE_NO_POLICIES = 'NO_POLICIES';
export const RESULT_CODE_POLICY_COMPILE_ERROR = 'POLICY_COMPILE_ERROR';
export const RESULT_CODE_EVAL_TIMEOUT = 'EVAL_TIMEOUT';

const REASON_NO_POLICIES = 'no bundle loaded — failing closed';
const REASON_POLICY_COMPILE_ERROR =
  'policy contains a regex pattern that failed to compile — failing closed';
const REASON_EVAL_TIMEOUT = 'evaluation exceeded wall-clock budget — failing closed';

export type EvaluationRequest = Record<string, unknown> & {
  tool_name: string;
  agent_id?: string | null;
};

export interface EvaluationResult {
  decision: Decision;
  matchedPolicyId?: string | null;
  /** Human-readable name of the matched policy (`metadata.name`), for UI/reasons. */
  matchedPolicyName?: string | null;
  matchedPolicyVersion?: number | null;
  matchedRuleId?: string | null;
  /** The matched rule's `description`, surfaced as the user-facing explanation. */
  matchedRuleDescription?: string | null;
  latencyMs: number;
  /**
   * Stable result code on denies that aren't the result of a regular rule
   * match. One of:
   *   - `AGENT_FROZEN` — kill-switch fired before any rule
   *   - `NO_POLICIES` — bundle missing or empty
   *   - `POLICY_COMPILE_ERROR` — a policy contains an uncompileable regex
   *   - `EVAL_TIMEOUT` — per-evaluation budget exceeded
   */
  code?: string;
  reason?: string;
}

export interface EvaluatorOptions {
  /**
   * Called when a `matches` operator's pattern fails to compile (invalid
   * regex, or a feature re2 doesn't support — lookaround, backrefs).
   *
   * An uncompileable pattern is NOT silently skipped: the containing
   * policy is marked "errored" and every evaluation that would touch
   * it returns `deny / POLICY_COMPILE_ERROR`. This callback is the
   * observability hook so the daemon can log/alert; the deny is the
   * enforcement.
   *
   * Defaults to a no-op so @rubric-app/core stays logger-free.
   */
  onCompileError?: (err: {
    policyId: string;
    ruleId: string;
    pattern: string;
    cause: unknown;
  }) => void;
}

/**
 * Evaluates a tool-call request against the bundle's policies.
 *
 * Construct, then `updateBundle()` whenever the BundlePoller reports a new
 * bundle; call `evaluate()` on the hot path.
 */
export class Evaluator {
  private _bundle: Bundle | null = null;
  // Per-bundle compiled patterns. Key: PolicyCondition reference. Value: a
  // compiled RE2. A failed-compile is no longer stored as `null`; instead,
  // the containing policyId is added to `_erroredPolicyIds` and any
  // evaluation touching that policy returns POLICY_COMPILE_ERROR.
  private _compiledPatterns = new WeakMap<PolicyCondition, RE2>();
  // Policy IDs whose document contains at least one `matches` condition
  // whose pattern failed to compile under re2. Populated in `updateBundle`,
  // checked on every evaluation. Defaults to deny: any request that would
  // otherwise be evaluated against such a policy returns DENY.
  private _erroredPolicyIds = new Set<string>();
  private readonly _onCompileError: EvaluatorOptions['onCompileError'];

  constructor(options: EvaluatorOptions = {}) {
    this._onCompileError = options.onCompileError;
  }

  updateBundle(bundle: Bundle): void {
    this._bundle = bundle;
    this._compiledPatterns = new WeakMap<PolicyCondition, RE2>();
    this._erroredPolicyIds = new Set<string>();
    for (const entry of bundle.policies) {
      for (const rule of entry.document.spec.rules) {
        for (const condition of rule.conditions) {
          if (condition.operator !== 'matches') continue;
          if (typeof condition.value !== 'string') {
            // A non-string value on `matches` is a schema-level oddity; treat
            // as a compile error so the policy fails closed rather than
            // silently never-matching.
            this._erroredPolicyIds.add(entry.policyId);
            this._onCompileError?.({
              policyId: entry.policyId,
              ruleId: rule.id,
              pattern: String(condition.value),
              cause: new Error('matches value must be a string'),
            });
            continue;
          }
          try {
            this._compiledPatterns.set(condition, new RE2(condition.value));
          } catch (cause) {
            this._erroredPolicyIds.add(entry.policyId);
            this._onCompileError?.({
              policyId: entry.policyId,
              ruleId: rule.id,
              pattern: condition.value,
              cause,
            });
          }
        }
      }
    }
  }

  evaluate(request: EvaluationRequest): EvaluationResult {
    const start = process.hrtime.bigint();
    // performance.now() is used for the wall-clock budget — same monotonic
    // clock as hrtime, just simpler arithmetic for the per-loop check.
    const budgetStartMs = performance.now();
    const bundle = this._bundle;

    // Frozen agent kill-switch fires before any rule.
    if (
      bundle !== null &&
      request.agent_id !== null &&
      request.agent_id !== undefined &&
      isFrozen(bundle, request.agent_id)
    ) {
      return {
        decision: DECISION_DENY,
        code: RESULT_CODE_AGENT_FROZEN,
        reason: DENY_REASON_AGENT_FROZEN,
        latencyMs: elapsedMs(start),
      };
    }

    // MCP default-deny: a call to an `mcp__<server>__*` tool whose server
    // isn't in the agent's approved set fails closed *before* policy
    // evaluation (so even a policy-less agent gets the actionable reason).
    // `enforce: false` (solo / local bundles) turns the gate off; absent →
    // true so connected bundles default to deny.
    if (bundle !== null) {
      const parsed = parseMcpServer(request.tool_name);
      const approvedServers = bundle.mcpAccess?.approvedServers ?? [];
      const enforceMcp = bundle.mcpAccess?.enforce ?? true;
      if (enforceMcp && parsed && !approvedServers.includes(parsed.server)) {
        return {
          decision: DECISION_DENY,
          code: RESULT_CODE_MCP_NOT_APPROVED,
          reason: denyReasonMcpNotApproved(parsed.server),
          latencyMs: elapsedMs(start),
        };
      }
    }

    // Empty bundle / cold-start is not permissive. A bundle we haven't
    // pulled yet (null) and a bundle the server says is empty are both
    // treated as "we don't know what the policy is" → deny.
    if (bundle === null || bundle.policies.length === 0) {
      return {
        decision: DECISION_DENY,
        code: RESULT_CODE_NO_POLICIES,
        reason: REASON_NO_POLICIES,
        latencyMs: elapsedMs(start),
      };
    }

    // Ask is deferred + sticky: a matched `ask` is remembered and applied at
    // the end with precedence deny > ask > allow. A later `allow` must not
    // downgrade it; a later `deny` (which returns immediately) still wins.
    let sawAsk = false;
    let askPolicyId: string | null = null;
    let askPolicyName: string | null = null;
    let askPolicyVersion: number | null = null;
    let askRuleId: string | null = null;
    let askRuleDescription: string | null = null;

    let finalDecision: Decision = DECISION_ALLOW;
    let matchedPolicyId: string | null = null;
    let matchedPolicyName: string | null = null;
    let matchedPolicyVersion: number | null = null;
    let matchedRuleId: string | null = null;
    let matchedRuleDescription: string | null = null;

    for (const entry of bundle.policies) {
      // Any policy with an uncompileable regex fails closed for every
      // request that would have touched it. We check at the policy
      // level (not the rule level) because a deny rule with a broken
      // pattern shouldn't be silently treated as never-matching while
      // sibling allow rules continue to fire.
      if (this._erroredPolicyIds.has(entry.policyId)) {
        return {
          decision: DECISION_DENY,
          code: RESULT_CODE_POLICY_COMPILE_ERROR,
          reason: REASON_POLICY_COMPILE_ERROR,
          matchedPolicyId: entry.policyId,
          matchedPolicyVersion: entry.policyVersion,
          latencyMs: elapsedMs(start),
        };
      }
      for (const rule of entry.document.spec.rules) {
        // Bound per-evaluation wall-clock. Checked at the rule
        // boundary — fine-grained enough to bail out of a pathological
        // bundle without paying the check cost on every condition.
        if (performance.now() - budgetStartMs > EVAL_WALL_CLOCK_BUDGET_MS) {
          return {
            decision: DECISION_DENY,
            code: RESULT_CODE_EVAL_TIMEOUT,
            reason: REASON_EVAL_TIMEOUT,
            latencyMs: elapsedMs(start),
          };
        }
        const allMatch = rule.conditions.every((c) => this._matches(c, request));
        if (!allMatch) continue;

        if (rule.effect === DECISION_DENY) {
          // Deny is absolute and short-circuits — highest precedence.
          return {
            decision: DECISION_DENY,
            matchedPolicyId: entry.policyId,
            matchedPolicyName: entry.document.metadata.name,
            matchedPolicyVersion: entry.policyVersion,
            matchedRuleId: rule.id,
            matchedRuleDescription: rule.description ?? null,
            latencyMs: elapsedMs(start),
          };
        }

        if (rule.effect === DECISION_ASK) {
          // Remember and keep scanning so a later deny can still override.
          sawAsk = true;
          askPolicyId = entry.policyId;
          askPolicyName = entry.document.metadata.name;
          askPolicyVersion = entry.policyVersion;
          askRuleId = rule.id;
          askRuleDescription = rule.description ?? null;
          continue;
        }

        // allow — last-allow-wins among allows.
        finalDecision = DECISION_ALLOW;
        matchedPolicyId = entry.policyId;
        matchedPolicyName = entry.document.metadata.name;
        matchedPolicyVersion = entry.policyVersion;
        matchedRuleId = rule.id;
        matchedRuleDescription = rule.description ?? null;
      }
    }

    // No deny fired. Ask beats allow, so surface a pending ask before the
    // allow / defaultEffect resolution.
    if (sawAsk) {
      return {
        decision: DECISION_ASK,
        matchedPolicyId: askPolicyId,
        matchedPolicyName: askPolicyName,
        matchedPolicyVersion: askPolicyVersion,
        matchedRuleId: askRuleId,
        matchedRuleDescription: askRuleDescription,
        latencyMs: elapsedMs(start),
      };
    }

    if (matchedPolicyId === null) {
      // No rule matched — resolve the default across ALL policies in an
      // order-independent way: deny if ANY policy defaults to deny, else ask
      // if ANY defaults to ask, else allow. Resolving across every policy
      // (rather than honoring only `policies[0]`) means the result does not
      // depend on policy ordering. The shipped all-`allow` pack still
      // resolves to allow. `bundle.policies` is non-empty here: we returned
      // early on empty policies.
      const defaults = bundle.policies.map((p) => p.document.spec.defaultEffect);
      const defaultEffect: Decision = defaults.includes(DECISION_DENY)
        ? DECISION_DENY
        : defaults.includes(DECISION_ASK)
          ? DECISION_ASK
          : DECISION_ALLOW;
      return { decision: defaultEffect, latencyMs: elapsedMs(start) };
    }

    return {
      decision: finalDecision,
      matchedPolicyId,
      matchedPolicyName,
      matchedPolicyVersion,
      matchedRuleId,
      matchedRuleDescription,
      latencyMs: elapsedMs(start),
    };
  }

  // ---- Internals ------------------------------------------------------------

  private _matches(condition: PolicyCondition, request: EvaluationRequest): boolean {
    const actual = resolveField(request, condition.field);
    const expected = condition.value;
    switch (condition.operator) {
      case 'eq':
        return actual === expected;
      case 'neq':
        return actual !== expected;
      case 'in':
        return inMatch(actual, expected);
      case 'not_in':
        return !inMatch(actual, expected);
      case 'contains':
        return stringOpMatch(actual, expected, (a, b) => a.includes(b));
      case 'starts_with':
        return stringOpMatch(actual, expected, (a, b) => a.startsWith(b));
      case 'ends_with':
        return stringOpMatch(actual, expected, (a, b) => a.endsWith(b));
      case 'matches':
        return this._matchesRegex(condition, actual);
    }
  }

  private _matchesRegex(condition: PolicyCondition, actual: unknown): boolean {
    if (actual === null || actual === undefined) return false;
    if (typeof condition.value !== 'string') return false;
    const re = this._compiledPatterns.get(condition);
    // Missing entry means either the pattern failed to compile (in which
    // case we wouldn't have reached this code path — the policy-level
    // POLICY_COMPILE_ERROR fires earlier) or the evaluator is being driven
    // with a condition object that didn't come from the cached bundle.
    // Returns no match in both cases.
    if (!re) return false;
    const actualStr = typeof actual === 'string' ? actual : String(actual);
    return re.test(actualStr);
  }
}

// ---- Helpers ----------------------------------------------------------------

// Reserved object keys that, if walked as field-path parts, escape the
// request object into Object.prototype. `JSON.parse` promotes
// `__proto__` to an own property rather than mutating the prototype,
// but `resolveField` rejects these regardless to keep policy authors
// from accidentally constructing rules that resolve through the
// prototype chain. Mirrors the schema-level forbidden-parts list in
// types.ts.
const FORBIDDEN_FIELD_PARTS = new Set(['__proto__', 'constructor', 'prototype']);

/**
 * Walk a dot-separated path through the request. `kwargs.amount` →
 * `request["kwargs"]["amount"]`. Missing components or non-object
 * intermediates resolve to `undefined`, which compares unequal to
 * anything a policy would `eq` against.
 *
 * Defense-in-depth:
 *   - reject any part that names a prototype slot
 *   - use `Object.hasOwn` so inherited properties don't resolve
 */
function resolveField(request: Record<string, unknown>, field: string): unknown {
  const parts = field.split('.');
  let cur: unknown = request;
  for (const part of parts) {
    if (FORBIDDEN_FIELD_PARTS.has(part)) return undefined;
    if (cur === null || cur === undefined) return undefined;
    if (typeof cur !== 'object') return undefined;
    if (!Object.hasOwn(cur as object, part)) return undefined;
    cur = (cur as Record<string, unknown>)[part];
  }
  return cur;
}

function inMatch(actual: unknown, expected: PolicyCondition['value']): boolean {
  // Type-strict comparisons. `[1000].includes("1000")` returns false,
  // so a `cond('input.amount', 'in', [1000])` against a string-rendered
  // numeric arg silently misses. Stringify both sides for membership
  // checks — same approach `matches` already uses for `actual`.
  if (actual === null || actual === undefined) return false;
  const actualStr = typeof actual === 'string' ? actual : String(actual);
  const list = Array.isArray(expected) ? expected : [expected];
  for (const item of list) {
    if (item === null || item === undefined) continue;
    const itemStr = typeof item === 'string' ? item : String(item);
    if (itemStr === actualStr) return true;
  }
  return false;
}

function stringOpMatch(
  actual: unknown,
  expected: PolicyCondition['value'],
  op: (a: string, b: string) => boolean,
): boolean {
  // `contains`/`starts_with`/`ends_with` match `matches` semantics by
  // stringifying both sides. Array `expected` is a type-system
  // possibility (per PolicyConditionSchema) that doesn't make semantic
  // sense for these operators; refuse to match in that case rather than
  // picking an arbitrary element.
  if (actual === null || actual === undefined) return false;
  if (Array.isArray(expected)) return false;
  if (expected === null || expected === undefined) return false;
  const actualStr = typeof actual === 'string' ? actual : String(actual);
  const expectedStr = typeof expected === 'string' ? expected : String(expected);
  return op(actualStr, expectedStr);
}

function isFrozen(bundle: Bundle, agentId: string): boolean {
  // Frozen-agent kill-switch is case-insensitive. Operator typo in the
  // dashboard ("Agent-123" vs "agent-123") shouldn't silently unfreeze.
  // Lowercased compare on both sides.
  const needle = agentId.toLowerCase();
  for (const id of bundle.frozenAgentIds) {
    if (id.toLowerCase() === needle) return true;
  }
  return false;
}

function elapsedMs(startNs: bigint): number {
  const elapsed = process.hrtime.bigint() - startNs;
  return Number(elapsed) / NANOS_PER_MS;
}
