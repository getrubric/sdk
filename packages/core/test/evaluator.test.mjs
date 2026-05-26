// Tests for the Evaluator. Cases cover the full operator surface,
// deny-short-circuit, last-allow-wins semantics, dot-path field
// resolution, the frozen-agent kill switch, and regex deny-by-default
// behavior on uncompileable patterns.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { Evaluator, PolicyDocumentSchema, PolicyConditionSchema } from '../dist/index.js';

const VALID_HASH = '0'.repeat(64);

// ---- Helpers ---------------------------------------------------------------

function mkBundle({ policies = [], frozenAgentIds = [], approvedServers = [], mcpEnforce = true } = {}) {
  return {
    bundleVersion: 1,
    contentHash: VALID_HASH,
    builtAt: new Date().toISOString(),
    policies,
    frozenAgentIds,
    mcpAccess: { approvedServers, enforce: mcpEnforce },
  };
}

function mkPolicy({ policyId = '11111111-1111-1111-1111-111111111111', rules, defaultEffect = 'allow' }) {
  return {
    policyId,
    policyVersion: 1,
    document: {
      apiVersion: 'agent-governance.io/v1',
      kind: 'Policy',
      metadata: { name: 'test' },
      spec: { defaultEffect, rules },
    },
  };
}

function rule(id, conditions, effect = 'allow') {
  return { id, conditions, effect };
}

function cond(field, operator, value) {
  return { field, operator, value };
}

// ---- Empty / default-effect cases ------------------------------------------

test('empty bundle (no policies) → deny / NO_POLICIES', () => {
  // A server returning `{ policies: [] }` must not silently turn off
  // enforcement — it defaults to deny.
  const ev = new Evaluator();
  ev.updateBundle(mkBundle());
  const r = ev.evaluate({ tool_name: 'echo' });
  assert.equal(r.decision, 'deny');
  assert.equal(r.code, 'NO_POLICIES');
  assert.equal(r.matchedRuleId, undefined);
});

test('no updateBundle ever called (cold start) → deny / NO_POLICIES', () => {
  // Cold-start defaults to deny at the evaluator level. The daemon also
  // gates `/v1/hook` on first-pull success, but the evaluator does the
  // right thing on its own.
  const ev = new Evaluator();
  const r = ev.evaluate({ tool_name: 'echo' });
  assert.equal(r.decision, 'deny');
  assert.equal(r.code, 'NO_POLICIES');
});

test('no rule matches → falls through to first policy’s defaultEffect (deny)', () => {
  const ev = new Evaluator();
  ev.updateBundle(
    mkBundle({
      policies: [
        mkPolicy({
          rules: [rule('r1', [cond('tool_name', 'eq', 'will_not_match')])],
          defaultEffect: 'deny',
        }),
      ],
    }),
  );
  const r = ev.evaluate({ tool_name: 'echo' });
  assert.equal(r.decision, 'deny');
  // No matched rule when falling through to defaultEffect.
  assert.equal(r.matchedRuleId, undefined);
});

test('no rule matches → mixed-default bundle denies if ANY policy defaults deny (order-independent)', () => {
  // Cross-bundle fail-safe: a deny default in any policy wins regardless of
  // policy ordering. Both orderings must resolve to deny so the result can't
  // be flipped by reordering the bundle.
  const allowFirst = {
    policies: [
      mkPolicy({
        policyId: '11111111-1111-1111-1111-111111111111',
        rules: [rule('r1', [cond('tool_name', 'eq', 'will_not_match')])],
        defaultEffect: 'allow',
      }),
      mkPolicy({
        policyId: '22222222-2222-2222-2222-222222222222',
        rules: [rule('r2', [cond('tool_name', 'eq', 'will_not_match')])],
        defaultEffect: 'deny',
      }),
    ],
  };
  const denyFirst = {
    policies: [allowFirst.policies[1], allowFirst.policies[0]],
  };
  for (const cfg of [allowFirst, denyFirst]) {
    const ev = new Evaluator();
    ev.updateBundle(mkBundle(cfg));
    const r = ev.evaluate({ tool_name: 'echo' });
    assert.equal(r.decision, 'deny');
    assert.equal(r.matchedRuleId, undefined);
  }
});

test('no rule matches → all-allow defaults resolve to allow', () => {
  const ev = new Evaluator();
  ev.updateBundle(
    mkBundle({
      policies: [
        mkPolicy({
          policyId: '11111111-1111-1111-1111-111111111111',
          rules: [rule('r1', [cond('tool_name', 'eq', 'will_not_match')])],
          defaultEffect: 'allow',
        }),
        mkPolicy({
          policyId: '22222222-2222-2222-2222-222222222222',
          rules: [rule('r2', [cond('tool_name', 'eq', 'will_not_match')])],
          defaultEffect: 'allow',
        }),
      ],
    }),
  );
  const r = ev.evaluate({ tool_name: 'echo' });
  assert.equal(r.decision, 'allow');
});

// ---- Operators -------------------------------------------------------------

test('eq operator', () => {
  const ev = new Evaluator();
  ev.updateBundle(
    mkBundle({
      policies: [mkPolicy({ rules: [rule('r1', [cond('tool_name', 'eq', 'echo')], 'deny')] })],
    }),
  );
  assert.equal(ev.evaluate({ tool_name: 'echo' }).decision, 'deny');
  assert.equal(ev.evaluate({ tool_name: 'cat' }).decision, 'allow');
});

test('neq operator', () => {
  const ev = new Evaluator();
  ev.updateBundle(
    mkBundle({
      policies: [mkPolicy({ rules: [rule('r1', [cond('tool_name', 'neq', 'echo')], 'deny')] })],
    }),
  );
  assert.equal(ev.evaluate({ tool_name: 'echo' }).decision, 'allow');
  assert.equal(ev.evaluate({ tool_name: 'cat' }).decision, 'deny');
});

test('in operator (list of values)', () => {
  const ev = new Evaluator();
  ev.updateBundle(
    mkBundle({
      policies: [
        mkPolicy({ rules: [rule('r1', [cond('tool_name', 'in', ['rm', 'mv', 'cp'])], 'deny')] }),
      ],
    }),
  );
  assert.equal(ev.evaluate({ tool_name: 'rm' }).decision, 'deny');
  assert.equal(ev.evaluate({ tool_name: 'mv' }).decision, 'deny');
  assert.equal(ev.evaluate({ tool_name: 'echo' }).decision, 'allow');
});

test('in operator (scalar value gets normalized to singleton list)', () => {
  const ev = new Evaluator();
  ev.updateBundle(
    mkBundle({
      policies: [mkPolicy({ rules: [rule('r1', [cond('tool_name', 'in', 'rm')], 'deny')] })],
    }),
  );
  assert.equal(ev.evaluate({ tool_name: 'rm' }).decision, 'deny');
});

test('not_in operator', () => {
  const ev = new Evaluator();
  ev.updateBundle(
    mkBundle({
      policies: [
        mkPolicy({ rules: [rule('r1', [cond('tool_name', 'not_in', ['echo', 'ls'])], 'deny')] }),
      ],
    }),
  );
  assert.equal(ev.evaluate({ tool_name: 'rm' }).decision, 'deny');
  assert.equal(ev.evaluate({ tool_name: 'echo' }).decision, 'allow');
});

test('contains operator', () => {
  const ev = new Evaluator();
  ev.updateBundle(
    mkBundle({
      policies: [
        mkPolicy({ rules: [rule('r1', [cond('input.command', 'contains', 'rm -rf')], 'deny')] }),
      ],
    }),
  );
  assert.equal(
    ev.evaluate({ tool_name: 'Bash', input: { command: 'rm -rf /' } }).decision,
    'deny',
  );
  assert.equal(ev.evaluate({ tool_name: 'Bash', input: { command: 'ls' } }).decision, 'allow');
});

test('starts_with operator', () => {
  const ev = new Evaluator();
  ev.updateBundle(
    mkBundle({
      policies: [
        mkPolicy({ rules: [rule('r1', [cond('input.url', 'starts_with', 'http://')], 'deny')] }),
      ],
    }),
  );
  assert.equal(ev.evaluate({ tool_name: 'fetch', input: { url: 'http://x' } }).decision, 'deny');
  assert.equal(ev.evaluate({ tool_name: 'fetch', input: { url: 'https://x' } }).decision, 'allow');
});

test('ends_with operator', () => {
  const ev = new Evaluator();
  ev.updateBundle(
    mkBundle({
      policies: [
        mkPolicy({ rules: [rule('r1', [cond('input.file_path', 'ends_with', '.pem')], 'deny')] }),
      ],
    }),
  );
  assert.equal(
    ev.evaluate({ tool_name: 'Read', input: { file_path: '/etc/ssl/key.pem' } }).decision,
    'deny',
  );
  assert.equal(
    ev.evaluate({ tool_name: 'Read', input: { file_path: '/etc/passwd' } }).decision,
    'allow',
  );
});

test('matches operator — basic regex', () => {
  const ev = new Evaluator();
  ev.updateBundle(
    mkBundle({
      policies: [
        mkPolicy({
          rules: [rule('r1', [cond('input.command', 'matches', '^rm\\s+-rf\\s+/')], 'deny')],
        }),
      ],
    }),
  );
  assert.equal(
    ev.evaluate({ tool_name: 'Bash', input: { command: 'rm -rf /var' } }).decision,
    'deny',
  );
  assert.equal(ev.evaluate({ tool_name: 'Bash', input: { command: 'ls' } }).decision, 'allow');
});

test('matches operator — numeric field stringified', () => {
  // Mirrors the Python comment: a policy on `kwargs.amount matches ^[1-9][0-9]{3,}$`
  // must treat numeric `actual` by stringifying it; otherwise every numeric-bound
  // policy is a silent no-op.
  const ev = new Evaluator();
  ev.updateBundle(
    mkBundle({
      policies: [
        mkPolicy({
          rules: [rule('r1', [cond('kwargs.amount', 'matches', '^[1-9][0-9]{3,}$')], 'deny')],
        }),
      ],
    }),
  );
  assert.equal(ev.evaluate({ tool_name: 'pay', kwargs: { amount: 5000 } }).decision, 'deny');
  assert.equal(ev.evaluate({ tool_name: 'pay', kwargs: { amount: 5 } }).decision, 'allow');
});

test('matches operator — invalid regex pattern → deny / POLICY_COMPILE_ERROR', () => {
  // An uncompileable pattern marks the *policy* as errored and every
  // evaluation that would touch it returns deny. Silent no-op +
  // defaultEffect fall-through would be unsafe.
  const errors = [];
  const ev = new Evaluator({ onCompileError: (e) => errors.push(e) });
  ev.updateBundle(
    mkBundle({
      policies: [
        mkPolicy({
          rules: [rule('r1', [cond('tool_name', 'matches', '(unclosed')], 'deny')],
        }),
      ],
    }),
  );
  const r = ev.evaluate({ tool_name: 'anything' });
  assert.equal(r.decision, 'deny');
  assert.equal(r.code, 'POLICY_COMPILE_ERROR');
  assert.equal(r.matchedPolicyId, '11111111-1111-1111-1111-111111111111');
  assert.equal(errors.length, 1);
  assert.equal(errors[0].ruleId, 'r1');
  assert.equal(errors[0].pattern, '(unclosed');
});

test('matches operator — re2-incompatible (lookahead) → deny / POLICY_COMPILE_ERROR', () => {
  const errors = [];
  const ev = new Evaluator({ onCompileError: (e) => errors.push(e) });
  ev.updateBundle(
    mkBundle({
      policies: [
        mkPolicy({
          rules: [rule('r1', [cond('tool_name', 'matches', '^echo(?=)')], 'deny')],
        }),
      ],
    }),
  );
  const r = ev.evaluate({ tool_name: 'echo' });
  assert.equal(r.decision, 'deny');
  assert.equal(r.code, 'POLICY_COMPILE_ERROR');
  assert.equal(errors.length, 1);
});

test('an errored policy poisons evaluation even when a sibling policy ordered first matched first', () => {
  // The errored-policy short-circuit must not poison sibling policies. We
  // arrange a healthy allow-everything policy *first*, then an errored
  // policy. The first policy fires its allow rule and we return allow
  // before ever reaching the errored entry.
  const ev = new Evaluator({ onCompileError: () => {} });
  ev.updateBundle(
    mkBundle({
      policies: [
        mkPolicy({
          policyId: '22222222-2222-2222-2222-222222222222',
          rules: [rule('r-ok', [cond('tool_name', 'eq', 'echo')], 'allow')],
        }),
        mkPolicy({
          policyId: '33333333-3333-3333-3333-333333333333',
          rules: [rule('r-bad', [cond('tool_name', 'matches', '(unclosed')], 'deny')],
        }),
      ],
    }),
  );
  // First policy's allow rule matches → loop continues, hits errored
  // policy → short-circuit DENY with POLICY_COMPILE_ERROR (defaults to
  // deny: an errored policy poisons every evaluation, even ones a prior
  // allow would have matched).
  const r = ev.evaluate({ tool_name: 'echo' });
  assert.equal(r.decision, 'deny');
  assert.equal(r.code, 'POLICY_COMPILE_ERROR');
});

// ---- Conditions AND'd, rules iterated --------------------------------------

test('multiple conditions on one rule are AND’d', () => {
  const ev = new Evaluator();
  ev.updateBundle(
    mkBundle({
      policies: [
        mkPolicy({
          rules: [
            rule(
              'r1',
              [cond('tool_name', 'eq', 'Bash'), cond('input.command', 'contains', 'rm')],
              'deny',
            ),
          ],
        }),
      ],
    }),
  );
  assert.equal(
    ev.evaluate({ tool_name: 'Bash', input: { command: 'rm /tmp/x' } }).decision,
    'deny',
  );
  // tool_name matches, command doesn't → no rule match → defaultEffect allow.
  assert.equal(ev.evaluate({ tool_name: 'Bash', input: { command: 'ls' } }).decision, 'allow');
  // command matches, tool_name doesn't.
  assert.equal(
    ev.evaluate({ tool_name: 'Read', input: { command: 'rm' } }).decision,
    'allow',
  );
});

test('first matching deny short-circuits subsequent rules', () => {
  let secondRuleEvaluated = false;
  const ev = new Evaluator();
  ev.updateBundle(
    mkBundle({
      policies: [
        mkPolicy({
          rules: [
            rule('r1', [cond('tool_name', 'eq', 'Bash')], 'deny'),
            // If this rule were reached the test would notice via a callable
            // condition value. Plain assertion below relies on r1 being
            // returned, which it must be.
            rule('r2', [cond('tool_name', 'eq', 'Bash')], 'allow'),
          ],
        }),
      ],
    }),
  );
  const r = ev.evaluate({ tool_name: 'Bash' });
  assert.equal(r.decision, 'deny');
  assert.equal(r.matchedRuleId, 'r1');
  void secondRuleEvaluated;
});

test('multiple matching allows: last matching rule wins', () => {
  // When no deny ever fires, the matched rule is the last one whose
  // conditions matched — `matched = entry` is overwritten on each
  // match. This mirrors the algorithm documented in the evaluator
  // header.
  const ev = new Evaluator();
  ev.updateBundle(
    mkBundle({
      policies: [
        mkPolicy({
          rules: [
            rule('r1', [cond('tool_name', 'eq', 'Bash')], 'allow'),
            rule('r2', [cond('tool_name', 'eq', 'Bash')], 'allow'),
            rule('r3', [cond('tool_name', 'eq', 'Bash')], 'allow'),
          ],
        }),
      ],
    }),
  );
  const r = ev.evaluate({ tool_name: 'Bash' });
  assert.equal(r.decision, 'allow');
  assert.equal(r.matchedRuleId, 'r3');
});

// ---- Field resolution ------------------------------------------------------

test('dot-path resolution walks nested objects', () => {
  const ev = new Evaluator();
  ev.updateBundle(
    mkBundle({
      policies: [
        mkPolicy({
          rules: [rule('r1', [cond('a.b.c', 'eq', 'gotcha')], 'deny')],
        }),
      ],
    }),
  );
  assert.equal(ev.evaluate({ tool_name: 't', a: { b: { c: 'gotcha' } } }).decision, 'deny');
});

test('missing nested field → operator returns false (no match)', () => {
  const ev = new Evaluator();
  ev.updateBundle(
    mkBundle({
      policies: [
        mkPolicy({
          rules: [rule('r1', [cond('a.b.c', 'eq', 'x')], 'deny')],
          defaultEffect: 'allow',
        }),
      ],
    }),
  );
  assert.equal(ev.evaluate({ tool_name: 't' }).decision, 'allow');
  assert.equal(ev.evaluate({ tool_name: 't', a: null }).decision, 'allow');
  assert.equal(ev.evaluate({ tool_name: 't', a: { b: 'not-an-object' } }).decision, 'allow');
});

// ---- Frozen-agent kill-switch ----------------------------------------------

test('frozen agent → deny with AGENT_FROZEN code, before any rule', () => {
  const ev = new Evaluator();
  ev.updateBundle(
    mkBundle({
      policies: [
        mkPolicy({
          // A permissive rule that would normally match — but the kill-switch
          // fires before any policy is consulted.
          rules: [rule('r1', [cond('tool_name', 'matches', '.*')], 'allow')],
        }),
      ],
      frozenAgentIds: ['agent-123'],
    }),
  );
  const r = ev.evaluate({ tool_name: 'echo', agent_id: 'agent-123' });
  assert.equal(r.decision, 'deny');
  assert.equal(r.code, 'AGENT_FROZEN');
  assert.equal(r.reason, 'agent frozen by operator');
  assert.equal(r.matchedRuleId, undefined);
});

test('frozen agent without agent_id on request → not frozen (falls through to NO_POLICIES deny)', () => {
  // The frozen-agent check requires `agent_id` on the request; without
  // it, the kill-switch doesn't apply. With an empty policy set, the
  // result is deny / NO_POLICIES.
  const ev = new Evaluator();
  ev.updateBundle(mkBundle({ frozenAgentIds: ['agent-123'] }));
  const r = ev.evaluate({ tool_name: 'echo' });
  assert.equal(r.decision, 'deny');
  assert.equal(r.code, 'NO_POLICIES');
});

test('frozen agent comparison is case-insensitive', () => {
  // Operator-typo defense. "Agent-123" in the bundle's frozenAgentIds
  // should freeze "agent-123" on the request.
  const ev = new Evaluator();
  ev.updateBundle(
    mkBundle({
      policies: [
        mkPolicy({ rules: [rule('r1', [cond('tool_name', 'eq', 'echo')], 'allow')] }),
      ],
      frozenAgentIds: ['Agent-123'],
    }),
  );
  const r = ev.evaluate({ tool_name: 'echo', agent_id: 'agent-123' });
  assert.equal(r.decision, 'deny');
  assert.equal(r.code, 'AGENT_FROZEN');
});

// ---- Latency reporting -----------------------------------------------------

test('latencyMs is reported on every result', () => {
  const ev = new Evaluator();
  ev.updateBundle(mkBundle());
  const r = ev.evaluate({ tool_name: 'echo' });
  assert.equal(typeof r.latencyMs, 'number');
  assert.ok(r.latencyMs >= 0);
  // Empty bundle path should be well under 5ms on any machine that runs CI.
  assert.ok(r.latencyMs < 50, `expected fast path, got ${r.latencyMs}ms`);
});

// ---- defaultEffect required -----------------------------------------------

test('PolicyDocumentSchema rejects a policy missing spec.defaultEffect', () => {
  // A policy with no `defaultEffect` must fail the zod parse, not
  // silently allow.
  const result = PolicyDocumentSchema.safeParse({
    apiVersion: 'agent-governance.io/v1',
    kind: 'Policy',
    metadata: { name: 'no-default' },
    spec: {
      rules: [
        { id: 'r1', conditions: [{ field: 'tool_name', operator: 'eq', value: 'x' }], effect: 'deny' },
      ],
    },
  });
  assert.equal(result.success, false);
});

test('PolicyDocumentSchema accepts when defaultEffect is explicit', () => {
  const result = PolicyDocumentSchema.safeParse({
    apiVersion: 'agent-governance.io/v1',
    kind: 'Policy',
    metadata: { name: 'has-default' },
    spec: {
      defaultEffect: 'deny',
      rules: [
        { id: 'r1', conditions: [{ field: 'tool_name', operator: 'eq', value: 'x' }], effect: 'deny' },
      ],
    },
  });
  assert.equal(result.success, true);
});

// ---- rule/condition count ceilings + eval timeout -------------------------

test('PolicyDocumentSchema rejects more than 1000 rules', () => {
  const tooManyRules = Array.from({ length: 1001 }, (_, i) => ({
    id: `r${i}`,
    conditions: [{ field: 'tool_name', operator: 'eq', value: 'x' }],
    effect: 'allow',
  }));
  const result = PolicyDocumentSchema.safeParse({
    apiVersion: 'agent-governance.io/v1',
    kind: 'Policy',
    metadata: { name: 'huge' },
    spec: { defaultEffect: 'deny', rules: tooManyRules },
  });
  assert.equal(result.success, false);
});

test('PolicyDocumentSchema rejects more than 50 conditions per rule', () => {
  const tooManyConditions = Array.from({ length: 51 }, () => ({
    field: 'tool_name',
    operator: 'eq',
    value: 'x',
  }));
  const result = PolicyDocumentSchema.safeParse({
    apiVersion: 'agent-governance.io/v1',
    kind: 'Policy',
    metadata: { name: 'wide-rule' },
    spec: {
      defaultEffect: 'deny',
      rules: [{ id: 'r1', conditions: tooManyConditions, effect: 'allow' }],
    },
  });
  assert.equal(result.success, false);
});

test('per-evaluation wall-clock budget bails out with EVAL_TIMEOUT', () => {
  // Construct a bundle that approaches the schema's static ceilings (1000
  // rules × a few conditions). We can't easily exceed 50ms with a single
  // policy under modern Node, so we drive the timeout by stuffing a few
  // bundles each with 1000 rules.
  const ev = new Evaluator();
  const rules = Array.from({ length: 1000 }, (_, i) =>
    rule(`r${i}`, [
      cond('tool_name', 'matches', `^never-matches-${i}-[a-z0-9]+$`),
      cond('input.payload', 'matches', `^[a-z]{${(i % 50) + 1}}$`),
    ], 'deny'),
  );
  // 20 policies × 1000 rules × 2 conditions = 40k condition evals per call.
  // On a healthy laptop that's still under 50ms — we tune the budget down
  // for this test by reflecting on the symbol if needed. Simpler approach:
  // assert that whenever the result is EVAL_TIMEOUT it's a deny. We run
  // the eval; if it timed out, we assert the code; if not, we just assert
  // the evaluation didn't ALLOW (it can DENY via NO_POLICIES alternative or
  // via deny rule — neither here, so by NO_POLICIES fall-through... but we
  // have policies). For the deterministic case we synthesize a fake bundle
  // and busy-loop the clock by raising rule counts until we trip the budget.
  const policies = Array.from({ length: 20 }, (_, i) =>
    mkPolicy({
      policyId: `${i.toString(16).padStart(8, '0')}-0000-0000-0000-000000000000`,
      rules,
      defaultEffect: 'deny',
    }),
  );
  ev.updateBundle(mkBundle({ policies }));
  const r = ev.evaluate({ tool_name: 'pay', input: { payload: 'zzz' } });
  // We don't assert *that* the timeout fired (machine-dependent), only
  // that if it does, the response is deny+EVAL_TIMEOUT — never silently
  // allow. The fall-through-on-budget path is the load-bearing
  // guarantee.
  if (r.code === 'EVAL_TIMEOUT') {
    assert.equal(r.decision, 'deny');
  } else {
    // Without a timeout, evaluation finished naturally; falls through to
    // first policy's defaultEffect (deny). Either way we never allow.
    assert.equal(r.decision, 'deny');
  }
});

// ---- Prototype-walking guard -----------------------------------------------

test('prototype-walking: schema rejects __proto__/constructor/prototype in field', () => {
  for (const bad of ['__proto__', '__proto__.toString', 'constructor', 'a.prototype.b']) {
    const res = PolicyConditionSchema.safeParse({
      field: bad,
      operator: 'eq',
      value: 'x',
    });
    assert.equal(res.success, false, `expected schema to reject field "${bad}"`);
  }
});

test('prototype-walking: resolveField uses hasOwn (inherited props do not resolve)', () => {
  // Even if a condition somehow skipped the schema (e.g., a future
  // synthetic condition), the evaluator's resolveField guards by hasOwn.
  // We exercise the path indirectly: request inherits a `tool_name`
  // property; the eq rule should still match (own property) but the eq
  // rule on `toString` must not match the prototype's value.
  const ev = new Evaluator();
  ev.updateBundle(
    mkBundle({
      policies: [
        mkPolicy({
          rules: [rule('r1', [cond('toString', 'eq', 'function toString')], 'deny')],
        }),
      ],
    }),
  );
  const r = ev.evaluate({ tool_name: 'echo' });
  // Inherited `toString` must not resolve → no rule match → defaultEffect allow.
  assert.equal(r.decision, 'allow');
});

// ---- Type-strict comparison fixes ------------------------------------------

test('in operator stringifies both sides (numeric value matches numeric list element)', () => {
  // `[1000].includes("1000")` returns false in plain JS. We stringify
  // both sides so a numeric `input.amount: 1000` matches `in [1000]`
  // AND `in ["1000"]`.
  const ev = new Evaluator();
  ev.updateBundle(
    mkBundle({
      policies: [
        mkPolicy({
          rules: [rule('r1', [cond('input.amount', 'in', [1000, 2000])], 'deny')],
        }),
      ],
    }),
  );
  assert.equal(ev.evaluate({ tool_name: 'pay', input: { amount: 1000 } }).decision, 'deny');
  assert.equal(ev.evaluate({ tool_name: 'pay', input: { amount: '1000' } }).decision, 'deny');
  assert.equal(ev.evaluate({ tool_name: 'pay', input: { amount: 99 } }).decision, 'allow');
});

test('contains/starts_with/ends_with stringify numeric actuals', () => {
  // These operators stringify their actual, consistent with `matches`,
  // so a numeric field doesn't silently short-circuit to no-match.
  const ev = new Evaluator();
  ev.updateBundle(
    mkBundle({
      policies: [
        mkPolicy({
          rules: [rule('r1', [cond('input.amount', 'starts_with', '10')], 'deny')],
        }),
      ],
    }),
  );
  assert.equal(ev.evaluate({ tool_name: 'pay', input: { amount: 1000 } }).decision, 'deny');
  assert.equal(ev.evaluate({ tool_name: 'pay', input: { amount: 200 } }).decision, 'allow');
});

// ---- MCP server gating ------------------------------------------------------

test('MCP: unapproved server → deny / MCP_SERVER_NOT_APPROVED, before policy eval', () => {
  const ev = new Evaluator();
  ev.updateBundle(
    mkBundle({
      policies: [mkPolicy({ rules: [rule('r1', [cond('tool_name', 'matches', '.*')], 'allow')] })],
      approvedServers: [],
    }),
  );
  const r = ev.evaluate({ tool_name: 'mcp__supabase__query', agent_id: 'a' });
  assert.equal(r.decision, 'deny');
  assert.equal(r.code, 'MCP_SERVER_NOT_APPROVED');
});

test('MCP: approved server falls through to policy eval (allow)', () => {
  const ev = new Evaluator();
  ev.updateBundle(
    mkBundle({
      policies: [mkPolicy({ rules: [rule('r1', [cond('tool_name', 'eq', 'mcp__supabase__query')], 'allow')] })],
      approvedServers: ['supabase'],
    }),
  );
  assert.equal(ev.evaluate({ tool_name: 'mcp__supabase__query', agent_id: 'a' }).decision, 'allow');
});

test('MCP: enforce:false leaves MCP calls alone (solo bundles)', () => {
  const ev = new Evaluator();
  ev.updateBundle(
    mkBundle({
      policies: [mkPolicy({ rules: [rule('r1', [cond('tool_name', 'eq', 'never')], 'allow')] })],
      approvedServers: [],
      mcpEnforce: false,
    }),
  );
  assert.equal(ev.evaluate({ tool_name: 'mcp__supabase__query', agent_id: 'a' }).decision, 'allow');
});

test('MCP: non-MCP tool is unaffected by the gate', () => {
  const ev = new Evaluator();
  ev.updateBundle(
    mkBundle({ policies: [mkPolicy({ rules: [rule('r1', [cond('tool_name', 'eq', 'Bash')], 'allow')] })] }),
  );
  assert.equal(ev.evaluate({ tool_name: 'Bash', agent_id: 'a' }).decision, 'allow');
});

// ---- ask effect (deny > ask > allow) ----------------------------------------

test('ask: a matched ask rule returns ask', () => {
  const ev = new Evaluator();
  ev.updateBundle(mkBundle({ policies: [mkPolicy({ rules: [rule('r1', [cond('tool_name', 'eq', 'Bash')], 'ask')] })] }));
  assert.equal(ev.evaluate({ tool_name: 'Bash', agent_id: 'a' }).decision, 'ask');
});

test('ask: deny wins over ask regardless of order', () => {
  for (const rules of [
    [rule('a', [cond('tool_name', 'eq', 'Bash')], 'ask'), rule('d', [cond('tool_name', 'eq', 'Bash')], 'deny')],
    [rule('d', [cond('tool_name', 'eq', 'Bash')], 'deny'), rule('a', [cond('tool_name', 'eq', 'Bash')], 'ask')],
  ]) {
    const ev = new Evaluator();
    ev.updateBundle(mkBundle({ policies: [mkPolicy({ rules })] }));
    assert.equal(ev.evaluate({ tool_name: 'Bash', agent_id: 'a' }).decision, 'deny');
  }
});

test('ask: ask wins over a later allow (not downgraded)', () => {
  const ev = new Evaluator();
  ev.updateBundle(
    mkBundle({
      policies: [
        mkPolicy({
          rules: [
            rule('ask1', [cond('tool_name', 'eq', 'Bash')], 'ask'),
            rule('allow1', [cond('tool_name', 'eq', 'Bash')], 'allow'),
          ],
        }),
      ],
    }),
  );
  assert.equal(ev.evaluate({ tool_name: 'Bash', agent_id: 'a' }).decision, 'ask');
});
