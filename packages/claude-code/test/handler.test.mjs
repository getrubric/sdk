// Handler tests. Stubs Evaluator + AuditSink so we can pin exactly
// what flows through the routing layer.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { handleHookPayload } from '../dist/daemon/handler.js';

function fakeEvaluator(result) {
  const calls = [];
  return {
    evaluate(req) {
      calls.push(req);
      return result;
    },
    calls,
  };
}

function fakeSink() {
  const events = [];
  return {
    enqueue(e) {
      events.push(e);
    },
    events,
  };
}

const FIXED_TS = '2026-05-15T12:00:00.000Z';

test('PreToolUse allow → continue, permissionDecision allow, audit event tagged claude-code', () => {
  const ev = fakeEvaluator({
    decision: 'allow',
    matchedPolicyId: null,
    matchedPolicyVersion: null,
    matchedRuleId: null,
    latencyMs: 1.2,
  });
  const sink = fakeSink();
  const resp = handleHookPayload(
    {
      hook_event_name: 'PreToolUse',
      session_id: 'sess-1',
      tool_name: 'Bash',
      tool_input: { command: 'ls' },
    },
    { evaluator: ev, audit: sink, agentId: 'agent-X', now: () => FIXED_TS },
  );
  assert.equal(resp.continue, true);
  assert.equal(resp.hookSpecificOutput?.hookEventName, 'PreToolUse');
  assert.equal(resp.hookSpecificOutput?.permissionDecision, 'allow');
  // Allows don't carry a reason — keeps the developer's terminal quiet on
  // the 99% path.
  assert.equal(resp.hookSpecificOutput?.permissionDecisionReason, undefined);
  // Audit event is well-formed.
  assert.equal(sink.events.length, 1);
  assert.equal(sink.events[0].toolName, 'Bash');
  assert.equal(sink.events[0].decision, 'allow');
  assert.equal(sink.events[0].framework, 'claude-code');
  assert.equal(sink.events[0].agentId, 'agent-X');
  assert.equal(sink.events[0].sessionId, 'sess-1');
  assert.equal(sink.events[0].ts, FIXED_TS);
  assert.equal(sink.events[0].metadata.hook, 'PreToolUse');
});

test('PreToolUse deny → permissionDecision deny + reason; audit event captures rule', () => {
  const ev = fakeEvaluator({
    decision: 'deny',
    matchedPolicyId: 'pol-1',
    matchedPolicyName: 'secret-file-access',
    matchedPolicyVersion: 7,
    matchedRuleId: 'block-secrets',
    matchedRuleDescription: 'This reads or writes a secret file.',
    latencyMs: 0.5,
  });
  const sink = fakeSink();
  const resp = handleHookPayload(
    {
      hook_event_name: 'PreToolUse',
      session_id: 'sess-1',
      tool_name: 'Read',
      tool_input: { file_path: '/Users/x/.ssh/id_rsa' },
    },
    { evaluator: ev, audit: sink, agentId: 'agent-X', now: () => FIXED_TS },
  );
  assert.equal(resp.hookSpecificOutput?.permissionDecision, 'deny');
  const reason = resp.hookSpecificOutput?.permissionDecisionReason;
  assert.ok(reason);
  // Reason names the policy and carries the friendly rule description, not raw ids.
  assert.match(reason, /blocked this action per policy "secret-file-access"/);
  assert.match(reason, /reads or writes a secret file/);
  // Audit event still carries the raw ids for the dashboard.
  assert.equal(sink.events[0].decision, 'deny');
  assert.equal(sink.events[0].policyId, 'pol-1');
  assert.equal(sink.events[0].policyVersion, 7);
  assert.equal(sink.events[0].metadata.matchedRuleId, 'block-secrets');
});

test('PreToolUse frozen-agent deny → surfaces the kill-switch reason', () => {
  const ev = fakeEvaluator({
    decision: 'deny',
    matchedPolicyId: null,
    matchedPolicyVersion: null,
    matchedRuleId: null,
    code: 'AGENT_FROZEN',
    reason: 'agent frozen by operator',
    latencyMs: 0.1,
  });
  const sink = fakeSink();
  const resp = handleHookPayload(
    {
      hook_event_name: 'PreToolUse',
      session_id: 'sess-1',
      tool_name: 'Bash',
      tool_input: { command: 'ls' },
    },
    { evaluator: ev, audit: sink, agentId: 'agent-X', now: () => FIXED_TS },
  );
  // The kill-switch reason (no matched policy) is surfaced as the
  // explanation under the Rubric mark — operators recognize this string.
  assert.match(resp.hookSpecificOutput?.permissionDecisionReason, /agent frozen by operator/);
  assert.equal(sink.events[0].metadata.code, 'AGENT_FROZEN');
});

test('PreToolUse ask → permissionDecision ask + "requires approval from policy <name>" reason', () => {
  const ev = fakeEvaluator({
    decision: 'ask',
    matchedPolicyId: 'pol-9',
    matchedPolicyName: 'risky-shell-commands',
    matchedPolicyVersion: 1,
    matchedRuleId: 'ask-risky-bash',
    matchedRuleDescription: 'This command uses sudo.',
    latencyMs: 0.2,
  });
  const sink = fakeSink();
  const resp = handleHookPayload(
    {
      hook_event_name: 'PreToolUse',
      session_id: 'sess-1',
      tool_name: 'Bash',
      tool_input: { command: 'sudo apt-get install foo' },
    },
    { evaluator: ev, audit: sink, agentId: 'agent-X', now: () => FIXED_TS },
  );
  assert.equal(resp.hookSpecificOutput?.permissionDecision, 'ask');
  const reason = resp.hookSpecificOutput?.permissionDecisionReason;
  assert.ok(reason);
  assert.match(reason, /requires approval from policy "risky-shell-commands"/);
  assert.match(reason, /This command uses sudo\./);
  // The Rubric mark is rendered above the headline.
  assert.match(reason, /Rubric/);
});

test('PostToolUse → continue only, audit event tagged hook=PostToolUse', () => {
  const ev = fakeEvaluator(null /* never called */);
  const sink = fakeSink();
  const resp = handleHookPayload(
    {
      hook_event_name: 'PostToolUse',
      session_id: 'sess-1',
      tool_name: 'Bash',
      tool_input: { command: 'ls' },
      tool_response: 'file1\nfile2',
    },
    { evaluator: ev, audit: sink, agentId: 'agent-X', now: () => FIXED_TS },
  );
  assert.deepEqual(resp, { continue: true });
  assert.equal(ev.calls.length, 0, 'evaluator must not be called on PostToolUse');
  assert.equal(sink.events.length, 1);
  assert.equal(sink.events[0].metadata.hook, 'PostToolUse');
  assert.equal(sink.events[0].metadata.tool_response, 'file1\nfile2');
});

test('SessionStart → continue only, sentinel toolName=__session_start__', () => {
  const sink = fakeSink();
  const resp = handleHookPayload(
    {
      hook_event_name: 'SessionStart',
      session_id: 'sess-1',
      source: 'startup',
    },
    { evaluator: fakeEvaluator(null), audit: sink, agentId: 'agent-X', now: () => FIXED_TS },
  );
  assert.deepEqual(resp, { continue: true });
  assert.equal(sink.events[0].toolName, '__session_start__');
  assert.equal(sink.events[0].metadata.source, 'startup');
});

test('PreToolUse: tool_input strings are scrubbed for secrets before audit', () => {
  const ev = fakeEvaluator({ decision: 'allow', latencyMs: 0 });
  const sink = fakeSink();
  const jwt =
    'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.4Adcj3UFYzPUVaVF43FmMze8aBkPo2PnxYbB-_d7gB8';
  handleHookPayload(
    {
      hook_event_name: 'PreToolUse',
      session_id: 'sess-1',
      tool_name: 'Bash',
      tool_input: {
        command: `curl -H "Authorization: Bearer ${jwt}" https://api.example.com`,
        env: { AWS_KEY: 'AKIAIOSFODNN7EXAMPLE' },
        urls: [`postgres://user:hunter2@db.example.com/prod`],
      },
    },
    { evaluator: ev, audit: sink, agentId: 'agent-X', now: () => FIXED_TS },
  );
  const meta = sink.events[0].metadata.tool_input;
  // JWT collapsed to a single redacted token.
  assert.equal(meta.command.includes(jwt), false, 'raw JWT must not appear in metadata');
  assert.match(meta.command, /<redacted/);
  // AWS key in a nested object is redacted.
  assert.equal(meta.env.AWS_KEY, '<redacted:secret>');
  // Postgres URL credential pair is collapsed.
  assert.match(meta.urls[0], /postgres:\/\/<redacted>@/);
});

test('PostToolUse: tool_response is scrubbed too', () => {
  const sink = fakeSink();
  handleHookPayload(
    {
      hook_event_name: 'PostToolUse',
      session_id: 'sess-1',
      tool_name: 'Bash',
      tool_input: { command: 'echo' },
      tool_response: 'token=ghp_1234567890abcdef1234567890ABCDEFghij',
    },
    {
      evaluator: fakeEvaluator(null),
      audit: sink,
      agentId: 'agent-X',
      now: () => FIXED_TS,
    },
  );
  assert.match(sink.events[0].metadata.tool_response, /<redacted/);
  assert.equal(
    sink.events[0].metadata.tool_response.includes('ghp_1234567890abcdef'),
    false,
  );
});

test('agentVersion is stamped on every event when supplied', () => {
  const ev = fakeEvaluator({ decision: 'allow', latencyMs: 0 });
  const sink = fakeSink();
  handleHookPayload(
    { hook_event_name: 'SessionStart', session_id: 'sess-1' },
    {
      evaluator: ev,
      audit: sink,
      agentId: 'agent-X',
      agentVersion: '1.2.3-test',
      now: () => FIXED_TS,
    },
  );
  assert.equal(sink.events[0].version, '1.2.3-test');
});
