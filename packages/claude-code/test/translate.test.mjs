// Translator tests. Pure function — no fixtures or globals needed.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { toEvaluationRequest } from '../dist/daemon/translate.js';

test('PreToolUse → tool_name, agent_id, input.* mapping', () => {
  const req = toEvaluationRequest(
    {
      hook_event_name: 'PreToolUse',
      session_id: 'sess-1',
      cwd: '/repo',
      tool_name: 'Bash',
      tool_input: { command: 'ls -la', description: 'list files' },
    },
    'agent-123',
  );
  assert.equal(req.tool_name, 'Bash');
  assert.equal(req.agent_id, 'agent-123');
  // The whole point of the translator: tool_input is hoisted under input.*
  // so a single policy field path works for Bash here AND Python/Langchain
  // call sites.
  assert.deepEqual(req.input, { command: 'ls -la', description: 'list files' });
  assert.equal(req.session_id, 'sess-1');
  assert.equal(req.cwd, '/repo');
});

test('PostToolUse uses the same shape (handler dispatches separately)', () => {
  const req = toEvaluationRequest(
    {
      hook_event_name: 'PostToolUse',
      session_id: 'sess-1',
      tool_name: 'Read',
      tool_input: { file_path: '/etc/passwd' },
      tool_response: 'ignored at translate layer',
    },
    'agent-123',
  );
  assert.equal(req.tool_name, 'Read');
  assert.deepEqual(req.input, { file_path: '/etc/passwd' });
});

test('empty tool_input is preserved as an empty object, not stripped', () => {
  const req = toEvaluationRequest(
    {
      hook_event_name: 'PreToolUse',
      session_id: 'sess-1',
      tool_name: 'NoArgs',
      tool_input: {},
    },
    'agent-123',
  );
  assert.deepEqual(req.input, {});
});
