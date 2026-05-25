// The default safety pack shipped with `rubric` solo mode.
//
// Permissive baseline: `defaultEffect: allow` (get out of the developer's way)
// with deny rules for the genuine landmines and an ask rule for the gray area.
// Only rules expressible from the fields the Claude Code adapter provides
// (tool_name, input.command, input.file_path, input.url — see
// daemon/translate.ts) are included.

import { createHash } from 'node:crypto';
import { BundleSchema, type Bundle, type PolicyDocument } from '@rubric-app/core';

const API_VERSION = 'agent-governance.io/v1';
const KIND = 'Policy';

// Stable v4-shaped UUIDs so the compiled bundle's policy ids don't churn
// across runs (the bundle contentHash stays deterministic).
const POLICY_IDS = {
  destructiveShell: '00000000-0000-4000-8000-000000000001',
  secretFiles: '00000000-0000-4000-8000-000000000002',
  webfetchInternal: '00000000-0000-4000-8000-000000000003',
  confirmRiskyShell: '00000000-0000-4000-8000-000000000004',
} as const;

/** Block obviously-catastrophic Bash commands. */
const DESTRUCTIVE_SHELL: PolicyDocument = {
  apiVersion: API_VERSION,
  kind: KIND,
  metadata: { name: 'block-destructive-shell' },
  spec: {
    defaultEffect: 'allow',
    rules: [
      {
        id: 'deny-destructive-bash',
        description: 'Recursive deletes of root/home, SQL drops, force-push, reformat/overwrite, pipe-to-shell, forkbomb, chmod 777 /.',
        effect: 'deny',
        conditions: [
          { field: 'tool_name', operator: 'eq', value: 'Bash' },
          {
            field: 'input.command',
            operator: 'matches',
            value:
              '(rm\\s+-rf?\\s+(/|~|\\$HOME)|DROP\\s+TABLE|TRUNCATE\\s+TABLE|git\\s+push\\s+(-f\\b|--force\\b)|mkfs\\.|dd\\s+if=.+\\s+of=/dev/|(curl|wget)\\s+[^|]*\\|\\s*(sudo\\s+)?(ba)?sh|chmod\\s+-R?\\s*777\\s+/|:\\(\\)\\s*\\{\\s*:\\|:&\\s*\\};:)',
          },
        ],
      },
    ],
  },
};

/** Block reads/writes of secret files. */
const SECRET_FILES: PolicyDocument = {
  apiVersion: API_VERSION,
  kind: KIND,
  metadata: { name: 'block-secret-files' },
  spec: {
    defaultEffect: 'allow',
    rules: [
      {
        id: 'deny-secret-file-access',
        description: 'Claude Code file-IO tools targeting dotenv files, PEM/SSH keys, cloud-credential paths, or kubeconfig.',
        effect: 'deny',
        conditions: [
          { field: 'tool_name', operator: 'in', value: ['Read', 'Edit', 'Write', 'MultiEdit'] },
          {
            field: 'input.file_path',
            operator: 'matches',
            value: '(?i)(\\.env(\\.|$)|\\.pem$|/\\.ssh/|/\\.aws/credentials|/\\.kube/config$|id_rsa|id_ed25519)',
          },
        ],
      },
    ],
  },
};

/** Block WebFetch/WebSearch to loopback, RFC1918, link-local, and cloud metadata. */
const WEBFETCH_INTERNAL: PolicyDocument = {
  apiVersion: API_VERSION,
  kind: KIND,
  metadata: { name: 'block-internal-webfetch' },
  spec: {
    defaultEffect: 'allow',
    rules: [
      {
        id: 'deny-webfetch-metadata-service',
        description: 'Cloud instance-metadata endpoints — almost always an SSRF probe.',
        effect: 'deny',
        conditions: [
          { field: 'tool_name', operator: 'in', value: ['WebFetch', 'WebSearch'] },
          {
            field: 'input.url',
            operator: 'matches',
            value: '^https?://(169\\.254\\.169\\.254|metadata\\.google\\.internal|169\\.254\\.170\\.2)(/|$|:)',
          },
        ],
      },
      {
        id: 'deny-webfetch-loopback-and-private',
        description: 'Loopback + RFC1918 + link-local targets.',
        effect: 'deny',
        conditions: [
          { field: 'tool_name', operator: 'in', value: ['WebFetch', 'WebSearch'] },
          {
            field: 'input.url',
            operator: 'matches',
            value: '^https?://(localhost|127\\.|0\\.0\\.0\\.0|\\[::1\\]|10\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.|192\\.168\\.|169\\.254\\.)',
          },
        ],
      },
    ],
  },
};

/** Ask (prompt the human) on risky-but-not-catastrophic Bash. */
const CONFIRM_RISKY_SHELL: PolicyDocument = {
  apiVersion: API_VERSION,
  kind: KIND,
  metadata: { name: 'confirm-risky-shell' },
  spec: {
    defaultEffect: 'allow',
    rules: [
      {
        id: 'ask-risky-bash',
        description: 'Prompt before sudo, recursive deletes, pushes to protected branches, or writes under /etc.',
        effect: 'ask',
        conditions: [
          { field: 'tool_name', operator: 'eq', value: 'Bash' },
          {
            field: 'input.command',
            operator: 'matches',
            value: '(\\bsudo\\s|rm\\s+-rf?\\s|git\\s+push\\b[^\\n]*\\b(main|master|production|release)\\b|>\\s*/etc/)',
          },
        ],
      },
    ],
  },
};

/** The shipped default pack, paired with stable policy ids. */
export const DEFAULT_SAFETY_PACK: ReadonlyArray<{ id: string; document: PolicyDocument }> = [
  { id: POLICY_IDS.destructiveShell, document: DESTRUCTIVE_SHELL },
  { id: POLICY_IDS.secretFiles, document: SECRET_FILES },
  { id: POLICY_IDS.webfetchInternal, document: WEBFETCH_INTERNAL },
  { id: POLICY_IDS.confirmRiskyShell, document: CONFIRM_RISKY_SHELL },
];

/**
 * Compile policies into a local Bundle the Evaluator can consume directly — no
 * control plane involved. `mcpAccess.enforce: false` keeps solo permissive
 * toward MCP. contentHash is a deterministic SHA-256 over the entries.
 */
export function compileLocalBundle(
  policies: ReadonlyArray<{ id: string; document: PolicyDocument }> = DEFAULT_SAFETY_PACK,
): Bundle {
  const entries = policies.map((p) => ({
    policyId: p.id,
    policyVersion: 1,
    document: p.document,
  }));
  const contentHash = createHash('sha256').update(JSON.stringify(entries)).digest('hex');

  return BundleSchema.parse({
    bundleVersion: 0,
    contentHash,
    builtAt: new Date(0).toISOString(),
    policies: entries,
    frozenAgentIds: [],
    mcpAccess: { approvedServers: [], enforce: false },
  });
}
