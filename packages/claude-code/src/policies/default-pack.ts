// The default safety pack shipped with `rubric` solo mode.
//
// Philosophy (from OWASP "Excessive Agency" + practical agent-guardrail
// research): hard-DENY only what is catastrophic AND essentially never
// legitimate; ASK (human-in-the-loop) for high-risk-but-sometimes-legitimate
// actions; ALLOW everyday dev work so the pack adds value without being an
// obstacle. Decisions are deterministic pattern matches, not an LLM judging
// safety. A regex denylist is a high-signal gate on *accidental* catastrophe
// and a human-in-loop trigger — not a hard boundary against a determined
// adversary (those bypass via base64/subshells); OS sandboxing is that layer.
//
// Only fields the Claude Code adapter provides are matched: tool_name,
// input.command, input.file_path, input.url (see daemon/translate.ts).

import { createHash } from 'node:crypto';
import { BundleSchema, type Bundle, type PolicyDocument } from '@rubric-app/core';

const API_VERSION = 'agent-governance.io/v1';
const KIND = 'Policy';

// Stable v4-shaped UUIDs so the compiled bundle's policy ids don't churn.
const POLICY_IDS = {
  destructiveShell: '00000000-0000-4000-8000-000000000001',
  secretKeys: '00000000-0000-4000-8000-000000000002',
  cloudMetadata: '00000000-0000-4000-8000-000000000003',
  riskyDataGit: '00000000-0000-4000-8000-000000000004',
  riskyInfraRelease: '00000000-0000-4000-8000-000000000005',
} as const;

// Private-key / credential file paths a coding agent never legitimately needs.
const KEY_FILE_PATHS =
  '(?i)(/\\.ssh/|id_rsa|id_ed25519|id_ecdsa|\\.pem\\b|\\.p12\\b|\\.keystore\\b|/\\.aws/credentials|/\\.gnupg/|\\.git-credentials|/\\.netrc|\\.pgpass|\\.tfstate\\b|/\\.config/gcloud/|/\\.azure/|/\\.docker/config\\.json)';

/** DENY — catastrophic shell that is essentially never part of real dev. */
const DESTRUCTIVE_SHELL: PolicyDocument = {
  apiVersion: API_VERSION,
  kind: KIND,
  metadata: { name: 'destructive-shell-commands' },
  spec: {
    defaultEffect: 'allow',
    rules: [
      {
        id: 'deny-destructive-shell',
        description:
          'This command can irreversibly destroy your system or data — wiping the root or home directory, deleting a system directory, reformatting a disk, overwriting a block device, a fork bomb, or chmod 777 on /. These are never part of normal development.',
        effect: 'deny',
        conditions: [
          { field: 'tool_name', operator: 'eq', value: 'Bash' },
          {
            field: 'input.command',
            operator: 'matches',
            value:
              '(rm\\s+-\\w*r\\w*\\s+(-\\w+\\s+)*(/($|\\s|\\*)|~($|/|\\s)|\\$HOME|\\$\\{HOME\\}|/(etc|usr|bin|sbin|var|lib|boot|sys|opt|root|home|System|Library|Applications|Users)($|/|\\s))|\\bmkfs|\\bdd\\s+[^|]*of=/dev/|>\\s*/dev/(disk|sd|nvme|hd|vd)|:\\(\\)\\s*\\{\\s*:\\|:&\\s*\\};:|chmod\\s+-R\\s+777\\s+/)',
          },
        ],
      },
    ],
  },
};

/** DENY — reads/writes of private keys & credential files (never agent-needed). */
const SECRET_KEYS: PolicyDocument = {
  apiVersion: API_VERSION,
  kind: KIND,
  metadata: { name: 'secret-and-key-files' },
  spec: {
    defaultEffect: 'allow',
    rules: [
      {
        id: 'deny-key-file-io',
        description:
          'This reads or writes a private key or credential file (SSH/PEM keys, cloud credentials, .git-credentials, .netrc, .pgpass, Terraform state). A coding agent never needs these, and exposing them risks account or infrastructure takeover.',
        effect: 'deny',
        conditions: [
          { field: 'tool_name', operator: 'in', value: ['Read', 'Edit', 'Write', 'MultiEdit'] },
          { field: 'input.file_path', operator: 'matches', value: KEY_FILE_PATHS },
        ],
      },
      {
        id: 'deny-key-file-shell',
        description:
          'This shell command reads or copies a private key or credential file (SSH/PEM keys, cloud credentials, etc.). A coding agent never needs these — blocking prevents secret exfiltration.',
        effect: 'deny',
        conditions: [
          { field: 'tool_name', operator: 'eq', value: 'Bash' },
          {
            field: 'input.command',
            operator: 'matches',
            value:
              '(?i)\\b(cat|less|more|head|tail|nl|bat|xxd|od|strings|base64|cp|scp|rsync|grep|rg|ag|sed|awk|tar|curl|nc|openssl)\\b[^|;&]*' +
              '(/\\.ssh/|id_rsa|id_ed25519|id_ecdsa|\\.pem\\b|/\\.aws/credentials|/\\.gnupg/|\\.git-credentials|/\\.netrc|\\.pgpass|\\.tfstate\\b|/\\.config/gcloud/|/\\.azure/|/\\.docker/config\\.json)',
          },
        ],
      },
    ],
  },
};

/** DENY — cloud instance-metadata endpoints (SSRF credential theft). */
const CLOUD_METADATA: PolicyDocument = {
  apiVersion: API_VERSION,
  kind: KIND,
  metadata: { name: 'cloud-metadata-endpoints' },
  spec: {
    defaultEffect: 'allow',
    rules: [
      {
        id: 'deny-cloud-metadata',
        description:
          'This fetches a cloud instance-metadata address (e.g. 169.254.169.254), the classic way credentials get stolen via SSRF. It is effectively never a legitimate request from a dev machine.',
        effect: 'deny',
        conditions: [
          { field: 'tool_name', operator: 'in', value: ['WebFetch', 'WebSearch'] },
          {
            field: 'input.url',
            operator: 'matches',
            value:
              '^https?://(169\\.254\\.169\\.254|metadata\\.google\\.internal|169\\.254\\.170\\.2|\\[?fd00:ec2::254\\]?)(/|$|:)',
          },
        ],
      },
    ],
  },
};

/** ASK — history rewrites, destructive SQL, pipe-to-shell, protected-branch pushes, .env. */
const RISKY_DATA_GIT: PolicyDocument = {
  apiVersion: API_VERSION,
  kind: KIND,
  metadata: { name: 'risky-data-and-git' },
  spec: {
    defaultEffect: 'allow',
    rules: [
      {
        id: 'ask-risky-git-data',
        description:
          'This can rewrite history or destroy data — a force push, a hard reset, git clean -fd, dropping or truncating a database table, piping a download straight into a shell, or pushing to a protected branch (main/master/production). Approve if you intend it.',
        effect: 'ask',
        conditions: [
          { field: 'tool_name', operator: 'eq', value: 'Bash' },
          {
            field: 'input.command',
            operator: 'matches',
            value:
              '(?i)(git\\s+push\\s+[^\\n]*(-f\\b|--force\\b|--force-with-lease\\b)|git\\s+reset\\s+[^\\n]*--hard\\b|git\\s+clean\\s+[^\\n]*-[a-z]*f|\\b(drop|truncate)\\s+(table|database|schema)\\b|(curl|wget)\\s+[^|]*\\|\\s*(sudo\\s+)?(ba|z|d)?sh\\b|git\\s+push\\b[^\\n]*\\b(main|master|production|prod|release)\\b)',
          },
        ],
      },
      {
        id: 'ask-env-file-io',
        description:
          'This reads or writes a .env file, which usually holds secrets. Approve if you intend the agent to see them.',
        effect: 'ask',
        conditions: [
          { field: 'tool_name', operator: 'in', value: ['Read', 'Edit', 'Write', 'MultiEdit'] },
          { field: 'input.file_path', operator: 'matches', value: '(?i)\\.env(\\.|$)' },
        ],
      },
      {
        id: 'ask-env-file-shell',
        description:
          'This shell command reads a .env file, which usually holds secrets. Approve if you intend the agent to see them.',
        effect: 'ask',
        conditions: [
          { field: 'tool_name', operator: 'eq', value: 'Bash' },
          {
            field: 'input.command',
            operator: 'matches',
            value: '(?i)\\b(cat|less|more|head|tail|nl|bat|xxd|grep|rg|cp|scp)\\b[^|;&]*\\.env(\\.|\\b)',
          },
        ],
      },
    ],
  },
};

/** ASK — consequential infrastructure & release actions (OWASP human-in-loop). */
const RISKY_INFRA_RELEASE: PolicyDocument = {
  apiVersion: API_VERSION,
  kind: KIND,
  metadata: { name: 'risky-infra-and-release' },
  spec: {
    defaultEffect: 'allow',
    rules: [
      {
        id: 'ask-infra-release',
        description:
          'This is a consequential infrastructure or release action — applying or destroying infrastructure (Terraform, kubectl, Helm), deleting cloud resources (aws/gcloud/az), publishing a package or image, or running sudo. Approve if you intend it.',
        effect: 'ask',
        conditions: [
          { field: 'tool_name', operator: 'eq', value: 'Bash' },
          {
            field: 'input.command',
            operator: 'matches',
            value:
              '(?i)(\\bterraform\\s+(destroy|apply|import)\\b|-auto-approve\\b|\\bkubectl\\s+(delete|apply|drain|cordon|scale|patch|replace)\\b|\\bhelm\\s+(install|upgrade|uninstall|rollback)\\b|\\b(aws|gcloud|az)\\b[^\\n]*\\b(delete|destroy|terminate|rb|rm|remove)\\b|\\b(npm|pnpm|yarn)\\s+publish\\b|\\bdocker\\s+push\\b|\\bcargo\\s+publish\\b|\\btwine\\s+upload\\b|\\bgh\\s+release\\s+create\\b|\\bsudo\\s)',
          },
        ],
      },
    ],
  },
};

/** The shipped default pack, paired with stable policy ids. */
export const DEFAULT_SAFETY_PACK: ReadonlyArray<{ id: string; document: PolicyDocument }> = [
  { id: POLICY_IDS.destructiveShell, document: DESTRUCTIVE_SHELL },
  { id: POLICY_IDS.secretKeys, document: SECRET_KEYS },
  { id: POLICY_IDS.cloudMetadata, document: CLOUD_METADATA },
  { id: POLICY_IDS.riskyDataGit, document: RISKY_DATA_GIT },
  { id: POLICY_IDS.riskyInfraRelease, document: RISKY_INFRA_RELEASE },
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
