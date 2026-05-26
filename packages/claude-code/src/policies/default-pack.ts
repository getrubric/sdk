// The default safety pack shipped with `rubric` solo mode.
//
// Philosophy (from OWASP "Excessive Agency" + practical agent-guardrail
// research): hard-DENY only what is catastrophic AND essentially never
// legitimate; ASK (human-in-the-loop) for high-risk-but-sometimes-legitimate
// actions; ALLOW everyday dev work so the pack adds value without being an
// obstacle. Decisions are deterministic pattern matches, not an LLM judging
// safety. A regex denylist is a high-signal gate on *accidental* catastrophe
// and a human-in-loop trigger — not a hard boundary against deliberately
// obfuscated commands (e.g. base64/subshells); OS sandboxing is that layer.
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

// Private-key / credential file path fragments a coding agent never legitimately
// needs. Shared (without a leading anchor) by the file_path match (tools), the
// shell match, and the credential-path-anywhere check — so adding a path here
// closes it across every surface at once.
const KEY_FILE_PATH_FRAGMENTS =
  '/\\.ssh/|id_rsa|id_ed25519|id_ecdsa|\\.pem\\b|\\.p12\\b|\\.keystore\\b|/\\.aws/credentials|/\\.gnupg/|\\.git-credentials|/\\.netrc|\\.pgpass|\\.tfstate\\b|/\\.config/gcloud/|/\\.azure/|/\\.docker/config\\.json|/\\.kube/config|/\\.npmrc\\b|/\\.config/gh/|/\\.config/hub\\b';
const KEY_FILE_PATHS = `(?i)(${KEY_FILE_PATH_FRAGMENTS})`;

// A recursive `rm` followed by a catastrophic target. Between `rm` and the
// target sits a flag block: short flags (`-rf`/`-fr`/`-r`/`-f`/…) and/or long
// flags (`--recursive`/`--force`/…), in any order, separated by whitespace.
// We require the recursive intent (`r` somewhere in a short flag, or
// `--recursive`); force is not required because a recursive delete of root/home
// is catastrophic with or without `-f`, matching the original rule's intent.
// Quote characters are treated as transparent so quoted targets like
// `rm -rf "/"` / `rm -rf './'` are still matched. Targets: root, home
// (`~`/`$HOME`), a known system dir, a bare `.`/`./` (e.g. `cd / && rm -rf .`),
// or a parent-dir walk (`..`). NOT a
// nested path like `./dist` or `../sibling/build`, which stay allowed.
// RE2-safe: the flag block is a bounded repetition of disjoint tokens (linear).
const RM_FLAG = '(?:-\\w*r\\w*|-\\w*f\\w*|--recursive|--force|-\\w+)';
const RM_RECURSIVE_FORCE =
  'rm\\s+' +
  `(?:${RM_FLAG}\\s+)*` + // any leading flags
  `(?:-\\w*r\\w*|--recursive)(?:\\s+${RM_FLAG})*\\s+` + // at least one recursive flag
  '[\'"]?\\s*' + // transparent opening quote
  '(?:' +
  '/(?:$|\\s|\\*|[\'"])' + // bare /
  '|~(?:$|/|\\s|[\'"])' + // home
  '|\\$\\{?HOME\\}?' + // $HOME / ${HOME}
  '|\\.(?:$|\\s|[\'"]|/(?:$|\\s|[\'"]))' + // bare . or ./
  '|(?:\\.\\./)*\\.\\.(?:$|\\s|[\'"])' + // pure parent walk: .., ../.., ../../.. (not ../nested/path)
  '|/(?:etc|usr|bin|sbin|var|lib|boot|sys|opt|root|home|System|Library|Applications|Users)(?:$|/|\\s)' + // system dir
  ')';

// Other catastrophic, never-legitimate disk/file destruction.
const DESTRUCTIVE_MISC =
  '\\bmkfs|\\bdd\\s+[^|]*of=/dev/|>\\s*/dev/(disk|sd|nvme|hd|vd)|:\\(\\)\\s*\\{\\s*:\\|:&\\s*\\};:|chmod\\s+-R\\s+777\\s+/|\\bfind\\s+[^|;&]*\\s-delete\\b|\\bshred\\b';

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
            value: `(?i)(${RM_RECURSIVE_FORCE}|${DESTRUCTIVE_MISC})`,
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
          'This shell command references a private key or credential file (SSH/PEM keys, cloud credentials, etc.). A coding agent never needs these, so the read is blocked.',
        effect: 'deny',
        conditions: [
          { field: 'tool_name', operator: 'eq', value: 'Bash' },
          // Match on the credential PATH anywhere in the command, since the
          // path is the high-signal token. This covers shapes with any read
          // verb (cat, tac, gpg, ssh-keygen -y -f, dd if=, vim,
          // python -c 'open(...)') and the bare-redirect shape
          // (`done < ~/.ssh/id_rsa`) that has no verb at all.
          { field: 'input.command', operator: 'matches', value: KEY_FILE_PATHS },
        ],
      },
    ],
  },
};

// A cloud instance-metadata host, in its common encodings:
// dotted IPv4 (`169.254.169.254`), its decimal (`2852039166`) and hex
// (`0xa9fea9fe`) integer forms, DNS-rebinding wrappers (`169.254.169.254.nip.io`
// — caught because the dotted IP appears as a host substring), the GCP/ECS
// hostnames, the ECS task-role IP, and the IPv6 link-local. Used both for the
// `input.url` match (WebFetch/WebSearch) and the `input.command` match (a `curl`
// to the same address via Bash).
const METADATA_HOST =
  '(?:169\\.254\\.169\\.254|2852039166|0x[aA]9[fF][eE][aA]9[fF][eE]|metadata\\.google\\.internal|169\\.254\\.170\\.2|\\[?fd00:ec2::254\\]?)';
const METADATA_URL = `(?i)https?://[^\\s/]*${METADATA_HOST}`;

/** DENY — cloud instance-metadata endpoints (can expose instance credentials). */
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
          { field: 'input.url', operator: 'matches', value: METADATA_URL },
        ],
      },
      {
        id: 'deny-cloud-metadata-shell',
        description:
          'Fetching a cloud instance-metadata address (e.g. 169.254.169.254) can expose instance credentials, so it is blocked.',
        effect: 'deny',
        conditions: [
          { field: 'tool_name', operator: 'eq', value: 'Bash' },
          { field: 'input.command', operator: 'matches', value: METADATA_URL },
        ],
      },
    ],
  },
};

// Shells / script interpreters that running a freshly downloaded payload feeds.
const SHELL_INTERPRETERS = '(?:ba|z|d|a|k)?sh|fish|python[0-9.]*|ruby|perl|node|php';
// Tools that fetch a remote payload.
const DOWNLOADERS = 'curl|wget|fetch|httpie|http|aria2c';
// Pipe-to-shell (`curl … | sh`, `… | fish`, `… | python`) OR download-to-file
// then run it (`curl … -o /tmp/a && sh /tmp/a`, `… | tee /tmp/a && sh /tmp/a`).
// For the download-then-run form we accept any later invocation of an
// interpreter on an argument (high-signal: a download command co-occurs with a
// shell being handed a path).
const CURL_TO_SHELL =
  `\\b(?:${DOWNLOADERS})\\b[^|\\n]*\\|\\s*(?:sudo\\s+)?(?:${SHELL_INTERPRETERS})\\b` +
  `|\\b(?:${DOWNLOADERS})\\b[\\s\\S]*?\\b(?:${SHELL_INTERPRETERS})\\s+[./~]?[\\w./~-]+`;
// `git push` with an optional interposed global-option block. Covers the
// argument-taking globals (`git -c k=v push`, `git -C /repo push`), `=`-form
// long options (`git --git-dir=… push`), and bare short/long flags. No
// lookahead — RE2 rejects it — so the block is a bounded repetition of disjoint
// option tokens, none of which can be the bare `push` keyword.
const GIT_PUSH =
  'git\\s+(?:-[cC]\\s+\\S+\\s+|--[\\w-]+=\\S+\\s+|--[\\w-]+\\s+|-\\w+\\s+)*push';
const RISKY_GIT_DATA =
  `(?i)(${GIT_PUSH}\\s+[^\\n]*(-f\\b|--force\\b|--force-with-lease\\b)` +
  `|git\\s+reset\\s+[^\\n]*--hard\\b` +
  `|git\\s+clean\\s+[^\\n]*-[a-z]*f` +
  `|\\b(drop|truncate)\\s+(table|database|schema)\\b` +
  `|${CURL_TO_SHELL}` +
  `|${GIT_PUSH}\\b[^\\n]*\\b(main|master|production|prod|release)\\b)`;

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
            value: RISKY_GIT_DATA,
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
            // `[\\w.-]*` after a binary name tolerates version-suffixed
            // launchers (`kubectl-1.28`, `terraform-1.5`). `tofu` is the
            // OpenTofu fork of terraform; `doas`/`pkexec` are sudo equivalents.
            value:
              '(?i)(\\b(terraform|tofu)[\\w.-]*\\s+(destroy|apply|import)\\b|-auto-approve\\b|\\bkubectl[\\w.-]*\\s+(delete|apply|drain|cordon|scale|patch|replace)\\b|\\bhelm[\\w.-]*\\s+(install|upgrade|uninstall|rollback)\\b|\\b(aws|gcloud|az)\\b[^\\n]*\\b(delete|destroy|terminate|rb|rm|remove)\\b|\\b(npm|pnpm|yarn)\\s+publish\\b|\\bdocker\\s+push\\b|\\bcargo\\s+publish\\b|\\btwine\\s+upload\\b|\\bgh\\s+release\\s+create\\b|\\b(sudo|doas|pkexec)\\s)',
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
