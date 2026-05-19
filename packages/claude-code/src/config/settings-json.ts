// Idempotent patcher for `~/.claude/settings.json`.
//
// `rubric init` adds a hook block to the user's settings.json without
// disturbing anything the user has set themselves; `rubric uninstall`
// removes only what we added. Identification is via the hook URL —
// every Rubric hook entry points at the same loopback URL, which is
// unique enough to detect with no extra metadata.
//
// Shape we write (per event):
//
//     [{
//       "matcher": "*",
//       "hooks": [
//         { "type": "command", "command": "<configDir>/ensure-daemon.sh", "timeout": 3 },
//         { "type": "http", "url": "...", "headers": {...}, "timeout": 5 }
//       ]
//     }]
//
// The leading `command` hook curls /healthz and kicks the platform
// service manager if the daemon isn't responding — see
// `ensure-daemon-script.ts`. It always exits 0, so a failed revive
// just falls through to the http hook (which is the one that
// surfaces real errors to Claude Code).
//
// The Authorization header is `Bearer <literal-token>` — the daemon
// token is inlined directly rather than referenced via `env`. Claude
// Code's `env` map is plain `{string: string}` (no `${file:...}`
// expansion); and even with the right env value, `$VAR` interpolation
// in headers requires an explicit `allowedEnvVars` allowlist per hook.
// The inline-literal approach skips both surfaces. Trade-off: the
// daemon token lives in settings.json (typically 0644). For tighter
// permissions, callers can chmod ~/.claude/settings.json after
// patching; the token only guards a loopback daemon.

const DEFAULT_HOOK_URL = 'http://127.0.0.1:47821/v1/hook';

// Filename heuristic used by `removeRubricHooks` so an uninstall still
// finds the command hook even if the user moved their config dir
// (`XDG_CONFIG_HOME` change between install and uninstall, etc.).
const ENSURE_DAEMON_SCRIPT_BASENAME = 'ensure-daemon.sh';
const ENSURE_DAEMON_SCRIPT_PARENT = 'rubric';

// Timeout in seconds for the ensure-daemon command hook. The script
// itself bounds its own work to ~5s (one fast curl + up to 50 polls at
// 0.1s each). 6s gives Claude Code a small buffer before it would kill
// the process — and the script's per-tool-call cooldown means this
// budget is only ever spent at most once per 30s anyway.
const ENSURE_DAEMON_TIMEOUT_S = 6;

// Legacy keys we wrote in earlier versions of this patcher. We strip
// these on every apply so a re-run heals the broken state from older
// installs (env-var indirection that Claude Code never honored).
const LEGACY_RUBRIC_ENV_KEYS = ['RUBRIC_DAEMON_TOKEN'];

type Json = Record<string, unknown>;

interface ClaudeHookEntry {
  type: 'http' | 'command' | string;
  url?: string;
  command?: string;
  headers?: Record<string, string>;
  timeout?: number;
}

interface ClaudeHookGroup {
  matcher?: string;
  hooks?: ClaudeHookEntry[];
}

type ClaudeHooksMap = Record<string, ClaudeHookGroup[]>;

export interface PatchOptions {
  /**
   * URL the hook entry posts to. Defaults to the conventional
   * `http://127.0.0.1:47821/v1/hook`. Override is for tests and for
   * the rare case where the daemon binds an OS-assigned port — but
   * note that the URL needs to remain *stable* across runs, since it's
   * the identifier used by `removeRubricHooks` to find our entries.
   * If you want the daemon to use a non-default port, change the
   * URL once and stick with it.
   */
  hookUrl?: string;
}

export interface ApplyOptions extends PatchOptions {
  /**
   * The literal daemon-token value to inline in every Rubric hook's
   * `Authorization: Bearer …` header. 64-char hex string from
   * `~/.config/rubric/daemon.token`. Required.
   */
  daemonToken: string;
  /**
   * Absolute path to the ensure-daemon shell script. If omitted, the
   * apply skips the command hook and writes only the http hook —
   * useful for tests and for managed installs that don't want a
   * service-manager kick path. Production callers (`rubric init`)
   * always pass this so the http hook is preceded by an auto-revive
   * preflight.
   */
  ensureDaemonScriptPath?: string;
}

const EVENT_TIMEOUTS: Record<string, number> = {
  PreToolUse: 5,
  PostToolUse: 2,
  SessionStart: 2,
};

/**
 * Return a new settings object with Rubric's hook entries merged in.
 * Idempotent: running this twice produces the same result as running
 * it once (no duplicate entries with the same URL).
 *
 * The function never mutates the input; it returns a fresh value
 * suitable for writing back to disk. The supplied `daemonToken` is
 * inlined directly into every hook's Authorization header.
 */
export function applyRubricHooks(existing: unknown, options: ApplyOptions): Json {
  if (!options.daemonToken || !/^[a-f0-9]{64}$/.test(options.daemonToken)) {
    throw new Error('applyRubricHooks: daemonToken must be a 64-char hex string');
  }
  const hookUrl = options.hookUrl ?? DEFAULT_HOOK_URL;
  const authHeader = `Bearer ${options.daemonToken}`;
  const root: Json = isObject(existing) ? deepClone(existing) : {};

  // ---- env scrub ------------------------------------------------------------
  // Earlier versions wrote `env.RUBRIC_DAEMON_TOKEN: "${file:...}"` —
  // Claude Code never honored that and the resulting hooks 401'd
  // silently. Strip the legacy entry on every apply so a re-run heals
  // pre-existing broken installs.
  if (isObject(root['env'])) {
    const env = { ...root['env'] };
    let mutated = false;
    for (const key of LEGACY_RUBRIC_ENV_KEYS) {
      if (key in env) {
        delete env[key];
        mutated = true;
      }
    }
    if (mutated) {
      if (Object.keys(env).length === 0) delete root['env'];
      else root['env'] = env;
    }
  }

  // ---- hooks ----------------------------------------------------------------
  const hooks: ClaudeHooksMap = isObject(root['hooks'])
    ? (deepClone(root['hooks']) as ClaudeHooksMap)
    : {};

  for (const event of Object.keys(EVENT_TIMEOUTS)) {
    const existingGroups: ClaudeHookGroup[] = Array.isArray(hooks[event]) ? hooks[event]! : [];
    // Strip any pre-existing Rubric entries (either the http hook with
    // our URL, or the ensure-daemon command hook) so we re-write a
    // single canonical group. This is what makes the function
    // idempotent — `applyRubricHooks(applyRubricHooks(x)) === applyRubricHooks(x)`.
    const stripped = existingGroups
      .map((group) => filterOutRubricEntries(group, hookUrl, options.ensureDaemonScriptPath))
      .filter((group) => (group.hooks ?? []).length > 0);

    const innerHooks: ClaudeHookEntry[] = [];
    if (options.ensureDaemonScriptPath) {
      innerHooks.push({
        type: 'command',
        command: options.ensureDaemonScriptPath,
        timeout: ENSURE_DAEMON_TIMEOUT_S,
      });
    }
    innerHooks.push({
      type: 'http',
      url: hookUrl,
      headers: {
        Authorization: authHeader,
        'Content-Type': 'application/json',
      },
      timeout: EVENT_TIMEOUTS[event] ?? 5,
    });

    hooks[event] = [...stripped, { matcher: '*', hooks: innerHooks }];
  }

  root['hooks'] = hooks;
  return root;
}

/**
 * Return a new settings object with all Rubric entries stripped. The
 * inverse of `applyRubricHooks`: leaves user-authored entries intact,
 * removes the env var, and prunes any empty hook groups / arrays /
 * the top-level `hooks` object if it becomes empty.
 *
 * Identification: any hook entry whose URL equals `hookUrl` is ours.
 */
export interface RemoveOptions extends PatchOptions {
  /**
   * Absolute path to the ensure-daemon script the install wrote, if
   * known. When provided, it's matched exactly. Even without it, the
   * remover falls back to a filename heuristic so older installs and
   * users who moved their config dir still get cleaned up.
   */
  ensureDaemonScriptPath?: string;
}

export function removeRubricHooks(existing: unknown, options: RemoveOptions = {}): Json {
  const hookUrl = options.hookUrl ?? DEFAULT_HOOK_URL;
  const root: Json = isObject(existing) ? deepClone(existing) : {};

  // ---- env scrub ------------------------------------------------------------
  // Strip any legacy env entries (we used to write
  // `env.RUBRIC_DAEMON_TOKEN: "${file:...}"`; that's gone, but uninstall
  // still cleans it up for users on older installs).
  if (isObject(root['env'])) {
    const env = { ...root['env'] };
    let mutated = false;
    for (const key of LEGACY_RUBRIC_ENV_KEYS) {
      if (key in env) {
        delete env[key];
        mutated = true;
      }
    }
    if (mutated) {
      if (Object.keys(env).length === 0) delete root['env'];
      else root['env'] = env;
    }
  }

  // ---- hooks ----------------------------------------------------------------
  if (isObject(root['hooks'])) {
    const hooks = deepClone(root['hooks']) as ClaudeHooksMap;
    for (const event of Object.keys(hooks)) {
      const groups = Array.isArray(hooks[event]) ? hooks[event]! : [];
      const remaining = groups
        .map((group) => filterOutRubricEntries(group, hookUrl, options.ensureDaemonScriptPath))
        .filter((group) => (group.hooks ?? []).length > 0);
      if (remaining.length === 0) {
        delete hooks[event];
      } else {
        hooks[event] = remaining;
      }
    }
    if (Object.keys(hooks).length === 0) {
      delete root['hooks'];
    } else {
      root['hooks'] = hooks;
    }
  }
  return root;
}

// ---- Helpers ---------------------------------------------------------------

function filterOutRubricEntries(
  group: ClaudeHookGroup,
  rubricUrl: string,
  ensureDaemonScriptPath?: string,
): ClaudeHookGroup {
  const inner = Array.isArray(group.hooks) ? group.hooks : [];
  const filtered = inner.filter((h) => !isRubricEntry(h, rubricUrl, ensureDaemonScriptPath));
  if (filtered.length === inner.length) return group; // nothing of ours in here
  return { ...group, hooks: filtered };
}

function isRubricEntry(
  entry: ClaudeHookEntry,
  rubricUrl: string,
  ensureDaemonScriptPath?: string,
): boolean {
  if (entry.type === 'http' && entry.url === rubricUrl) return true;
  if (entry.type === 'command' && typeof entry.command === 'string') {
    const cmd = entry.command;
    if (ensureDaemonScriptPath && cmd === ensureDaemonScriptPath) return true;
    // Fallback heuristic: the command ends with `.../rubric/ensure-daemon.sh`.
    // Specific enough to not collide with user-authored hooks; survives
    // the user moving `XDG_CONFIG_HOME` between install and uninstall.
    if (
      cmd.endsWith(`/${ENSURE_DAEMON_SCRIPT_PARENT}/${ENSURE_DAEMON_SCRIPT_BASENAME}`)
    ) {
      return true;
    }
  }
  return false;
}

function isObject(v: unknown): v is Json {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function deepClone<T>(v: T): T {
  // structuredClone is built-in since Node 17. For JSON-shaped data
  // (which `settings.json` always is) it's the cheapest correct option.
  return structuredClone(v);
}
