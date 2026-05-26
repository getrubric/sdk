// Classifier for the git seatbelt: which Bash commands should trigger a
// snapshot of the working tree *before* they run.
//
// This is deliberately distinct from the deny/ask rules in
// `policies/default-pack.ts`. Those decide whether a call is *allowed*;
// this decides whether an allowed call is *destructive enough to be worth
// a safety snapshot first*. The target is the gap Claude Code's native
// `/rewind` explicitly leaves: bash-driven git that discards uncommitted
// work (`reset --hard`, `checkout -- .`, `clean -fd`, `stash drop`, …).
//
// Matching style mirrors the regexes in default-pack.ts (single source of
// truth for shell-pattern shape) but the patterns here are tuned for
// "history/worktree-destroying", not "catastrophic".
//
// A raw regex over the whole command string doesn't account for git's *global
// option block* — `git -C <dir>`, `git -c <k=v>`, `git --git-dir=…`, etc.
// sit between the `git` token and the subcommand, breaking subcommand
// adjacency (e.g. `git -C /path reset --hard`). Leading `VAR=val`
// env-assignments do the same to the `git` token itself. So we first
// normalize each git invocation down to `git <subcommand> <args…>` and
// match the destructive patterns against that normalized form.

// Splits a command line into the individual pipeline/sequence segments that
// each begin a fresh command (`;`, `&&`, `||`, `|`, `&`). Keeps this simple
// and linear — we only need rough segmentation to find git invocations, and
// over-segmenting can only ever flag *more*, which is the safe direction.
const COMMAND_SEPARATORS = /(?:&&|\|\||[;|&\n])/;

// A leading shell env-assignment token, e.g. `GIT_DIR=foo` or `FOO=bar`.
const ENV_ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;

// Git's global options that take a separate-token value (`git -C <dir>`,
// `git -c <k=v>`, `git --namespace <ns>`). When seen, skip the value too.
const GIT_GLOBAL_OPT_WITH_VALUE = /^(-C|-c|--namespace|--exec-path|--git-dir|--work-tree)$/;

// Git's global options in attached `--opt=value` / `-c k=v`-as-one-token form,
// plus value-less global flags (`--bare`, `--no-pager`, `--paginate`, …).
const GIT_GLOBAL_OPT_ATTACHED =
  /^(--git-dir=|--work-tree=|--namespace=|--exec-path=|--super-prefix=|--bare$|--no-pager$|--paginate$|-p$|--no-replace-objects$|--literal-pathspecs$|--glob-pathspecs$|--noglob-pathspecs$|--icase-pathspecs$)/;

// Each pattern targets one family of work-discarding git invocation, matched
// against the *normalized* `git <subcommand> …` string (see normalizeGit).
const DESTRUCTIVE_GIT_PATTERNS: readonly RegExp[] = [
  // `git reset --hard [<ref>]` — discards uncommitted tracked changes.
  /^git\s+reset\s+(--hard|--merge|--keep)\b/,
  // `git checkout -- <path>` / `git checkout .` / `git checkout <ref> -- …`
  // — discards working-tree edits.
  /^git\s+checkout\b[^\n]*?(\s--(\s|$)|\s\.(\s|$))/,
  // `git checkout -f` / `git checkout --force` — force discards the worktree.
  /^git\s+checkout\b[^\n]*?\s(-[a-zA-Z]*f\b|--force\b)/,
  // `git restore` that targets the worktree (default, or explicit --worktree)
  // is a discard. `--staged` alone is just unstaging, but `--worktree`
  // discards regardless of whether `--staged` is also present.
  /^git\s+restore\b[^\n]*?\s--worktree\b/,
  /^git\s+restore\b(?![^\n]*\s--staged\b)/,
  // `git clean -f` / `-fd` / `-fdx` — deletes untracked files. The force flag
  // may be its own token or grouped, in any order (`-d -f`, `-f -d`, `-fd`).
  /^git\s+clean\b[^\n]*?\s(-[a-z]*f[a-z]*\b|--force\b)/,
  // `git stash drop` / `git stash clear` — destroys stashed work.
  /^git\s+stash\s+(drop|clear)\b/,
  // `git rebase` (incl. -i) — rewrites history; abort/--continue excluded.
  /^git\s+rebase\b(?![^\n]*\s--(abort|continue|skip|edit-todo)\b)/,
  // `git branch -D` / `--delete --force` — force-deletes a branch.
  /^git\s+branch\s+(-D|-[a-zA-Z]*D|--delete\s+--force|-d\s+--force)\b/,
];

/**
 * Strip leading `VAR=val` env-assignments and git's global-option block from a
 * single command segment, returning the canonical `git <subcommand> <args…>`
 * string. Returns `null` when the segment is not a `git` invocation, so the
 * subcommand-anchored patterns above aren't triggered by an unrelated command
 * that merely contains the substring `git`.
 */
function normalizeGit(segment: string): string | null {
  const tokens = segment.trim().split(/\s+/).filter(Boolean);
  let i = 0;
  // Drop leading env-assignments: `GIT_DIR=… git …`.
  while (i < tokens.length && ENV_ASSIGNMENT.test(tokens[i]!)) i++;
  if (tokens[i] !== 'git') return null;
  i++; // consume the `git` token itself.
  // Skip the global-option block to reach the subcommand token.
  while (i < tokens.length) {
    const tok = tokens[i]!;
    if (GIT_GLOBAL_OPT_WITH_VALUE.test(tok)) {
      i += 2; // skip the flag and its separate-token value.
      continue;
    }
    if (GIT_GLOBAL_OPT_ATTACHED.test(tok)) {
      i++;
      continue;
    }
    break; // first non-global token is the subcommand.
  }
  if (i >= tokens.length) return null; // `git` with no subcommand.
  return `git ${tokens.slice(i).join(' ')}`;
}

/**
 * True if `command` contains a work-discarding git invocation worth
 * snapshotting before execution. Conservative by design: a false positive
 * just costs one cheap extra snapshot; a false negative means no undo.
 */
export function isDestructiveGit(command: string): boolean {
  if (!command) return false;
  for (const segment of command.split(COMMAND_SEPARATORS)) {
    const normalized = normalizeGit(segment);
    if (!normalized) continue;
    if (DESTRUCTIVE_GIT_PATTERNS.some((re) => re.test(normalized))) return true;
  }
  return false;
}
