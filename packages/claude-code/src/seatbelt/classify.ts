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

// Each pattern targets one family of work-discarding git invocation.
// Anchored on `git` with flexible whitespace so `git   reset --hard` and
// `git reset  --hard` both match; the command string is the raw
// `tool_input.command` Claude Code reports.
const DESTRUCTIVE_GIT_PATTERNS: readonly RegExp[] = [
  // `git reset --hard [<ref>]` — discards uncommitted tracked changes.
  /\bgit\s+reset\s+(--hard|--merge|--keep)\b/,
  // `git checkout -- <path>` / `git checkout .` — discards working-tree edits.
  /\bgit\s+checkout\s+(--\s|\.(\s|$))/,
  // `git restore` without --staged is a discard (default --worktree).
  /\bgit\s+restore\b(?!.*--staged\b)/,
  // `git clean -f` / `-fd` / `-fdx` — deletes untracked files.
  /\bgit\s+clean\s+(-[a-z]*f|--force)/,
  // `git stash drop` / `git stash clear` — destroys stashed work.
  /\bgit\s+stash\s+(drop|clear)\b/,
  // `git rebase` (incl. -i) — rewrites history; abort/--continue excluded.
  /\bgit\s+rebase\b(?!.*--(abort|continue|skip|edit-todo)\b)/,
  // `git branch -D` / `--delete --force` — force-deletes a branch.
  /\bgit\s+branch\s+(-D|-[a-zA-Z]*D|--delete\s+--force|-d\s+--force)\b/,
];

/**
 * True if `command` contains a work-discarding git invocation worth
 * snapshotting before execution. Conservative by design: a false positive
 * just costs one cheap extra snapshot; a false negative means no undo.
 */
export function isDestructiveGit(command: string): boolean {
  if (!command) return false;
  return DESTRUCTIVE_GIT_PATTERNS.some((re) => re.test(command));
}
