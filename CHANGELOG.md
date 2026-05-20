# Changelog

All notable changes to `@rubric-app/core` and `@rubric-app/claude-code` are recorded here.

## 0.1.4 — 2026-05-20

### Fixed

- **`rubric init --force`**: now reuses the `enrollmentToken` already persisted in `~/.config/rubric/config.json` instead of re-prompting for it. Matches the behavior already in place for `agentName` and `apiUrl`. Tokens passed via `--enrollment-token` / `RUBRIC_ENROLLMENT_TOKEN` still take precedence.
- **`rubric init --force`** now restarts the daemon at the end of install so the running process picks up the rotated bearer token immediately. Previously `launchctl bootstrap` / `systemctl enable --now` were no-ops against an already-loaded unit, leaving the old token cached in memory and producing a `[fail] bundle non-empty + fresh status returned 401` from `rubric doctor` until the service was kicked by hand.

## 0.1.3 — 2026-05-19

### Added

- **`@rubric-app/claude-code`**: Each Rubric hook in `~/.claude/settings.json` is now preceded by an auto-revive preflight. `rubric init` writes a small shell script to `~/.config/rubric/ensure-daemon.sh` that curls `/healthz` and, if the daemon isn't responding, brings it back up via the platform service manager — `launchctl bootstrap` (for unloaded services) or `kickstart -k` (for hung but loaded services) on macOS, `systemctl --user restart` on Linux. The script polls up to ~5s for the daemon to bind and is throttled to one slow-path attempt per 30s so a broken install doesn't burn the full budget on every tool call. Fast path (daemon already up) adds ~20ms. The script always exits 0, so a failed revive falls through to the http hook and surfaces the real error to Claude Code instead of masking it. `rubric uninstall` strips the command hook by exact path with a basename fallback for older or relocated installs.

### Changed

- **launchd plist**: `ThrottleInterval` now set to `2` (down from launchd's 10s default). The previous default meant a killed daemon waited a full 10s before launchd would respawn it; with `2`, a kill-then-restart respawns within ~2s — fast enough for the new auto-revive script to confirm health inside its poll budget. Mirrors the `RestartSec=2` already used on the systemd-user unit. New plist applies on the next `rubric init` (or `--force`); existing installs are unaffected until they re-run init.

## 0.1.2 — 2026-05-19

### Changed

- The SDK now accepts only `https://` API URLs whose host is `rubric-app.com` or a subdomain of it (`api.`, `staging.`, etc.). Loopback hosts (`localhost`, `127.0.0.1`, `::1`) and the previous `RUBRIC_INSECURE_HTTP=1` escape hatch are no longer accepted. `validateApiUrl` is now exported from `@rubric-app/core` and called from every primitive (`TokenStore`, `BundlePoller`, `AuditSink`) at construction — failure raises `TypeError` immediately. Existing installs pointing at the production URL are unaffected.

## 0.1.1 — 2026-05-18

### Fixed

- Published `@rubric-app/claude-code@0.1.0` shipped with a literal `"workspace:*"` dependency on `@rubric-app/core`, causing `npm install -g @rubric-app/claude-code` to fail with `EUNSUPPORTEDPROTOCOL`. `0.1.1` resolves the dependency to a concrete version. `0.1.0` is deprecated on npm.

## 0.1.0 — 2026-05-18

First public release.

### Added

- `@rubric-app/claude-code` — `rubric` CLI + long-lived loopback daemon that routes Claude Code `PreToolUse` / `PostToolUse` / `SessionStart` hooks through the Rubric policy engine and audit log.
- `@rubric-app/core` — framework-neutral runtime: `TokenStore`, `BundlePoller`, `AuditSink`, `Evaluator`, and `scrubSecrets` helper.
- macOS launchd and Linux systemd-user service installers (auto-detected by `rubric init`).
- `rubric doctor` with six health checks covering config, daemon liveness, control-plane reachability, identity refresh, settings.json hook entries, and bundle freshness.
- Authenticated `POST /v1/shutdown` endpoint (used by `rubric stop`); SIGTERM fallback gated behind `--force`.
- Secret-redaction pass on `tool_input` and `tool_response` before audit events are queued — covers JWTs, `Bearer` headers, postgres credentials, AWS / OpenAI / GitHub / Slack provider keys, and 64-char hex tokens.

### Security posture

- Daemon binds `127.0.0.1` only; host is whitelisted to loopback at startup.
- Constant-time bearer compare with shape validation (`/^[a-f0-9]{64}$/`).
- Refuses cold-start: no hook is served until the first policy bundle pull succeeds.
- Evaluator returns `deny / NO_POLICIES` for null or empty bundles.
- `matches` regex compile failure fails closed — the policy is marked errored and any evaluation reaching it denies.
- Bundle monotonicity check rejects rollback attempts (`bundleVersion` strictly increasing; `builtAt` within 5 min tolerance).
- `writeFileSecure()` helper for every secret-file write: `lstat` symlink pre-check, `O_NOFOLLOW`, explicit `chmodSync` after write, atomic write-rename available for `settings.json` and `config.json`.
- HTTP server timeouts: `headersTimeout=5s`, `requestTimeout=10s`, `keepAliveTimeout=5s`.
- HTTPS required for non-loopback control-plane URLs; `RUBRIC_INSECURE_HTTP=1` testing escape hatch.
- Bearer scheme case-insensitive (RFC 7235); array-valued `Authorization` headers rejected.

### Known limitations

- Bundle signing with an org-rooted key is not yet implemented; trust in the policy bundle relies on TLS to the control plane + the rollback check above.
- The daemon talks to itself over TCP loopback rather than a Unix-domain socket; same-UID processes on the machine can forge audit events with the daemon token.
- No append-only local audit log fallback for control-plane outages; dropped events are surfaced via `/v1/status.audit.dropped*` counters.

These items are tracked for future releases.
