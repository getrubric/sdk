# Changelog

All notable changes to `@rubric-app/core` and `@rubric-app/claude-code` are recorded here.

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
