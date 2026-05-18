# @rubric/claude-code

> Gate every Claude Code tool call through the Rubric policy engine, with a tamper-evident audit log.

`@rubric/claude-code` is the official Rubric adapter for [Anthropic Claude Code](https://docs.claude.com/en/docs/claude-code). It installs a long-lived loopback daemon and patches `~/.claude/settings.json` so that every `PreToolUse` and `PostToolUse` hook routes through Rubric — your policies decide allow vs. deny, and every decision is recorded in the dashboard.

Built for security teams that want one control plane for both their production AI agents and the coding agents engineers are running on their laptops.

---

## Install

Requires **Node.js 22+**.

```sh
npm i -g @rubric/claude-code
```

Or with `pnpm`:

```sh
pnpm add -g @rubric/claude-code
```

The package installs a single binary, `rubric`.

## First-run setup

You'll need an **enrollment token** from your Rubric dashboard at <https://app.rubric-app.com>. Tokens start with `enr_`. If you don't have an account yet, sign up at <https://rubric-app.com> first.

```sh
rubric init
```

This will:

1. Prompt for an agent name (the label that shows up in your dashboard) and your `enr_…` enrollment token.
2. Test the enrollment by exchanging the token with the Rubric control plane.
3. Write a 0600-mode daemon token to `~/.config/rubric/daemon.token`.
4. Patch `~/.claude/settings.json` to route Claude Code's hooks through `http://127.0.0.1:47821/v1/hook`.
5. Install a launchd (macOS) or systemd-user (Linux) service so the daemon survives logouts and reboots.

When `rubric init` exits cleanly, open any Claude Code session and your tool calls are governed.

## Verify it's working

```sh
rubric doctor
```

Runs six health checks: config integrity, daemon liveness, control-plane reachability, identity-refresh round-trip, settings.json hook entries, and bundle freshness. Each line ends in `ok` or a one-line hint at what's wrong.

To watch live decisions:

```sh
rubric logs --follow
```

Each `PreToolUse` shows up as a JSON line with `event`, `tool`, and `decision`.

## Other commands

| Command | What it does |
| --- | --- |
| `rubric status` | One-shot status (pid, port, healthz, log file path) |
| `rubric stop` | Authenticated shutdown via the daemon's loopback API; SIGTERM fallback with `--force` |
| `rubric uninstall` | Stop the service, remove config, scrub Rubric hooks from `~/.claude/settings.json` |
| `rubric daemon` | Run the daemon in the foreground (used by the service manager; rarely run by hand) |

`rubric <command> --help` always works.

## Troubleshooting

**`rubric init` fails with "enrollment failed"**

- Verify the API is reachable: `curl https://api.rubric-app.com/health` should print `{"ok":true}`.
- Confirm your token hasn't been revoked or used past its cap — generate a fresh one in the dashboard.
- Make sure the agent name is unique within your organization.

**Claude Code logs `PreToolUse:Read hook error → HTTP 401`**

The bearer token in `~/.claude/settings.json` is out of sync with what the daemon loaded. Most common cause: you ran `rubric init --force` while an older daemon was still in memory.

```sh
launchctl kickstart -k "gui/$(id -u)/dev.rubric.claude-code"   # macOS
systemctl --user restart rubric-claude-code                    # Linux
```

If that doesn't fix it, run `rubric doctor` — it surfaces a token-mismatch hint in the daemon-liveness check.

**Daemon won't start after reboot**

- macOS: `launchctl print gui/$(id -u)/dev.rubric.claude-code` — check `state` and `last exit reason`.
- Linux: `systemctl --user status rubric-claude-code` and `journalctl --user -u rubric-claude-code -n 50`.

**"daemon refused to bind: first bundle pull failed"**

The daemon refuses to serve tool-call hooks until it has an authoritative policy bundle from the control plane. This is intentional — failing closed prevents a cold-start window of unrestricted tool calls. Fix the upstream issue (network outage, expired token, control-plane downtime) and the daemon will start automatically on the next service-manager retry.

## What data leaves your machine

Every governed tool call sends an audit event to your configured control plane (`https://api.rubric-app.com` by default). Each event includes:

- The tool name (e.g. `Read`, `Bash`, `Write`).
- The agent identity (the name you chose at init time).
- Decision metadata: `allow` / `deny`, which policy + rule matched.
- The `tool_input` and `tool_response` payloads, **passed through a secrets-redaction pass** that masks JWTs, `Bearer …` headers, postgres credentials, AWS keys, OpenAI / GitHub / Slack tokens, and 64-char hex strings before they ever leave the daemon.

The redaction is best-effort, not a guarantee — never paste raw secrets into a Claude Code session expecting them to be scrubbed. Treat the audit log as you would any internal observability pipeline.

The daemon does not phone home anywhere else. The only network egress is to your configured Rubric API URL.

## Trust model & local security

- The daemon binds **`127.0.0.1` only** (loopback). It is not reachable from another machine on your network.
- Authentication is a 64-char hex bearer token written to `~/.config/rubric/daemon.token` at mode `0600`. The same token is inlined in `~/.claude/settings.json` (also at `0600`).
- Same-UID processes on your machine can read both files and forge audit events. This is the documented trust model — the daemon is designed to defend against tools and prompts inside Claude Code, not against another local process you've already given full access.
- The daemon never runs as root. The service supervisor runs it as your own user account.

## Configuration

| Env var | Effect |
| --- | --- |
| `RUBRIC_API_URL` | Override the Rubric control plane URL (default `https://api.rubric-app.com`). HTTPS is required for non-loopback hosts. |
| `RUBRIC_AGENT_NAME` | Skip the agent-name prompt during `rubric init`. |
| `RUBRIC_ENROLLMENT_TOKEN` | Skip the enrollment-token prompt during `rubric init`. |
| `RUBRIC_INSECURE_HTTP=1` | (Testing only) Allow plaintext `http://` for non-loopback API URLs. Do not set this in production. |

## License

MIT. See [LICENSE](./LICENSE).

## Links

- Dashboard: <https://app.rubric-app.com>
- Marketing: <https://rubric-app.com>
- Issues: <https://github.com/getrubric/sdk/issues>
