# Rubric SDK

The official Node.js SDK for [Rubric](https://rubric-app.com) — governance, policy enforcement, and tamper-evident audit logging for AI agents.

This repository hosts two npm packages:

| Package | What it's for |
| --- | --- |
| [`@rubric/claude-code`](./packages/claude-code) | Drop-in adapter that routes every Anthropic Claude Code tool call through Rubric. One command (`rubric init`) installs a loopback daemon and patches `~/.claude/settings.json`. |
| [`@rubric/core`](./packages/core) | Framework-neutral runtime building blocks: agent identity, policy bundle polling, audit sink, policy evaluator. Use this when building adapters for other agent frameworks. |

## Quick start

You probably want the Claude Code adapter:

```sh
npm i -g @rubric/claude-code
rubric init
```

You'll need an enrollment token from your Rubric dashboard at [app.rubric-app.com](https://app.rubric-app.com). See the [adapter README](./packages/claude-code/README.md) for the full setup walkthrough.

## Repository layout

```
.
├── packages/
│   ├── core/          # @rubric/core
│   └── claude-code/   # @rubric/claude-code
├── CHANGELOG.md
└── pnpm-workspace.yaml
```

## Development

Requires Node.js 22+ and pnpm 9+.

```sh
pnpm install
pnpm -r build
pnpm -r test
```

Each package has its own README with internals and test coverage notes.

## Releases

Released to npm under the `@rubric` scope. See [CHANGELOG.md](./CHANGELOG.md) for version history. Each release is tagged in this repository.

## Security

If you find a security issue, please email security@rubric-app.com rather than opening a public issue. We respond within 48 hours.

The Claude Code adapter underwent a multi-agent parallel security audit before its first public release; the resulting findings and remediation report are summarized in the [CHANGELOG](./CHANGELOG.md).

## License

MIT. See the `LICENSE` file in each package.

## Links

- [Dashboard](https://app.rubric-app.com)
- [Marketing site](https://rubric-app.com)
- [Issues](https://github.com/getrubric/sdk/issues)
