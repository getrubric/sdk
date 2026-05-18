# @rubric/core

> Framework-neutral runtime building blocks for [Rubric](https://rubric-app.com) SDK adapters.

This package is a low-level library — it is the engine behind framework-specific adapters like [`@rubric/claude-code`](https://www.npmjs.com/package/@rubric/claude-code).

**Most users don't install `@rubric/core` directly.** If you want to govern Claude Code, install the Claude Code adapter:

```sh
npm i -g @rubric/claude-code
```

## What's in here

If you're building a new adapter (e.g. for Cursor, Windsurf, or your own agent framework) you'll consume:

| Export | Purpose |
| --- | --- |
| `TokenStore` + `bootstrapTokenStore` | JWT-SVID enrollment + proactive refresh against the Rubric control plane. |
| `BundlePoller` | 30-second polling for policy bundles, with content-hash short-circuit and rollback rejection. |
| `AuditSink` | Batched, retried shipping of audit events with operator-visible drop counters. |
| `Evaluator` | re2-backed tool-call evaluator: first-deny-wins, last-allow-wins, frozen-agent kill switch, 50ms wall-clock budget, empty-bundle = deny. |
| `scrubSecrets` | Best-effort redaction of JWTs, bearer headers, postgres creds, provider keys, and hex64 daemon tokens — used by adapters before audit events leave the machine. |

Plus zod schemas for `AuditEvent`, `Bundle`, `PolicyDocument`, `PolicyRule`, and the SDK token response shape.

## Install

```sh
npm i @rubric/core
```

Requires **Node.js 22+**. Native dependency on [`re2`](https://www.npmjs.com/package/re2) for non-backtracking regex evaluation in policy `matches` conditions; prebuilt binaries are available for Linux, macOS, and Windows on common architectures.

## Stability

The exports listed above follow [semver](https://semver.org/). Underscore-prefixed utilities re-exported from `_internal.js` (`scrubSecrets`, `errMessage`) are exposed as a convenience for the official adapter packages — they are stable in practice but not covered by the public semver contract.

## License

MIT. See [LICENSE](./LICENSE).
