# Changelog

All notable changes to `rubric-app` (the Python SDK for Rubric) are recorded here.

## 0.1.0 — 2026-05-20

First public release on PyPI.

### Added

- `rubric.init()` + `@rubric.tool` decorator — Sentry-style top-level API for wrapping function calls in a governance + audit pipeline.
- `Governance` client + `Governance.bootstrap()` for multi-agent processes that need explicit lifecycle control.
- Adapters:
  - `rubric.adapters.langchain` — drop-in `LangChainGovernanceCallback`
  - `rubric.adapters.claude_agent` — `claude_agent_sdk` permission-callback bridge
  - `rubric.adapters.mcp` — wrap MCP tool handlers with one call
- `Detector` + `DlpField` for inline DLP scanning of tool inputs/outputs.
- `TraceContext` + the trace-upload pipeline so audit rows in the dashboard carry the full session transcript.
- `scrub_secrets()` helper applied to every string leaf of `tool_input` / `tool_response` before audit egress — covers JWTs, `Bearer` headers, postgres credentials, AWS / OpenAI / GitHub / Slack provider keys, and 64-char hex tokens.

### Security posture

- API URL allowlist: only `https://` URLs whose host is `rubric-app.com` or a subdomain of it are accepted by `TokenStore`, `BundlePoller`, and `AuditSink`. Plaintext `http://` and arbitrary hosts are refused at construction time with `ValueError`.
- ReDoS-immune regex: `matches` uses the third-party `regex` library with a per-match `timeout=` budget; pathological patterns abort within the budget instead of hanging the agent process.
- Bundle monotonicity check: rollback bundles (older `bundleVersion`, or `builtAt` skew beyond 5 min) are rejected — silently unfreezing an agent or shrinking the policy set is not possible via a polling response.
- Fail-closed evaluator: a detector crash or regex compile failure marks the policy errored and any evaluation reaching it denies. A null/empty bundle returns `deny / NO_POLICIES`.
- HTTP egress uses `trust_env=False` so a caller's `HTTPS_PROXY` / `SSL_CERT_FILE` can't redirect uploads to an unexpected endpoint.
- Strict Pydantic v2 models on every wire-format payload; field-path resolution refuses `__proto__` / `constructor` / `prototype` parts.

### Optional extras

- `pip install 'rubric-app[langchain]'` — LangChain callback integration
- `pip install 'rubric-app[claude-agent]'` — `claude_agent_sdk` integration
- `pip install 'rubric-app[mcp]'` — MCP server integration
- `pip install 'rubric-app[dev]'` — pytest / ruff / mypy

### Known limitations

- The `agent_os` native evaluator backend, when present, is used in preference to the pure-Python evaluator (`try: import agent_os.policies`). `agent_os` is not yet published to PyPI; until then the pure-Python evaluator is the only available backend.
- No append-only local audit log fallback yet — events dropped during control-plane outages are surfaced via the `AuditSink` drop counters; recovery is manual.
