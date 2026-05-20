# rubric-app

> Runtime governance for AI agents — Python SDK.

`rubric-app` is the official Python SDK for [Rubric](https://rubric-app.com). Wrap a tool call with one decorator and every invocation is evaluated against your central policy bundle and logged to a tamper-evident audit trail. Built for teams running LangChain, MCP, the Claude Agent SDK, or anything else that calls tools on behalf of an LLM.

## Install

Requires **Python 3.10+**.

```bash
pip install rubric-app
```

Optional adapter extras:

```bash
pip install 'rubric-app[langchain]'        # LangChain callback
pip install 'rubric-app[claude-agent]'     # claude_agent_sdk PreToolUse hook
pip install 'rubric-app[mcp]'              # MCP ClientSession wrapper
```

## Quickstart

You'll need an **enrollment token** from your Rubric dashboard at <https://app.rubric-app.com>. Tokens start with `enr_`.

```python
import os
import rubric

# 1. Bootstrap once at process startup.
os.environ["RUBRIC_ENROLLMENT_TOKEN"] = "enr_…"   # or pass enrollment_token=...
rubric.init(agent_name="payments-bot")

# 2. Decorate any tool function. The decorator calls evaluate() before
#    invoking it; if the policy denies, GovernanceDeniedError is raised.
@rubric.tool
def delete_file(path: str) -> str:
    return _do_delete(path)

# 3. Optional: group calls under a session so audit rows can be filtered
#    by conversation in the dashboard.
with rubric.session("conv-42"):
    try:
        delete_file("/tmp/foo")
    except rubric.GovernanceDeniedError as e:
        print(f"blocked by policy: {e}")
```

## Adapters

End-to-end examples live under `examples/` in the source repo:

| Example | Integrates with |
| --- | --- |
| `examples/decorator_quickstart.py` | Plain Python functions (the shortest possible governed agent) |
| `examples/langchain_quickstart.py` | LangChain `BaseTool` subclasses — denies raise `GovernanceDeniedError` |
| `examples/claude_agent_quickstart.py` | `claude_agent_sdk` — installs a `PreToolUse` permission callback |
| `examples/mcp_quickstart.py` | Raw `mcp.ClientSession` — denies surface as `CallToolResult(isError=True)` |

## How it works

- **Bundle poller** — a background thread pulls `GET /v1/bundle?since=<hash>` every 30s. New bundles atomically replace the in-process evaluator state.
- **Evaluator** — pure-Python by default. ReDoS-immune (`regex` library with a per-match timeout) and fail-closed (a detector crash or regex compile failure denies).
- **Audit sink** — events queue without blocking the hot path, ship in batches, retry on transient failures, and pass through `scrub_secrets()` before egress.
- **DLP** — optional `Detector` for inline scanning of tool inputs and outputs; same scrubber covers JWTs, `Bearer` headers, postgres credentials, AWS / OpenAI / GitHub / Slack provider keys, and 64-char hex tokens.

## Environment variables

| Variable | Purpose |
| --- | --- |
| `RUBRIC_ENROLLMENT_TOKEN` | Token from the dashboard. Required unless passed via `enrollment_token=`. |
| `RUBRIC_AGENT_NAME` | Stable name for this agent in the dashboard. Required unless passed via `agent_name=`. |
| `RUBRIC_API_URL` | Override the default `https://api.rubric-app.com`. Must be `https://` and on `rubric-app.com` or a subdomain — the SDK refuses everything else at construction. |
| `RUBRIC_DLP` | DLP mode override: `off`, `regex`, `presidio`, `auto`. |

## License

Apache-2.0. See [LICENSE](./LICENSE).

## Links

- Dashboard: <https://app.rubric-app.com>
- Documentation: <https://docs.rubric-app.com>
- Issues: <https://github.com/getrubric/sdk/issues>
