"""Claude Agent SDK end-to-end quickstart.

What this proves:
  1. SDK pulls a policy bundle from the Rubric API on startup.
  2. Tool calls are evaluated locally in-process via a PreToolUse hook.
  3. A denied call is surfaced to the model as a permission denial.
  4. An audit event ships back to the Rubric API.
  5. The dashboard's Insights page shows the event within seconds.

Setup:
  pip install 'rubric[claude-agent]'
  # Create an enrollment token in the dashboard, then:
  export RUBRIC_ENROLLMENT_TOKEN=enr_...
  export RUBRIC_AGENT_NAME=claude-quickstart
  export RUBRIC_API_URL=https://api.rubric-app.com
  export ANTHROPIC_API_KEY=sk-ant-...

Run:
  python examples/claude_agent_quickstart.py
"""

from __future__ import annotations

import argparse
import asyncio
import logging

from rubric import Governance
from rubric.adapters.claude_agent import governance_hook_matchers

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


async def run(
    enrollment_token: str | None,
    agent_name: str | None,
    api_url: str | None,
) -> None:
    from claude_agent_sdk import (
        ClaudeAgentOptions,
        ClaudeSDKClient,
        create_sdk_mcp_server,
        tool,
    )

    @tool("list_files", "List files in a directory.", {"path": str})
    async def list_files(args: dict) -> dict:
        return {
            "content": [
                {"type": "text", "text": f"[stub] would list files in {args['path']}"}
            ]
        }

    @tool("delete_file", "Delete a file at a given path.", {"path": str})
    async def delete_file(args: dict) -> dict:
        return {
            "content": [
                {"type": "text", "text": f"[stub] deleted {args['path']}"}
            ]
        }

    server = create_sdk_mcp_server(
        name="quickstart-tools",
        tools=[list_files, delete_file],
    )

    with Governance.bootstrap(
        enrollment_token=enrollment_token,
        agent_name=agent_name,
        api_url=api_url,
    ) as gov:
        ready = gov.wait_until_ready(timeout=10.0)
        if not ready:
            print("warning: bundle did not load within 10s; proceeding (default-allow)")

        bundle = gov.current_bundle
        if bundle is None:
            print("no bundle published yet — publish a policy in the dashboard first")
        else:
            print(f"loaded bundle v{bundle.bundleVersion} with {len(bundle.policies)} policies")

        options = ClaudeAgentOptions(
            mcp_servers={"quickstart-tools": server},
            allowed_tools=[
                "mcp__quickstart-tools__list_files",
                "mcp__quickstart-tools__delete_file",
            ],
            hooks=governance_hook_matchers(gov, session_id="quickstart-session"),
        )

        async with ClaudeSDKClient(options=options) as client:
            print("\n→ asking the agent to list /tmp (expected: allow)")
            await client.query("Please list the files in /tmp using the list_files tool.")
            async for msg in client.receive_response():
                print(f"   {msg}")

            print("\n→ asking the agent to delete /tmp/foo (expected: deny if policy is published)")
            await client.query("Please delete /tmp/foo using the delete_file tool.")
            async for msg in client.receive_response():
                print(f"   {msg}")

        print("\nFlushing audit events...")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--enrollment-token",
        default=None,
        help="Override RUBRIC_ENROLLMENT_TOKEN",
    )
    parser.add_argument(
        "--agent-name",
        default=None,
        help="Override RUBRIC_AGENT_NAME",
    )
    parser.add_argument("--api-url", default=None, help="Override RUBRIC_API_URL")
    args = parser.parse_args()
    asyncio.run(
        run(
            args.enrollment_token,
            args.agent_name,
            args.api_url,
        )
    )


if __name__ == "__main__":
    main()
