"""Raw MCP end-to-end quickstart.

What this proves:
  1. SDK pulls a policy bundle from the Rubric API on startup.
  2. Tool calls dispatched through `mcp.ClientSession` are evaluated locally
     in-process via `MCPClientWrapper`.
  3. A denied call is surfaced as a native `CallToolResult(isError=True)` —
     no exceptions, no special-casing in the caller.
  4. An audit event ships back to the Rubric API.
  5. The dashboard's Insights page shows the event within seconds.

Unlike the Claude Agent quickstart, this example uses raw `mcp` only — no
Claude Agent SDK, no LangChain. It works against any MCP-speaking agent.

Setup:
  pip install 'rubric[mcp]'
  # Create an enrollment token in the dashboard, then:
  export RUBRIC_ENROLLMENT_TOKEN=enr_...
  export RUBRIC_AGENT_NAME=mcp-quickstart
  export RUBRIC_API_URL=https://api.rubric-app.com

Run:
  python examples/mcp_quickstart.py
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from rubric import Governance
from rubric.adapters.mcp import govern_mcp_session

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

_SERVER_FLAG = "--server"
_SESSION_ID = "mcp-quickstart"
_MCP_SERVER_NAME = "quickstart-tools"


def run_server() -> None:
    """Run as the in-tree FastMCP server. Spawned as a subprocess by the client."""
    from mcp.server.fastmcp import FastMCP

    server = FastMCP(_MCP_SERVER_NAME)

    @server.tool()
    async def list_files(path: str) -> str:
        return f"[stub] would list files in {path}"

    @server.tool()
    async def delete_file(path: str) -> str:
        return f"[stub] deleted {path}"

    server.run()


async def run_client(
    enrollment_token: str | None,
    agent_name: str | None,
    api_url: str | None,
) -> None:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    server_params = StdioServerParameters(
        command=sys.executable,
        args=[__file__, _SERVER_FLAG],
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

        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                wrapped = govern_mcp_session(gov, session, session_id=_SESSION_ID)

                tools = await wrapped.list_tools()
                print(f"discovered {len(tools.tools)} tools: {[t.name for t in tools.tools]}")

                print("\n→ calling list_files (expected: allow)")
                allow_result = await wrapped.call_tool("list_files", {"path": "/tmp"})
                print(f"   isError={allow_result.isError}")
                for block in allow_result.content:
                    if hasattr(block, "text"):
                        print(f"   text: {block.text}")

                print("\n→ calling delete_file (expected: deny if policy is published)")
                deny_result = await wrapped.call_tool("delete_file", {"path": "/tmp/foo"})
                print(f"   isError={deny_result.isError}")
                for block in deny_result.content:
                    if hasattr(block, "text"):
                        print(f"   text: {block.text}")

        print("\nFlushing audit events...")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(_SERVER_FLAG, action="store_true", help=argparse.SUPPRESS)
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

    if args.server:
        run_server()
        return

    asyncio.run(
        run_client(
            args.enrollment_token,
            args.agent_name,
            args.api_url,
        )
    )


if __name__ == "__main__":
    main()
