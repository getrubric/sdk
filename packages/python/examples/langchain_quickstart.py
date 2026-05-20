"""End-to-end quickstart.

What this proves:
  1. SDK pulls a policy bundle from the Rubric API on startup.
  2. Tool calls are evaluated locally in-process.
  3. A denied call raises GovernanceDeniedError.
  4. An audit event ships back to the Rubric API.
  5. The dashboard's Insights page shows the event within seconds.

Setup:
  pip install 'rubric[langchain]'
  # Create an enrollment token in the dashboard, then:
  export RUBRIC_ENROLLMENT_TOKEN=enr_...
  export RUBRIC_AGENT_NAME=quickstart-bot
  export RUBRIC_API_URL=https://api.rubric-app.com

Run:
  python examples/langchain_quickstart.py
"""

from __future__ import annotations

import argparse
import logging

from rubric import Governance
from rubric.adapters.langchain import GovernanceDeniedError, govern_tools

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def list_files(path: str) -> str:
    return f"[stub] would list files in {path}"


def delete_file(path: str) -> str:
    return f"[stub] deleted {path}"


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

    from langchain_core.tools import Tool

    raw_tools = [
        Tool(name="list_files", description="List files in a directory.", func=list_files),
        Tool(name="delete_file", description="Delete a file at a given path.", func=delete_file),
    ]

    with Governance.bootstrap(
        enrollment_token=args.enrollment_token,
        agent_name=args.agent_name,
        api_url=args.api_url,
    ) as gov:
        ready = gov.wait_until_ready(timeout=10.0)
        if not ready:
            print("warning: bundle did not load within 10s; proceeding (default-allow)")

        bundle = gov.current_bundle
        if bundle is None:
            print("no bundle published yet — publish a policy in the dashboard first")
        else:
            print(f"loaded bundle v{bundle.bundleVersion} with {len(bundle.policies)} policies")

        tools = govern_tools(gov, raw_tools, session_id="quickstart-session")

        print("\n→ calling list_files (expected: allow)")
        result = next(t for t in tools if t.name == "list_files").invoke({"path": "/tmp"})
        print(f"   result: {result}")

        print("\n→ calling delete_file (expected: deny if policy is published)")
        try:
            result = next(t for t in tools if t.name == "delete_file").invoke({"path": "/tmp/foo"})
            print(f"   result: {result}")
        except GovernanceDeniedError as e:
            print(f"   denied: {e}")

        print("\nFlushing audit events...")


if __name__ == "__main__":
    main()
