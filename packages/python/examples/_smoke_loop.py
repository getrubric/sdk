"""Throwaway: drive traffic into a running Rubric instance via the SDK.

Boots one Governance instance per --agents, then loops calling evaluate()
on a small pool of tools (some safe, some likely-denied) at --rate per second.
"""

from __future__ import annotations

import argparse
import logging
import os
import random
import threading
import time

from rubric import Governance
from rubric.trace import (
    AssistantMessage,
    ToolResultMessage,
    TraceContext,
    UserMessage,
)
from rubric.types import EvaluationMetadata

log = logging.getLogger("smoke")

TOOLS = [
    "list_files",
    "read_file",
    "search",
    "delete_file",
    "shell.exec",
    "email.send",
    "db.write",
    "git.push",
]

USER_PROMPTS = [
    "Could you list the files in /tmp for me?",
    "I think we need to clean up some old logs.",
    "Pull the latest from main and check the deploy script.",
    "Send Alice the quarterly numbers — her email is alice@example.com.",
    "Drop the staging users table; we'll repopulate it.",
    "Search the codebase for TODO comments older than 90 days.",
]
ASSISTANT_REPLIES = [
    "Sure — let me start by inspecting the directory.",
    "I'll need to run a quick check first.",
    "Got it. Reaching for the right tool now.",
    "Before I do that, let me read the config.",
]
SAMPLE_ARGS = [
    {"path": "/tmp"},
    {"query": "TODO"},
    {"recipient": "alice@example.com", "subject": "Q3 numbers"},
    {"path": "/var/log/old.log"},
    {"sql": "DROP TABLE staging_users;"},
    {"command": "rm -rf /tmp/cache"},
]


def run_one_agent(agent_name: str, rate_per_sec: float, stop: threading.Event) -> None:
    log.info("agent %s booting", agent_name)
    with Governance.bootstrap(agent_name=agent_name) as gov:
        ready = gov.wait_until_ready(timeout=8.0)
        log.info(
            "agent %s ready=%s bundle=%s",
            agent_name,
            ready,
            gov.current_bundle.bundleVersion if gov.current_bundle else None,
        )
        session_id = f"smoke-{agent_name}-{int(time.time())}"
        # Build a running TraceContext per session so the dashboard's drawer
        # has something to show when the user clicks into an audit row.
        trace = TraceContext()
        trace.append(UserMessage(content=random.choice(USER_PROMPTS)))
        trace.append(AssistantMessage(content=random.choice(ASSISTANT_REPLIES)))
        i = 0
        sleep_between = 1.0 / max(rate_per_sec, 0.1)
        while not stop.is_set():
            tool = random.choice(TOOLS)
            args = random.choice(SAMPLE_ARGS)
            try:
                result = gov.evaluate(
                    tool,
                    session_id=session_id,
                    metadata=EvaluationMetadata(input=args),
                    trace=trace,
                )
                # Append a fake tool_result so the trace keeps growing — the SDK
                # already appended the imminent tool_call inside evaluate().
                if result.decision == "allow":
                    trace.append(
                        ToolResultMessage(
                            content=f"[stub] result of {tool}",
                            isError=False,
                        )
                    )
                else:
                    trace.append(
                        ToolResultMessage(
                            content=f"denied by policy: {result.reason or 'no reason'}",
                            isError=True,
                        )
                    )
                # Occasionally add a fresh assistant turn so traces don't grow
                # without bound and look like a real conversation.
                if i > 0 and i % 8 == 0:
                    trace.append(AssistantMessage(content=random.choice(ASSISTANT_REPLIES)))
                    trace.append(UserMessage(content=random.choice(USER_PROMPTS)))
                if i % 10 == 0:
                    log.info(
                        "%s #%d %s -> %s (%s)",
                        agent_name,
                        i,
                        tool,
                        result.decision,
                        result.matchedPolicyId or "no-match",
                    )
            except Exception as e:
                log.warning("%s eval error: %s", agent_name, e)
            i += 1
            stop.wait(sleep_between)
    log.info("agent %s stopped after %d evals", agent_name, i)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--agents", type=int, default=2)
    parser.add_argument("--rate", type=float, default=2.0, help="evals/sec per agent")
    parser.add_argument("--duration", type=float, default=120.0, help="seconds")
    args = parser.parse_args()

    if not os.environ.get("RUBRIC_ENROLLMENT_TOKEN"):
        raise SystemExit("set RUBRIC_ENROLLMENT_TOKEN")
    if not os.environ.get("RUBRIC_API_URL"):
        os.environ["RUBRIC_API_URL"] = "https://api.rubric-app.com"

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    stop = threading.Event()
    threads: list[threading.Thread] = []
    for n in range(args.agents):
        agent_name = f"smoke-bot-{n + 1}"
        # Each thread picks up RUBRIC_AGENT_NAME via the call signature, not env.
        t = threading.Thread(
            target=run_one_agent,
            args=(agent_name, args.rate, stop),
            daemon=True,
            name=f"agent-{n + 1}",
        )
        t.start()
        threads.append(t)

    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        pass
    finally:
        log.info("stopping all agents")
        stop.set()
        for t in threads:
            t.join(timeout=5.0)


if __name__ == "__main__":
    main()
