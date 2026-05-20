"""The decorator-style quickstart — the shortest possible governed agent.

Setup:
  pip install rubric-app
  # Create an enrollment token in the dashboard, then:
  export RUBRIC_ENROLLMENT_TOKEN=enr_...
  export RUBRIC_API_URL=https://api.rubric-app.com

Run:
  python examples/decorator_quickstart.py
"""

from __future__ import annotations

import logging

import rubric

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")


# 1. Bootstrap once at process startup. Reads RUBRIC_ENROLLMENT_TOKEN from env.
rubric.init(agent_name="decorator-quickstart")


# 2. Decorate any function. The decorator runs evaluate() before invoking
#    the function and raises GovernanceDeniedError if the policy denies it.
@rubric.tool
def list_files(path: str) -> str:
    return f"(would list files in {path})"


@rubric.tool
def delete_file(path: str) -> str:
    return f"(would delete {path})"


# 3. Optional: group calls under an explicit session so the audit log can
#    filter by conversation. Default session is "default".
def main() -> None:
    with rubric.session("demo-session"):
        # This call should be allowed (no policy targets list_files by default).
        print("→ list_files(/tmp):", list_files("/tmp"))

        # This call hits a policy if you've published the deny-destructive-fs
        # template. Catch the deny like any other exception.
        try:
            print("→ delete_file(/tmp/foo):", delete_file("/tmp/foo"))
        except rubric.GovernanceDeniedError as e:
            print(f"→ delete_file blocked: {e}")


if __name__ == "__main__":
    main()
    # Process exit triggers the atexit hook that flushes the audit sink.
