"""DLP recognizers run with a per-string wall-clock timeout.

The DLP recognizers scan untrusted tool input on the evaluate hot path, so
each match is bounded via the `regex` module's `timeout=` (the same mechanism
the policy evaluator uses). These tests assert (a) normal detection is
unchanged and (b) a pathological-input pattern is bounded rather than hanging.
"""

from __future__ import annotations

import time

import regex

from rubric.dlp.detector import RegexDetector
from rubric.dlp.recognizers import DLP_MATCH_TIMEOUT_SECONDS, Recognizer


def test_normal_detection_unchanged() -> None:
    d = RegexDetector()
    result = d.detect(
        {
            "input": {
                "note": "email bob@example.com or call 415-555-1234",
                "key": "AKIAIOSFODNN7EXAMPLE",
            }
        }
    )
    assert result is not None
    assert set(result.types) == {"EMAIL_ADDRESS", "PHONE_NUMBER", "AWS_ACCESS_KEY"}
    assert result.severity == "high"


def test_clean_payload_returns_none() -> None:
    d = RegexDetector()
    assert d.detect({"input": {"note": "nothing sensitive here"}}) is None


def test_recognizer_bounds_pathological_input() -> None:
    # A nested-quantifier pattern that blows up the engine against a long
    # all-`x` string with no terminating `y`. Without the timeout this hangs;
    # with it, `find` returns [] within roughly the budget.
    bomb = Recognizer(type="BOMB", pattern=regex.compile(r"(x+x+)+y"))
    payload = "x" * 5000

    start = time.perf_counter()
    spans = bomb.find(payload)
    elapsed = time.perf_counter() - start

    assert spans == []  # timed out → treated as no-match
    # Generous ceiling: the per-string budget plus scheduling slack.
    assert elapsed < DLP_MATCH_TIMEOUT_SECONDS + 1.0


def test_recognizer_still_matches_within_budget() -> None:
    # A normal pattern over a normal string completes well under budget and
    # returns the expected span.
    r = Recognizer(type="DIGITS", pattern=regex.compile(r"\d{3}-\d{2}-\d{4}"))
    spans = r.find("ssn 123-45-6789 end")
    assert len(spans) == 1
