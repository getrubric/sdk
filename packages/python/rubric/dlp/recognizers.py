"""Regex recognizers used by both the regex-only baseline and the Presidio path.

Each recognizer is a (type, compiled_pattern, optional field-name guard). The
Presidio path adds its own NER-driven recognizers on top — these stay shared
because they cover the highest-signal types (PII basics + secrets).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Pattern

# `regex` (PyPI) is API-compatible with stdlib `re` but adds a `timeout=`
# kwarg that aborts a single match with `TimeoutError` once the budget is
# exceeded. The policy evaluator already uses it for exactly this reason
# (see `evaluator._matches`); DLP recognizers run on the same hot path and
# over untrusted tool input, so they use it the same way to bound time spent
# matching. It is already a hard dependency (see pyproject.toml) — no new dep
# is added.
import regex as re

from rubric.constants import (
    DLP_KEYISH_FIELD_PATTERN,
    DLP_TYPE_AWS_ACCESS_KEY,
    DLP_TYPE_CREDIT_CARD,
    DLP_TYPE_EMAIL,
    DLP_TYPE_GCP_API_KEY,
    DLP_TYPE_GENERIC_API_KEY,
    DLP_TYPE_GITHUB_TOKEN,
    DLP_TYPE_IBAN_CODE,
    DLP_TYPE_IP_ADDRESS,
    DLP_TYPE_PHONE,
    DLP_TYPE_URL,
    DLP_TYPE_US_SSN,
)

# Transport-shape secret types used by the scrubber. Kept local to this
# module (rather than in constants.py) because they don't have a shared
# schema counterpart.
_DLP_TYPE_JWT = "JWT"
_DLP_TYPE_BEARER_TOKEN = "BEARER_TOKEN"
_DLP_TYPE_POSTGRES_URL = "POSTGRES_URL"
_DLP_TYPE_OPENAI_API_KEY = "OPENAI_API_KEY"
_DLP_TYPE_SLACK_TOKEN = "SLACK_TOKEN"
_DLP_TYPE_HEX64_TOKEN = "HEX64_TOKEN"


log = logging.getLogger(__name__)

# Per-string wall-clock budget for a single recognizer's scan. Matches the
# evaluator's `_MATCH_TIMEOUT_SECONDS` — generous for any well-formed
# pattern over the (already 64KB-capped) payload, but bounds the time spent
# matching untrusted input. On timeout the recognizer yields no spans (treated
# as "did not detect" for that recognizer/string) rather than hanging the
# evaluate path; the per-call DLP signal in `client._run_dlp` still covers a
# detector-level crash.
DLP_MATCH_TIMEOUT_SECONDS = 0.5


@dataclass(frozen=True)
class Recognizer:
    type: str
    pattern: Pattern[str]
    requires_keyish_field: bool = False

    def find(self, value: str) -> list[tuple[int, int]]:
        try:
            return [
                m.span()
                for m in self.pattern.finditer(value, timeout=DLP_MATCH_TIMEOUT_SECONDS)
            ]
        except TimeoutError:
            log.warning(
                "DLP recognizer exceeded per-string timeout; treating as no-match "
                "(type=%s)",
                self.type,
            )
            return []


# Recognizers that match by content alone.
_PII_RECOGNIZERS: tuple[Recognizer, ...] = (
    Recognizer(
        type=DLP_TYPE_EMAIL,
        pattern=re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"),
    ),
    Recognizer(
        # Credit cards — 13–19 digits, optionally hyphen/space-separated. Doesn't
        # validate the Luhn checksum; v1 accepts false positives over misses.
        type=DLP_TYPE_CREDIT_CARD,
        pattern=re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    ),
    Recognizer(
        type=DLP_TYPE_US_SSN,
        pattern=re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    ),
    Recognizer(
        type=DLP_TYPE_PHONE,
        pattern=re.compile(
            r"\b(?:\+?1[ -.]?)?(?:\(?\d{3}\)?[ -.]?)\d{3}[ -.]?\d{4}\b"
        ),
    ),
    Recognizer(
        type=DLP_TYPE_IBAN_CODE,
        pattern=re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b"),
    ),
    Recognizer(
        type=DLP_TYPE_AWS_ACCESS_KEY,
        pattern=re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ),
    Recognizer(
        type=DLP_TYPE_GCP_API_KEY,
        pattern=re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ),
    Recognizer(
        type=DLP_TYPE_GITHUB_TOKEN,
        pattern=re.compile(
            r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{82})\b"
        ),
    ),
    Recognizer(
        type=DLP_TYPE_URL,
        pattern=re.compile(r"\bhttps?://[^\s<>\"]+"),
    ),
    Recognizer(
        type=DLP_TYPE_IP_ADDRESS,
        pattern=re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    ),
    # JWT triplet — three base64url segments joined by `.`. Matches before
    # the keyish/generic catch-all so a single token is reported as one
    # detection rather than three separate fragments.
    Recognizer(
        type=_DLP_TYPE_JWT,
        pattern=re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    ),
    # `Authorization: Bearer …` headers leaking through error messages.
    Recognizer(
        type=_DLP_TYPE_BEARER_TOKEN,
        pattern=re.compile(r"Bearer\s+\S+"),
    ),
    # Postgres connection strings with embedded credentials.
    Recognizer(
        type=_DLP_TYPE_POSTGRES_URL,
        pattern=re.compile(r"postgres(?:ql)?://[^@\s:]+:[^@\s]+@"),
    ),
    # OpenAI API keys.
    Recognizer(
        type=_DLP_TYPE_OPENAI_API_KEY,
        pattern=re.compile(r"sk-[A-Za-z0-9]{20,}"),
    ),
    # Slack bot/user/personal/refresh tokens — `xoxb-`, `xoxa-`, `xoxp-`,
    # `xoxr-`, `xoxs-`.
    Recognizer(
        type=_DLP_TYPE_SLACK_TOKEN,
        pattern=re.compile(r"xox[abprs]-[A-Za-z0-9-]+"),
    ),
    # 64-char lowercase hex — matches the daemon-issued token shape used by
    # the Claude Code adapter and similar transports.
    Recognizer(
        type=_DLP_TYPE_HEX64_TOKEN,
        pattern=re.compile(r"\b[a-f0-9]{64}\b"),
    ),
)

# Recognizers that only fire when the surrounding field name looks like a key.
_KEYISH_RECOGNIZERS: tuple[Recognizer, ...] = (
    Recognizer(
        type=DLP_TYPE_GENERIC_API_KEY,
        # Hex / base64 string ≥ 32 chars. Confidence comes from the field-name
        # guard (the `requires_keyish_field` flag).
        pattern=re.compile(r"\b[A-Za-z0-9+/_\-]{32,}={0,2}\b"),
        requires_keyish_field=True,
    ),
)

KEYISH_FIELD_RE = re.compile(DLP_KEYISH_FIELD_PATTERN, re.IGNORECASE)

# Severity overrides for recognizer-local types that aren't in
# `constants.DLP_SEVERITY_BY_TYPE`. The detector consults this table before
# falling back to the constants map / `MEDIUM` default.
EXTRA_SEVERITY_BY_TYPE: dict[str, str] = {
    _DLP_TYPE_JWT: "high",
    _DLP_TYPE_BEARER_TOKEN: "high",
    _DLP_TYPE_POSTGRES_URL: "high",
    _DLP_TYPE_OPENAI_API_KEY: "high",
    _DLP_TYPE_SLACK_TOKEN: "high",
    _DLP_TYPE_HEX64_TOKEN: "high",
}


def all_recognizers() -> tuple[Recognizer, ...]:
    return _PII_RECOGNIZERS + _KEYISH_RECOGNIZERS


def is_keyish_field(field_path: str) -> bool:
    """Whether a JSON path's leaf-most segment hints at a credential."""
    leaf = field_path.rsplit(".", 1)[-1]
    return bool(KEYISH_FIELD_RE.search(leaf))
