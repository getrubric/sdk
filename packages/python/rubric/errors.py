"""RFC 9457 (Problem Details for HTTP APIs) types and exceptions.

The Rubric API returns errors as `application/problem+json` per RFC 9457.
We parse those bodies into a typed `ProblemDetails` model and raise
`GovernanceProblemError` so callers can branch on `problem.type` instead of
parsing strings.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx
import pydantic
from pydantic import BaseModel, ConfigDict

from rubric.constants import CONTENT_TYPE_PROBLEM_JSON, HTTP_HEADER_CONTENT_TYPE

log = logging.getLogger(__name__)


class ProblemDetails(BaseModel):
    """RFC 9457 Problem Details object.

    Standard members are typed; extension members are preserved via
    `extra="allow"` so callers can read e.g. `problem.errors` on a policy
    validation failure.
    """

    model_config = ConfigDict(extra="allow")

    type: str
    title: str
    status: int
    detail: str | None = None
    instance: str | None = None


class GovernanceError(Exception):
    """Base class for SDK errors."""


class GovernanceProblemError(GovernanceError):
    """Raised when the Rubric API returns a Problem Details response."""

    def __init__(self, problem: ProblemDetails) -> None:
        super().__init__(f"{problem.title} ({problem.status}): {problem.detail or ''}")
        self.problem = problem


def parse_problem_details(response: httpx.Response) -> ProblemDetails | None:
    """Best-effort parse of an httpx Response body as a ProblemDetails object.

    Returns None when the response is not application/problem+json or the body
    cannot be parsed; the caller decides how to surface the underlying failure.
    """
    content_type = response.headers.get(HTTP_HEADER_CONTENT_TYPE, "")
    if not content_type.startswith(CONTENT_TYPE_PROBLEM_JSON):
        return None
    try:
        payload: Any = response.json()
    except (json.JSONDecodeError, ValueError):
        return None
    try:
        return ProblemDetails.model_validate(payload)
    except (json.JSONDecodeError, pydantic.ValidationError) as e:
        # Narrowed from `except Exception` so server schema drift surfaces in
        # verbose logs rather than being swallowed silently. Anything that
        # isn't a JSON / Pydantic parse failure propagates to the caller.
        log.debug("problem-details parse failed: %s", type(e).__name__)
        return None
