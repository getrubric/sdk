"""DLP detection result types."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from rubric.constants import DlpSeverity


class DlpField(BaseModel):
    """One detection occurrence: where it landed, what type, and the span
    inside that field's stringified value."""

    model_config = ConfigDict(extra="forbid")

    path: str = Field(min_length=1, max_length=256)
    type: str = Field(min_length=1, max_length=64)
    span: tuple[int, int] | None = None


class DlpDetection(BaseModel):
    """Aggregated detection result for a single tool call's args payload."""

    model_config = ConfigDict(extra="forbid")

    detected: bool
    severity: DlpSeverity = "low"
    types: list[str] = Field(default_factory=list)
    counts: dict[str, int] = Field(default_factory=dict)
    fields: list[DlpField] = Field(default_factory=list)
    durationMs: float = Field(ge=0, default=0.0)


__all__ = ["DlpDetection", "DlpField"]
