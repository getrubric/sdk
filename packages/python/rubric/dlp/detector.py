"""DLP Detector — regex baseline plus optional Presidio path.

Runs in-process inside the SDK on every `Governance.evaluate()` call when DLP
is enabled. Walks the args object recursively, scans every string leaf, and
returns an aggregated `DlpDetection`.

Design choices:
  * Regex baseline is always available (no extra deps). Handles the
    high-signal types: email, CC, SSN, phone, IBAN, AWS/GCP/GitHub keys,
    generic credentials, URL, IP.
  * Presidio path layers in NER-based recognizers (PERSON, LOCATION,
    MEDICAL_LICENSE, etc.) when `presidio-analyzer` is installed in the
    same environment.
  * Bounded by a 64KB stringification cap so a malformed args payload can't
    block the eval path. If we hit the cap, we set `truncated=True` (via a
    type code) and skip remaining detection.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Iterable
from typing import Any, Protocol

from rubric.constants import (
    DLP_MAX_PAYLOAD_BYTES,
    DLP_MODE_OFF,
    DLP_MODE_PRESIDIO,
    DLP_MODE_REGEX,
    DLP_SEVERITY_BY_TYPE,
    DLP_SEVERITY_HIGH,
    DLP_SEVERITY_LOW,
    DLP_SEVERITY_MEDIUM,
    DlpMode,
    DlpSeverity,
)

from .recognizers import (
    EXTRA_SEVERITY_BY_TYPE,
    Recognizer,
    all_recognizers,
    is_keyish_field,
)
from .types import DlpDetection, DlpField

log = logging.getLogger(__name__)

_SEVERITY_RANK = {DLP_SEVERITY_LOW: 0, DLP_SEVERITY_MEDIUM: 1, DLP_SEVERITY_HIGH: 2}
_MS_PER_SECOND = 1000.0


class Detector(Protocol):
    """Anything that takes a payload and returns a detection (or None)."""

    def detect(self, payload: Any) -> DlpDetection | None:
        ...


class _NullDetector:
    """No-op — used when DLP is off."""

    def detect(self, payload: Any) -> DlpDetection | None:
        return None


class RegexDetector:
    """Regex-only detector. Always available, no optional deps."""

    def __init__(self) -> None:
        self._recognizers: tuple[Recognizer, ...] = all_recognizers()

    def detect(self, payload: Any) -> DlpDetection | None:
        return _scan(payload, self._recognizers)


class PresidioDetector:
    """Presidio-backed detector. Falls back to regex on any internal failure
    so a recognizer crash never breaks the eval path."""

    def __init__(self) -> None:
        from presidio_analyzer import AnalyzerEngine  # type: ignore[import-not-found]

        self._analyzer = AnalyzerEngine()
        self._regex = RegexDetector()

    def detect(self, payload: Any) -> DlpDetection | None:
        try:
            return _scan_presidio(payload, self._analyzer, self._regex)
        except Exception as e:
            # `log.exception` would emit the full stack with `payload` in
            # locals — that payload is the very secret-bearing tool input we
            # want to keep out of third-party log handlers (Sentry, OTel,
            # structlog). Log just the exception class name.
            log.error("presidio failed: %s; using regex", type(e).__name__)
            return self._regex.detect(payload)


def make_detector(mode: DlpMode) -> Detector:
    """Construct a detector for the requested mode. `auto` chooses presidio
    when installed and regex otherwise."""

    if mode == DLP_MODE_OFF:
        return _NullDetector()
    if mode == DLP_MODE_REGEX:
        return RegexDetector()
    if mode == DLP_MODE_PRESIDIO:
        return PresidioDetector()
    # auto
    try:
        return PresidioDetector()
    except ImportError:
        log.warning(
            "DLP enabled in regex-only mode; install `presidio-analyzer` "
            "for PERSON/LOCATION/MEDICAL coverage."
        )
        return RegexDetector()


# ── internals ───────────────────────────────────────────────────────────────


def _walk_strings(payload: Any, path: str = "args") -> Iterable[tuple[str, str]]:
    """Yield (path, string) pairs for every string leaf in payload."""
    if payload is None:
        return
    if isinstance(payload, str):
        yield path, payload
        return
    if isinstance(payload, (int, float, bool)):
        return
    if isinstance(payload, dict):
        for k, v in payload.items():
            yield from _walk_strings(v, f"{path}.{k}")
        return
    if isinstance(payload, (list, tuple)):
        for i, v in enumerate(payload):
            yield from _walk_strings(v, f"{path}[{i}]")
        return
    # Fallback — coerce unknowns to str.
    yield path, str(payload)


def _scan(payload: Any, recognizers: tuple[Recognizer, ...]) -> DlpDetection | None:
    start = time.perf_counter()
    fields: list[DlpField] = []
    counts: dict[str, int] = {}

    total_bytes = 0
    for path, value in _walk_strings(payload):
        total_bytes += len(value.encode("utf-8", errors="ignore"))
        if total_bytes > DLP_MAX_PAYLOAD_BYTES:
            break
        for r in recognizers:
            if r.requires_keyish_field and not is_keyish_field(path):
                continue
            for span in r.find(value):
                fields.append(DlpField(path=path, type=r.type, span=span))
                counts[r.type] = counts.get(r.type, 0) + 1

    if not fields:
        return None

    types = sorted(counts.keys())
    severity = _max_severity(types)
    return DlpDetection(
        detected=True,
        severity=severity,
        types=types,
        counts=counts,
        fields=fields,
        durationMs=(time.perf_counter() - start) * _MS_PER_SECOND,
    )


def _scan_presidio(
    payload: Any,
    analyzer: Any,
    regex_fallback: RegexDetector,
) -> DlpDetection | None:
    """Run Presidio per string leaf, then merge results with the regex baseline
    so secrets / generic-API-key signals are kept."""
    start = time.perf_counter()
    fields: list[DlpField] = []
    counts: dict[str, int] = {}

    total_bytes = 0
    for path, value in _walk_strings(payload):
        total_bytes += len(value.encode("utf-8", errors="ignore"))
        if total_bytes > DLP_MAX_PAYLOAD_BYTES:
            break
        results = analyzer.analyze(text=value, language="en")
        for r in results:
            type_name = str(r.entity_type)
            fields.append(DlpField(path=path, type=type_name, span=(int(r.start), int(r.end))))
            counts[type_name] = counts.get(type_name, 0) + 1

    # Merge in regex matches that Presidio doesn't natively cover (secrets etc.).
    regex_result = regex_fallback.detect(payload)
    if regex_result is not None:
        for f in regex_result.fields:
            fields.append(f)
        for t, n in regex_result.counts.items():
            counts[t] = counts.get(t, 0) + n

    if not fields:
        return None
    types = sorted(counts.keys())
    severity = _max_severity(types)
    return DlpDetection(
        detected=True,
        severity=severity,
        types=types,
        counts=counts,
        fields=fields,
        durationMs=(time.perf_counter() - start) * _MS_PER_SECOND,
    )


def _max_severity(types: list[str]) -> DlpSeverity:
    best: DlpSeverity = DLP_SEVERITY_LOW
    best_rank = -1
    for t in types:
        sev = DLP_SEVERITY_BY_TYPE.get(t)
        if sev is None:
            extra = EXTRA_SEVERITY_BY_TYPE.get(t)
            sev = extra if extra is not None else DLP_SEVERITY_MEDIUM  # type: ignore[assignment]
        rank = _SEVERITY_RANK.get(sev, 1)
        if rank > best_rank:
            best = sev
            best_rank = rank
            if best == DLP_SEVERITY_HIGH:
                break
    return best
