# Internal helpers shared across `rubric` modules. The underscore-prefixed
# filename signals that callers consume these at their own risk — the
# surface is exposed via top-level imports for adapter packages but is not
# covered by the public semver contract.
"""Secret-scrubbing utilities for log lines, error messages, and outbound
audit/trace payloads.

The pattern set and pattern ordering are load-bearing — see the inline
comments before each `_RE` constant for the rationale. Module-level
pre-compiled `re.Pattern` objects keep the regex engine work to import
time, not every audit event.

In addition to `scrub_secrets()`, this module exposes:

* `scrub_deep()` — recursive walker over dict/list/tuple/str leaves with an
  `id()`-keyed cycle guard. Used by the audit pipeline to scrub structured
  metadata payloads before they leave the host.
* `err_message()` / `err_code()` — equivalents of Node's `errMessage` and
  `errCode`, for safely interpolating caught exceptions into log messages.
"""

from __future__ import annotations

import re
from typing import Any

__all__ = [
    "scrub_secrets",
    "scrub_deep",
    "err_message",
    "err_code",
]


# ---- scrub_secrets ---------------------------------------------------------
#
# Patterns are intentionally conservative — false-positive redactions are
# cheap (you just lose a chunk of an error message); false-negatives (a real
# secret leaking into a log line or a daemon error message) are not.
#
# Order matters in a few places:
#   * JWT must run before the generic base64-ish catch-all so the
#     dot-separated triplet is collapsed into one `<redacted:jwt>` token
#     rather than three separate `<redacted:blob>` tokens.
#   * Bearer must run before the generic base64-ish catch-all so the
#     literal `Bearer ` prefix is preserved in the redacted output
#     (useful for ops triage).
#   * postgres:// URLs must run before the catch-all so the URL shape
#     (`postgres://<redacted>@host/db`) is still recognizable in logs.
#
# Patterns are anchored with `\b` where the surrounding character class
# allows; we deliberately do NOT anchor on `^…$` because the input is
# typically an error message with secrets embedded mid-string.

_JWT_RE: re.Pattern[str] = re.compile(
    r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
)
_BEARER_RE: re.Pattern[str] = re.compile(
    r"Bearer\s+[A-Za-z0-9._\-=+/]{16,}"
)
_POSTGRES_URL_RE: re.Pattern[str] = re.compile(
    r"postgres(?:ql)?://[^@\s]+:[^@\s]+@"
)
_HEX64_RE: re.Pattern[str] = re.compile(r"\b[a-f0-9]{64}\b")
# Catches generic base64url / base64-ish blobs. Kept last because the more
# specific patterns above produce more useful redactions.
_BASE64ISH_RE: re.Pattern[str] = re.compile(r"\b[A-Za-z0-9+/_-]{24,}={0,2}\b")

_PROVIDER_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"xox[bpas]-[A-Za-z0-9-]{20,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\benr_[A-Za-z0-9_-]+"),
)

_REDACTED_JWT: str = "<redacted:jwt>"
_REDACTED_BEARER: str = "Bearer <redacted>"
_REDACTED_SECRET: str = "<redacted:secret>"
_REDACTED_HEX64: str = "<redacted:hex64>"
_REDACTED_BLOB: str = "<redacted:blob>"
_REDACTED_CYCLE: str = "<redacted:cycle>"


def _postgres_sub(match: re.Match[str]) -> str:
    """Preserve the URL scheme (`postgres` vs `postgresql`) so the shape is
    still recognizable in the redacted output."""
    scheme = "postgresql" if match.group(0).startswith("postgresql") else "postgres"
    return f"{scheme}://<redacted>@"


def scrub_secrets(s: str) -> str:
    """Replace likely secrets in ``s`` with ``<redacted:…>`` markers.

    Designed for interpolation into error messages and log lines.

    Patterns covered (in priority order):

    * JWT triplets — ``eyJ…\\.eyJ…\\.…``
    * ``Authorization: Bearer …`` headers — preserves the literal
      ``Bearer`` prefix
    * Postgres URLs with embedded credentials — ``postgres(ql)?://user:pw@host``
      becomes ``postgres(ql)?://<redacted>@host``
    * Provider-shape API keys: ``sk-…``, ``ghp_…``, ``xox[bpas]-…``,
      AWS ``AKIA…``, Rubric enrollment tokens ``enr_…``
    * Daemon-shape 64-char lowercase hex tokens
    * Generic base64url-ish blobs of ≥ 24 chars (last-resort catch-all)

    Running the output back through ``scrub_secrets`` is a no-op (idempotent
    on its own output for the common cases).
    """
    if not s:
        return s
    out = s
    out = _JWT_RE.sub(_REDACTED_JWT, out)
    out = _BEARER_RE.sub(_REDACTED_BEARER, out)
    out = _POSTGRES_URL_RE.sub(_postgres_sub, out)
    for pattern in _PROVIDER_PATTERNS:
        out = pattern.sub(_REDACTED_SECRET, out)
    out = _HEX64_RE.sub(_REDACTED_HEX64, out)
    out = _BASE64ISH_RE.sub(_REDACTED_BLOB, out)
    return out


# ---- scrub_deep ------------------------------------------------------------


def scrub_deep(value: Any) -> Any:
    """Recursively walk ``value``, applying ``scrub_secrets()`` to every
    string leaf.

    Handles ``dict``, ``list``, ``tuple``, and ``str``; other types are
    returned unchanged. Cycle-safe via an ``id()``-keyed seen set
    (``dict`` and ``list`` aren't hashable, so identity-based tracking
    is required). Self-referential nodes are replaced with
    ``"<redacted:cycle>"``.

    Used by the audit pipeline to scrub structured metadata payloads
    before they leave the host.
    """
    return _scrub_deep(value, set())


def _scrub_deep(value: Any, seen: set[int]) -> Any:
    if isinstance(value, str):
        return scrub_secrets(value)
    if isinstance(value, (dict, list, tuple)):
        node_id = id(value)
        if node_id in seen:
            return _REDACTED_CYCLE
        seen.add(node_id)
        try:
            if isinstance(value, dict):
                return {k: _scrub_deep(v, seen) for k, v in value.items()}
            if isinstance(value, list):
                return [_scrub_deep(v, seen) for v in value]
            # tuple
            return tuple(_scrub_deep(v, seen) for v in value)
        finally:
            seen.discard(node_id)
    return value


# ---- err_message / err_code ------------------------------------------------


def err_message(err: BaseException) -> str:
    """Return a human-readable message from a caught exception.

    Equivalent of Node's ``errMessage``. Falls back to ``str(err)`` so the
    caller never has to worry about the exception type.
    """
    try:
        return str(err)
    except Exception:  # pragma: no cover — defensive against broken __str__
        return repr(err)


def err_code(err: BaseException) -> str | None:
    """Return ``err.code`` if it's a string, else ``None``.

    Equivalent of Node's ``errCode``. Useful for ``OSError``-style exceptions
    where ``code`` carries values like ``'ENOENT'`` or ``'EPERM'``. Note that
    ``OSError.errno`` is an ``int``, not a ``str`` — callers wanting the
    numeric errno should read it directly.
    """
    code = getattr(err, "code", None)
    return code if isinstance(code, str) else None
