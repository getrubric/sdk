"""SDK version (single source of truth).

Imported by both the package `__init__` and `client.py` so audit events can
report the SDK version without creating a circular import.
"""

from typing import Final

__version__: Final = "0.1.0"
