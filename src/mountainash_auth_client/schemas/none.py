"""The 'no authentication' variant."""

from __future__ import annotations

import typing as t

from .base import AuthSpec

__all__ = ["NoAuth"]


class NoAuth(AuthSpec):
    """No authentication required (SQLite, DuckDB, PySpark)."""

    kind: t.Literal["none"] = "none"
