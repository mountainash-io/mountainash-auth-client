"""Google-style service-account authentication."""

from __future__ import annotations

import typing as t
from pathlib import Path

from .base import AuthSpec

__all__ = ["ServiceAccountAuth"]


class ServiceAccountAuth(AuthSpec):
    """Google Cloud service-account key (JSON dict or file path)."""

    kind: t.Literal["service_account"] = "service_account"
    info: dict[str, t.Any] | None = None
    file: Path | None = None
