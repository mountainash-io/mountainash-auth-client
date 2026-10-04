"""Google-style service-account authentication."""
from __future__ import annotations

import typing as t
from pathlib import Path
from typing import TYPE_CHECKING

from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from .registry import register

__all__ = ["ServiceAccountAuthProfile", "SERVICE_ACCOUNT_SPEC"]

SERVICE_ACCOUNT_SPEC = ProfileSpec(
    name="service_account",
    provider_type="service_account",
    parameters=[
        ParameterSpec(name="INFO", type=dict[str, t.Any] | None, tier="core", default=None),
        ParameterSpec(name="FILE", type=Path | None, tier="core", default=None),
    ],
)


@register
class ServiceAccountAuthProfile(Profile):
    if TYPE_CHECKING:
        INFO: dict[str, t.Any] | None
        FILE: Path | None

    __spec__ = SERVICE_ACCOUNT_SPEC
