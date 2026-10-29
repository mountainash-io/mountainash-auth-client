"""Google-style service-account authentication."""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import SecretStr
from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from .registry import register

__all__ = ["ServiceAccountAuthProfile", "SERVICE_ACCOUNT_SPEC"]

SERVICE_ACCOUNT_SPEC = ProfileSpec(
    name="service_account",
    provider_type="service_account",
    parameters=[
        ParameterSpec(name="INFO", type=str | None, tier="core", default=None, secret=True),
        ParameterSpec(name="FILE", type=Path | None, tier="core", default=None),
    ],
)


@register
class ServiceAccountAuthProfile(Profile):
    if TYPE_CHECKING:
        INFO: SecretStr | None
        FILE: Path | None

    __spec__ = SERVICE_ACCOUNT_SPEC
