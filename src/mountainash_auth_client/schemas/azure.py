"""Microsoft-centric authentication: Windows integrated + Azure AD."""
from __future__ import annotations

from typing import TYPE_CHECKING

from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from .registry import register

if TYPE_CHECKING:
    from pydantic import SecretStr

__all__ = ["WindowsAuthProfile", "AzureADAuthProfile", "WINDOWS_SPEC", "AZURE_AD_SPEC"]

WINDOWS_SPEC = ProfileSpec(
    name="windows",
    provider_type="windows",
    parameters=[
        ParameterSpec(name="USERNAME", type=str | None, tier="core", default=None),
        ParameterSpec(name="DOMAIN", type=str | None, tier="core", default=None),
    ],
)


@register
class WindowsAuthProfile(Profile):
    if TYPE_CHECKING:
        USERNAME: str | None
        DOMAIN: str | None

    __spec__ = WINDOWS_SPEC


AZURE_AD_SPEC = ProfileSpec(
    name="azure_ad",
    provider_type="azure_ad",
    parameters=[
        ParameterSpec(name="TENANT_ID", type=str | None, tier="core", default=None),
        ParameterSpec(name="CLIENT_ID", type=str | None, tier="core", default=None),
        ParameterSpec(name="CLIENT_SECRET", type=str | None, tier="core", default=None, secret=True),
        ParameterSpec(name="MANAGED_IDENTITY", type=bool, tier="advanced", default=False),
        ParameterSpec(name="MSI_ENDPOINT", type=str | None, tier="advanced", default=None),
    ],
)


@register
class AzureADAuthProfile(Profile):
    if TYPE_CHECKING:
        TENANT_ID: str | None
        CLIENT_ID: str | None
        CLIENT_SECRET: SecretStr | None
        MANAGED_IDENTITY: bool
        MSI_ENDPOINT: str | None

    __spec__ = AZURE_AD_SPEC
