"""Microsoft-centric authentication: Windows integrated + Azure AD."""

from __future__ import annotations

import typing as t

from pydantic import SecretStr

from .base import AuthSpec

__all__ = ["WindowsAuth", "AzureADAuth"]


class WindowsAuth(AuthSpec):
    """Integrated Windows authentication (MSSQL)."""

    kind: t.Literal["windows"] = "windows"
    username: str | None = None
    domain: str | None = None


class AzureADAuth(AuthSpec):
    """Azure Active Directory authentication (MSSQL)."""

    kind: t.Literal["azure_ad"] = "azure_ad"
    tenant_id: str | None = None
    client_id: str | None = None
    client_secret: SecretStr | None = None
    managed_identity: bool = False
    msi_endpoint: str | None = None
