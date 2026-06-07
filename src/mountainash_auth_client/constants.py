"""Auth mode constants — canonical names for auth mode registry lookup."""

from __future__ import annotations

from enum import StrEnum

__all__ = ["CONST_AUTH_MODE"]


class CONST_AUTH_MODE(StrEnum):
    """Auth mode identifiers matching AUTH_REGISTRY keys."""

    NONE = "none"
    PASSWORD = "password"
    TOKEN = "token"
    JWT = "jwt"
    OAUTH1 = "oauth1"
    OAUTH2 = "oauth2"
    OAUTH2_AUTHCODE = "oauth2_authcode"
    IAM = "iam"
    AZURE_AD = "azure_ad"
    WINDOWS = "windows"
    KERBEROS = "kerberos"
    CERTIFICATE = "certificate"
    SERVICE_ACCOUNT = "service_account"
