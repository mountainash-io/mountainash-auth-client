"""AWS IAM authentication."""

from __future__ import annotations

import typing as t

from pydantic import SecretStr

from .base import AuthSpec

__all__ = ["IAMAuth"]


class IAMAuth(AuthSpec):
    """AWS IAM credentials (Redshift, S3-backed catalogs)."""

    kind: t.Literal["iam"] = "iam"
    role_arn: str | None = None
    access_key_id: str | None = None
    secret_access_key: SecretStr | None = None
    session_token: SecretStr | None = None
    profile_name: str | None = None
