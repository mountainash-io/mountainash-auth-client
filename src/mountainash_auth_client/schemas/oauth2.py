"""OAuth2 client-credentials / token authentication."""

from __future__ import annotations

import typing as t

from pydantic import SecretStr

from .base import AuthSpec

__all__ = ["OAuth2Auth"]


class OAuth2Auth(AuthSpec):
    """OAuth2 credential set (Snowflake, Trino, PyIceberg REST)."""

    kind: t.Literal["oauth2"] = "oauth2"
    client_id: str | None = None
    client_secret: SecretStr | None = None
    token: SecretStr | None = None
    refresh_token: SecretStr | None = None
    server_uri: str | None = None
    scope: str | None = None
