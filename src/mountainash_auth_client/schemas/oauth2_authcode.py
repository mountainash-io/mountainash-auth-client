"""OAuth 2.0 Authorization Code grant authentication."""

from __future__ import annotations

import typing as t

from pydantic import SecretStr

from .base import AuthSpec

__all__ = ["OAuth2AuthCodeAuth"]


class OAuth2AuthCodeAuth(AuthSpec):
    """OAuth 2.0 Authorization Code grant credentials and tokens."""

    kind: t.Literal["oauth2_authcode"] = "oauth2_authcode"
    client_id: str
    client_secret: SecretStr
    access_token: SecretStr | None = None
    refresh_token: SecretStr | None = None
    token_expires_at: int | None = None
    scope: str | None = None
