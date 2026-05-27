"""OAuth 1.0a authentication."""

from __future__ import annotations

import typing as t

from pydantic import SecretStr

from .base import AuthSpec

__all__ = ["OAuth1Auth"]


class OAuth1Auth(AuthSpec):
    """OAuth 1.0a credentials and tokens."""

    kind: t.Literal["oauth1"] = "oauth1"
    consumer_key: str
    consumer_secret: SecretStr
    access_token: SecretStr | None = None
    access_token_secret: SecretStr | None = None
