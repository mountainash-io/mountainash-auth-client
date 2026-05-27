"""Bearer-token and JWT authentication."""

from __future__ import annotations

import typing as t

from pydantic import SecretStr

from .base import AuthSpec

__all__ = ["TokenAuth", "JWTAuth"]


class TokenAuth(AuthSpec):
    """Opaque bearer token (e.g. MotherDuck, PyIceberg REST)."""

    kind: t.Literal["token"] = "token"
    token: SecretStr


class JWTAuth(AuthSpec):
    """JSON Web Token authentication (e.g. Trino)."""

    kind: t.Literal["jwt"] = "jwt"
    token: SecretStr
