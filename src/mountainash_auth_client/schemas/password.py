"""Classic username + password authentication."""

from __future__ import annotations

import typing as t

from pydantic import SecretStr

from .base import AuthSpec

__all__ = ["PasswordAuth"]


class PasswordAuth(AuthSpec):
    """Username + password authentication."""

    kind: t.Literal["password"] = "password"
    username: str
    password: SecretStr
