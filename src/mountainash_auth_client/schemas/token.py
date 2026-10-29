"""Bearer-token and JWT authentication."""
from __future__ import annotations

import base64 as _b64
import json as _json
from typing import TYPE_CHECKING

from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from ..errors import MalformedJWTError
from ..targets import TargetFamily
from .registry import register

if TYPE_CHECKING:
    from pydantic import SecretStr

__all__ = ["TokenAuthProfile", "JWTAuthProfile", "TOKEN_SPEC", "JWT_SPEC"]


def _b64url_json(seg: str) -> dict:
    seg += "=" * (-len(seg) % 4)  # restore base64url padding
    return _json.loads(_b64.urlsafe_b64decode(seg))


def _decode_jwt_claims(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise MalformedJWTError(reason="expected three '.'-separated segments")
    try:
        _b64url_json(parts[0])  # header must decode too (spec: validate header + payload)
        return _b64url_json(parts[1])
    except (ValueError, TypeError) as exc:
        raise MalformedJWTError(reason=f"header/payload did not decode: {exc}") from exc


def _bearer_header(profile, kw):
    """Render the token as an HTTP ``Authorization: Bearer`` header.

    Matches the old ``resolve_auth_strategy`` truthiness: an empty token yields
    no header (the resolver fell through to NoAuth when the token was falsy).
    """
    token = profile.TOKEN.get_secret_value()
    if not token:
        return kw
    headers = {**kw.get("headers", {}), "Authorization": f"Bearer {token}"}
    return {**kw, "headers": headers}


TOKEN_SPEC = ProfileSpec(
    name="token",
    provider_type="token",
    parameters=[
        ParameterSpec(name="TOKEN", type=str, tier="core", secret=True),
    ],
)


@register
class TokenAuthProfile(Profile):
    if TYPE_CHECKING:
        TOKEN: SecretStr

    __spec__ = TOKEN_SPEC
    __adapters__ = {TargetFamily.HTTP: _bearer_header}


JWT_SPEC = ProfileSpec(
    name="jwt",
    provider_type="jwt",
    parameters=[
        ParameterSpec(name="TOKEN", type=str, tier="core", secret=True),
    ],
)


@register
class JWTAuthProfile(Profile):
    if TYPE_CHECKING:
        TOKEN: SecretStr

    __spec__ = JWT_SPEC
    __adapters__ = {TargetFamily.HTTP: _bearer_header}

    def claims(self) -> dict:
        return _decode_jwt_claims(self.TOKEN.get_secret_value())

    @property
    def exp(self) -> int | None:
        v = self.claims().get("exp")
        return int(v) if v is not None else None
