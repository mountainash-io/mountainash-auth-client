"""Bearer-token and JWT authentication."""
from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from .registry import register

__all__ = ["TokenAuth", "JWTAuth", "TOKEN_SPEC", "JWT_SPEC"]

TOKEN_SPEC = ProfileSpec(
    name="token",
    provider_type="token",
    parameters=[
        ParameterSpec(name="TOKEN", type=str, tier="core", driver_key="token", secret=True),
    ],
)


@register
class TokenAuth(Profile):
    __spec__ = TOKEN_SPEC


JWT_SPEC = ProfileSpec(
    name="jwt",
    provider_type="jwt",
    parameters=[
        ParameterSpec(name="TOKEN", type=str, tier="core", driver_key="token", secret=True),
    ],
)


@register
class JWTAuth(Profile):
    __spec__ = JWT_SPEC
