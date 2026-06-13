"""Bearer-token and JWT authentication."""
from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from ..targets import TargetFamily
from .registry import register

__all__ = ["TokenAuthProfile", "JWTAuthProfile", "TOKEN_SPEC", "JWT_SPEC"]


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
    __spec__ = JWT_SPEC
    __adapters__ = {TargetFamily.HTTP: _bearer_header}
