"""OAuth 2.0 Authorization Code grant authentication."""
from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from ..targets import TargetFamily
from .registry import register

__all__ = ["OAuth2AuthCodeAuthProfile", "OAUTH2_AUTHCODE_SPEC"]


def _bearer_from_access_token(profile, kw):
    """Render the *current* access token as a Bearer header (have-a-token case).

    Token acquisition/refresh is the flow's job, not emission; when no access
    token is present (None or empty) this renders nothing — matching the old
    resolver's truthiness on the unwrapped token.
    """
    token = profile.ACCESS_TOKEN.get_secret_value() if profile.ACCESS_TOKEN else None
    if not token:
        return kw
    headers = {**kw.get("headers", {}), "Authorization": f"Bearer {token}"}
    return {**kw, "headers": headers}


OAUTH2_AUTHCODE_SPEC = ProfileSpec(
    name="oauth2_authcode",
    provider_type="oauth2_authcode",
    parameters=[
        ParameterSpec(name="CLIENT_ID", type=str, tier="core"),
        ParameterSpec(name="CLIENT_SECRET", type=str, tier="core", secret=True),
        ParameterSpec(name="ACCESS_TOKEN", type=str | None, tier="core", default=None, secret=True),
        ParameterSpec(name="REFRESH_TOKEN", type=str | None, tier="core", default=None, secret=True),
        ParameterSpec(name="TOKEN_EXPIRES_AT", type=int | None, tier="advanced", default=None),
        ParameterSpec(name="SCOPE", type=str | None, tier="advanced", default=None),
    ],
)


@register
class OAuth2AuthCodeAuthProfile(Profile):
    __spec__ = OAUTH2_AUTHCODE_SPEC
    __adapters__ = {TargetFamily.HTTP: _bearer_from_access_token}
