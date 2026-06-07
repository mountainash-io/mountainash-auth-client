"""OAuth 2.0 Authorization Code grant authentication."""
from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from .registry import register

__all__ = ["OAuth2AuthCodeAuth", "OAUTH2_AUTHCODE_SPEC"]

OAUTH2_AUTHCODE_SPEC = ProfileSpec(
    name="oauth2_authcode",
    provider_type="oauth2_authcode",
    parameters=[
        ParameterSpec(name="CLIENT_ID", type=str, tier="core", driver_key="client_id"),
        ParameterSpec(name="CLIENT_SECRET", type=str, tier="core", driver_key="client_secret", secret=True),
        ParameterSpec(name="ACCESS_TOKEN", type=str | None, tier="core", driver_key="access_token", default=None, secret=True),
        ParameterSpec(name="REFRESH_TOKEN", type=str | None, tier="core", driver_key="refresh_token", default=None, secret=True),
        ParameterSpec(name="TOKEN_EXPIRES_AT", type=int | None, tier="advanced", default=None),
        ParameterSpec(name="SCOPE", type=str | None, tier="advanced", default=None),
    ],
)


@register
class OAuth2AuthCodeAuth(Profile):
    __spec__ = OAUTH2_AUTHCODE_SPEC
