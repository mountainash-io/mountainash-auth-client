"""OAuth2 client-credentials / token authentication."""
from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from .registry import register

__all__ = ["OAuth2AuthProfile", "OAUTH2_SPEC"]

OAUTH2_SPEC = ProfileSpec(
    name="oauth2",
    provider_type="oauth2",
    parameters=[
        ParameterSpec(name="CLIENT_ID", type=str | None, tier="core", driver_key="client_id", default=None),
        ParameterSpec(name="CLIENT_SECRET", type=str | None, tier="core", driver_key="client_secret", default=None, secret=True),
        ParameterSpec(name="TOKEN", type=str | None, tier="core", driver_key="token", default=None, secret=True),
        ParameterSpec(name="REFRESH_TOKEN", type=str | None, tier="advanced", default=None, secret=True),
        ParameterSpec(name="SERVER_URI", type=str | None, tier="advanced", default=None),
        ParameterSpec(name="SCOPE", type=str | None, tier="advanced", default=None),
    ],
)


@register
class OAuth2AuthProfile(Profile):
    __spec__ = OAUTH2_SPEC
