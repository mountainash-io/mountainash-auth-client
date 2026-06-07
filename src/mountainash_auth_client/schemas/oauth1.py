"""OAuth 1.0a authentication."""
from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from .registry import register

__all__ = ["OAuth1Auth", "OAUTH1_SPEC"]

OAUTH1_SPEC = ProfileSpec(
    name="oauth1",
    provider_type="oauth1",
    parameters=[
        ParameterSpec(name="CONSUMER_KEY", type=str, tier="core", driver_key="consumer_key"),
        ParameterSpec(name="CONSUMER_SECRET", type=str, tier="core", driver_key="consumer_secret", secret=True),
        ParameterSpec(name="ACCESS_TOKEN", type=str | None, tier="core", default=None, secret=True),
        ParameterSpec(name="ACCESS_TOKEN_SECRET", type=str | None, tier="core", default=None, secret=True),
    ],
)


@register
class OAuth1Auth(Profile):
    __spec__ = OAUTH1_SPEC
