"""OAuth 1.0a authentication."""
from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from ..connections._optional import require_authlib
from ..targets import TargetFamily
from .registry import register

__all__ = ["OAuth1AuthProfile", "OAUTH1_SPEC"]


def _oauth1_signer(profile, kw):
    """Build an authlib ``OAuth1Auth`` signer under httpx's ``auth=`` kwarg."""
    OAuth1Auth = require_authlib("OAuth1Auth")
    return {
        **kw,
        "auth": OAuth1Auth(
            client_id=profile.CONSUMER_KEY,
            client_secret=profile.CONSUMER_SECRET.get_secret_value(),
            token=profile.ACCESS_TOKEN.get_secret_value() if profile.ACCESS_TOKEN else None,
            token_secret=profile.ACCESS_TOKEN_SECRET.get_secret_value() if profile.ACCESS_TOKEN_SECRET else None,
        ),
    }


OAUTH1_SPEC = ProfileSpec(
    name="oauth1",
    provider_type="oauth1",
    parameters=[
        ParameterSpec(name="CONSUMER_KEY", type=str, tier="core"),
        ParameterSpec(name="CONSUMER_SECRET", type=str, tier="core", secret=True),
        ParameterSpec(name="ACCESS_TOKEN", type=str | None, tier="core", default=None, secret=True),
        ParameterSpec(name="ACCESS_TOKEN_SECRET", type=str | None, tier="core", default=None, secret=True),
    ],
)


@register
class OAuth1AuthProfile(Profile):
    __spec__ = OAUTH1_SPEC
    __adapters__ = {TargetFamily.HTTP: _oauth1_signer}
