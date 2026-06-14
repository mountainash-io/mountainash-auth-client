"""OAuth1 provider coordinates — typed, validated Profile (not an auth mode)."""
from __future__ import annotations

from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from ..targets import TargetFamily
from .oauth2 import _provider_http_kwargs

__all__ = ["OAuth1ProviderProfile", "OAUTH1_PROVIDER_PARAMS", "OAUTH1_PROVIDER_SPEC"]


OAUTH1_PROVIDER_PARAMS = [
    ParameterSpec(name="NAME", type=str, tier="core"),
    ParameterSpec(name="REQUEST_TOKEN_URL", type=str, tier="core"),
    ParameterSpec(name="AUTHORIZE_URL", type=str, tier="core"),
    ParameterSpec(name="ACCESS_TOKEN_URL", type=str, tier="core"),
    ParameterSpec(name="BASE_URL", type=str, tier="core"),
    ParameterSpec(name="CALLBACK_PORT", type=int | None, tier="advanced", default=None),
]


OAUTH1_PROVIDER_SPEC = ProfileSpec(
    name="oauth1_provider",
    provider_type="oauth1_provider",
    parameters=OAUTH1_PROVIDER_PARAMS,
)


class OAuth1ProviderProfile(Profile):
    __spec__ = OAUTH1_PROVIDER_SPEC
    __adapters__ = {TargetFamily.HTTP: _provider_http_kwargs}
