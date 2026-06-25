"""OAuth2 provider coordinates — a typed, validated Profile (not an auth mode).

auth-client ships this *schema*; clients instantiate it with their provider's
*values*. There is no provider registry: there are infinitely many providers,
so provider data lives with the client, not here.
"""
from __future__ import annotations

from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from ..targets import TargetFamily

__all__ = ["OAuth2ProviderProfile", "OAUTH2_PROVIDER_PARAMS", "OAUTH2_PROVIDER_SPEC"]


OAUTH2_PROVIDER_PARAMS = [
    ParameterSpec(name="NAME", type=str, tier="core"),            # provider identity for error labels/logging
    ParameterSpec(name="AUTHORIZE_URL", type=str, tier="core"),
    ParameterSpec(name="TOKEN_URL", type=str, tier="core"),
    ParameterSpec(name="BASE_URL", type=str, tier="core"),        # resource API root
    ParameterSpec(name="DEFAULT_SCOPE", type=str | None, tier="advanced", default=None),
    ParameterSpec(name="USE_PKCE", type=bool, tier="advanced", default=False),
    ParameterSpec(name="CALLBACK_PORT", type=int | None, tier="advanced", default=None),
    ParameterSpec(name="TOKEN_ENDPOINT_AUTH_METHOD", type=str, tier="advanced", default="client_secret_post"),
    ParameterSpec(name="TOKEN_REQUEST_HEADERS", type=dict | None, tier="advanced", default=None),
    ParameterSpec(name="TOKEN_REQUEST_CONTENT_TYPE", type=str, tier="advanced", default="application/x-www-form-urlencoded"),
]


def _provider_http_kwargs(profile, kw):
    """Emit the resource-client config (base_url + future httpx knobs)."""
    return {**kw, "base_url": profile.BASE_URL}


OAUTH2_PROVIDER_SPEC = ProfileSpec(
    name="oauth2_provider",
    provider_type="oauth2_provider",
    parameters=OAUTH2_PROVIDER_PARAMS,
)


class OAuth2ProviderProfile(Profile):
    __spec__ = OAUTH2_PROVIDER_SPEC
    __adapters__ = {TargetFamily.HTTP: _provider_http_kwargs}
