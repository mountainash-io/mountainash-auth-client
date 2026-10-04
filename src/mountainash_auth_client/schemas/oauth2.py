"""OAuth2 credential (client-credentials or authorization-code grant).

The grant flow is selected by the provider profile (oauth/providers/), not the
credential — so one credential class serves both. Carries client identity, the
access/refresh tokens, and the per-user requested SCOPE; the IdP coordinates
(AUTHORIZE_URL/TOKEN_URL/…) live on the provider profile.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from ..targets import TargetFamily
from .registry import register

if TYPE_CHECKING:
    from pydantic import SecretStr

__all__ = ["OAuth2AuthProfile", "OAUTH2_SPEC"]


def _bearer_from_access_token(profile, kw):
    """Render the current ``ACCESS_TOKEN`` as an HTTP Bearer header.

    Token acquisition/refresh is the flow's job; an empty/None token renders
    nothing (matches the resolver's truthiness on the unwrapped token).
    """
    token = profile.ACCESS_TOKEN.get_secret_value() if profile.ACCESS_TOKEN else None
    if not token:
        return kw
    headers = {**kw.get("headers", {}), "Authorization": f"Bearer {token}"}
    return {**kw, "headers": headers}


OAUTH2_SPEC = ProfileSpec(
    name="oauth2",
    provider_type="oauth2",
    parameters=[
        ParameterSpec(name="CLIENT_ID", type=str | None, tier="core", default=None),
        ParameterSpec(name="CLIENT_SECRET", type=str | None, tier="core", default=None, secret=True),
        ParameterSpec(name="ACCESS_TOKEN", type=str | None, tier="core", default=None, secret=True),
        ParameterSpec(name="REFRESH_TOKEN", type=str | None, tier="advanced", default=None, secret=True),
        ParameterSpec(name="SCOPE", type=str | None, tier="advanced", default=None),
    ],
)


@register
class OAuth2AuthProfile(Profile):
    if TYPE_CHECKING:
        CLIENT_ID: str | None
        CLIENT_SECRET: SecretStr | None
        ACCESS_TOKEN: SecretStr | None
        REFRESH_TOKEN: SecretStr | None
        SCOPE: str | None

    __spec__ = OAUTH2_SPEC
    __adapters__ = {TargetFamily.HTTP: _bearer_from_access_token}
