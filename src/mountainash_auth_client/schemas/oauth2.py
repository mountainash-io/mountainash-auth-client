"""OAuth2 client-credentials / token authentication."""
from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from ..targets import TargetFamily
from .registry import register

__all__ = ["OAuth2AuthProfile", "OAUTH2_SPEC"]


def _bearer_from_token(profile, kw):
    """Render the current ``TOKEN`` as an HTTP Bearer header (have-a-token case).

    Token acquisition via client credentials is the flow's job; an empty/None
    token renders nothing (matches the old resolver's truthiness).
    """
    token = profile.TOKEN.get_secret_value() if profile.TOKEN else None
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
        ParameterSpec(name="TOKEN", type=str | None, tier="core", default=None, secret=True),
        ParameterSpec(name="REFRESH_TOKEN", type=str | None, tier="advanced", default=None, secret=True),
        ParameterSpec(name="SERVER_URI", type=str | None, tier="advanced", default=None),
        ParameterSpec(name="SCOPE", type=str | None, tier="advanced", default=None),
    ],
)


@register
class OAuth2AuthProfile(Profile):
    __spec__ = OAUTH2_SPEC
    __adapters__ = {TargetFamily.HTTP: _bearer_from_token}
