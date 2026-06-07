"""The 'no authentication' variant."""
from mountainash_settings import Profile, ProfileSpec

from .registry import register

__all__ = ["NoAuth", "NOAUTH_SPEC"]

NOAUTH_SPEC = ProfileSpec(
    name="none",
    provider_type="none",
    parameters=[],
)


@register
class NoAuth(Profile):
    __spec__ = NOAUTH_SPEC
