"""The 'no authentication' variant."""
from mountainash_settings import Profile, ProfileSpec

from .registry import register

__all__ = ["NoAuthProfile", "NOAUTH_SPEC"]

NOAUTH_SPEC = ProfileSpec(
    name="none",
    provider_type="none",
    parameters=[],
)


@register
class NoAuthProfile(Profile):
    __spec__ = NOAUTH_SPEC
