"""Classic username + password authentication."""
from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from .registry import register

__all__ = ["PasswordAuthProfile", "PASSWORD_SPEC"]

PASSWORD_SPEC = ProfileSpec(
    name="password",
    provider_type="password",
    parameters=[
        ParameterSpec(
            name="USERNAME",
            type=str,
            tier="core",
            driver_key="user",
        ),
        ParameterSpec(
            name="PASSWORD",
            type=str,
            tier="core",
            driver_key="password",
            secret=True,
        ),
    ],
)


@register
class PasswordAuthProfile(Profile):
    __spec__ = PASSWORD_SPEC
