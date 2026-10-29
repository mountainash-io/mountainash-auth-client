"""Classic username + password authentication."""
from __future__ import annotations

import base64
from typing import TYPE_CHECKING

from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from ..targets import TargetFamily
from .registry import register

if TYPE_CHECKING:
    from pydantic import SecretStr

__all__ = ["PasswordAuthProfile", "PASSWORD_SPEC"]


def _basic_header(profile, kw):
    """Render USERNAME/PASSWORD as an HTTP Basic ``Authorization`` header."""
    raw = f"{profile.USERNAME}:{profile.PASSWORD.get_secret_value()}".encode()
    token = base64.b64encode(raw).decode()
    headers = {**kw.get("headers", {}), "Authorization": f"Basic {token}"}
    return {**kw, "headers": headers}


PASSWORD_SPEC = ProfileSpec(
    name="password",
    provider_type="password",
    parameters=[
        ParameterSpec(
            name="USERNAME",
            type=str,
            tier="core",
            driver_key={TargetFamily.PARAMIKO: "username"},
        ),
        ParameterSpec(
            name="PASSWORD",
            type=str,
            tier="core",
            secret=True,
            driver_key={TargetFamily.PARAMIKO: "password"},
        ),
    ],
)


@register
class PasswordAuthProfile(Profile):
    if TYPE_CHECKING:
        USERNAME: str
        PASSWORD: SecretStr

    __spec__ = PASSWORD_SPEC
    __adapters__ = {TargetFamily.HTTP: _basic_header}
