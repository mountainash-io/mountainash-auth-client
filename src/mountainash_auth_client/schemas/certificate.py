"""Private-key / certificate authentication (Snowflake JWT)."""
from pathlib import Path

from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from .registry import register

__all__ = ["CertificateAuthProfile", "CERTIFICATE_SPEC"]

CERTIFICATE_SPEC = ProfileSpec(
    name="certificate",
    provider_type="certificate",
    parameters=[
        ParameterSpec(name="PRIVATE_KEY", type=str | None, tier="core", default=None, secret=True),
        ParameterSpec(name="PRIVATE_KEY_PATH", type=Path | None, tier="core", default=None),
        ParameterSpec(name="PASSPHRASE", type=str | None, tier="advanced", default=None, secret=True),
    ],
)


@register
class CertificateAuthProfile(Profile):
    __spec__ = CERTIFICATE_SPEC
