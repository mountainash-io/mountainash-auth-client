"""Kerberos / GSSAPI authentication."""
from pathlib import Path

from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from .registry import register

__all__ = ["KerberosAuth", "KERBEROS_SPEC"]

KERBEROS_SPEC = ProfileSpec(
    name="kerberos",
    provider_type="kerberos",
    parameters=[
        ParameterSpec(name="SERVICE_NAME", type=str, tier="core", default="postgres"),
        ParameterSpec(name="PRINCIPAL", type=str | None, tier="core", default=None),
        ParameterSpec(name="KEYTAB", type=Path | None, tier="advanced", default=None),
    ],
)


@register
class KerberosAuth(Profile):
    __spec__ = KERBEROS_SPEC
