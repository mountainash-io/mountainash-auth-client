"""Kerberos / GSSAPI authentication."""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from ..targets import TargetFamily
from .registry import register

__all__ = ["KerberosAuthProfile", "KERBEROS_SPEC"]


def _gss_flags(profile, kw):
    """Render paramiko GSS/Kerberos connect flags.

    Mirrors the old ``SSHKerberosStrategy(gss_host=SERVICE_NAME)``: enable
    ``gss_auth`` and set ``gss_host`` from SERVICE_NAME (gss_kex stays off).
    """
    out = {**kw, "gss_auth": True}
    if profile.SERVICE_NAME is not None:
        out["gss_host"] = profile.SERVICE_NAME
    return out


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
class KerberosAuthProfile(Profile):
    if TYPE_CHECKING:
        SERVICE_NAME: str
        PRINCIPAL: str | None
        KEYTAB: Path | None

    __spec__ = KERBEROS_SPEC
    __adapters__ = {TargetFamily.PARAMIKO: _gss_flags}
