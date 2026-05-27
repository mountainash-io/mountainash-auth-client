"""Kerberos / GSSAPI authentication."""

from __future__ import annotations

import typing as t
from pathlib import Path

from .base import AuthSpec

__all__ = ["KerberosAuth"]


class KerberosAuth(AuthSpec):
    """Kerberos authentication (Trino, PostgreSQL via GSS)."""

    kind: t.Literal["kerberos"] = "kerberos"
    service_name: str = "postgres"
    principal: str | None = None
    keytab: Path | None = None
