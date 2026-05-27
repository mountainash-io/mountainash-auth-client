"""Private-key / certificate authentication (Snowflake JWT)."""

from __future__ import annotations

import typing as t
from pathlib import Path

from pydantic import SecretStr

from .base import AuthSpec

__all__ = ["CertificateAuth"]


class CertificateAuth(AuthSpec):
    """Private-key signed JWT authentication (Snowflake)."""

    kind: t.Literal["certificate"] = "certificate"
    private_key: SecretStr | None = None
    private_key_path: Path | None = None
    passphrase: SecretStr | None = None
