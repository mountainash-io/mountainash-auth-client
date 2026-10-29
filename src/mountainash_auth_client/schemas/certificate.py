"""Private-key / certificate authentication (Snowflake JWT, SSH keys)."""
from __future__ import annotations

import io
from pathlib import Path
from typing import TYPE_CHECKING

from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from .._optional import require_paramiko
from ..targets import TargetFamily
from .registry import register

if TYPE_CHECKING:
    from pydantic import SecretStr

__all__ = ["CertificateAuthProfile", "CERTIFICATE_SPEC"]


def _parse_private_key(key_string: str, passphrase: str | None):
    """Parse a PEM/OpenSSH private key string into a paramiko PKey.

    Tries RSA, Ed25519, ECDSA, DSS in order; raises ``ValueError`` if none match.
    """
    paramiko = require_paramiko()
    for cls in (paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey):
        try:
            return cls.from_private_key(io.StringIO(key_string), password=passphrase)
        except paramiko.SSHException:
            continue
    raise ValueError("Could not parse private key: no supported key type matched.")


def _ssh_key(profile, kw):
    """Render PRIVATE_KEY_PATH (key_filename) or PRIVATE_KEY (parsed pkey).

    Fail-fast when neither is set, matching the old ``SSHKeyStrategy`` (which
    raised on construction with no key material). A certificate profile with no
    key would otherwise connect with no key auth silently.
    """
    passphrase = profile.PASSPHRASE.get_secret_value() if profile.PASSPHRASE else None
    if profile.PRIVATE_KEY_PATH is not None:
        out = {**kw, "key_filename": str(profile.PRIVATE_KEY_PATH)}
        if passphrase is not None:
            out["passphrase"] = passphrase
        return out
    if profile.PRIVATE_KEY is not None:
        pem = profile.PRIVATE_KEY.get_secret_value()
        return {**kw, "pkey": _parse_private_key(pem, passphrase)}
    raise ValueError(
        "CertificateAuthProfile requires PRIVATE_KEY_PATH or PRIVATE_KEY "
        "to emit PARAMIKO key auth."
    )


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
    if TYPE_CHECKING:
        PRIVATE_KEY: SecretStr | None
        PRIVATE_KEY_PATH: Path | None
        PASSPHRASE: SecretStr | None

    __spec__ = CERTIFICATE_SPEC
    __adapters__ = {TargetFamily.PARAMIKO: _ssh_key}
