"""Client-certificate and private-key authentication for HTTP and SSH."""
from __future__ import annotations

import io
import os
import ssl
import tempfile
from contextlib import ExitStack
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import certifi

from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from .._optional import require_paramiko
from .._safe_errors import raise_safe, safe_detail
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


def _http_context(verify: object, trust_env: bool) -> ssl.SSLContext:
    """Select consumer trust without modifying a caller-owned context."""
    if isinstance(verify, ssl.SSLContext):
        raise TypeError("HTTP verify requires a fresh-context factory, not an existing SSLContext")
    if callable(verify):
        try:
            context = verify()
        except Exception:
            raise_safe(ValueError("HTTP TLS context factory failed"))
        if not isinstance(context, ssl.SSLContext):
            raise TypeError("HTTP TLS context factory must return SSLContext")
        return context
    if verify is False:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    if isinstance(verify, str):
        if os.path.isdir(verify):
            return ssl.create_default_context(capath=verify)
        return ssl.create_default_context(cafile=verify)
    if verify is not True:
        raise TypeError("HTTP verify requires a bool, CA path, or fresh-context factory")
    if trust_env and os.environ.get("SSL_CERT_FILE"):
        return ssl.create_default_context(cafile=os.environ["SSL_CERT_FILE"])
    if trust_env and os.environ.get("SSL_CERT_DIR"):
        return ssl.create_default_context(capath=os.environ["SSL_CERT_DIR"])
    return ssl.create_default_context(cafile=certifi.where())


def _http_certificate(value: Profile, kw: dict[str, Any]) -> dict[str, Any]:
    """Load client identity before handing the context to the consumer."""
    profile = cast(CertificateAuthProfile, value)
    try:
        context = _http_context(kw.get("verify", True), kw.get("trust_env", True))
        with ExitStack() as resources:
            directory: str | None = None

            def source(path: Path | None, secret: SecretStr | None) -> str | None:
                nonlocal directory
                if path is not None:
                    return str(path)
                if secret is None:
                    return None
                if directory is None:
                    directory = resources.enter_context(tempfile.TemporaryDirectory())
                fd, filename = tempfile.mkstemp(dir=directory)
                try:
                    stream = os.fdopen(fd, "w", encoding="utf-8")
                except BaseException:
                    os.close(fd)
                    raise
                with stream:
                    stream.write(secret.get_secret_value())
                return filename

            certfile = source(profile.CERTIFICATE_PATH, profile.CERTIFICATE)
            if certfile is None:
                raise ValueError("HTTP client identity requires CERTIFICATE_PATH or CERTIFICATE")
            keyfile = source(profile.PRIVATE_KEY_PATH, profile.PRIVATE_KEY)
            password = profile.PASSPHRASE.get_secret_value() if profile.PASSPHRASE is not None else ""
            context.load_cert_chain(certfile, keyfile, password=password)
    except (OSError, ValueError) as error:
        raise_safe(ValueError(f"HTTP client certificate loading failed: {safe_detail(error)}"), error)
    out = dict(kw)
    out.pop("cert", None)
    out["verify"] = context
    return out


CERTIFICATE_SPEC = ProfileSpec(
    name="certificate",
    provider_type="certificate",
    parameters=[
        ParameterSpec(name="CERTIFICATE", type=str | None, tier="core", default=None, secret=True),
        ParameterSpec(name="CERTIFICATE_PATH", type=Path | None, tier="core", default=None),
        ParameterSpec(name="PRIVATE_KEY", type=str | None, tier="core", default=None, secret=True),
        ParameterSpec(name="PRIVATE_KEY_PATH", type=Path | None, tier="core", default=None),
        ParameterSpec(name="PASSPHRASE", type=str | None, tier="advanced", default=None, secret=True),
    ],
)


@register
class CertificateAuthProfile(Profile):
    if TYPE_CHECKING:
        CERTIFICATE: SecretStr | None
        CERTIFICATE_PATH: Path | None
        PRIVATE_KEY: SecretStr | None
        PRIVATE_KEY_PATH: Path | None
        PASSPHRASE: SecretStr | None

    __spec__ = CERTIFICATE_SPEC
    __adapters__ = {TargetFamily.PARAMIKO: _ssh_key, TargetFamily.HTTP: _http_certificate}
