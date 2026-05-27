"""Default mapping from AuthSpec instances to driver kwargs.

Backend adapters can override individual auth types by consulting this map or
by writing bespoke match statements. The defaults cover the common case.
"""

from __future__ import annotations

import typing as t

from .base import AuthSpec
from .iam import IAMAuth
from .none import NoAuth
from .oauth2 import OAuth2Auth
from .password import PasswordAuth
from .token import JWTAuth, TokenAuth

__all__ = ["AUTH_TO_DRIVER_KWARGS", "auth_to_driver_kwargs", "auth_kwargs"]


def _noauth(_auth: NoAuth) -> dict[str, t.Any]:
    return {}


def _password(auth: PasswordAuth) -> dict[str, t.Any]:
    return {
        "user": auth.username,
        "password": auth.password.get_secret_value(),
    }


def _token(auth: TokenAuth) -> dict[str, t.Any]:
    return {"token": auth.token.get_secret_value()}


def _jwt(auth: JWTAuth) -> dict[str, t.Any]:
    return {"token": auth.token.get_secret_value()}


def _oauth2(auth: OAuth2Auth) -> dict[str, t.Any]:
    if auth.token is not None:
        return {"token": auth.token.get_secret_value()}
    if auth.client_id is not None and auth.client_secret is not None:
        return {"credential": f"{auth.client_id}:{auth.client_secret.get_secret_value()}"}
    return {}


def _iam(auth: IAMAuth) -> dict[str, t.Any]:
    """Empty dict means 'use ambient AWS credentials' (env vars, instance profile, SSO)."""
    out: dict[str, t.Any] = {}
    if auth.role_arn is not None:
        out["iam_role_arn"] = auth.role_arn
    if auth.access_key_id is not None:
        out["aws_access_key_id"] = auth.access_key_id
    if auth.secret_access_key is not None:
        out["aws_secret_access_key"] = auth.secret_access_key.get_secret_value()
    if auth.session_token is not None:
        out["aws_session_token"] = auth.session_token.get_secret_value()
    return out


AUTH_TO_DRIVER_KWARGS: dict[type[AuthSpec], t.Callable[[t.Any], dict[str, t.Any]]] = {
    NoAuth: _noauth,
    PasswordAuth: _password,
    TokenAuth: _token,
    JWTAuth: _jwt,
    OAuth2Auth: _oauth2,
    IAMAuth: _iam,
    # WindowsAuth, AzureADAuth, KerberosAuth, ServiceAccountAuth, CertificateAuth:
    # no sensible default — their respective backend adapters handle mapping.
}


def auth_to_driver_kwargs(auth: AuthSpec) -> dict[str, t.Any]:
    """Look up the default mapper for ``auth`` and produce driver kwargs.

    Raises:
        KeyError: if no mapper is registered for ``type(auth)``.
    """
    return AUTH_TO_DRIVER_KWARGS[type(auth)](auth)


def auth_kwargs(profile: object) -> dict[str, t.Any]:
    """Extract auth kwargs from any object with an optional .auth attribute."""
    auth = getattr(profile, "auth", None)
    if auth is None:
        return {}
    return auth_to_driver_kwargs(auth)
