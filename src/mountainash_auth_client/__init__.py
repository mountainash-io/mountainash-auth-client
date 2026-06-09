"""mountainash-auth-client — client-side authentication for the mountainash ecosystem."""
from mountainash_auth_client.constants import CONST_AUTH_MODE
from mountainash_auth_client.errors import (
    AuthorizationRequired,
    TokenExchangeError,
    TokenRefreshError,
)
from mountainash_auth_client.flows.oauth2 import OAuthFlow
from mountainash_auth_client.mixins.oauth2 import OAuth2ConnectionMixin
from mountainash_auth_client.schemas import (
    AUTH_REGISTRY,
    AzureADAuth,
    CertificateAuth,
    IAMAuth,
    JWTAuth,
    KerberosAuth,
    NoAuth,
    OAuth1Auth,
    OAuth2Auth,
    OAuth2AuthCodeAuth,
    PasswordAuth,
    ServiceAccountAuth,
    TokenAuth,
    WindowsAuth,
)
from mountainash_auth_client.server.callback import LocalCallbackServer

AuthProfile = (
    NoAuth | PasswordAuth | TokenAuth | JWTAuth | OAuth1Auth | OAuth2Auth
    | OAuth2AuthCodeAuth | IAMAuth | WindowsAuth | AzureADAuth
    | KerberosAuth | CertificateAuth | ServiceAccountAuth
)

__all__ = [
    "AUTH_REGISTRY",
    "AuthProfile",
    "AuthorizationRequired",
    "AzureADAuth",
    "CONST_AUTH_MODE",
    "CertificateAuth",
    "IAMAuth",
    "JWTAuth",
    "KerberosAuth",
    "LocalCallbackServer",
    "NoAuth",
    "OAuth1Auth",
    "OAuth2Auth",
    "OAuth2AuthCodeAuth",
    "OAuth2ConnectionMixin",
    "OAuthFlow",
    "PasswordAuth",
    "ServiceAccountAuth",
    "TokenAuth",
    "TokenExchangeError",
    "TokenRefreshError",
    "WindowsAuth",
]
