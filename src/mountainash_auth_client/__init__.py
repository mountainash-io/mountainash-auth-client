"""mountainash-auth-client — client-side authentication for the mountainash ecosystem."""
from mountainash_auth_client.constants import CONST_AUTH_PROFILES
from mountainash_auth_client.errors import (
    AuthorizationDeniedError,
    AuthorizationRequired,
    CallbackError,
    CallbackTimeoutError,
    MalformedCallbackError,
    TokenExchangeError,
    TokenRefreshError,
)
from mountainash_auth_client.connections.oauth2.flow import OAuthFlow
from mountainash_auth_client.connections.oauth2.connection import OAuth2Connection
from mountainash_auth_client.schemas import (
    AUTH_REGISTRY,
    AzureADAuthProfile,
    CertificateAuthProfile,
    IAMAuthProfile,
    JWTAuthProfile,
    KerberosAuthProfile,
    NoAuthProfile,
    OAuth1AuthProfile,
    OAuth2AuthCodeAuthProfile,
    OAuth2AuthProfile,
    PasswordAuthProfile,
    ServiceAccountAuthProfile,
    TokenAuthProfile,
    WindowsAuthProfile,
)
from mountainash_auth_client.connections.server.callback import LocalCallbackServer
from mountainash_auth_client.connections.protocols import CallbackServerProtocol
from mountainash_auth_client.connections.server.manual import ManualCallbackServer

AuthProfile = (
    NoAuthProfile | PasswordAuthProfile | TokenAuthProfile | JWTAuthProfile
    | OAuth1AuthProfile | OAuth2AuthProfile | OAuth2AuthCodeAuthProfile
    | IAMAuthProfile | WindowsAuthProfile | AzureADAuthProfile
    | KerberosAuthProfile | CertificateAuthProfile | ServiceAccountAuthProfile
)

__all__ = [
    "AUTH_REGISTRY",
    "AuthProfile",
    "AuthorizationDeniedError",
    "AuthorizationRequired",
    "AzureADAuthProfile",
    "CONST_AUTH_PROFILES",
    "CallbackError",
    "CallbackServerProtocol",
    "CallbackTimeoutError",
    "CertificateAuthProfile",
    "IAMAuthProfile",
    "JWTAuthProfile",
    "KerberosAuthProfile",
    "LocalCallbackServer",
    "MalformedCallbackError",
    "ManualCallbackServer",
    "NoAuthProfile",
    "OAuth1AuthProfile",
    "OAuth2AuthCodeAuthProfile",
    "OAuth2AuthProfile",
    "OAuth2Connection",
    "OAuthFlow",
    "PasswordAuthProfile",
    "ServiceAccountAuthProfile",
    "TokenAuthProfile",
    "TokenExchangeError",
    "TokenRefreshError",
    "WindowsAuthProfile",
]
