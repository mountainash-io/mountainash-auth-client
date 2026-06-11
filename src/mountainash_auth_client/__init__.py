"""mountainash-auth-client — client-side authentication for the mountainash ecosystem."""
from mountainash_auth_client.constants import CONST_AUTH_PROFILES
from mountainash_auth_client.errors import (
    AuthorizationRequired,
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

AuthProfile = (
    NoAuthProfile | PasswordAuthProfile | TokenAuthProfile | JWTAuthProfile
    | OAuth1AuthProfile | OAuth2AuthProfile | OAuth2AuthCodeAuthProfile
    | IAMAuthProfile | WindowsAuthProfile | AzureADAuthProfile
    | KerberosAuthProfile | CertificateAuthProfile | ServiceAccountAuthProfile
)

__all__ = [
    "AUTH_REGISTRY",
    "AuthProfile",
    "AuthorizationRequired",
    "AzureADAuthProfile",
    "CONST_AUTH_PROFILES",
    "CertificateAuthProfile",
    "IAMAuthProfile",
    "JWTAuthProfile",
    "KerberosAuthProfile",
    "LocalCallbackServer",
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
