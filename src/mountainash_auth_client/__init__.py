"""mountainash-auth-client — client-side authentication for the mountainash ecosystem."""
from mountainash_auth_client.constants import CONST_AUTH_PROFILES
from mountainash_auth_client.targets import TargetFamily
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
from mountainash_auth_client.connections.oauth1.flow import OAuth1Flow
from mountainash_auth_client.connections.oauth1.connection import OAuth1Connection
from mountainash_auth_client.providers import (
    OAuth1ProviderProfile,
    OAuth1ProviderProfileProtocol,
    OAuth2ProviderProfile,
    OAuth2ProviderProfileProtocol,
    ProviderProfileProtocol,
)
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
from mountainash_auth_client.connections.protocols import (
    CallbackServerFactory,
    CallbackServerProtocol,
)
from mountainash_auth_client.connections.server.manual import ManualCallbackServer
from mountainash_auth_client.persistence import PersistableAuthProfile
from mountainash_auth_client.lifecycle import (
    OAuth1TokenManager,
    OAuth2TokenManager,
    TokenState,
    TokenStatus,
)

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
    "CallbackServerFactory",
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
    "OAuth1Connection",
    "OAuth1Flow",
    "OAuth1ProviderProfile",
    "OAuth1ProviderProfileProtocol",
    "OAuth1TokenManager",
    "OAuth2AuthCodeAuthProfile",
    "OAuth2AuthProfile",
    "OAuth2Connection",
    "OAuth2ProviderProfile",
    "OAuth2ProviderProfileProtocol",
    "OAuth2TokenManager",
    "OAuthFlow",
    "PasswordAuthProfile",
    "PersistableAuthProfile",
    "ProviderProfileProtocol",
    "ServiceAccountAuthProfile",
    "TargetFamily",
    "TokenAuthProfile",
    "TokenExchangeError",
    "TokenRefreshError",
    "TokenState",
    "TokenStatus",
    "WindowsAuthProfile",
]
