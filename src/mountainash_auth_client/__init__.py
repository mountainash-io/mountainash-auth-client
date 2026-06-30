"""mountainash-auth-client — client-side authentication for the mountainash ecosystem."""
from __future__ import annotations

import importlib

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
from mountainash_auth_client.schemas import (
    AUTH_REGISTRY,
    AzureADAuthProfile,
    CertificateAuthProfile,
    IAMAuthProfile,
    JWTAuthProfile,
    KerberosAuthProfile,
    NoAuthProfile,
    OAuth1AuthProfile,
    OAuth2AuthProfile,
    PasswordAuthProfile,
    ServiceAccountAuthProfile,
    TokenAuthProfile,
    WindowsAuthProfile,
)

# Lazy (PEP 562) re-exports for the OAuth ops layer. These names stay exported but resolve
# on first attribute access, so `import mountainash_auth_client` / `import …schemas` never
# pulls in httpx/authlib/paramiko/oauth. Keep this map and __all__ in sync.
_LAZY = {
    "OAuthFlow": "mountainash_auth_client.oauth.oauth2.flow",
    "OAuth2Connection": "mountainash_auth_client.oauth.oauth2.connection",
    "OAuth1Flow": "mountainash_auth_client.oauth.oauth1.flow",
    "OAuth1Connection": "mountainash_auth_client.oauth.oauth1.connection",
    "LocalCallbackServer": "mountainash_auth_client.oauth.server.callback",
    "ManualCallbackServer": "mountainash_auth_client.oauth.server.manual",
    "CallbackServerFactory": "mountainash_auth_client.oauth.protocols",
    "CallbackServerProtocol": "mountainash_auth_client.oauth.protocols",
    "PersistableAuthProfile": "mountainash_auth_client.oauth.persistence",
    "OAuth1ProviderProfile": "mountainash_auth_client.oauth.providers",
    "OAuth1ProviderProfileProtocol": "mountainash_auth_client.oauth.providers",
    "OAuth2ProviderProfile": "mountainash_auth_client.oauth.providers",
    "OAuth2ProviderProfileProtocol": "mountainash_auth_client.oauth.providers",
    "ProviderProfileProtocol": "mountainash_auth_client.oauth.providers",
    "OAuth1TokenManager": "mountainash_auth_client.oauth.lifecycle",
    "OAuth2TokenManager": "mountainash_auth_client.oauth.lifecycle",
    "TokenState": "mountainash_auth_client.oauth.lifecycle",
    "TokenStatus": "mountainash_auth_client.oauth.lifecycle",
}


def __getattr__(name: str):
    """Resolve OAuth-side public names lazily (PEP 562)."""
    module = _LAZY.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    return getattr(importlib.import_module(module), name)


def __dir__() -> list[str]:
    return sorted(__all__)


AuthProfile = (
    NoAuthProfile | PasswordAuthProfile | TokenAuthProfile | JWTAuthProfile
    | OAuth1AuthProfile | OAuth2AuthProfile
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
