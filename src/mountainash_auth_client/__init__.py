"""mountainash-auth-client — client-side authentication for the mountainash ecosystem."""
from __future__ import annotations

import importlib
from typing import TYPE_CHECKING

from mountainash_auth_client.constants import CONST_AUTH_PROFILES
from mountainash_auth_client.targets import TargetFamily
from mountainash_auth_client.errors import (
    AuthorizationCancelled,
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

if TYPE_CHECKING:
    from mountainash_auth_client.oauth.lifecycle import (
        OAuth1TokenManager as OAuth1TokenManager,
        OAuth2TokenManager as OAuth2TokenManager,
        TokenState as TokenState,
        TokenStatus as TokenStatus,
    )
    from mountainash_auth_client.oauth.lifecycle.credential import (
        SignOutResult as SignOutResult,
        TokenCredential as TokenCredential,
    )
    from mountainash_auth_client.oauth.lifecycle.oauth2 import OAuthFlowFactory as OAuthFlowFactory
    from mountainash_auth_client.oauth.oauth2.flow import OAuth2Context as OAuth2Context
    from mountainash_auth_client.oauth.oauth1.flow import OAuth1Flow as OAuth1Flow
    from mountainash_auth_client.oauth.oauth2.flow import OAuthFlow as OAuthFlow
    from mountainash_auth_client.oauth.persistence import PersistableAuthProfile as PersistableAuthProfile
    from mountainash_auth_client.oauth.protocols import (
        CallbackServerFactory as CallbackServerFactory,
        CallbackServerProtocol as CallbackServerProtocol,
    )
    from mountainash_auth_client.oauth.providers import (
        OAuth1ProviderProfile as OAuth1ProviderProfile,
        OAuth1ProviderProfileProtocol as OAuth1ProviderProfileProtocol,
        OAuth2ProviderProfile as OAuth2ProviderProfile,
        OAuth2ProviderProfileProtocol as OAuth2ProviderProfileProtocol,
        ProviderProfileProtocol as ProviderProfileProtocol,
    )
    from mountainash_auth_client.oauth.server.callback import LocalCallbackServer as LocalCallbackServer
    from mountainash_auth_client.oauth.server.manual import ManualCallbackServer as ManualCallbackServer

# Lazy (PEP 562) re-exports for the OAuth ops layer. These names stay exported but resolve
# on first attribute access, so `import mountainash_auth_client` / `import …schemas` never
# pulls in httpx/authlib/paramiko/oauth. Keep this map and __all__ in sync.
_LAZY = {
    "OAuthFlow": "mountainash_auth_client.oauth.oauth2.flow",
    "OAuth2Context": "mountainash_auth_client.oauth.oauth2.flow",
    "OAuthFlowFactory": "mountainash_auth_client.oauth.lifecycle.oauth2",
    "OAuth1Flow": "mountainash_auth_client.oauth.oauth1.flow",
    "TokenCredential": "mountainash_auth_client.oauth.lifecycle.credential",
    "SignOutResult": "mountainash_auth_client.oauth.lifecycle.credential",
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
    "AuthorizationCancelled",
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
    "OAuth1Flow",
    "OAuth1ProviderProfile",
    "OAuth1ProviderProfileProtocol",
    "OAuth1TokenManager",
    "OAuth2AuthProfile",
    "OAuth2Context",
    "OAuth2ProviderProfile",
    "OAuth2ProviderProfileProtocol",
    "OAuth2TokenManager",
    "OAuthFlow",
    "OAuthFlowFactory",
    "PasswordAuthProfile",
    "PersistableAuthProfile",
    "ProviderProfileProtocol",
    "ServiceAccountAuthProfile",
    "SignOutResult",
    "TargetFamily",
    "TokenAuthProfile",
    "TokenCredential",
    "TokenExchangeError",
    "TokenRefreshError",
    "TokenState",
    "TokenStatus",
    "WindowsAuthProfile",
]
