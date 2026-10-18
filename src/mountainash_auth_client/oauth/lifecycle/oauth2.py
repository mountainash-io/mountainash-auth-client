"""OAuth2 token-lifecycle manager — authorize / refresh / status / revoke."""
from __future__ import annotations

import typing as t

from mountainash_auth_client.oauth.oauth2.flow import OAuthFlow
from mountainash_auth_client.oauth.server.factory import resolve_callback_factory
from mountainash_auth_client.oauth.lifecycle.status import TokenState, TokenStatus, classify_oauth2
from mountainash_auth_client.oauth.persistence import token_store

if t.TYPE_CHECKING:
    from mountainash_settings.secrets import ClearableSecretStore, NamespacedSecretStore
    from mountainash_auth_client.oauth.lifecycle.credential import SignOutResult, TokenCredential
    from mountainash_auth_client.oauth.providers.protocols import OAuth2ProviderProfileProtocol
    from mountainash_auth_client.oauth.persistence import OAuth2CredentialProfile
    from mountainash_auth_client.oauth.protocols import CallbackServerFactory

__all__ = ["OAuth2TokenManager", "OAuthFlowFactory"]


class OAuthFlowFactory(t.Protocol):
    """Construct a consumer flow while retaining the selected store and callback."""

    def __call__(
        self, provider: OAuth2ProviderProfileProtocol, *,
        token_store: ClearableSecretStore | None = None,
        callback_server: CallbackServerFactory | None = None,
    ) -> OAuthFlow: ...


class OAuth2TokenManager:
    """Full OAuth2 token lifecycle over a consumer-selected store.

    Manages *tokens* (persisted under the "oauth" namespace by persist_key()).
    ``acquire()`` returns a ``TokenCredential``; render it for HTTP via ``emit(HTTP)``.
    Every mutation is serialized through the per-key transaction (design spec §5.1).
    """

    def __init__(
        self,
        provider: OAuth2ProviderProfileProtocol,
        auth_profile: OAuth2CredentialProfile,
        *,
        token_store: ClearableSecretStore,
        callback_server: CallbackServerFactory | None = None,
        flow_factory: OAuthFlowFactory = OAuthFlow,
    ) -> None:
        self._provider = provider
        self._auth = auth_profile
        self._token_store = token_store
        self._callback_server = callback_server
        self._flow_factory = flow_factory

    def _flow(self) -> OAuthFlow:
        return self._flow_factory(
            self._provider, token_store=self._token_store, callback_server=self._callback_server,
        )

    def _store(self) -> NamespacedSecretStore:
        return token_store(self._token_store)

    def authorize(self, *, mode: str = "local_server", manual_redirect_uri: str | None = None) -> TokenStatus:
        factory = resolve_callback_factory(
            redirect_mode=mode,
            callback_server=None,
            instance_default=self._callback_server,
            callback_port=self._provider.CALLBACK_PORT,
            manual_redirect_uri=manual_redirect_uri,
        )
        self._flow()._authorize_and_store(self._auth, callback_server=factory)
        return self.status()

    def acquire(self) -> TokenCredential:
        """Resolve a valid access token (refresh-if-stale) and return it as a
        TokenCredential. Non-interactive: raises AuthorizationRequired when no usable
        token exists — it never launches the interactive authorize dance.
        """
        return self._flow().resolve_credential(self._auth)

    def refresh(self) -> TokenCredential:
        """Force a refresh: unconditionally exchange the refresh token at the token
        endpoint under the per-key transaction (ignores is_expired), then return the
        credential. Contrast acquire(), which is refresh-if-stale.
        """
        return self._flow().resolve_credential(self._auth, force=True)

    def access_token(self) -> str:
        return self.acquire().access_token

    def sign_out(self) -> SignOutResult:
        """Retain registration, cancel pending authorization and attempt remote revocation."""
        return self._flow().sign_out(self._auth)

    def status(self) -> TokenStatus:
        backend = self._store()
        key = self._auth.persist_key()
        with backend.transaction(key):  # consistent is_cleared + get snapshot
            if backend.is_cleared(key):
                return TokenStatus(TokenState.CLEARED)
            record = backend.get(key)
        return classify_oauth2(record)

    def revoke(self) -> None:
        backend = self._store()
        key = self._auth.persist_key()
        with backend.transaction(key):
            backend.delete(key)
