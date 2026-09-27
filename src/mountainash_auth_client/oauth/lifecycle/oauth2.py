"""OAuth2 token-lifecycle manager — authorize / refresh / status / revoke."""
from __future__ import annotations

import typing as t

from mountainash_auth_client.errors import AuthorizationRequired
from mountainash_auth_client.oauth.oauth2.flow import OAuthFlow
from mountainash_auth_client.oauth.server.factory import resolve_callback_factory
from mountainash_auth_client.oauth.lifecycle.credential import TokenCredential
from mountainash_auth_client.oauth.lifecycle.status import TokenState, TokenStatus, classify_oauth2
from mountainash_auth_client.oauth.persistence import token_store

if t.TYPE_CHECKING:
    from mountainash_settings.secrets import ClearableSecretStore
    from mountainash_auth_client.oauth.providers.protocols import OAuth2ProviderProfileProtocol
    from mountainash_auth_client.oauth.persistence import PersistableAuthProfile
    from mountainash_auth_client.oauth.protocols import CallbackServerFactory

__all__ = ["OAuth2TokenManager"]


class OAuth2TokenManager:
    """Full OAuth2 token lifecycle over a consumer-selected store.

    Manages *tokens* (persisted under the "oauth" namespace by persist_key()).
    ``acquire()`` returns a ``TokenCredential``; render it for HTTP via ``emit(HTTP)``.
    Every mutation is serialized through the per-key transaction (design spec §5.1).
    """

    def __init__(
        self,
        provider: OAuth2ProviderProfileProtocol,
        auth_profile: PersistableAuthProfile,
        *,
        token_store: ClearableSecretStore,
        callback_server: CallbackServerFactory | None = None,
    ) -> None:
        self._provider = provider
        self._auth = auth_profile
        self._token_store = token_store
        self._callback_server = callback_server

    @classmethod
    def _flow_cls(cls) -> type[OAuthFlow]:
        """The flow class this manager constructs (a test seam for patching)."""
        return OAuthFlow

    def _store(self):
        return token_store(self._token_store)

    def authorize(self, *, mode: str = "local_server", manual_redirect_uri: str | None = None) -> TokenStatus:
        factory = resolve_callback_factory(
            redirect_mode=mode,
            callback_server=None,
            instance_default=self._callback_server,
            callback_port=self._provider.CALLBACK_PORT,
            manual_redirect_uri=manual_redirect_uri,
        )
        # Interactive dance runs OUTSIDE any lock (can take minutes).
        method = getattr(self._provider, "TOKEN_ENDPOINT_AUTH_METHOD", "client_secret_post")
        if method == "none":
            client_id = client_secret = None
        else:
            client_id = self._auth.CLIENT_ID
            client_secret = (
                self._auth.CLIENT_SECRET.get_secret_value()
                if self._auth.CLIENT_SECRET else None
            )
        tokens = self._flow_cls()(self._provider, token_store=self._token_store).authorize(
            client_id=client_id,
            client_secret=client_secret,
            scope=self._auth.SCOPE,
            callback_server=factory,
        )
        backend = self._store()
        key = self._auth.persist_key()
        with backend.transaction(key):  # short serialized write
            backend.set(key, tokens)
        return self.status()

    def acquire(self) -> TokenCredential:
        """Resolve a valid access token (refresh-if-stale) and return it as a
        TokenCredential. Non-interactive: raises AuthorizationRequired when no usable
        token exists — it never launches the interactive authorize dance.
        """
        flow = self._flow_cls()(self._provider, token_store=self._token_store)
        flow.resolve_access_token(self._auth, auto_authorize=False)   # refresh-or-raise, single-flight
        return self._credential()

    def refresh(self) -> TokenCredential:
        """Force a refresh: unconditionally exchange the refresh token at the token
        endpoint under the per-key transaction (ignores is_expired), then return the
        credential. Contrast acquire(), which is refresh-if-stale.
        """
        self._flow_cls()(self._provider, token_store=self._token_store).force_refresh(self._auth)
        return self._credential()

    def _credential(self) -> TokenCredential:
        backend = self._store()
        key = self._auth.persist_key()
        with backend.transaction(key):
            if backend.is_cleared(key):
                raise AuthorizationRequired(provider=self._provider.NAME, user="default")
            record = backend.get(key)
        if not record or not record.get("access_token"):
            raise AuthorizationRequired(provider=self._provider.NAME, user="default")
        return TokenCredential.from_record(record)

    def access_token(self) -> str:
        return self._flow_cls()(self._provider, token_store=self._token_store).resolve_access_token(self._auth)

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
