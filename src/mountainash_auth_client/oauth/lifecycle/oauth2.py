"""OAuth2 token-lifecycle manager — authorize / refresh / status / revoke."""
from __future__ import annotations

import typing as t

from mountainash_auth_client.oauth.oauth2.flow import OAuthFlow
from mountainash_auth_client.oauth.server.factory import resolve_callback_factory
from mountainash_auth_client.oauth.lifecycle.credential import TokenCredential
from mountainash_auth_client.oauth.lifecycle.status import TokenState, TokenStatus, classify_oauth2
from mountainash_auth_client.oauth.persistence import token_store

if t.TYPE_CHECKING:
    from mountainash_secrets import SecretStoreResolver
    from mountainash_auth_client.oauth.providers.protocols import OAuth2ProviderProfileProtocol
    from mountainash_auth_client.oauth.persistence import PersistableAuthProfile
    from mountainash_auth_client.oauth.protocols import CallbackServerFactory

__all__ = ["OAuth2TokenManager"]


class OAuth2TokenManager:
    """Full OAuth2 token lifecycle over an injected resolver.

    Manages *tokens* (persisted under the "oauth" namespace by persist_key());
    for an authed httpx client use OAuth2Connection instead. Every mutation is
    serialized through the per-key transaction (design spec §5.1).
    """

    def __init__(
        self,
        provider: OAuth2ProviderProfileProtocol,
        auth_profile: PersistableAuthProfile,
        *,
        resolver: SecretStoreResolver,
        callback_server: CallbackServerFactory | None = None,
    ) -> None:
        self._provider = provider
        self._auth = auth_profile
        self._resolver = resolver
        self._callback_server = callback_server

    @classmethod
    def _flow_cls(cls) -> type[OAuthFlow]:
        """The flow class this manager constructs (a test seam for patching)."""
        return OAuthFlow

    def _store(self):
        return token_store(self._resolver, self._auth)

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
        tokens = self._flow_cls()(self._provider, resolver=self._resolver).authorize(
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
        flow = self._flow_cls()(self._provider, resolver=self._resolver)
        flow.resolve_access_token(self._auth, auto_authorize=False)   # refresh-or-raise, single-flight
        return self._credential()

    def refresh(self) -> TokenCredential:
        """Force a refresh under the per-key transaction, then return the credential."""
        flow = self._flow_cls()(self._provider, resolver=self._resolver)
        flow.resolve_access_token(self._auth, auto_authorize=False)
        return self._credential()

    def _credential(self) -> TokenCredential:
        backend = self._store()
        key = self._auth.persist_key()
        with backend.transaction(key):
            record = backend.get(key)
        if not record or not record.get("access_token"):
            from mountainash_auth_client.errors import AuthorizationRequired
            raise AuthorizationRequired(provider=self._provider.NAME, user="default")
        return TokenCredential.from_record(record)

    def access_token(self) -> str:
        return self._flow_cls()(self._provider, resolver=self._resolver).resolve_access_token(self._auth)

    def status(self) -> TokenStatus:
        backend = self._store()
        key = self._auth.persist_key()
        with backend.transaction(key):  # consistent is_cleared + get snapshot
            cleared = backend.is_cleared(key)
            record = backend.get(key)
        if cleared:
            return TokenStatus(TokenState.CLEARED)
        return classify_oauth2(record)

    def revoke(self) -> None:
        backend = self._store()
        key = self._auth.persist_key()
        with backend.transaction(key):
            backend.delete(key)
