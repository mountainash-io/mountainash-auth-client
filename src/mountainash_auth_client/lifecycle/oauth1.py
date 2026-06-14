"""OAuth1 token-lifecycle manager — authorize / token_pair / status / revoke.

OAuth1 tokens are long-lived (no refresh/expiry), so the surface is smaller than
OAuth2's and status() is PRESENT/MISSING/CLEARED only.
"""
from __future__ import annotations

import typing as t

from mountainash_auth_client.connections.oauth1.flow import OAuth1Flow
from mountainash_auth_client.connections.server.factory import resolve_callback_factory
from mountainash_auth_client.lifecycle.status import TokenState, TokenStatus
from mountainash_auth_client.persistence import token_store

if t.TYPE_CHECKING:
    from mountainash_secrets import SecretStoreResolver
    from mountainash_auth_client.providers.oauth1 import OAuth1ProviderProfile
    from mountainash_auth_client.persistence import PersistableAuthProfile
    from mountainash_auth_client.connections.protocols import CallbackServerFactory

__all__ = ["OAuth1TokenManager"]


class OAuth1TokenManager:
    def __init__(
        self,
        provider: OAuth1ProviderProfile,
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
    def _flow_cls(cls) -> type[OAuth1Flow]:
        return OAuth1Flow

    def _store(self):
        return token_store(self._resolver, self._auth)

    def authorize(self, *, mode: str = "local_server", manual_redirect_uri: str | None = None) -> TokenStatus:
        factory = resolve_callback_factory(
            redirect_mode=mode,
            callback_server=None,
            instance_default=self._callback_server,
            callback_port=self._provider.CALLBACK_PORT,
            manual_redirect_uri=manual_redirect_uri or "oob",
        )
        tokens = self._flow_cls()(self._provider, resolver=self._resolver).authorize(
            consumer_key=self._auth.CONSUMER_KEY,
            consumer_secret=self._auth.CONSUMER_SECRET.get_secret_value(),
            callback_server=factory,
        )
        backend = self._store()
        key = self._auth.persist_key()
        with backend.transaction(key):
            backend.set(key, tokens)
        return self.status()

    def token_pair(self) -> tuple[str, str]:
        return self._flow_cls()(self._provider, resolver=self._resolver).resolve_token_pair(self._auth)

    def status(self) -> TokenStatus:
        backend = self._store()
        key = self._auth.persist_key()
        with backend.transaction(key):
            cleared = backend.is_cleared(key)
            record = backend.get(key)
        if cleared:
            return TokenStatus(TokenState.CLEARED)
        if record is None:
            return TokenStatus(TokenState.MISSING)
        return TokenStatus(TokenState.PRESENT)

    def revoke(self) -> None:
        backend = self._store()
        key = self._auth.persist_key()
        with backend.transaction(key):
            backend.delete(key)
