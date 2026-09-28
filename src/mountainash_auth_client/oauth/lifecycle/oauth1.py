"""OAuth1 token-lifecycle manager — authorize / token_pair / status / revoke.

OAuth1 tokens are long-lived (no refresh/expiry), so the surface is smaller than
OAuth2's and status() is PRESENT/MISSING/CLEARED only.
"""
from __future__ import annotations

import typing as t

from mountainash_auth_client.oauth.oauth1.flow import OAuth1Flow
from mountainash_auth_client.oauth.server.factory import resolve_callback_factory
from mountainash_auth_client.oauth.lifecycle.status import TokenState, TokenStatus
from mountainash_auth_client.oauth.persistence import token_store
from mountainash_auth_client.schemas.oauth1 import OAuth1AuthProfile
from mountainash_auth_client.targets import TargetFamily

if t.TYPE_CHECKING:
    from mountainash_settings.secrets import ClearableSecretStore
    from mountainash_auth_client.oauth.providers.protocols import OAuth1ProviderProfileProtocol
    from mountainash_auth_client.oauth.persistence import PersistableAuthProfile
    from mountainash_auth_client.oauth.protocols import CallbackServerFactory

__all__ = ["OAuth1TokenManager"]


class OAuth1TokenManager:
    def __init__(
        self,
        provider: OAuth1ProviderProfileProtocol,
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
    def _flow_cls(cls) -> type[OAuth1Flow]:
        return OAuth1Flow

    def _store(self):
        return token_store(self._token_store)

    def authorize(self, *, mode: str = "local_server", manual_redirect_uri: str | None = None) -> TokenStatus:
        factory = resolve_callback_factory(
            redirect_mode=mode,
            callback_server=None,
            instance_default=self._callback_server,
            callback_port=self._provider.CALLBACK_PORT,
            manual_redirect_uri=manual_redirect_uri or "oob",
        )
        tokens = self._flow_cls()(self._provider, token_store=self._token_store).authorize(
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
        return self._flow_cls()(self._provider, token_store=self._token_store).resolve_token_pair(self._auth)

    def status(self) -> TokenStatus:
        backend = self._store()
        key = self._auth.persist_key()
        with backend.transaction(key):
            if backend.is_cleared(key):
                return TokenStatus(TokenState.CLEARED)
            record = backend.get(key)
        if record is None:
            return TokenStatus(TokenState.MISSING)
        return TokenStatus(TokenState.PRESENT)

    def acquire_auth(self):
        """Resolve the OAuth1 token pair and return the httpx.Auth signer.

        OAuth1 is per-request signing, not a Bearer header — the consumer applies
        this via RequestCreds(auth=...). Reuses the schema's _oauth1_signer through emit(HTTP).
        """
        token, secret = self.token_pair()
        signer = OAuth1AuthProfile(
            CONSUMER_KEY=self._auth.CONSUMER_KEY,
            CONSUMER_SECRET=self._auth.CONSUMER_SECRET.get_secret_value(),
            ACCESS_TOKEN=token,
            ACCESS_TOKEN_SECRET=secret,
        )
        return signer.emit(TargetFamily.HTTP)["auth"]

    def revoke(self) -> None:
        backend = self._store()
        key = self._auth.persist_key()
        with backend.transaction(key):
            backend.delete(key)
