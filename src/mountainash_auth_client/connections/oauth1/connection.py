"""OAuth1Connection — parameterised connect for any OAuth1 provider.

Resolves the access token pair, then dogfoods the unified emission: a fresh
OAuth1AuthProfile populated with the resolved pair emits the authlib signer
onto the provider's base_url.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Self

import httpx

from mountainash_auth_client.targets import TargetFamily
from mountainash_auth_client.connections.oauth1.flow import OAuth1Flow
from mountainash_auth_client.schemas.oauth1 import OAuth1AuthProfile

if TYPE_CHECKING:
    from mountainash_secrets import SecretStoreResolver
    from mountainash_auth_client.providers.protocols import OAuth1ProviderProfileProtocol
    from mountainash_auth_client.connections.protocols import CallbackServerFactory


class OAuth1Connection:
    def __init__(
        self,
        provider: OAuth1ProviderProfileProtocol,
        auth_profile: OAuth1AuthProfile,
        *,
        resolver: SecretStoreResolver,
        auto_authorize: bool = False,
        callback_server: CallbackServerFactory | None = None,
    ) -> None:
        self._provider = provider
        self._auth = auth_profile
        self._resolver = resolver
        self._auto_authorize = auto_authorize
        self._callback_server = callback_server
        self._client: httpx.Client | None = None

    @property
    def client(self) -> httpx.Client | None:
        return self._client

    def connect(self) -> Self:
        oauth_token, oauth_token_secret = OAuth1Flow(self._provider, resolver=self._resolver).resolve_token_pair(
            self._auth,
            auto_authorize=self._auto_authorize,
            callback_server=self._callback_server,
        )
        base = self._provider.emit(TargetFamily.HTTP)
        signed = OAuth1AuthProfile(
            CONSUMER_KEY=self._auth.CONSUMER_KEY,
            CONSUMER_SECRET=self._auth.CONSUMER_SECRET.get_secret_value(),
            ACCESS_TOKEN=oauth_token,
            ACCESS_TOKEN_SECRET=oauth_token_secret,
        )
        merged = signed.emit(TargetFamily.HTTP, base=base)
        merged.setdefault("timeout", 30.0)
        self._client = httpx.Client(**merged)
        return self

    def disconnect(self) -> None:
        if self._client is not None:
            self._client.close()
        self._client = None

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args) -> None:
        self.disconnect()
