"""OAuth2Connection — parameterised connect for any OAuth2 provider.

Composes the unified two-stage HTTP emission: the provider emits its resource
config (base_url), then a TokenAuthProfile emits the Bearer header onto it.
No ClassVars, no subclass-per-provider.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Self

import httpx

from mountainash_auth_client.targets import TargetFamily
from mountainash_auth_client.oauth.oauth2.flow import OAuthFlow
from mountainash_auth_client.schemas.token import TokenAuthProfile

if TYPE_CHECKING:
    from mountainash_secrets import SecretStoreResolver
    from mountainash_auth_client.oauth.providers.protocols import OAuth2ProviderProfileProtocol
    from mountainash_auth_client.schemas.oauth2 import OAuth2AuthProfile
    from mountainash_auth_client.oauth.protocols import CallbackServerFactory


class OAuth2Connection:
    def __init__(
        self,
        provider: OAuth2ProviderProfileProtocol,
        auth_profile: OAuth2AuthProfile,
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
        token = OAuthFlow(self._provider, resolver=self._resolver).resolve_access_token(
            self._auth,
            auto_authorize=self._auto_authorize,
            callback_server=self._callback_server,
        )
        base = self._provider.emit(TargetFamily.HTTP)
        merged = TokenAuthProfile(TOKEN=token).emit(TargetFamily.HTTP, base=base)
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
