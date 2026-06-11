"""OAuth1Connection — connect/auth for OAuth1 providers."""
from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, Self

import httpx

from mountainash_auth_client.errors import AuthorizationRequired
from mountainash_auth_client.connections._optional import require_authlib
from mountainash_auth_client.connections.oauth1.flow import OAuth1Flow
from mountainash_settings.secrets.registry import get_secrets_backend

if TYPE_CHECKING:
    from mountainash_settings import ProfileSpec
    from ...schemas.oauth1 import OAuth1AuthProfile
    from mountainash_auth_client.connections.protocols import CallbackServerFactory

class OAuth1Connection:
    _spec: ClassVar[ProfileSpec]
    _base_url: ClassVar[str]
    _client: httpx.Client | None

    def connect(
        self,
        auth_profile: OAuth1AuthProfile,
        *,
        auto_authorize: bool = False,
        callback_server: CallbackServerFactory | None = None,
    ) -> Self:
        provider = self._spec.name

        backend = get_secrets_backend(auth_profile.SETTINGS_SOURCE_SECRETS_PROVIDER)
        key = auth_profile.persist_key()
        tokens = backend.get(key)

        if tokens and tokens.get("oauth_token"):
            self._build_client(tokens, auth_profile)
            return self

        if auto_authorize:
            flow = OAuth1Flow(self._spec)
            new_tokens = flow.authorize(
                consumer_key=auth_profile.CONSUMER_KEY,
                consumer_secret=auth_profile.CONSUMER_SECRET.get_secret_value(),
                callback_server=callback_server,
            )
            backend.set(key, new_tokens)
            self._build_client(new_tokens, auth_profile)
            return self

        raise AuthorizationRequired(provider=provider, user="default")

    def _build_client(self, tokens: dict[str, str], auth_profile: OAuth1AuthProfile) -> None:
        OAuth1Auth = require_authlib("OAuth1Auth")

        self._client = httpx.Client(
            base_url=self._base_url,
            auth=OAuth1Auth(
                client_id=auth_profile.CONSUMER_KEY,
                client_secret=auth_profile.CONSUMER_SECRET.get_secret_value(),
                token=tokens["oauth_token"],
                token_secret=tokens["oauth_token_secret"],
            ),
            timeout=30.0,
        )

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args) -> None:
        self.disconnect()
