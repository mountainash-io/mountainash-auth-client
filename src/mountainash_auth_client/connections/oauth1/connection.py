"""OAuth1Connection — connect/auth for OAuth1 providers."""
from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, Self

import httpx

from mountainash_auth_client.errors import AuthorizationRequired
from mountainash_auth_client.connections.oauth1.flow import OAuth1Flow
from mountainash_settings.secrets.registry import get_secrets_backend

if TYPE_CHECKING:
    from mountainash_settings import ProfileSpec
    from ...schemas.oauth1 import OAuth1Auth

class OAuth1Connection:
    _spec: ClassVar[ProfileSpec]
    _base_url: ClassVar[str]
    _client: httpx.Client | None

    def connect(
        self,
        auth: OAuth1Auth,
        *,
        auto_authorize: bool = False,
    ) -> Self:
        provider = self._spec.name

        backend = get_secrets_backend(auth.SETTINGS_SOURCE_SECRETS_PROVIDER)
        key = auth.persist_key()
        tokens = backend.get(key)

        if tokens and tokens.get("oauth_token"):
            self._build_client(tokens, auth)
            return self

        if auto_authorize:
            flow = OAuth1Flow(self._spec)
            new_tokens = flow.authorize(
                consumer_key=auth.CONSUMER_KEY,
                consumer_secret=auth.CONSUMER_SECRET.get_secret_value(),
            )
            backend.set(key, new_tokens)
            self._build_client(new_tokens, auth)
            return self

        raise AuthorizationRequired(provider=provider, user="default")

    def _build_client(self, tokens: dict[str, str], auth_settings: OAuth1Auth) -> None:
        try:
            from authlib.integrations.httpx_client import OAuth1Auth
        except ImportError as exc:
            raise ImportError(
                "OAuth1 requires authlib: pip install mountainash-auth-client[oauth1]"
            ) from exc

        self._client = httpx.Client(
            base_url=self._base_url,
            auth=OAuth1Auth(
                client_id=auth_settings.CONSUMER_KEY,
                client_secret=auth_settings.CONSUMER_SECRET.get_secret_value(),
                token=tokens["oauth_token"],
                token_secret=tokens["oauth_token_secret"],
            ),
            timeout=30.0,
        )

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args) -> None:
        self.disconnect()
