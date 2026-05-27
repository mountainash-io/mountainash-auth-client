"""OAuth1ConnectionMixin — connect/auth for OAuth1 providers."""
from __future__ import annotations

from typing import ClassVar, Self

import httpx

from mountainash_auth_client.errors import AuthorizationRequired
from mountainash_auth_client.flows.oauth1 import OAuth1Flow
from mountainash_auth_client.store.protocol import SecretStore


class OAuth1ConnectionMixin:
    _spec: ClassVar
    _base_url: ClassVar[str]
    _client: httpx.Client | None

    def connect(self, profile, *, user: str = "default", store: SecretStore, domain: str, auto_authorize: bool = False) -> Self:
        provider = self._spec.name
        tokens = store.load(domain, provider, user)

        if tokens is None and not store.is_cleared(domain, provider, user):
            auth = profile.auth
            if getattr(auth, "access_token", None) is not None:
                tokens = {
                    "oauth_token": auth.access_token.get_secret_value(),
                    "oauth_token_secret": auth.access_token_secret.get_secret_value() if auth.access_token_secret else None,
                }
                store.save(domain, provider, user, tokens)

        if tokens and tokens.get("oauth_token"):
            self._build_client(tokens, profile)
            return self

        if auto_authorize:
            auth = profile.auth
            flow = OAuth1Flow(self._spec)
            new_tokens = flow.authorize(consumer_key=auth.consumer_key, consumer_secret=auth.consumer_secret.get_secret_value())
            store.save(domain, provider, user, new_tokens)
            self._build_client(new_tokens, profile)
            return self

        raise AuthorizationRequired(provider=provider, user=user)

    def _build_client(self, tokens: dict, profile) -> None:
        try:
            from authlib.integrations.httpx_client import OAuth1Auth
        except ImportError as exc:
            raise ImportError("OAuth1 requires authlib: pip install mountainash-auth-client[oauth1]") from exc

        auth = profile.auth
        self._client = httpx.Client(
            base_url=self._base_url,
            auth=OAuth1Auth(client_id=auth.consumer_key, client_secret=auth.consumer_secret.get_secret_value(), token=tokens["oauth_token"], token_secret=tokens["oauth_token_secret"]),
            timeout=30.0,
        )

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args) -> None:
        self.disconnect()
