"""OAuth2ConnectionMixin — reusable connect/refresh for OAuth2 providers."""
from __future__ import annotations

from typing import ClassVar, Self

import httpx

from mountainash_auth_client.errors import AuthorizationRequired
from mountainash_auth_client.flows.oauth2 import OAuthFlow
from mountainash_settings.secrets.registry import get_secrets_backend


class OAuth2ConnectionMixin:
    _spec: ClassVar
    _base_url: ClassVar[str]
    _client: httpx.Client | None

    @property
    def client(self) -> httpx.Client | None:
        return self._client

    def connect(
        self,
        profile,
        *,
        auto_authorize: bool = False,
    ) -> Self:
        auth = profile.auth
        provider = self._spec.name
        flow = OAuthFlow(self._spec)

        backend = get_secrets_backend(auth.SETTINGS_SOURCE_SECRETS_PROVIDER)
        key = auth.persist_key()
        tokens = backend.get(key)

        access_token: str | None = None

        if tokens and not flow.is_expired(tokens.get("token_expires_at")):
            access_token = tokens["access_token"]
        elif tokens and tokens.get("refresh_token"):
            with backend.transaction(key):
                tokens = backend.get(key)
                if tokens and not flow.is_expired(tokens.get("token_expires_at")):
                    access_token = tokens["access_token"]
                else:
                    try:
                        new_tokens = flow.refresh(
                            refresh_token=tokens["refresh_token"],
                            client_id=auth.CLIENT_ID,
                            client_secret=auth.CLIENT_SECRET.get_secret_value(),
                        )
                        backend.set(key, new_tokens)
                        access_token = new_tokens["access_token"]
                    except Exception:
                        backend.delete(key)
                        if not auto_authorize:
                            raise AuthorizationRequired(provider=provider, user="default")

        if access_token is None:
            if auto_authorize:
                new_tokens = flow.authorize(
                    client_id=auth.CLIENT_ID,
                    client_secret=auth.CLIENT_SECRET.get_secret_value(),
                    scope=auth.SCOPE,
                )
                backend.set(key, new_tokens)
                access_token = new_tokens["access_token"]
            else:
                raise AuthorizationRequired(provider=provider, user="default")

        self._client = httpx.Client(
            base_url=self._base_url,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=30.0,
        )
        return self

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args) -> None:
        self.disconnect()
