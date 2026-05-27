"""OAuth2ConnectionMixin — reusable connect/refresh for OAuth2 providers."""
from __future__ import annotations

from typing import ClassVar, Self

import httpx

from mountainash_auth_client.errors import AuthorizationRequired
from mountainash_auth_client.flows.oauth2 import OAuthFlow
from mountainash_auth_client.store.protocol import SecretStore


class OAuth2ConnectionMixin:
    _spec: ClassVar  # ProfileSpec or any object with .name and .metadata
    _base_url: ClassVar[str]
    _client: httpx.Client | None

    def connect(
        self,
        profile,
        *,
        user: str = "default",
        store: SecretStore,
        domain: str,
        auto_authorize: bool = False,
    ) -> Self:
        provider = self._spec.name
        flow = OAuthFlow(self._spec)

        tokens = store.load(domain, provider, user)

        # Migration: fall back to profile.auth token fields if no token file and not cleared
        if tokens is None and not store.is_cleared(domain, provider, user):
            auth = profile.auth
            if getattr(auth, "access_token", None) is not None:
                tokens = {
                    "access_token": auth.access_token.get_secret_value(),
                    "refresh_token": auth.refresh_token.get_secret_value() if auth.refresh_token else None,
                    "token_expires_at": auth.token_expires_at,
                }
                store.save(domain, provider, user, tokens)

        access_token: str | None = None

        if tokens and not flow.is_expired(tokens.get("token_expires_at")):
            access_token = tokens["access_token"]
        elif tokens and tokens.get("refresh_token"):
            with store.lock(domain, provider, user):
                tokens = store.load(domain, provider, user)
                if tokens and not flow.is_expired(tokens.get("token_expires_at")):
                    access_token = tokens["access_token"]
                else:
                    try:
                        auth = profile.auth
                        new_tokens = flow.refresh(
                            refresh_token=tokens["refresh_token"],
                            client_id=auth.client_id,
                            client_secret=auth.client_secret.get_secret_value(),
                        )
                        store.save(domain, provider, user, new_tokens)
                        access_token = new_tokens["access_token"]
                    except Exception:
                        store.clear(domain, provider, user)
                        if not auto_authorize:
                            raise AuthorizationRequired(provider=provider, user=user)

        if access_token is None:
            if auto_authorize:
                auth = profile.auth
                new_tokens = flow.authorize(
                    client_id=auth.client_id,
                    client_secret=auth.client_secret.get_secret_value(),
                    scope=auth.scope,
                )
                store.save(domain, provider, user, new_tokens)
                access_token = new_tokens["access_token"]
            else:
                raise AuthorizationRequired(provider=provider, user=user)

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
