"""OAuth2Connection — reusable connect/refresh for OAuth2 providers."""
from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, Self

import httpx

from mountainash_auth_client.errors import AuthorizationRequired
from mountainash_auth_client.connections.oauth2.flow import OAuthFlow
from mountainash_settings.secrets.registry import get_secrets_backend

if TYPE_CHECKING:
    from mountainash_settings import ProfileSpec
    from ...schemas.oauth2 import OAuth2AuthProfile
    from ...schemas.oauth2_authcode import OAuth2AuthCodeAuthProfile


class OAuth2Connection:
    _spec: ClassVar[ProfileSpec]
    _base_url: ClassVar[str]
    _client: httpx.Client | None

    @property
    def client(self) -> httpx.Client | None:
        return self._client

    def connect(
        self,
        auth_profile: OAuth2AuthProfile | OAuth2AuthCodeAuthProfile,
        *,
        auto_authorize: bool = False,
    ) -> Self:
        provider = self._spec.name
        flow = OAuthFlow(self._spec)

        backend = get_secrets_backend(auth_profile.SETTINGS_SOURCE_SECRETS_PROVIDER)
        key = auth_profile.persist_key()
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
                            client_id=auth_profile.CLIENT_ID,
                            client_secret=auth_profile.CLIENT_SECRET.get_secret_value(),
                        )
                    except Exception:
                        backend.delete(key)
                        if not auto_authorize:
                            raise AuthorizationRequired(provider=provider, user="default")
                    else:
                        backend.set(key, new_tokens)
                        access_token = new_tokens["access_token"]

        if access_token is None:
            if auto_authorize:
                new_tokens = flow.authorize(
                    client_id=auth_profile.CLIENT_ID,
                    client_secret=auth_profile.CLIENT_SECRET.get_secret_value(),
                    scope=auth_profile.SCOPE,
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
