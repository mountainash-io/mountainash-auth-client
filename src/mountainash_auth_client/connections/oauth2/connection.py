"""OAuth2Connection — reusable connect/refresh for OAuth2 providers."""
from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, Self

import httpx

from mountainash_auth_client.connections.oauth2.flow import OAuthFlow

if TYPE_CHECKING:
    from mountainash_settings import ProfileSpec
    from ...schemas.oauth2 import OAuth2AuthProfile
    from ...schemas.oauth2_authcode import OAuth2AuthCodeAuthProfile
    from mountainash_auth_client.connections.protocols import CallbackServerFactory


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
        callback_server: CallbackServerFactory | None = None,
    ) -> Self:
        access_token = OAuthFlow(self._spec).resolve_access_token(
            auth_profile,
            auto_authorize=auto_authorize,
            callback_server=callback_server,
        )
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
