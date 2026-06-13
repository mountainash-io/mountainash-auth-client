"""OAuth1Connection — connect/auth for OAuth1 providers."""
from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, Self

import httpx

from mountainash_auth_client.connections._optional import require_authlib
from mountainash_auth_client.connections.oauth1.flow import OAuth1Flow

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
        oauth_token, oauth_token_secret = OAuth1Flow(self._spec).resolve_token_pair(
            auth_profile,
            auto_authorize=auto_authorize,
            callback_server=callback_server,
        )
        self._build_client(
            {"oauth_token": oauth_token, "oauth_token_secret": oauth_token_secret},
            auth_profile,
        )
        return self

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
