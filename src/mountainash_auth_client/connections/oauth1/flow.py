"""OAuth1 3-legged flow for providers like Garmin Health API."""
from __future__ import annotations

from typing import TYPE_CHECKING, Literal
from urllib.parse import urlencode

import httpx

from mountainash_auth_client.errors import MalformedCallbackError, TokenExchangeError
from mountainash_auth_client.connections._optional import require_authlib
from mountainash_auth_client.connections.server.factory import resolve_callback_factory

if TYPE_CHECKING:
    from mountainash_settings import ProfileSpec
    from mountainash_auth_client.connections.protocols import CallbackServerFactory


class OAuth1Flow:
    """Runs OAuth 1.0a 3-legged authorization flow."""

    def __init__(
        self,
        spec: ProfileSpec,
        *,
        callback_server: CallbackServerFactory | None = None,
    ) -> None:
        self._metadata = spec.metadata
        self._callback_server = callback_server

    @property
    def request_token_url(self) -> str:
        return self._metadata["request_token_url"]

    @property
    def authorize_url(self) -> str:
        return self._metadata["authorize_url"]

    @property
    def access_token_url(self) -> str:
        return self._metadata["access_token_url"]

    def build_authorize_url(self, oauth_token: str) -> str:
        return f"{self.authorize_url}?{urlencode({'oauth_token': oauth_token})}"

    def request_token(
        self,
        consumer_key: str,
        consumer_secret: str,
        callback_url: str = "oob",
    ) -> dict[str, str]:
        OAuth1Client = require_authlib("OAuth1Client")

        client = OAuth1Client(client_id=consumer_key, client_secret=consumer_secret)
        try:
            token = client.fetch_request_token(
                self.request_token_url, params={"oauth_callback": callback_url}
            )
        except httpx.HTTPStatusError as exc:
            raise TokenExchangeError(
                url=self.request_token_url,
                status_code=exc.response.status_code,
                body=exc.response.text[:2000],
            ) from exc
        return token

    def exchange_verifier(
        self,
        consumer_key: str,
        consumer_secret: str,
        oauth_token: str,
        oauth_token_secret: str,
        verifier: str,
    ) -> dict[str, str]:
        OAuth1Client = require_authlib("OAuth1Client")

        client = OAuth1Client(
            client_id=consumer_key,
            client_secret=consumer_secret,
            token=oauth_token,
            token_secret=oauth_token_secret,
        )
        try:
            token = client.fetch_access_token(self.access_token_url, verifier=verifier)
        except httpx.HTTPStatusError as exc:
            raise TokenExchangeError(
                url=self.access_token_url,
                status_code=exc.response.status_code,
                body=exc.response.text[:2000],
            ) from exc
        return {
            "oauth_token": token["oauth_token"],
            "oauth_token_secret": token["oauth_token_secret"],
        }

    def authorize(
        self,
        consumer_key: str,
        consumer_secret: str,
        redirect_mode: Literal["local_server", "manual"] = "local_server",
        callback_server: CallbackServerFactory | None = None,
    ) -> dict[str, str]:
        factory = resolve_callback_factory(
            redirect_mode=redirect_mode,
            callback_server=callback_server,
            instance_default=self._callback_server,
            metadata=self._metadata,
            manual_redirect_uri="oob",
        )
        server = factory()

        request_token = self.request_token(consumer_key, consumer_secret, server.redirect_uri)
        url = self.build_authorize_url(request_token["oauth_token"])
        params = server.obtain_callback(url)

        returned_token = params.get("oauth_token")
        if returned_token is not None and returned_token != request_token["oauth_token"]:
            raise ValueError("OAuth1 token mismatch — possible CSRF")

        # Bare manual paste lands the verifier in "code"; accept it as a fallback.
        verifier = params.get("oauth_verifier") or params.get("code")
        if not verifier:
            raise MalformedCallbackError("OAuth1 callback missing 'oauth_verifier'")

        return self.exchange_verifier(
            consumer_key=consumer_key,
            consumer_secret=consumer_secret,
            oauth_token=request_token["oauth_token"],
            oauth_token_secret=request_token["oauth_token_secret"],
            verifier=verifier,
        )
