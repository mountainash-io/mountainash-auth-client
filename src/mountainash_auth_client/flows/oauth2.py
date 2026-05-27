from __future__ import annotations

import hashlib
import base64
import secrets
import time
import webbrowser
from typing import Literal
from urllib.parse import urlencode

import httpx

from mountainash_auth_client.errors import TokenExchangeError, TokenRefreshError
from mountainash_auth_client.server.callback import LocalCallbackServer
from mountainash_auth_client.server.manual import prompt_for_code


class OAuthFlow:
    """Runs OAuth 2.0 Authorization Code flow for an OAuth2 provider."""

    def __init__(self, spec) -> None:
        self._spec = spec
        self._metadata = spec.metadata
        self._code_verifier: str | None = None

    @property
    def authorize_url(self) -> str:
        return self._metadata["authorize_url"]

    @property
    def token_url(self) -> str:
        return self._metadata["token_url"]

    @property
    def use_pkce(self) -> bool:
        return self._metadata.get("use_pkce", False)

    @property
    def default_scope(self) -> str | None:
        return self._metadata.get("default_scope")

    def build_authorize_url(
        self,
        client_id: str,
        redirect_uri: str,
        scope: str | None = None,
    ) -> tuple[str, str]:
        """Build the authorization URL and generate state token."""
        state = secrets.token_urlsafe(32)
        params: dict[str, str] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "state": state,
        }
        effective_scope = scope or self.default_scope
        if effective_scope:
            params["scope"] = effective_scope

        if self.use_pkce:
            self._code_verifier = secrets.token_urlsafe(64)
            challenge = base64.urlsafe_b64encode(
                hashlib.sha256(self._code_verifier.encode()).digest()
            ).rstrip(b"=").decode()
            params["code_challenge"] = challenge
            params["code_challenge_method"] = "S256"

        url = f"{self.authorize_url}?{urlencode(params)}"
        return url, state

    def exchange_code(
        self,
        code: str,
        redirect_uri: str,
        client_id: str,
        client_secret: str,
        scope: str | None = None,
    ) -> dict[str, str | int | None]:
        """Exchange authorization code for tokens. Returns flat token dict."""
        data: dict[str, str] = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "client_secret": client_secret,
        }
        if self.use_pkce and self._code_verifier:
            data["code_verifier"] = self._code_verifier

        with httpx.Client() as client:
            try:
                resp = client.post(self.token_url, data=data)
                resp.raise_for_status()
            except httpx.HTTPStatusError as exc:
                raise TokenExchangeError(
                    url=self.token_url,
                    status_code=exc.response.status_code,
                    body=exc.response.text[:2000],
                ) from exc
            token_data = resp.json()

        expires_at: int | None = None
        if "expires_in" in token_data:
            expires_at = int(time.time()) + int(token_data["expires_in"])

        return {
            "access_token": token_data["access_token"],
            "refresh_token": token_data.get("refresh_token", ""),
            "token_expires_at": expires_at,
            "scope": scope or self.default_scope,
        }

    def refresh(
        self,
        refresh_token: str,
        client_id: str,
        client_secret: str,
    ) -> dict[str, str | int | None]:
        """Refresh an expired access token. Returns flat token dict."""
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": client_id,
            "client_secret": client_secret,
        }
        with httpx.Client() as client:
            try:
                resp = client.post(self.token_url, data=data)
                resp.raise_for_status()
            except httpx.HTTPStatusError as exc:
                raise TokenRefreshError(
                    url=self.token_url,
                    status_code=exc.response.status_code,
                    body=exc.response.text[:2000],
                ) from exc
            token_data = resp.json()

        expires_at: int | None = None
        if "expires_in" in token_data:
            expires_at = int(time.time()) + int(token_data["expires_in"])

        return {
            "access_token": token_data["access_token"],
            "refresh_token": token_data.get("refresh_token", refresh_token),
            "token_expires_at": expires_at,
        }

    @staticmethod
    def is_expired(token_expires_at: int | None, buffer_seconds: int = 300) -> bool:
        """Check if the access token is expired or about to expire."""
        if token_expires_at is None:
            return False
        return time.time() >= (token_expires_at - buffer_seconds)

    def authorize(
        self,
        client_id: str,
        client_secret: str,
        redirect_mode: Literal["local_server", "manual"] = "local_server",
        scope: str | None = None,
    ) -> dict[str, str | int | None]:
        """Run the full authorization code flow end-to-end. Returns flat token dict."""
        if redirect_mode == "local_server":
            port = self._metadata.get("callback_port", 0)
            server = LocalCallbackServer(port=port)
            redirect_uri = server.redirect_uri
        else:
            redirect_uri = "urn:ietf:wg:oauth:2.0:oob"

        url, state = self.build_authorize_url(
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
        )

        if redirect_mode == "local_server":
            webbrowser.open(url)
            params = server.wait_for_callback()
        else:
            params = prompt_for_code(url)

        if params.get("state") and params["state"] != state:
            raise ValueError("OAuth state mismatch — possible CSRF attack")

        return self.exchange_code(
            code=params["code"],
            redirect_uri=redirect_uri,
            client_id=client_id,
            client_secret=client_secret,
            scope=scope,
        )
