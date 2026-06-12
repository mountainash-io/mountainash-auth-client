from __future__ import annotations

import hashlib
import base64
import json
import secrets
import time
from typing import TYPE_CHECKING, Literal
from urllib.parse import urlencode

import httpx

from mountainash_auth_client.errors import (
    AuthorizationDeniedError,
    MalformedCallbackError,
    TokenExchangeError,
    TokenRefreshError,
)
from mountainash_auth_client.connections.server.factory import resolve_callback_factory

if TYPE_CHECKING:
    from mountainash_settings import ProfileSpec
    from mountainash_auth_client.connections.protocols import CallbackServerFactory


class OAuthFlow:
    """Runs OAuth 2.0 Authorization Code flow for an OAuth2 provider."""

    def __init__(
        self,
        spec: ProfileSpec,
        *,
        callback_server: CallbackServerFactory | None = None,
    ) -> None:
        self._spec = spec
        self._metadata = spec.metadata
        self._pending_verifiers: dict[str, str] = {}
        self._last_state: str | None = None
        self._callback_server = callback_server

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
        self._last_state = state
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
            verifier = secrets.token_urlsafe(64)
            self._pending_verifiers[state] = verifier
            challenge = base64.urlsafe_b64encode(
                hashlib.sha256(verifier.encode()).digest()
            ).rstrip(b"=").decode()
            params["code_challenge"] = challenge
            params["code_challenge_method"] = "S256"

        url = f"{self.authorize_url}?{urlencode(params)}"
        return url, state

    def _validate_callback_state(
        self, params: dict[str, str], expected_state: str
    ) -> None:
        """Reject the callback unless its state exactly matches the expected one."""
        if params.get("state") != expected_state:
            raise ValueError("OAuth state mismatch — possible CSRF attack")

    def exchange_code(
        self,
        code: str,
        redirect_uri: str,
        client_id: str,
        client_secret: str,
        scope: str | None = None,
        state: str | None = None,
    ) -> dict[str, str | int | None]:
        """Exchange authorization code for tokens. Returns flat token dict."""
        data: dict[str, str] = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "client_secret": client_secret,
        }

        lookup_state = state or self._last_state
        if self.use_pkce and lookup_state and lookup_state in self._pending_verifiers:
            data["code_verifier"] = self._pending_verifiers.pop(lookup_state)

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
            try:
                token_data = resp.json()
            except (ValueError, json.JSONDecodeError) as exc:
                raise TokenExchangeError(
                    url=self.token_url,
                    status_code=resp.status_code,
                    body=f"Invalid JSON in token response: {resp.text[:200]}",
                ) from exc

        if "access_token" not in token_data:
            raise TokenExchangeError(
                url=self.token_url,
                status_code=resp.status_code,
                body=f"Missing access_token in response: {str(token_data)[:200]}",
            )

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
            try:
                token_data = resp.json()
            except (ValueError, json.JSONDecodeError) as exc:
                raise TokenRefreshError(
                    url=self.token_url,
                    status_code=resp.status_code,
                    body=f"Invalid JSON in refresh response: {resp.text[:200]}",
                ) from exc

        if "access_token" not in token_data:
            raise TokenRefreshError(
                url=self.token_url,
                status_code=resp.status_code,
                body=f"Missing access_token in refresh response: {str(token_data)[:200]}",
            )

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
        callback_server: CallbackServerFactory | None = None,
    ) -> dict[str, str | int | None]:
        """Run the full authorization code flow end-to-end. Returns flat token dict."""
        factory = resolve_callback_factory(
            redirect_mode=redirect_mode,
            callback_server=callback_server,
            instance_default=self._callback_server,
            metadata=self._metadata,
        )
        server = factory()
        url, state = self.build_authorize_url(
            client_id=client_id,
            redirect_uri=server.redirect_uri,
            scope=scope,
        )
        params = server.obtain_callback(url)
        self._validate_callback_state(params, state)
        if "error" in params:
            raise AuthorizationDeniedError(
                error=params["error"],
                description=params.get("error_description", ""),
            )
        if "code" not in params or params["code"] is None:
            raise MalformedCallbackError("OAuth2 callback missing 'code'")
        return self.exchange_code(
            code=params["code"],
            redirect_uri=server.redirect_uri,
            client_id=client_id,
            client_secret=client_secret,
            scope=scope,
            state=state,
        )
