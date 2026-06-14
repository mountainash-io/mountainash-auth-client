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
    AuthorizationRequired,
    MalformedCallbackError,
    TokenExchangeError,
    TokenRefreshError,
)
from mountainash_auth_client.connections.server.factory import resolve_callback_factory
from mountainash_settings.secrets.registry import get_secrets_backend

if TYPE_CHECKING:
    from mountainash_auth_client.providers.oauth2 import OAuth2ProviderProfile
    from mountainash_auth_client.connections.protocols import CallbackServerFactory


class OAuthFlow:
    """Runs OAuth 2.0 Authorization Code flow for an OAuth2 provider."""

    def __init__(
        self,
        provider: OAuth2ProviderProfile,
        *,
        callback_server: CallbackServerFactory | None = None,
    ) -> None:
        self._provider = provider
        self._pending_verifiers: dict[str, str] = {}
        self._last_state: str | None = None
        self._callback_server = callback_server

    @property
    def authorize_url(self) -> str:
        return self._provider.AUTHORIZE_URL

    @property
    def token_url(self) -> str:
        return self._provider.TOKEN_URL

    @property
    def use_pkce(self) -> bool:
        return self._provider.USE_PKCE

    @property
    def default_scope(self) -> str | None:
        return self._provider.DEFAULT_SCOPE

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

    def resolve_access_token(
        self,
        auth_profile,
        *,
        auto_authorize: bool = False,
        callback_server: CallbackServerFactory | None = None,
    ) -> str:
        """Resolve a valid access token: cached → refresh → authorize → persist.

        Client construction is the caller's responsibility. Raises
        ``AuthorizationRequired`` when no usable token exists and
        ``auto_authorize`` is False. Uses the fail-closed ``if not
        access_token`` guard — an empty cached token is never returned.
        """
        provider = self._provider.NAME
        backend = get_secrets_backend(auth_profile.SETTINGS_SOURCE_SECRETS_PROVIDER)
        key = auth_profile.persist_key()
        tokens = backend.get(key)

        access_token: str | None = None

        if tokens and not self.is_expired(tokens.get("token_expires_at")):
            access_token = tokens["access_token"]
        elif tokens and tokens.get("refresh_token"):
            with backend.transaction(key):
                tokens = backend.get(key)
                if tokens and not self.is_expired(tokens.get("token_expires_at")):
                    access_token = tokens["access_token"]
                else:
                    try:
                        new_tokens = self.refresh(
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

        if not access_token and auto_authorize:
            new_tokens = self.authorize(
                client_id=auth_profile.CLIENT_ID,
                client_secret=auth_profile.CLIENT_SECRET.get_secret_value(),
                scope=auth_profile.SCOPE,
                callback_server=callback_server,
            )
            backend.set(key, new_tokens)
            access_token = new_tokens["access_token"]

        # Fail closed: no usable token — nothing cached/refreshed, authorize
        # disabled, OR authorize itself returned an empty token → raise.
        if not access_token:
            raise AuthorizationRequired(provider=provider, user="default")

        return access_token

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
            callback_port=self._provider.CALLBACK_PORT,
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
