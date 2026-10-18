from __future__ import annotations

import hashlib
import base64
import json
import secrets
import time
from copy import deepcopy
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Literal, cast, overload
from urllib.parse import urlencode

import httpx

from mountainash_auth_client.errors import (
    AuthorizationDeniedError,
    AuthorizationRequired,
    MalformedCallbackError,
    TokenExchangeError,
    TokenRefreshError,
)
from mountainash_auth_client.oauth.server.factory import resolve_callback_factory
from mountainash_auth_client.oauth.persistence import token_store as oauth_token_store
from mountainash_auth_client.oauth.records import read_oauth2_record, token_record

if TYPE_CHECKING:
    from mountainash_settings.secrets import ClearableSecretStore, JSONValue
    from mountainash_auth_client.oauth.lifecycle.credential import TokenCredential
    from mountainash_auth_client.oauth.persistence import OAuth2CredentialProfile, PersistableAuthProfile
    from mountainash_auth_client.oauth.records import OAuth2Tokens
    from mountainash_auth_client.oauth.providers.protocols import OAuth2ProviderProfileProtocol
    from mountainash_auth_client.oauth.protocols import CallbackServerFactory


@dataclass(frozen=True)
class OAuth2Context:
    """One wire operation's identity and detached consumer-owned attempt data."""

    grant_type: Literal["authorization_code", "refresh_token"]
    client_id: str | None
    redirect_uri: str | None
    scope: str | None
    state: str | None
    registration: dict[str, JSONValue] = field(default_factory=dict, repr=False)
    session_metadata: dict[str, JSONValue] = field(default_factory=dict, repr=False)
    data: dict[str, object] = field(default_factory=dict, repr=False)


class OAuthFlow:
    """Runs OAuth 2.0 Authorization Code flow for an OAuth2 provider."""

    def __init__(
        self,
        provider: OAuth2ProviderProfileProtocol,
        *,
        token_store: ClearableSecretStore | None = None,
        callback_server: CallbackServerFactory | None = None,
    ) -> None:
        self._provider = provider
        self._token_store = token_store
        self._pending_verifiers: dict[str, str] = {}
        self._pending_contexts: dict[str, OAuth2Context] = {}
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

    def authorization_parameters(self, context: OAuth2Context) -> dict[str, str]:
        """Return additional authorization query fields; generated fields are reserved."""
        return {}

    def token_parameters(self, context: OAuth2Context) -> dict[str, str]:
        """Return additional exchange/refresh body fields."""
        return {}

    def process_callback(
        self, params: dict[str, str], context: OAuth2Context,
    ) -> tuple[str | None, dict[str, JSONValue]]:
        """Select the issued client identity and approved non-secret registration."""
        return context.client_id, context.registration

    def validate_token_response(
        self, response: dict[str, JSONValue], context: OAuth2Context,
        previous: OAuth2Tokens | None, candidate: OAuth2Tokens,
    ) -> OAuth2Tokens:
        """Validate raw identity material and return only approved token fields."""
        return candidate

    def validate_credential(self, credential: TokenCredential) -> None:
        """Apply consumer operation policy after trust validation and persistence."""

    def revoke_remote(self, record: OAuth2Tokens) -> bool:
        """Revoke remotely if supported by the consumer; use bounded request timeouts."""
        return False

    @staticmethod
    def _context(
        grant_type: Literal["authorization_code", "refresh_token"],
        client_id: str | None, redirect_uri: str | None, scope: str | None,
        state: str | None, previous: OAuth2Tokens | None,
    ) -> OAuth2Context:
        return OAuth2Context(
            grant_type, client_id, redirect_uri, scope, state,
            registration=deepcopy(previous.get("registration", {})) if previous else {},
            session_metadata=deepcopy(previous.get("session_metadata", {})) if previous else {},
        )

    @staticmethod
    def _extend_parameters(params: dict[str, str], extra: dict[str, str]) -> None:
        reserved = {
            "state", "code_challenge", "code_challenge_method", "code_verifier",
            "code", "grant_type", "redirect_uri", "client_id", "client_secret",
            "response_type", "refresh_token",
        }
        if reserved.intersection(extra):
            raise ValueError("OAuth extension parameter collides with a generated field")
        params.update(extra)

    def build_authorize_url(
        self,
        client_id: str,
        redirect_uri: str,
        scope: str | None = None,
        *,
        previous: OAuth2Tokens | None = None,
    ) -> tuple[str, str]:
        """Build the authorization URL and generate state token."""
        if not isinstance(client_id, str) or not client_id:
            raise ValueError("OAuth2 authorization requires a non-empty client_id")
        state = secrets.token_urlsafe(32)
        prior = read_oauth2_record(token_record(previous)) if previous is not None else None
        params: dict[str, str] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "state": state,
        }
        effective_scope = self.default_scope if scope is None else scope
        if effective_scope is not None:
            params["scope"] = effective_scope

        if self.use_pkce:
            verifier = secrets.token_urlsafe(64)
            challenge = base64.urlsafe_b64encode(
                hashlib.sha256(verifier.encode()).digest()
            ).rstrip(b"=").decode()
            params["code_challenge"] = challenge
            params["code_challenge_method"] = "S256"

        context = self._context("authorization_code", client_id, redirect_uri, effective_scope, state, prior)
        self._extend_parameters(params, self.authorization_parameters(context))
        self._pending_contexts[state] = replace(context, scope=params.get("scope"))
        if self.use_pkce:
            self._pending_verifiers[state] = verifier
        self._last_state = state
        url = f"{self.authorize_url}?{urlencode(params)}"
        return url, state

    def _validate_callback_state(
        self, params: dict[str, str], expected_state: str
    ) -> None:
        """Reject the callback unless its state exactly matches the expected one."""
        if params.get("state") != expected_state:
            raise ValueError("OAuth state mismatch — possible CSRF attack")

    def _build_token_request(self, base_data: dict, client_id, client_secret) -> dict:
        """Return kwargs for httpx post: shaped by the provider's client-auth config.

        Defaults reproduce today's behaviour exactly: client_secret_post + form body + no headers.
        """
        method = getattr(self._provider, "TOKEN_ENDPOINT_AUTH_METHOD", "client_secret_post")
        headers = dict(getattr(self._provider, "TOKEN_REQUEST_HEADERS", None) or {})
        content_type = getattr(self._provider, "TOKEN_REQUEST_CONTENT_TYPE",
                               "application/x-www-form-urlencoded")
        data = dict(base_data)
        if method == "client_secret_post":
            if client_id is not None:
                data["client_id"] = client_id
            if client_secret is not None:
                data["client_secret"] = client_secret
        elif method == "client_secret_basic":
            token = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
            headers["Authorization"] = f"Basic {token}"
        elif method == "none":
            if client_id is not None:
                data["client_id"] = client_id
        else:
            raise ValueError(f"unknown TOKEN_ENDPOINT_AUTH_METHOD: {method}")
        kwargs: dict = {}
        if content_type == "application/json":
            kwargs["json"] = data
        else:
            kwargs["data"] = data
        if headers:
            kwargs["headers"] = headers
        return kwargs

    def exchange_code(
        self,
        code: str,
        redirect_uri: str,
        client_id: str | None = None,
        client_secret: str | None = None,
        scope: str | None = None,
        state: str | None = None,
        *,
        previous: OAuth2Tokens | None = None,
    ) -> OAuth2Tokens:
        """Exchange a code and validate the raw response before returning approved tokens."""
        prior = read_oauth2_record(token_record(previous)) if previous is not None else None
        base_data: dict[str, str] = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
        }

        lookup_state = state or self._last_state
        context = self._pending_contexts.pop(lookup_state, None) if lookup_state else None
        if context is None:
            context = self._context(
                "authorization_code", client_id, redirect_uri,
                self.default_scope if scope is None else scope, state, prior,
            )
        context = replace(context, client_id=client_id if client_id is not None else context.client_id,
                          redirect_uri=redirect_uri)
        if self.use_pkce and lookup_state and lookup_state in self._pending_verifiers:
            base_data["code_verifier"] = self._pending_verifiers.pop(lookup_state)

        self._extend_parameters(base_data, self.token_parameters(context))
        post_kwargs = self._build_token_request(base_data, context.client_id, client_secret)
        with httpx.Client() as client:
            try:
                resp = client.post(self.token_url, **post_kwargs)
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

        if not isinstance(token_data, dict) or "access_token" not in token_data:
            raise TokenExchangeError(
                url=self.token_url,
                status_code=resp.status_code,
                body=f"Missing access_token in response: {str(token_data)[:200]}",
            )

        expires_at: int | None = None
        if "expires_in" in token_data:
            expires_at = int(time.time()) + int(token_data["expires_in"])
        if expires_at is None:
            from mountainash_auth_client.oauth.lifecycle.status import jwt_exp
            expires_at = jwt_exp(token_data["access_token"])

        candidate: OAuth2Tokens = {
            "access_token": token_data["access_token"],
            "refresh_token": token_data.get("refresh_token", ""),
            "token_expires_at": expires_at,
            "scope": token_data.get("scope", context.scope),
            "client_id": context.client_id,
            "registration": deepcopy(context.registration),
            "session_metadata": {},
        }
        approved = self.validate_token_response(token_data, context, prior, candidate)
        return read_oauth2_record(token_record(approved))

    def refresh(
        self,
        refresh_token: str,
        client_id: str | None = None,
        client_secret: str | None = None,
        *,
        previous: OAuth2Tokens | None = None,
    ) -> OAuth2Tokens:
        """Refresh tokens, retaining the prior accepted grant when omitted."""
        prior = read_oauth2_record(token_record(previous)) if previous is not None else None
        if client_id is None and prior is not None:
            client_id = prior.get("client_id")
        context = self._context("refresh_token", client_id, None, prior.get("scope") if prior else None, None, prior)
        base_data = {"grant_type": "refresh_token", "refresh_token": refresh_token}
        self._extend_parameters(base_data, self.token_parameters(context))
        post_kwargs = self._build_token_request(base_data, client_id, client_secret)
        with httpx.Client() as client:
            try:
                resp = client.post(self.token_url, **post_kwargs)
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

        if not isinstance(token_data, dict) or "access_token" not in token_data:
            raise TokenRefreshError(
                url=self.token_url,
                status_code=resp.status_code,
                body=f"Missing access_token in refresh response: {str(token_data)[:200]}",
            )

        expires_at: int | None = None
        if "expires_in" in token_data:
            expires_at = int(time.time()) + int(token_data["expires_in"])
        if expires_at is None:
            from mountainash_auth_client.oauth.lifecycle.status import jwt_exp
            expires_at = jwt_exp(token_data["access_token"])

        candidate: OAuth2Tokens = {
            **deepcopy(prior or {}),
            "access_token": token_data["access_token"],
            "refresh_token": token_data.get("refresh_token", refresh_token),
            "token_expires_at": expires_at,
            "scope": token_data.get("scope", prior.get("scope") if prior else None),
            "client_id": client_id,
        }
        approved = self.validate_token_response(token_data, context, prior, candidate)
        return read_oauth2_record(token_record(approved))

    @staticmethod
    def is_expired(token_expires_at: int | None, buffer_seconds: int = 300) -> bool:
        """Check if the access token is expired or about to expire."""
        if token_expires_at is None:
            return False
        return time.time() >= (token_expires_at - buffer_seconds)

    @overload
    def resolve_access_token(
        self, auth_profile: PersistableAuthProfile, *, auto_authorize: Literal[False] = False,
        callback_server: CallbackServerFactory | None = None, force: bool = False,
    ) -> str: ...

    @overload
    def resolve_access_token(
        self, auth_profile: OAuth2CredentialProfile, *, auto_authorize: Literal[True],
        callback_server: CallbackServerFactory | None = None, force: bool = False,
    ) -> str: ...

    @overload
    def resolve_access_token(
        self, auth_profile: OAuth2CredentialProfile, *, auto_authorize: bool,
        callback_server: CallbackServerFactory | None = None, force: bool = False,
    ) -> str: ...

    def resolve_access_token(
        self,
        auth_profile: PersistableAuthProfile,
        *,
        auto_authorize: bool = False,
        callback_server: CallbackServerFactory | None = None,
        force: bool = False,
    ) -> str:
        """Resolve a valid access token: cached → refresh → authorize → persist.

        Client construction is the caller's responsibility. Raises
        ``AuthorizationRequired`` when no usable token exists and
        ``auto_authorize`` is False. Uses the fail-closed ``if not
        access_token`` guard — an empty cached token is never returned.
        Pass ``force=True`` to skip the is_expired check and unconditionally
        hit the token endpoint (used by force_refresh).
        """
        provider = self._provider.NAME
        if self._token_store is None:
            raise RuntimeError("OAuth persistence requires token_store")
        backend = oauth_token_store(self._token_store)
        key = auth_profile.persist_key()
        access_token: str | None = None

        with backend.transaction(key):
            cleared = backend.is_cleared(key)
            record = None if cleared else backend.get(key)
            tokens = read_oauth2_record(record) if record else None
            refresh_token = tokens.get("refresh_token") if tokens else None
            if tokens and not force and not self.is_expired(tokens.get("token_expires_at")):
                access_token = tokens["access_token"]
            elif tokens and refresh_token:
                _method = getattr(self._provider, "TOKEN_ENDPOINT_AUTH_METHOD", "client_secret_post")
                # A saved issued identity takes precedence over bootstrap configuration.
                # Key-only public clients retain their historical identity-free refresh.
                _cid = tokens.get("client_id") or getattr(auth_profile, "CLIENT_ID", None)
                if _method == "none":
                    _csec = None
                else:
                    credentials = cast("OAuth2CredentialProfile", auth_profile)
                    _csec = credentials.CLIENT_SECRET.get_secret_value() if credentials.CLIENT_SECRET else None
                try:
                    new_tokens = self.refresh(
                        refresh_token=refresh_token,
                        client_id=_cid,
                        client_secret=_csec,
                        previous=tokens,
                    )
                except TokenRefreshError as exc:
                    if exc.error_code in {"invalid_grant", "invalid_token"}:
                        backend.delete(key)
                        if not auto_authorize:
                            raise AuthorizationRequired(provider=provider, user="default")
                        # auto_authorize: record cleared, no raise — access_token stays
                        # None so control falls through to the re-authorize tail below.
                    else:
                        raise  # transient/server error: keep the record, surface retryably
                except Exception:
                    raise  # network/parse error: never destroy a valid refresh token
                else:
                    backend.set(key, token_record(new_tokens))
                    access_token = new_tokens["access_token"]

        if not access_token and auto_authorize:
            # The interactive overload guarantees this refinement, without inspecting
            # unrelated credential attributes on the cached-token path.
            credentials = cast("OAuth2CredentialProfile", auth_profile)
            client_id = credentials.CLIENT_ID
            if not isinstance(client_id, str) or not client_id:
                raise ValueError("OAuth2 authorization requires a non-empty client_id")
            _method = getattr(self._provider, "TOKEN_ENDPOINT_AUTH_METHOD", "client_secret_post")
            if _method == "none":
                _csec = None
            else:
                _csec = credentials.CLIENT_SECRET.get_secret_value() if credentials.CLIENT_SECRET else None
            new_tokens = self.authorize(
                client_id=client_id,
                client_secret=_csec,
                scope=credentials.SCOPE,
                callback_server=callback_server,
            )
            with backend.transaction(key):
                backend.set(key, token_record(new_tokens))
            access_token = new_tokens["access_token"]

        # Fail closed: no usable token — nothing cached/refreshed, authorize
        # disabled, OR authorize itself returned an empty token → raise.
        if not access_token:
            raise AuthorizationRequired(provider=provider, user="default")

        return access_token

    def force_refresh(self, auth_profile: PersistableAuthProfile) -> str:
        """Unconditionally exchange the stored refresh token at the token endpoint
        (ignoring is_expired), persist, and return the new access token — under the
        same per-key transaction, single-flight re-read, and error handling as
        resolve_access_token. Raises AuthorizationRequired when no refresh token is
        available to force with.
        """
        return self.resolve_access_token(auth_profile, auto_authorize=False, force=True)

    def authorize(
        self,
        client_id: str,
        client_secret: str | None,
        redirect_mode: Literal["local_server", "manual"] = "local_server",
        scope: str | None = None,
        callback_server: CallbackServerFactory | None = None,
        *,
        previous: OAuth2Tokens | None = None,
    ) -> OAuth2Tokens:
        """Run the full authorization code flow end-to-end. Returns flat token dict."""
        if not isinstance(client_id, str) or not client_id:
            raise ValueError("OAuth2 authorization requires a non-empty client_id")
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
            previous=previous,
        )
        try:
            params = server.obtain_callback(url)
            self._validate_callback_state(params, state)
            if "error" in params:
                raise AuthorizationDeniedError(
                    error=params["error"],
                    description=params.get("error_description", ""),
                )
            if not params.get("code"):
                raise MalformedCallbackError("OAuth2 callback missing 'code'")
            context = self._pending_contexts[state]
            effective_id, registration = self.process_callback(params, context)
            self._pending_contexts[state] = replace(
                context, client_id=effective_id, registration=deepcopy(registration),
            )
            return self.exchange_code(
                code=params["code"],
                redirect_uri=server.redirect_uri,
                client_id=effective_id,
                client_secret=client_secret,
                scope=scope,
                state=state,
                previous=previous,
            )
        finally:
            self._pending_contexts.pop(state, None)
            self._pending_verifiers.pop(state, None)
