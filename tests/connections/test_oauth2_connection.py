"""Tests for OAuth2Connection."""
from __future__ import annotations

import time
import typing as t
from contextlib import contextmanager

import pytest

from mountainash_auth_client.errors import AuthorizationRequired
from mountainash_auth_client.connections.oauth2.connection import OAuth2Connection
from mountainash_settings.secrets.registry import (
    clear_secrets_registry,
    register_secrets_backend,
)


class _InMemoryBackend:
    def __init__(self):
        self._store: dict[str, dict[str, t.Any]] = {}

    def get(self, key: str) -> dict[str, t.Any] | None:
        return self._store.get(key)

    def set(self, key: str, data: dict[str, t.Any]) -> None:
        self._store[key] = data

    def delete(self, key: str) -> None:
        self._store.pop(key, None)

    @contextmanager
    def transaction(self, key: str):
        yield


class FakeSpec:
    name = "testprovider"

    @property
    def metadata(self):
        return {
            "authorize_url": "https://auth.example.com/authorize",
            "token_url": "https://auth.example.com/token",
        }


class FakeAuth:
    CLIENT_ID = "cid"
    CLIENT_SECRET = property(lambda self: type("S", (), {"get_secret_value": lambda s: "csec"})())
    SCOPE = "read"
    SETTINGS_SOURCE_SECRETS_PROVIDER = "test_mem"

    def persist_key(self):
        return "test.oauth2"


class FakeProvider(OAuth2Connection):
    _spec = FakeSpec()
    _base_url = "https://api.example.com"
    _client = None

    def disconnect(self):
        if self._client:
            self._client.close()
        self._client = None


@pytest.fixture(autouse=True)
def clean():
    clear_secrets_registry()
    yield
    clear_secrets_registry()


@pytest.fixture
def backend():
    b = _InMemoryBackend()
    register_secrets_backend("test_mem", b)
    return b


class TestOAuth2ConnectionNoToken:
    def test_raises_authorization_required_when_no_token(self, backend):
        provider = FakeProvider()
        with pytest.raises(AuthorizationRequired) as exc_info:
            provider.connect(FakeAuth())
        assert exc_info.value.provider == "testprovider"


class TestOAuth2ConnectionWithToken:
    def test_connects_with_valid_stored_token(self, backend):
        backend.set("test.oauth2", {
            "access_token": "tok_abc",
            "refresh_token": "refresh_xyz",
            "token_expires_at": int(time.time()) + 3600,
        })
        provider = FakeProvider()
        result = provider.connect(FakeAuth())
        assert result is provider

    def test_client_is_set_after_connect(self, backend):
        backend.set("test.oauth2", {
            "access_token": "tok_abc",
            "refresh_token": "refresh_xyz",
            "token_expires_at": int(time.time()) + 3600,
        })
        provider = FakeProvider()
        provider.connect(FakeAuth())
        assert provider._client is not None

    def test_client_has_bearer_auth_header(self, backend):
        backend.set("test.oauth2", {
            "access_token": "tok_abc",
            "refresh_token": "refresh_xyz",
            "token_expires_at": int(time.time()) + 3600,
        })
        provider = FakeProvider()
        provider.connect(FakeAuth())
        auth_header = provider._client.headers.get("authorization", "")
        assert "Bearer tok_abc" in auth_header

    def test_connect_with_unexpired_token_no_refresh(self, backend):
        backend.set("test.oauth2", {
            "access_token": "valid_tok",
            "refresh_token": "old_refresh",
            "token_expires_at": int(time.time()) + 7200,
        })
        provider = FakeProvider()
        provider.connect(FakeAuth())
        loaded = backend.get("test.oauth2")
        assert loaded["access_token"] == "valid_tok"


class TestOAuth2ConnectionExpiredToken:
    def test_raises_authorization_required_when_token_expired_and_no_refresh(self, backend):
        backend.set("test.oauth2", {
            "access_token": "old_tok",
            "refresh_token": None,
            "token_expires_at": int(time.time()) - 1000,
        })
        provider = FakeProvider()
        with pytest.raises(AuthorizationRequired):
            provider.connect(FakeAuth())


class TestConnectBuildsBearerClient:
    def test_connect_uses_resolved_token_for_bearer_header(self, backend):
        from unittest.mock import patch
        with patch(
            "mountainash_auth_client.connections.oauth2.connection.OAuthFlow"
        ) as flow_cls:
            flow_cls.return_value.resolve_access_token.return_value = "resolved_tok"
            provider = FakeProvider()
            provider.connect(FakeAuth())
        assert "Bearer resolved_tok" in provider._client.headers.get("authorization", "")

    def test_connect_forwards_callback_server_to_resolver(self, backend):
        # The connection→resolver forwarding seam (was previously asserted by the
        # now-relocated TestCallbackServerPassthrough). connect() must thread
        # callback_server into resolve_access_token.
        from unittest.mock import patch
        sentinel = object()
        with patch(
            "mountainash_auth_client.connections.oauth2.connection.OAuthFlow"
        ) as flow_cls:
            flow_cls.return_value.resolve_access_token.return_value = "tok"
            provider = FakeProvider()
            provider.connect(FakeAuth(), auto_authorize=True, callback_server=sentinel)
            _, kwargs = flow_cls.return_value.resolve_access_token.call_args
        assert kwargs["callback_server"] is sentinel


class TestClientProperty:
    def test_client_property_exposes_httpx_client(self):
        import httpx
        provider = FakeProvider()
        mock_client = httpx.Client()
        provider._client = mock_client
        assert provider.client is mock_client
        mock_client.close()

    def test_client_property_none_before_connect(self):
        provider = FakeProvider()
        assert provider.client is None


