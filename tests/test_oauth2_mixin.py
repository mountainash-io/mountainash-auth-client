"""Tests for OAuth2ConnectionMixin."""
from __future__ import annotations

import time
import typing as t
from contextlib import contextmanager

import pytest

from mountainash_auth_client.errors import AuthorizationRequired
from mountainash_auth_client.mixins.oauth2 import OAuth2ConnectionMixin
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


class FakeProfile:
    def __init__(self, auth=None):
        self.auth = auth or FakeAuth()


class FakeProvider(OAuth2ConnectionMixin):
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


class TestOAuth2ConnectionMixinNoToken:
    def test_raises_authorization_required_when_no_token(self, backend):
        provider = FakeProvider()
        with pytest.raises(AuthorizationRequired) as exc_info:
            provider.connect(FakeProfile())
        assert exc_info.value.provider == "testprovider"


class TestOAuth2ConnectionMixinWithToken:
    def test_connects_with_valid_stored_token(self, backend):
        backend.set("test.oauth2", {
            "access_token": "tok_abc",
            "refresh_token": "refresh_xyz",
            "token_expires_at": int(time.time()) + 3600,
        })
        provider = FakeProvider()
        result = provider.connect(FakeProfile())
        assert result is provider

    def test_client_is_set_after_connect(self, backend):
        backend.set("test.oauth2", {
            "access_token": "tok_abc",
            "refresh_token": "refresh_xyz",
            "token_expires_at": int(time.time()) + 3600,
        })
        provider = FakeProvider()
        provider.connect(FakeProfile())
        assert provider._client is not None

    def test_client_has_bearer_auth_header(self, backend):
        backend.set("test.oauth2", {
            "access_token": "tok_abc",
            "refresh_token": "refresh_xyz",
            "token_expires_at": int(time.time()) + 3600,
        })
        provider = FakeProvider()
        provider.connect(FakeProfile())
        auth_header = provider._client.headers.get("authorization", "")
        assert "Bearer tok_abc" in auth_header

    def test_connect_with_unexpired_token_no_refresh(self, backend):
        backend.set("test.oauth2", {
            "access_token": "valid_tok",
            "refresh_token": "old_refresh",
            "token_expires_at": int(time.time()) + 7200,
        })
        provider = FakeProvider()
        provider.connect(FakeProfile())
        loaded = backend.get("test.oauth2")
        assert loaded["access_token"] == "valid_tok"


class TestOAuth2ConnectionMixinExpiredToken:
    def test_raises_authorization_required_when_token_expired_and_no_refresh(self, backend):
        backend.set("test.oauth2", {
            "access_token": "old_tok",
            "refresh_token": None,
            "token_expires_at": int(time.time()) - 1000,
        })
        provider = FakeProvider()
        with pytest.raises(AuthorizationRequired):
            provider.connect(FakeProfile())


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
