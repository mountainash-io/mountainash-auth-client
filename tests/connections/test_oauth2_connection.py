"""Tests for the parameterised OAuth2Connection."""
from __future__ import annotations

import time
import typing as t
from contextlib import contextmanager
from unittest.mock import patch

import pytest

from mountainash_auth_client.errors import AuthorizationRequired
from mountainash_auth_client.connections.oauth2.connection import OAuth2Connection
from mountainash_auth_client.providers.oauth2 import OAuth2ProviderProfile
from mountainash_settings.secrets.registry import (
    clear_secrets_registry,
    register_secrets_backend,
)


class _InMemoryBackend:
    def __init__(self):
        self._store: dict[str, dict[str, t.Any]] = {}

    def get(self, key):
        return self._store.get(key)

    def set(self, key, data):
        self._store[key] = data

    def delete(self, key):
        self._store.pop(key, None)

    @contextmanager
    def transaction(self, key):
        yield


def _provider():
    return OAuth2ProviderProfile(
        NAME="testprovider",
        AUTHORIZE_URL="https://auth.example.com/authorize",
        TOKEN_URL="https://auth.example.com/token",
        BASE_URL="https://api.example.com",
    )


class FakeAuth:
    CLIENT_ID = "cid"
    CLIENT_SECRET = property(lambda self: type("S", (), {"get_secret_value": lambda s: "csec"})())
    SCOPE = "read"
    SETTINGS_SOURCE_SECRETS_PROVIDER = "test_mem"

    def persist_key(self):
        return "test.oauth2"


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


class TestNoToken:
    def test_raises_authorization_required_when_no_token(self, backend):
        conn = OAuth2Connection(_provider(), FakeAuth())
        with pytest.raises(AuthorizationRequired) as exc_info:
            conn.connect()
        assert exc_info.value.provider == "testprovider"


class TestWithToken:
    def _seed(self, backend):
        backend.set("test.oauth2", {
            "access_token": "tok_abc",
            "refresh_token": "refresh_xyz",
            "token_expires_at": int(time.time()) + 3600,
        })

    def test_connect_returns_self(self, backend):
        self._seed(backend)
        conn = OAuth2Connection(_provider(), FakeAuth())
        assert conn.connect() is conn

    def test_client_set_after_connect(self, backend):
        self._seed(backend)
        conn = OAuth2Connection(_provider(), FakeAuth())
        conn.connect()
        assert conn.client is not None

    def test_client_has_bearer_header(self, backend):
        self._seed(backend)
        conn = OAuth2Connection(_provider(), FakeAuth())
        conn.connect()
        assert "Bearer tok_abc" in conn.client.headers.get("authorization", "")

    def test_client_base_url_from_provider(self, backend):
        self._seed(backend)
        conn = OAuth2Connection(_provider(), FakeAuth())
        conn.connect()
        assert str(conn.client.base_url) == "https://api.example.com"


class TestExpiredToken:
    def test_raises_when_expired_and_no_refresh(self, backend):
        backend.set("test.oauth2", {
            "access_token": "old_tok",
            "refresh_token": None,
            "token_expires_at": int(time.time()) - 1000,
        })
        conn = OAuth2Connection(_provider(), FakeAuth())
        with pytest.raises(AuthorizationRequired):
            conn.connect()


class TestResolverSeam:
    def test_uses_resolved_token_for_bearer_header(self, backend):
        with patch(
            "mountainash_auth_client.connections.oauth2.connection.OAuthFlow"
        ) as flow_cls:
            flow_cls.return_value.resolve_access_token.return_value = "resolved_tok"
            conn = OAuth2Connection(_provider(), FakeAuth())
            conn.connect()
        assert "Bearer resolved_tok" in conn.client.headers.get("authorization", "")

    def test_forwards_auto_authorize_and_callback_server(self, backend):
        sentinel = object()
        with patch(
            "mountainash_auth_client.connections.oauth2.connection.OAuthFlow"
        ) as flow_cls:
            flow_cls.return_value.resolve_access_token.return_value = "tok"
            conn = OAuth2Connection(
                _provider(), FakeAuth(), auto_authorize=True, callback_server=sentinel)
            conn.connect()
            _, kwargs = flow_cls.return_value.resolve_access_token.call_args
        assert kwargs["auto_authorize"] is True
        assert kwargs["callback_server"] is sentinel


class TestClientProperty:
    def test_client_none_before_connect(self):
        conn = OAuth2Connection(_provider(), FakeAuth())
        assert conn.client is None

    def test_context_manager_closes_client(self, backend):
        backend.set("test.oauth2", {
            "access_token": "tok_abc", "refresh_token": "r",
            "token_expires_at": int(time.time()) + 3600,
        })
        with OAuth2Connection(_provider(), FakeAuth()).connect() as conn:
            assert conn.client is not None
        assert conn.client is None
