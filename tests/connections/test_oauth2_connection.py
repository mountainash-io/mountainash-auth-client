"""Tests for the parameterised OAuth2Connection."""
from __future__ import annotations

import time
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from mountainash_auth_client.errors import AuthorizationRequired
from mountainash_auth_client.connections.oauth2.connection import OAuth2Connection
from mountainash_auth_client.providers.oauth2 import OAuth2ProviderProfile
from mountainash_secrets import InMemoryStore, NamespacedStore, RegistryResolver


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


@pytest.fixture
def env():
    # `tokens` is the "oauth"-namespaced view the flow persists through.
    store = InMemoryStore()
    return SimpleNamespace(
        resolver=RegistryResolver({"test_mem": store}),
        tokens=NamespacedStore(store, "oauth"),
        store=store,
    )


class TestNoToken:
    def test_raises_authorization_required_when_no_token(self, env):
        conn = OAuth2Connection(_provider(), FakeAuth(), resolver=env.resolver)
        with pytest.raises(AuthorizationRequired) as exc_info:
            conn.connect()
        assert exc_info.value.provider == "testprovider"


class TestWithToken:
    def _seed(self, env):
        env.tokens.set("test.oauth2", {
            "access_token": "tok_abc",
            "refresh_token": "refresh_xyz",
            "token_expires_at": int(time.time()) + 3600,
        })

    def test_connect_returns_self(self, env):
        self._seed(env)
        conn = OAuth2Connection(_provider(), FakeAuth(), resolver=env.resolver)
        assert conn.connect() is conn

    def test_client_set_after_connect(self, env):
        self._seed(env)
        conn = OAuth2Connection(_provider(), FakeAuth(), resolver=env.resolver)
        conn.connect()
        assert conn.client is not None

    def test_client_has_bearer_header(self, env):
        self._seed(env)
        conn = OAuth2Connection(_provider(), FakeAuth(), resolver=env.resolver)
        conn.connect()
        assert "Bearer tok_abc" in conn.client.headers.get("authorization", "")

    def test_client_base_url_from_provider(self, env):
        self._seed(env)
        conn = OAuth2Connection(_provider(), FakeAuth(), resolver=env.resolver)
        conn.connect()
        assert str(conn.client.base_url) == "https://api.example.com"


class TestExpiredToken:
    def test_raises_when_expired_and_no_refresh(self, env):
        env.tokens.set("test.oauth2", {
            "access_token": "old_tok",
            "refresh_token": None,
            "token_expires_at": int(time.time()) - 1000,
        })
        conn = OAuth2Connection(_provider(), FakeAuth(), resolver=env.resolver)
        with pytest.raises(AuthorizationRequired):
            conn.connect()


class TestResolverSeam:
    def test_uses_resolved_token_for_bearer_header(self, env):
        with patch(
            "mountainash_auth_client.connections.oauth2.connection.OAuthFlow"
        ) as flow_cls:
            flow_cls.return_value.resolve_access_token.return_value = "resolved_tok"
            conn = OAuth2Connection(_provider(), FakeAuth(), resolver=env.resolver)
            conn.connect()
        assert "Bearer resolved_tok" in conn.client.headers.get("authorization", "")

    def test_forwards_auto_authorize_and_callback_server(self, env):
        sentinel = object()
        with patch(
            "mountainash_auth_client.connections.oauth2.connection.OAuthFlow"
        ) as flow_cls:
            flow_cls.return_value.resolve_access_token.return_value = "tok"
            conn = OAuth2Connection(
                _provider(), FakeAuth(), resolver=env.resolver,
                auto_authorize=True, callback_server=sentinel)
            conn.connect()
            _, kwargs = flow_cls.return_value.resolve_access_token.call_args
        assert kwargs["auto_authorize"] is True
        assert kwargs["callback_server"] is sentinel


class TestClientProperty:
    def test_client_none_before_connect(self, env):
        conn = OAuth2Connection(_provider(), FakeAuth(), resolver=env.resolver)
        assert conn.client is None

    def test_context_manager_closes_client(self, env):
        env.tokens.set("test.oauth2", {
            "access_token": "tok_abc", "refresh_token": "r",
            "token_expires_at": int(time.time()) + 3600,
        })
        with OAuth2Connection(
            _provider(), FakeAuth(), resolver=env.resolver).connect() as conn:
            assert conn.client is not None
        assert conn.client is None
