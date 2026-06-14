"""Tests for the parameterised OAuth1Connection."""
from __future__ import annotations

import typing as t
from contextlib import contextmanager

import httpx
import pytest

from mountainash_auth_client.connections.oauth1.connection import OAuth1Connection
from mountainash_auth_client.providers.oauth1 import OAuth1ProviderProfile
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
    return OAuth1ProviderProfile(
        NAME="testprovider_oauth1",
        REQUEST_TOKEN_URL="https://auth.example.com/request_token",
        AUTHORIZE_URL="https://auth.example.com/authorize",
        ACCESS_TOKEN_URL="https://auth.example.com/access_token",
        BASE_URL="https://api.example.com",
    )


class FakeAuth:
    CONSUMER_KEY = "consumer_key"
    CONSUMER_SECRET = property(
        lambda self: type("S", (), {"get_secret_value": lambda s: "consumer_secret"})()
    )
    SETTINGS_SOURCE_SECRETS_PROVIDER = "test_mem_oauth1"

    def persist_key(self):
        return "test.oauth1"


@pytest.fixture(autouse=True)
def clean():
    clear_secrets_registry()
    yield
    clear_secrets_registry()


@pytest.fixture
def backend():
    b = _InMemoryBackend()
    register_secrets_backend("test_mem_oauth1", b)
    return b


class _StubSigner(httpx.Auth):
    """A valid httpx auth object standing in for authlib's OAuth1Auth.

    authlib is an OPTIONAL `[oauth1]` extra and is NOT installed in the local
    dev venv, so the connection's real emit path (which calls
    `require_authlib("OAuth1Auth")` inside `_oauth1_signer`) would raise
    ImportError rather than build a client. Patching the `require_authlib`
    seam to return this stub lets the wiring (resolved pair -> emit -> client
    with provider base_url + an `auth` signer) be verified green in any env,
    while still exercising the genuine two-stage emit.
    """

    def __init__(self, **kwargs):
        self.kwargs = kwargs

    def auth_flow(self, request):
        yield request


class TestConnect:
    def test_connect_builds_signed_client_from_resolved_pair(self, monkeypatch, backend):
        captured = {}

        def fake_resolve(self, auth_profile, *, auto_authorize=False, callback_server=None):
            captured["auto_authorize"] = auto_authorize
            captured["callback_server"] = callback_server
            return ("AT", "ATS")

        monkeypatch.setattr(
            "mountainash_auth_client.connections.oauth1.flow.OAuth1Flow.resolve_token_pair",
            fake_resolve,
        )
        monkeypatch.setattr(
            "mountainash_auth_client.schemas.oauth1.require_authlib",
            lambda name: _StubSigner,
        )
        sentinel = object()
        conn = OAuth1Connection(
            _provider(), FakeAuth(), auto_authorize=True, callback_server=sentinel)
        conn.connect()

        assert captured["auto_authorize"] is True
        assert captured["callback_server"] is sentinel
        assert str(conn.client.base_url) == "https://api.example.com"
        assert isinstance(conn.client.auth, _StubSigner)
        assert conn.client.auth.kwargs["token"] == "AT"
        assert conn.client.auth.kwargs["token_secret"] == "ATS"

    def test_client_none_before_connect(self):
        conn = OAuth1Connection(_provider(), FakeAuth())
        assert conn.client is None
