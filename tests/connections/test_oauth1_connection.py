"""Tests for OAuth1Connection."""
from __future__ import annotations

import typing as t
from contextlib import contextmanager

import pytest

from mountainash_auth_client.connections.oauth1.connection import OAuth1Connection
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
    name = "testprovider_oauth1"

    @property
    def metadata(self):
        return {
            "request_token_url": "https://auth.example.com/request_token",
            "authorize_url": "https://auth.example.com/authorize",
            "access_token_url": "https://auth.example.com/access_token",
        }


class FakeAuth:
    CONSUMER_KEY = "consumer_key"
    CONSUMER_SECRET = property(
        lambda self: type("S", (), {"get_secret_value": lambda s: "consumer_secret"})()
    )
    SETTINGS_SOURCE_SECRETS_PROVIDER = "test_mem_oauth1"

    def persist_key(self):
        return "test.oauth1"


class FakeProvider(OAuth1Connection):
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
    register_secrets_backend("test_mem_oauth1", b)
    return b


class TestConnectUsesResolver:
    def test_connect_builds_client_from_resolved_pair(self, monkeypatch, backend):
        captured = {}

        def fake_resolve(self, auth_profile, *, auto_authorize=False, callback_server=None):
            captured["callback_server"] = callback_server
            return ("AT", "ATS")

        monkeypatch.setattr(
            "mountainash_auth_client.connections.oauth1.flow.OAuth1Flow.resolve_token_pair",
            fake_resolve,
        )
        built = {}
        monkeypatch.setattr(
            FakeProvider, "_build_client",
            lambda self, tokens, auth: built.update(tokens),
        )
        sentinel = object()
        provider = FakeProvider()
        provider.connect(FakeAuth(), auto_authorize=True, callback_server=sentinel)
        assert built == {"oauth_token": "AT", "oauth_token_secret": "ATS"}
        assert captured["callback_server"] is sentinel
