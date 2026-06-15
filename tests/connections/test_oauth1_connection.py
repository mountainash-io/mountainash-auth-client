"""Tests for the parameterised OAuth1Connection."""
from __future__ import annotations

import httpx
import pytest

from mountainash_auth_client.connections.oauth1.connection import OAuth1Connection
from mountainash_auth_client.providers.oauth1 import OAuth1ProviderProfile
from mountainash_secrets import InMemorySecretStore, SecretRegistryResolver


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


@pytest.fixture
def resolver():
    return SecretRegistryResolver({"test_mem_oauth1": InMemorySecretStore()})


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
    def test_connect_builds_signed_client_from_resolved_pair(self, monkeypatch, resolver):
        captured = {}

        def fake_resolve(self, auth_profile, *, auto_authorize=False, callback_server=None):
            # `self` is the OAuth1Flow instance connect() built; capturing its
            # resolver proves the connection forwarded resolver= into the flow
            # constructor (this test mocks resolve_token_pair, so the flow's own
            # None-guard can't catch a dropped forward — assert it directly).
            captured["flow_resolver"] = self._resolver
            captured["auto_authorize"] = auto_authorize
            captured["callback_server"] = callback_server
            return ("AT", "ATS")

        monkeypatch.setattr(
            "mountainash_auth_client.connections.oauth1.flow.OAuth1Flow.resolve_token_pair",
            fake_resolve,
        )

        def _stub_require_authlib(name):
            assert name == "OAuth1Auth"
            return _StubSigner

        monkeypatch.setattr(
            "mountainash_auth_client.schemas.oauth1.require_authlib",
            _stub_require_authlib,
        )
        sentinel = object()
        conn = OAuth1Connection(
            _provider(), FakeAuth(), resolver=resolver,
            auto_authorize=True, callback_server=sentinel)
        conn.connect()

        assert captured["flow_resolver"] is resolver
        assert captured["auto_authorize"] is True
        assert captured["callback_server"] is sentinel
        assert str(conn.client.base_url) == "https://api.example.com"
        assert isinstance(conn.client.auth, _StubSigner)
        assert conn.client.auth.kwargs["token"] == "AT"
        assert conn.client.auth.kwargs["token_secret"] == "ATS"

    def test_client_none_before_connect(self, resolver):
        conn = OAuth1Connection(_provider(), FakeAuth(), resolver=resolver)
        assert conn.client is None
