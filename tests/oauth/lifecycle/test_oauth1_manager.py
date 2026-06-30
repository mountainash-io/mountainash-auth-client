from __future__ import annotations

from unittest.mock import patch

import pytest

from mountainash_auth_client.oauth.lifecycle.oauth1 import OAuth1TokenManager
from mountainash_auth_client.oauth.lifecycle.status import TokenState
from mountainash_auth_client.oauth.providers.oauth1 import OAuth1ProviderProfile
from mountainash_secrets import InMemorySecretStore, NamespacedSecretStore, SecretRegistryResolver


def _provider():
    return OAuth1ProviderProfile(
        NAME="garmin",
        REQUEST_TOKEN_URL="https://auth.example.com/request_token",
        AUTHORIZE_URL="https://auth.example.com/authorize",
        ACCESS_TOKEN_URL="https://auth.example.com/access_token",
        BASE_URL="https://api.example.com",
    )


class _Auth:
    CONSUMER_KEY = "ck"
    CONSUMER_SECRET = property(
        lambda self: type("S", (), {"get_secret_value": lambda s: "cs"})()
    )
    SETTINGS_SOURCE_SECRETS_PROVIDER = "mem"

    def persist_key(self) -> str:
        return "garmin.default"


def _env():
    store = InMemorySecretStore()
    return (
        OAuth1TokenManager(_provider(), _Auth(), resolver=SecretRegistryResolver({"mem": store})),
        NamespacedSecretStore(store, "oauth"),
    )


def test_status_missing_then_present_then_cleared():
    mgr, tokens = _env()
    assert mgr.status().state is TokenState.MISSING
    tokens.set("garmin.default", {"oauth_token": "AT", "oauth_token_secret": "ATS"})
    s = mgr.status()
    assert s.state is TokenState.PRESENT
    # OAuth1 invariants:
    assert s.expires_at is None and s.expires_in_seconds is None and s.has_refresh_token is False
    mgr.revoke()
    assert mgr.status().state is TokenState.CLEARED


def test_token_pair_returns_seeded():
    mgr, tokens = _env()
    tokens.set("garmin.default", {"oauth_token": "AT", "oauth_token_secret": "ATS"})
    assert mgr.token_pair() == ("AT", "ATS")


def test_token_pair_raises_when_missing():
    from mountainash_auth_client.errors import AuthorizationRequired

    mgr, _ = _env()
    with pytest.raises(AuthorizationRequired):
        mgr.token_pair()


def test_acquire_auth_returns_httpx_auth(monkeypatch):
    OAuth1Auth = pytest.importorskip("authlib.integrations.httpx_client").OAuth1Auth
    mgr, _ = _env()
    monkeypatch.setattr(type(mgr), "token_pair", lambda self: ("tok", "tok_secret"))
    auth = mgr.acquire_auth()
    assert isinstance(auth, OAuth1Auth)


def test_authorize_persists_and_returns_present():
    mgr, tokens = _env()
    with patch.object(
        type(mgr)._flow_cls(), "authorize",
        return_value={"oauth_token": "newAT", "oauth_token_secret": "newATS"},
    ):
        status = mgr.authorize()
    assert status.state is TokenState.PRESENT
    assert tokens.get("garmin.default")["oauth_token"] == "newAT"
