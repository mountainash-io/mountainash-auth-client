from __future__ import annotations

from unittest.mock import patch

import pytest

from mountainash_auth_client.oauth.lifecycle.oauth1 import OAuth1TokenManager
from mountainash_auth_client.oauth.lifecycle.status import TokenState
from mountainash_auth_client.oauth.providers.oauth1 import OAuth1ProviderProfile
from mountainash_settings.secrets import MemorySecretStore, NamespacedSecretStore


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

    def persist_key(self) -> str:
        return "garmin.default"


def _env():
    store = MemorySecretStore()
    return (
        OAuth1TokenManager(_provider(), _Auth(), token_store=store),
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


def test_interrupted_clear_blocks_credential(monkeypatch):
    from mountainash_auth_client.errors import AuthorizationRequired
    from mountainash_auth_client.oauth.oauth1.flow import OAuth1Flow

    class InterruptedClear(MemorySecretStore):
        def is_cleared(self, key):
            return True

        def get(self, key):
            raise AssertionError("cleared record was read")

    store = InterruptedClear()
    store.set("oauth.garmin.default", {
        "oauth_token": "must-not-return", "oauth_token_secret": "must-not-return",
    })
    manager = OAuth1TokenManager(_provider(), _Auth(), token_store=store)

    def forbidden(*args, **kwargs):
        raise AssertionError("cleared record reached endpoint")

    monkeypatch.setattr(OAuth1Flow, "authorize", forbidden)
    assert manager.status().state is TokenState.CLEARED
    for operation in (manager.token_pair, manager.acquire_auth):
        with pytest.raises(AuthorizationRequired):
            operation()


def test_selected_stores_are_isolated():
    first, first_tokens = _env()
    second, second_tokens = _env()
    first_tokens.set("garmin.default", {"oauth_token": "one", "oauth_token_secret": "s1"})
    second_tokens.set("garmin.default", {"oauth_token": "two", "oauth_token_secret": "s2"})
    assert first.token_pair() == ("one", "s1")
    assert second.token_pair() == ("two", "s2")
    first.revoke()
    assert second.token_pair() == ("two", "s2")


def test_revoke_then_authorize_returns_present():
    manager, _ = _env()
    manager.revoke()
    with patch.object(type(manager)._flow_cls(), "authorize", return_value={
        "oauth_token": "fresh", "oauth_token_secret": "secret",
    }):
        assert manager.authorize().state is TokenState.PRESENT
    assert manager.token_pair() == ("fresh", "secret")
