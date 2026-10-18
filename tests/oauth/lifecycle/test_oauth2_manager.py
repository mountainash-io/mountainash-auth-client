from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from tempfile import TemporaryDirectory
from threading import Event
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from mountainash_auth_client.oauth.lifecycle.credential import TokenCredential
from mountainash_auth_client.oauth.lifecycle.oauth2 import OAuth2TokenManager
from mountainash_auth_client.oauth.lifecycle.status import TokenState
from mountainash_auth_client.oauth.providers.oauth2 import OAuth2ProviderProfile
from mountainash_auth_client.oauth.oauth2.flow import OAuthFlow
from mountainash_settings.secrets import FilesystemBackend, MemorySecretStore, NamespacedSecretStore


def _provider():
    return OAuth2ProviderProfile(
        NAME="testprovider",
        AUTHORIZE_URL="https://auth.example.com/authorize",
        TOKEN_URL="https://auth.example.com/token",
        BASE_URL="https://api.example.com",
    )


class _Auth:
    CLIENT_ID = "cid"
    CLIENT_SECRET = property(
        lambda self: type("S", (), {"get_secret_value": lambda s: "csec"})()
    )
    SCOPE = "read"

    def persist_key(self) -> str:
        return "testprovider.default"


class _Callback:
    redirect_uri = "http://localhost/callback"

    def obtain_callback(self, url):
        return {"code": "accepted", "state": parse_qs(urlsplit(url).query)["state"][0]}


def _authorization_endpoint(monkeypatch):
    requests = []
    client = httpx.Client

    def endpoint(request):
        requests.append(parse_qs(request.content.decode()))
        return httpx.Response(200, json={"access_token": "new", "refresh_token": "r", "expires_in": 3600})

    monkeypatch.setattr(httpx, "Client", lambda: client(transport=httpx.MockTransport(endpoint)))
    return requests


def _env():
    store = MemorySecretStore()
    return (
        OAuth2TokenManager(_provider(), _Auth(), token_store=store, callback_server=_Callback),
        NamespacedSecretStore(store, "oauth"),  # the "oauth"-namespaced view to seed/read
    )


def test_status_missing():
    mgr, _ = _env()
    assert mgr.status().state is TokenState.MISSING


def test_status_valid_and_expired_and_refresh_needed():
    mgr, tokens = _env()
    tokens.set("testprovider.default", {"access_token": "a", "token_expires_at": int(time.time()) + 4000})
    assert mgr.status().state is TokenState.VALID
    tokens.set("testprovider.default", {"access_token": "a", "token_expires_at": int(time.time()) - 10})
    assert mgr.status().state is TokenState.EXPIRED
    tokens.set("testprovider.default", {"access_token": "a", "refresh_token": "r", "token_expires_at": int(time.time()) + 100})
    assert mgr.status().state is TokenState.REFRESH_NEEDED


def test_revoke_then_status_cleared():
    mgr, tokens = _env()
    tokens.set("testprovider.default", {"access_token": "a"})
    mgr.revoke()
    assert mgr.status().state is TokenState.CLEARED


def test_access_token_returns_seeded():
    mgr, tokens = _env()
    tokens.set("testprovider.default", {"access_token": "tok", "token_expires_at": int(time.time()) + 4000})
    assert mgr.access_token() == "tok"


def test_refresh_raises_when_nothing_to_refresh():
    from mountainash_auth_client.errors import AuthorizationRequired

    mgr, _ = _env()
    with pytest.raises(AuthorizationRequired):
        mgr.refresh()


@pytest.mark.parametrize("revoked", [False, True])
def test_authorize_persists_and_returns_valid(monkeypatch, revoked):
    mgr, tokens = _env()
    if revoked:
        tokens.set("testprovider.default", {"access_token": "old"})
        mgr.revoke()
    _authorization_endpoint(monkeypatch)
    assert mgr.authorize().state is TokenState.VALID
    assert tokens.get("testprovider.default")["access_token"] == "new"
    assert not tokens.is_cleared("testprovider.default")


def test_authorize_manual_mode_uses_manual_callback_server(monkeypatch):
    mgr = OAuth2TokenManager(_provider(), _Auth(), token_store=MemorySecretStore())
    requests = _authorization_endpoint(monkeypatch)
    monkeypatch.setattr(
        "mountainash_auth_client.oauth.server.manual.prompt_for_code", _Callback().obtain_callback,
    )
    assert mgr.authorize(mode="manual", manual_redirect_uri="https://app.example/callback").state is TokenState.VALID
    assert requests[0]["redirect_uri"] == ["https://app.example/callback"]


def test_authorize_tolerates_missing_client_secret(monkeypatch):
    class _NoSecretAuth(_Auth):
        CLIENT_SECRET = None

    mgr = OAuth2TokenManager(
        _provider(), _NoSecretAuth(), token_store=MemorySecretStore(), callback_server=_Callback,
    )
    requests = _authorization_endpoint(monkeypatch)
    assert mgr.authorize().state is TokenState.VALID
    assert requests[0]["client_id"] == ["cid"]
    assert "client_secret" not in requests[0]


def test_acquire_returns_token_credential():
    mgr, tokens = _env()
    tokens.set("testprovider.default",
               {"access_token": "tok", "refresh_token": "rt",
                "token_expires_at": int(time.time()) + 4000})
    cred = mgr.acquire()
    assert isinstance(cred, TokenCredential)
    assert cred.access_token == "tok"
    assert cred.refresh_token == "rt"


def test_acquire_raises_when_no_token_non_interactive():
    from mountainash_auth_client.errors import AuthorizationRequired
    mgr, _ = _env()                      # empty store, no refresh token
    with pytest.raises(AuthorizationRequired):
        mgr.acquire()                    # must NOT launch interactive authorize


def test_refresh_forces_endpoint_call():
    """mgr.refresh() must unconditionally hit the token endpoint even when the
    stored token is not expired (i.e. it must call force_refresh, not a stale-check).
    """
    from mountainash_auth_client.oauth.oauth2.flow import OAuthFlow

    mgr, tokens = _env()
    # Seed a NON-expired token with a refresh_token.
    tokens.set("testprovider.default", {
        "access_token": "old_valid_tok",
        "refresh_token": "r_xyz",
        "token_expires_at": int(time.time()) + 4000,
    })
    with patch.object(OAuthFlow, "refresh", return_value={
        "access_token": "forced_new_tok",
        "refresh_token": "new_r",
        "token_expires_at": int(time.time()) + 3600,
    }):
        cred = mgr.refresh()

    assert isinstance(cred, TokenCredential)
    assert cred.access_token == "forced_new_tok"


@pytest.mark.parametrize("bad_key", ["bad/key", "a..b"])
def test_bad_persist_key_is_rejected_by_filesystem(bad_key):
    # "/" (illegal char) and ".." (empty segment) both violate the §4 grammar;
    # FilesystemBackend validates each segment and raises ValueError.
    class _BadAuth(_Auth):
        def persist_key(self) -> str:
            return bad_key

    with TemporaryDirectory() as root, FilesystemBackend(base_dir=root) as store:
        mgr = OAuth2TokenManager(_provider(), _BadAuth(), token_store=store)
        with pytest.raises(ValueError):
            mgr.status()


def test_interrupted_clear_blocks_credential_and_refresh(monkeypatch):
    from mountainash_auth_client.errors import AuthorizationRequired
    from mountainash_auth_client.oauth.oauth2.flow import OAuthFlow

    class InterruptedClear(MemorySecretStore):
        def is_cleared(self, key):
            return True

        def get(self, key):
            raise AssertionError("cleared record was read")

    store = InterruptedClear()
    store.set("oauth.testprovider.default", {
        "access_token": "must-not-return", "refresh_token": "must-not-exchange",
        "token_expires_at": 4102444800,
    })
    manager = OAuth2TokenManager(_provider(), _Auth(), token_store=store)

    def forbidden(*args, **kwargs):
        raise AssertionError("cleared record reached endpoint")

    monkeypatch.setattr(OAuthFlow, "refresh", forbidden)
    assert manager.status().state is TokenState.CLEARED
    for operation in (manager.acquire, manager.access_token, manager.refresh):
        with pytest.raises(AuthorizationRequired):
            operation()


def test_selected_stores_are_isolated():
    first, first_tokens = _env()
    second, second_tokens = _env()
    first_tokens.set("testprovider.default", {"access_token": "one", "token_expires_at": 4102444800})
    second_tokens.set("testprovider.default", {"access_token": "two", "token_expires_at": 4102444800})
    assert first.acquire().access_token == "one"
    assert second.acquire().access_token == "two"
    first.revoke()
    assert second.acquire().access_token == "two"


def test_two_managers_acquire_single_flight(monkeypatch):
    store = MemorySecretStore()
    store.set("oauth.testprovider.default", {
        "access_token": "old", "refresh_token": "RT", "token_expires_at": 1,
    })
    entered, release, second_waiting = Event(), Event(), Event()
    real_transaction = store.transaction

    @contextmanager
    def observed_transaction(key):
        if entered.is_set():
            second_waiting.set()
        with real_transaction(key):
            yield

    monkeypatch.setattr(store, "transaction", observed_transaction)
    exchanges = []

    def post(client, url, **kwargs):
        exchanges.append(kwargs["data"])
        entered.set()
        assert release.wait(5)
        return httpx.Response(200, json={
            "access_token": "NEW", "refresh_token": "ROTATED", "expires_in": 3600,
        }, request=httpx.Request("POST", url))

    monkeypatch.setattr(httpx.Client, "post", post)
    first = OAuth2TokenManager(_provider(), _Auth(), token_store=store)
    second = OAuth2TokenManager(_provider(), _Auth(), token_store=store)
    with ThreadPoolExecutor(max_workers=2) as pool:
        a = pool.submit(first.acquire)
        try:
            assert entered.wait(5)
            b = pool.submit(second.acquire)
            assert second_waiting.wait(5)
        finally:
            release.set()
        first_credential, second_credential = a.result(timeout=5), b.result(timeout=5)
    assert first_credential == second_credential
    assert first_credential.access_token == "NEW"
    assert first_credential.refresh_token == "ROTATED"
    assert len(exchanges) == 1
    assert exchanges[0]["refresh_token"] == "RT"
