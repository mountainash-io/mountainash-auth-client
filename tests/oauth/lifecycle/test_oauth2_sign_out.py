"""Stronger sign-out over real selected stores and transaction-ordered races."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from threading import Event
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from mountainash_settings.secrets import FilesystemBackend, MemorySecretStore, NamespacedSecretStore

from mountainash_auth_client import errors
from mountainash_auth_client.oauth.lifecycle.oauth2 import OAuth2TokenManager
from mountainash_auth_client.oauth.lifecycle.status import TokenState
from mountainash_auth_client.oauth.oauth2.flow import OAuthFlow
from mountainash_auth_client.oauth.providers.oauth2 import OAuth2ProviderProfile


class Auth:
    CLIENT_ID = "bootstrap"
    CLIENT_SECRET = None
    SCOPE = "openid invoke"

    def persist_key(self):
        return "signout.account"


def provider():
    return OAuth2ProviderProfile(
        NAME="signout", AUTHORIZE_URL="https://issuer.example/authorize",
        TOKEN_URL="https://issuer.example/token", BASE_URL="https://resource.example",
        TOKEN_ENDPOINT_AUTH_METHOD="none",
    )


@pytest.fixture(params=["memory", "filesystem"])
def store(request, tmp_path):
    if request.param == "memory":
        yield MemorySecretStore()
    else:
        with FilesystemBackend(base_dir=tmp_path) as backend:
            yield backend


def seed(store, **overrides):
    record = {
        "access_token": "accepted", "refresh_token": "renewable", "token_expires_at": 4102444800,
        "scope": "openid invoke", "client_id": "issued", "registration": {"subject": "account"},
        "session_metadata": {"id_token": "private-identity"}, "lifecycle": {"epoch": "before"},
        **overrides,
    }
    NamespacedSecretStore(store, "oauth").set(Auth().persist_key(), record)
    return record


def endpoint(monkeypatch, handler):
    client = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda: client(transport=httpx.MockTransport(handler)))


class Callback:
    redirect_uri = "http://127.0.0.1/auth/callback"

    def obtain_callback(self, url):
        query = parse_qs(urlsplit(url).query)
        assert query["client_id"] == ["issued"]
        return {"code": "new", "state": query["state"][0]}


@pytest.mark.parametrize("remote_error", [None, RuntimeError, KeyboardInterrupt])
@pytest.mark.parametrize("write_failure", [False, True])
def test_sign_out_retains_registration_and_attempts_cleanup_on_every_remote_exit(store, monkeypatch, remote_error, write_failure):
    original = seed(store)
    records = NamespacedSecretStore(store, "oauth")
    seen = []

    class RemoteFlow(OAuthFlow):
        def revoke_remote(self, record):
            seen.append(record["refresh_token"])
            record["registration"]["subject"] = "adapter-mutated"
            if remote_error:
                raise remote_error("private-remote-detail")
            return True

    manager = OAuth2TokenManager(provider(), Auth(), token_store=store, flow_factory=RemoteFlow)
    writes = []
    real_set = store.set

    def write(key, value):
        writes.append(value)
        if write_failure:
            raise OSError("local write failed")
        return real_set(key, value)

    monkeypatch.setattr(store, "set", write)
    if write_failure:
        with pytest.raises(OSError, match="local write failed"):
            manager.sign_out()
        assert records.get(Auth().persist_key()) == original
    elif remote_error is KeyboardInterrupt:
        with pytest.raises(KeyboardInterrupt):
            manager.sign_out()
    else:
        result = manager.sign_out()
        assert result.remote_confirmed is (remote_error is None)
        assert "private-remote-detail" not in repr(result)
    assert seen == ["renewable"]
    assert len(writes) == 1
    if not write_failure:
        saved = records.get(Auth().persist_key())
        assert set(saved) == {"client_id", "registration", "lifecycle"}
        assert saved["client_id"] == "issued"
        assert saved["registration"] == {"subject": "account"}
        assert saved["lifecycle"]["epoch"] != "before"
        assert manager.status().state is TokenState.CLEARED
        for operation in (manager.acquire, manager.refresh, manager.access_token):
            with pytest.raises(errors.AuthorizationRequired):
                operation()


@pytest.mark.parametrize("record", [None, {"lifecycle": {"epoch": "pending"}}, {
    "client_id": "issued", "registration": {"subject": "account"}, "lifecycle": {"epoch": "cleared"},
}])
def test_no_session_sign_out_uses_empty_normalized_view(store, record):
    records = NamespacedSecretStore(store, "oauth")
    if record is not None:
        records.set(Auth().persist_key(), record)
    seen = []

    class RemoteFlow(OAuthFlow):
        def revoke_remote(self, snapshot):
            seen.append(snapshot)
            return False

    manager = OAuth2TokenManager(provider(), Auth(), token_store=store, flow_factory=RemoteFlow)
    assert manager.status().state is (TokenState.MISSING if record is None else TokenState.CLEARED)
    assert manager.sign_out().remote_confirmed is False
    assert seen[0]["access_token"] == ""
    assert "lifecycle" not in seen[0]
    assert manager.status().state is TokenState.CLEARED


@pytest.mark.parametrize("phase, caller", [("callback", "manager"), ("exchange", "manager"), ("exchange", "resolver")])
@pytest.mark.parametrize("remote_confirmed", [True, False])
def test_sign_out_cancels_old_attempt_without_overwriting_new_session(store, monkeypatch, phase, caller, remote_confirmed):
    seed(store, token_expires_at=1, refresh_token=None)
    records = NamespacedSecretStore(store, "oauth")
    entered, release = Event(), Event()
    revoked = []

    class OldCallback(Callback):
        def obtain_callback(self, url):
            params = super().obtain_callback(url)
            params["code"] = "old"
            if phase == "callback":
                entered.set()
                assert release.wait(5)
            return params

    class RemoteFlow(OAuthFlow):
        def revoke_remote(self, record):
            revoked.append(record["access_token"])
            if not remote_confirmed:
                raise RuntimeError("unavailable")
            return True

    def exchange(request):
        code = parse_qs(request.content.decode())["code"][0]
        if code == "old" and phase == "exchange":
            entered.set()
            assert release.wait(5)
        return httpx.Response(200, json={"access_token": code, "refresh_token": "renewable-" + code, "scope": "openid invoke"})

    endpoint(monkeypatch, exchange)
    manager = OAuth2TokenManager(provider(), Auth(), token_store=store, flow_factory=RemoteFlow, callback_server=OldCallback)
    flow = RemoteFlow(provider(), token_store=store, callback_server=OldCallback)
    operation = manager.authorize if caller == "manager" else lambda: flow.resolve_access_token(Auth(), auto_authorize=True)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(operation)
        try:
            assert entered.wait(5)
            manager.sign_out()
            assert manager.status().state is TokenState.CLEARED
            newer = OAuth2TokenManager(provider(), Auth(), token_store=store, flow_factory=RemoteFlow, callback_server=Callback)
            assert newer.authorize().state is TokenState.VALID
            assert newer.acquire().access_token == "new"
            accepted = records.get(Auth().persist_key())
        finally:
            release.set()
        with pytest.raises(errors.AuthorizationCancelled) as caught:
            pending.result(timeout=5)
    assert caught.value.remote_confirmed is remote_confirmed
    assert records.get(Auth().persist_key()) == accepted
    assert revoked == ["accepted", "old"]


def test_sign_out_waits_for_refresh_and_revokes_rotated_token(store, monkeypatch):
    seed(store, token_expires_at=1)
    entered, release, waiting = Event(), Event(), Event()
    transaction = store.transaction

    @contextmanager
    def observed_transaction(key):
        if entered.is_set():
            waiting.set()
        with transaction(key):
            yield

    monkeypatch.setattr(store, "transaction", observed_transaction)
    revoked = []

    class RemoteFlow(OAuthFlow):
        def revoke_remote(self, record):
            revoked.append(record["refresh_token"])
            return True

    def refresh(request):
        entered.set()
        assert release.wait(5)
        return httpx.Response(200, json={"access_token": "new", "refresh_token": "rotated", "expires_in": 3600})

    endpoint(monkeypatch, refresh)
    manager = OAuth2TokenManager(provider(), Auth(), token_store=store, flow_factory=RemoteFlow)
    with ThreadPoolExecutor(max_workers=2) as pool:
        refreshed = pool.submit(manager.acquire)
        try:
            assert entered.wait(5)
            signed_out = pool.submit(manager.sign_out)
            assert waiting.wait(5)
        finally:
            release.set()
        assert refreshed.result(timeout=5).refresh_token == "rotated"
        assert signed_out.result(timeout=5).remote_confirmed is True
    assert revoked == ["rotated"]
    assert manager.status().state is TokenState.CLEARED


def test_unrelated_record_remains_usable_during_remote_sign_out(store):
    seed(store)
    entered, release = Event(), Event()

    class OtherAuth(Auth):
        def persist_key(self):
            return "signout.other"

    store.set("oauth.signout.other", {"access_token": "other"})

    class BlockingFlow(OAuthFlow):
        def revoke_remote(self, record):
            entered.set()
            assert release.wait(5)
            return True

    manager = OAuth2TokenManager(provider(), Auth(), token_store=store, flow_factory=BlockingFlow)
    other = OAuth2TokenManager(provider(), OtherAuth(), token_store=store)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(manager.sign_out)
        try:
            assert entered.wait(5)
            assert other.acquire().access_token == "other"
        finally:
            release.set()
        assert pending.result(timeout=5).remote_confirmed is True


def test_filesystem_reopen_retains_registration_and_reuses_issued_identity(tmp_path, monkeypatch):
    with FilesystemBackend(base_dir=tmp_path) as store:
        seed(store)
        manager = OAuth2TokenManager(provider(), Auth(), token_store=store)
        assert manager.sign_out().remote_confirmed is False
    endpoint(monkeypatch, lambda request: httpx.Response(200, json={"access_token": "new", "scope": "openid"}))
    with FilesystemBackend(base_dir=tmp_path) as store:
        manager = OAuth2TokenManager(provider(), Auth(), token_store=store, callback_server=Callback)
        assert manager.status().state is TokenState.CLEARED
        with pytest.raises(errors.AuthorizationRequired):
            manager.acquire()
        assert manager.authorize().state is TokenState.VALID
        credential = manager.acquire()
        assert credential.client_id == "issued"
        assert credential.registration == {"subject": "account"}
        assert credential.session_metadata == {}


@pytest.mark.parametrize("replacement", [False, True])
def test_native_revoke_cancels_pending_authorization_even_after_recreation(store, monkeypatch, replacement):
    seed(store)
    entered, release = Event(), Event()
    revoked = []

    class WaitingCallback(Callback):
        def obtain_callback(self, url):
            params = super().obtain_callback(url)
            entered.set()
            assert release.wait(5)
            return params

    class CleanupFlow(OAuthFlow):
        def revoke_remote(self, record):
            revoked.append(record["access_token"])
            return True

    endpoint(monkeypatch, lambda request: httpx.Response(200, json={"access_token": "late"}))
    manager = OAuth2TokenManager(provider(), Auth(), token_store=store, callback_server=WaitingCallback, flow_factory=CleanupFlow)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(manager.authorize)
        try:
            assert entered.wait(5)
            manager.revoke()
            assert revoked == []
            if replacement:
                seed(store, access_token="replacement", lifecycle={"epoch": "recreated"})
        finally:
            release.set()
        with pytest.raises(errors.AuthorizationCancelled):
            pending.result(timeout=5)
    assert revoked == ["late"]
    if replacement:
        assert manager.acquire().access_token == "replacement"
    else:
        assert manager.status().state is TokenState.CLEARED


def test_epoch_only_pending_authorization_is_not_a_usable_session(store, monkeypatch):
    entered, release = Event(), Event()
    records = NamespacedSecretStore(store, "oauth")

    class WaitingCallback:
        redirect_uri = "http://localhost/callback"

        def obtain_callback(self, url):
            entered.set()
            assert release.wait(5)
            return {"code": "accepted", "state": parse_qs(urlsplit(url).query)["state"][0]}

    endpoint(monkeypatch, lambda request: httpx.Response(200, json={"access_token": "accepted", "refresh_token": "renewable"}))
    manager = OAuth2TokenManager(provider(), Auth(), token_store=store, callback_server=WaitingCallback)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(manager.authorize)
        try:
            assert entered.wait(5)
            assert manager.status().state is TokenState.CLEARED
            with pytest.raises(errors.AuthorizationRequired):
                manager.acquire()
            epoch = records.get(Auth().persist_key())["lifecycle"]
        finally:
            release.set()
        assert pending.result(timeout=5).state is TokenState.VALID
    assert records.get(Auth().persist_key())["lifecycle"] == epoch
    manager.refresh()
    assert records.get(Auth().persist_key())["lifecycle"] == epoch
