from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from mountainash_auth_client.oauth.lifecycle.oauth2 import OAuth2TokenManager
from mountainash_auth_client.oauth.lifecycle.status import TokenState
from mountainash_auth_client.oauth.providers.oauth2 import OAuth2ProviderProfile
from mountainash_auth_client.oauth.server.manual import ManualCallbackServer
from mountainash_secrets import InMemorySecretStore, NamespacedSecretStore, SecretRegistryResolver
from mountainash_secrets.stores.filesystem import FilesystemSecretStore


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
    SETTINGS_SOURCE_SECRETS_PROVIDER = "mem"

    def persist_key(self) -> str:
        return "testprovider.default"


def _env():
    store = InMemorySecretStore()
    return (
        OAuth2TokenManager(_provider(), _Auth(), resolver=SecretRegistryResolver({"mem": store})),
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


def test_authorize_persists_and_returns_valid():
    mgr, tokens = _env()
    with patch.object(
        type(mgr)._flow_cls(), "authorize",
        return_value={"access_token": "new", "refresh_token": "r", "token_expires_at": int(time.time()) + 3600},
    ):
        status = mgr.authorize()
    assert status.state is TokenState.VALID
    assert tokens.get("testprovider.default")["access_token"] == "new"


def test_revoke_then_authorize_returns_valid():
    mgr, tokens = _env()
    tokens.set("testprovider.default", {"access_token": "old"})
    mgr.revoke()
    with patch.object(
        type(mgr)._flow_cls(), "authorize",
        return_value={"access_token": "fresh", "token_expires_at": int(time.time()) + 3600},
    ):
        status = mgr.authorize()
    assert status.state is TokenState.VALID  # set() cleared the tombstone


def test_authorize_manual_mode_uses_manual_callback_server():
    mgr, _ = _env()
    captured = {}

    def fake_authorize(self, **kwargs):
        captured["callback_server"] = kwargs["callback_server"]
        return {"access_token": "a", "token_expires_at": int(time.time()) + 3600}

    with patch.object(type(mgr)._flow_cls(), "authorize", new=fake_authorize):
        mgr.authorize(mode="manual")
    assert isinstance(captured["callback_server"](), ManualCallbackServer)


@pytest.mark.parametrize("bad_key", ["bad/key", "a..b"])
def test_bad_persist_key_is_rejected_by_filesystem(tmp_path, bad_key):
    # "/" (illegal char) and ".." (empty segment) both violate the §4 grammar;
    # FilesystemSecretStore._key_to_paths validates each segment and raises ValueError.
    class _BadAuth(_Auth):
        SETTINGS_SOURCE_SECRETS_PROVIDER = "fs"

        def persist_key(self) -> str:
            return bad_key

    resolver = SecretRegistryResolver({"fs": FilesystemSecretStore(base_dir=tmp_path)})
    mgr = OAuth2TokenManager(_provider(), _BadAuth(), resolver=resolver)
    with pytest.raises(ValueError):
        mgr.status()  # opens transaction(key) -> _key_to_paths validates the segment
