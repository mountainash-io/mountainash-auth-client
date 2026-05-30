"""Tests for OAuth2ConnectionMixin."""
from __future__ import annotations

import time

import pytest

from mountainash_auth_client.errors import AuthorizationRequired
from mountainash_auth_client.mixins.oauth2 import OAuth2ConnectionMixin
from mountainash_auth_client.store.filesystem import FilesystemStore


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class FakeSpec:
    name = "testprovider"

    @property
    def metadata(self):
        return {
            "authorize_url": "https://auth.example.com/authorize",
            "token_url": "https://auth.example.com/token",
        }


class FakeAuth:
    client_id = "cid"
    access_token = None
    refresh_token = None
    token_expires_at = None

    def __init__(self, client_secret="csec", scope="read"):
        self._client_secret = client_secret
        self.scope = scope

    @property
    def client_secret(self):
        class _Secret:
            def __init__(self, val):
                self._val = val
            def get_secret_value(self):
                return self._val
        return _Secret(self._client_secret)


class FakeProfile:
    def __init__(self, auth=None):
        self.auth = auth or FakeAuth()


class FakeProvider(OAuth2ConnectionMixin):
    _spec = FakeSpec()
    _base_url = "https://api.example.com"
    _client = None

    def disconnect(self):
        if self._client:
            self._client.close()
        self._client = None


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestOAuth2ConnectionMixinNoToken:
    def test_raises_authorization_required_when_no_token(self, tmp_path):
        store = FilesystemStore(tmp_path)
        provider = FakeProvider()
        with pytest.raises(AuthorizationRequired) as exc_info:
            provider.connect(
                FakeProfile(),
                user="testuser",
                store=store,
                domain="wearables",
            )
        assert exc_info.value.provider == "testprovider"
        assert exc_info.value.user == "testuser"


class TestOAuth2ConnectionMixinWithToken:
    def test_connects_with_valid_stored_token(self, tmp_path):
        store = FilesystemStore(tmp_path)
        # Save a valid (not expired) token
        store.save("wearables", "testprovider", "testuser", {
            "access_token": "tok_abc",
            "refresh_token": "refresh_xyz",
            "token_expires_at": int(time.time()) + 3600,
        })
        provider = FakeProvider()
        result = provider.connect(
            FakeProfile(),
            user="testuser",
            store=store,
            domain="wearables",
        )
        assert result is provider

    def test_client_is_set_after_connect(self, tmp_path):
        store = FilesystemStore(tmp_path)
        store.save("wearables", "testprovider", "testuser", {
            "access_token": "tok_abc",
            "refresh_token": "refresh_xyz",
            "token_expires_at": int(time.time()) + 3600,
        })
        provider = FakeProvider()
        provider.connect(
            FakeProfile(),
            user="testuser",
            store=store,
            domain="wearables",
        )
        assert provider._client is not None

    def test_client_has_bearer_auth_header(self, tmp_path):
        store = FilesystemStore(tmp_path)
        store.save("wearables", "testprovider", "testuser", {
            "access_token": "tok_abc",
            "refresh_token": "refresh_xyz",
            "token_expires_at": int(time.time()) + 3600,
        })
        provider = FakeProvider()
        provider.connect(
            FakeProfile(),
            user="testuser",
            store=store,
            domain="wearables",
        )
        auth_header = provider._client.headers.get("authorization", "")
        assert "Bearer tok_abc" in auth_header

    def test_connect_with_unexpired_token_no_refresh(self, tmp_path):
        """When token is valid, no refresh should happen even if refresh_token exists."""
        store = FilesystemStore(tmp_path)
        store.save("wearables", "testprovider", "testuser", {
            "access_token": "valid_tok",
            "refresh_token": "old_refresh",
            "token_expires_at": int(time.time()) + 7200,
        })
        provider = FakeProvider()
        provider.connect(
            FakeProfile(),
            user="testuser",
            store=store,
            domain="wearables",
        )
        # Token file should be unchanged (no new save triggered)
        loaded = store.load("wearables", "testprovider", "testuser")
        assert loaded["access_token"] == "valid_tok"


class TestOAuth2ConnectionMixinExpiredToken:
    def test_raises_authorization_required_when_token_expired_and_no_refresh(self, tmp_path):
        """Expired token with no refresh_token should raise AuthorizationRequired."""
        store = FilesystemStore(tmp_path)
        store.save("wearables", "testprovider", "testuser", {
            "access_token": "old_tok",
            "refresh_token": None,
            "token_expires_at": int(time.time()) - 1000,
        })
        provider = FakeProvider()
        with pytest.raises(AuthorizationRequired):
            provider.connect(
                FakeProfile(),
                user="testuser",
                store=store,
                domain="wearables",
            )


class TestClientProperty:
    def test_client_property_exposes_httpx_client(self):
        import httpx
        provider = FakeProvider()
        mock_client = httpx.Client()
        provider._client = mock_client
        assert provider.client is mock_client
        mock_client.close()

    def test_client_property_none_before_connect(self):
        provider = FakeProvider()
        assert provider.client is None
