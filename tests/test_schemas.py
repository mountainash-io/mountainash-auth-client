"""Tests for auth schemas."""
from __future__ import annotations

import pytest

from mountainash_auth_client.schemas import (
    NoAuth,
    OAuth1Auth,
    OAuth2AuthCodeAuth,
    PasswordAuth,
    auth_kwargs,
    auth_to_driver_kwargs,
)


class TestOAuth2AuthCodeAuth:
    def test_round_trip(self):
        auth = OAuth2AuthCodeAuth(
            client_id="client_123",
            client_secret="secret_abc",
        )
        assert auth.kind == "oauth2_authcode"
        assert auth.client_id == "client_123"
        assert auth.access_token is None

    def test_dump_model(self):
        auth = OAuth2AuthCodeAuth(client_id="cid", client_secret="csec")
        data = auth.model_dump()
        assert data["kind"] == "oauth2_authcode"
        assert data["client_id"] == "cid"

    def test_with_tokens(self):
        auth = OAuth2AuthCodeAuth(
            client_id="cid",
            client_secret="csec",
            access_token="at",
            refresh_token="rt",
            token_expires_at=9999,
            scope="read write",
        )
        assert auth.scope == "read write"
        assert auth.token_expires_at == 9999


class TestOAuth1Auth:
    def test_round_trip(self):
        auth = OAuth1Auth(
            consumer_key="key",
            consumer_secret="secret",
        )
        assert auth.kind == "oauth1"
        assert auth.consumer_key == "key"
        assert auth.access_token is None

    def test_with_tokens(self):
        auth = OAuth1Auth(
            consumer_key="key",
            consumer_secret="secret",
            access_token="at",
            access_token_secret="ats",
        )
        assert auth.access_token is not None


class TestNoAuth:
    def test_creation(self):
        auth = NoAuth()
        assert auth.kind == "none"


class TestPasswordAuth:
    def test_creation(self):
        auth = PasswordAuth(username="alice", password="hunter2")
        assert auth.username == "alice"
        assert auth.kind == "password"


class TestAuthToDriverKwargs:
    def test_noauth_returns_empty(self):
        auth = NoAuth()
        result = auth_to_driver_kwargs(auth)
        assert result == {}

    def test_password_returns_user_password(self):
        auth = PasswordAuth(username="alice", password="hunter2")
        result = auth_to_driver_kwargs(auth)
        assert result["user"] == "alice"
        assert result["password"] == "hunter2"


class TestAuthKwargs:
    def test_object_with_auth_attribute(self):
        class FakeProfile:
            auth = NoAuth()

        result = auth_kwargs(FakeProfile())
        assert result == {}

    def test_object_without_auth_attribute(self):
        class FakeProfile:
            pass

        result = auth_kwargs(FakeProfile())
        assert result == {}

    def test_object_with_password_auth(self):
        class FakeProfile:
            auth = PasswordAuth(username="bob", password="pass123")

        result = auth_kwargs(FakeProfile())
        assert result["user"] == "bob"
        assert result["password"] == "pass123"

    def test_none_auth_attribute(self):
        class FakeProfile:
            auth = None

        result = auth_kwargs(FakeProfile())
        assert result == {}
