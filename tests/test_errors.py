"""Tests for auth error types."""
from __future__ import annotations

import pytest

from mountainash_auth_client.errors import (
    AuthorizationRequired,
    TokenExchangeError,
    TokenRefreshError,
)


class TestTokenExchangeError:
    def test_attributes_stored(self):
        err = TokenExchangeError(url="https://example.com/token", status_code=400, body='{"error":"invalid_grant"}')
        assert err.url == "https://example.com/token"
        assert err.status_code == 400
        assert err.body == '{"error":"invalid_grant"}'

    def test_str_contains_status_code(self):
        err = TokenExchangeError(url="https://example.com/token", status_code=401, body="Unauthorized")
        assert "401" in str(err)

    def test_str_contains_url(self):
        err = TokenExchangeError(url="https://example.com/token", status_code=400, body="bad")
        assert "https://example.com/token" in str(err)

    def test_str_excludes_body_but_attr_keeps_it(self):
        err = TokenExchangeError(url="https://example.com/token", status_code=400, body='{"error":"invalid_grant"}')
        assert "invalid_grant" not in str(err)
        assert err.body == '{"error":"invalid_grant"}'
        assert err.error_code == "invalid_grant"

    def test_is_exception(self):
        err = TokenExchangeError(url="https://example.com/token", status_code=400, body="err")
        assert isinstance(err, Exception)

    def test_can_be_raised_and_caught(self):
        with pytest.raises(TokenExchangeError) as exc_info:
            raise TokenExchangeError(url="https://example.com/token", status_code=500, body="server error")
        assert exc_info.value.status_code == 500


class TestTokenRefreshError:
    def test_attributes_stored(self):
        err = TokenRefreshError(url="https://example.com/refresh", status_code=401, body="expired")
        assert err.url == "https://example.com/refresh"
        assert err.status_code == 401
        assert err.body == "expired"

    def test_str_contains_status_code(self):
        err = TokenRefreshError(url="https://example.com/refresh", status_code=403, body="forbidden")
        assert "403" in str(err)

    def test_str_contains_url(self):
        err = TokenRefreshError(url="https://example.com/refresh", status_code=401, body="expired")
        assert "https://example.com/refresh" in str(err)

    def test_str_excludes_body_but_attr_keeps_it(self):
        err = TokenRefreshError(url="https://example.com/refresh", status_code=401, body="token_expired")
        assert "token_expired" not in str(err)
        assert err.body == "token_expired"
        assert err.error_code is None   # non-JSON body

    def test_is_exception(self):
        err = TokenRefreshError(url="https://example.com/refresh", status_code=401, body="err")
        assert isinstance(err, Exception)

    def test_can_be_raised_and_caught(self):
        with pytest.raises(TokenRefreshError) as exc_info:
            raise TokenRefreshError(url="https://example.com/refresh", status_code=401, body="expired")
        assert exc_info.value.url == "https://example.com/refresh"


class TestAuthorizationRequired:
    def test_attributes_stored(self):
        err = AuthorizationRequired(provider="fitbit", user="alice")
        assert err.provider == "fitbit"
        assert err.user == "alice"

    def test_str_contains_provider(self):
        err = AuthorizationRequired(provider="whoop", user="bob")
        assert "whoop" in str(err)

    def test_str_contains_user(self):
        err = AuthorizationRequired(provider="fitbit", user="charlie")
        assert "charlie" in str(err)

    def test_is_exception(self):
        err = AuthorizationRequired(provider="strava", user="dave")
        assert isinstance(err, Exception)

    def test_can_be_raised_and_caught(self):
        with pytest.raises(AuthorizationRequired) as exc_info:
            raise AuthorizationRequired(provider="oura", user="eve")
        assert exc_info.value.provider == "oura"
        assert exc_info.value.user == "eve"
