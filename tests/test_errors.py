"""Tests for auth error types."""

from __future__ import annotations

import pytest

from mountainash_auth_client.errors import (
    AuthorizationRequired,
    TokenExchangeError,
    TokenRefreshError,
)


@pytest.mark.parametrize("kind", [TokenExchangeError, TokenRefreshError])
class TestTokenErrors:
    def test_attributes_stored(self, kind):
        err = kind(url="https://example.com/token", status_code=400, body='{"error":"invalid_grant"}')
        assert err.url == "https://example.com/token"
        assert err.status_code == 400
        assert err.error_code == "invalid_grant"

    def test_str_contains_status_code(self, kind):
        err = kind(url="https://example.com/token", status_code=401, body="")
        assert "401" in str(err)

    def test_str_contains_safe_url(self, kind):
        err = kind(url="https://example.com/token", status_code=400, body="")
        assert "https://example.com/token" in str(err)

    def test_str_excludes_body(self, kind):
        err = kind(url="https://example.com/token", status_code=401, body='{"error":"invalid_grant"}')
        assert "invalid_grant" not in str(err)

    def test_is_exception(self, kind):
        assert isinstance(kind(url="https://example.com/token", status_code=400, body=""), Exception)


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
