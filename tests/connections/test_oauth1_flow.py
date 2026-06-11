"""Tests for OAuth1Flow."""
from __future__ import annotations

import pytest

from mountainash_auth_client.connections.oauth1.flow import OAuth1Flow


class FakeSpec:
    def __init__(self, metadata=None):
        self.metadata = metadata or {
            "request_token_url": "https://auth.example.com/oauth/request_token",
            "authorize_url": "https://auth.example.com/oauth/authorize",
            "access_token_url": "https://auth.example.com/oauth/access_token",
        }


class TestOAuth1FlowBuildAuthorizeUrl:
    def test_contains_oauth_token_param(self):
        flow = OAuth1Flow(FakeSpec())
        url = flow.build_authorize_url("test_oauth_token_123")
        assert "oauth_token=test_oauth_token_123" in url

    def test_contains_authorize_base_url(self):
        flow = OAuth1Flow(FakeSpec())
        url = flow.build_authorize_url("tok")
        assert "https://auth.example.com/oauth/authorize" in url

    def test_properties_read_from_metadata(self):
        flow = OAuth1Flow(FakeSpec())
        assert flow.request_token_url == "https://auth.example.com/oauth/request_token"
        assert flow.authorize_url == "https://auth.example.com/oauth/authorize"
        assert flow.access_token_url == "https://auth.example.com/oauth/access_token"


class TestOAuth1FlowAuthlib:
    """Tests that require authlib — skipped if not installed."""

    def test_request_token_requires_authlib(self, monkeypatch):
        """If authlib is not installed, request_token raises ImportError."""
        import builtins
        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "authlib.integrations.httpx_client":
                raise ImportError("No module named 'authlib'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)
        flow = OAuth1Flow(FakeSpec())
        with pytest.raises(ImportError, match="authlib"):
            flow.request_token("consumer_key", "consumer_secret")

    def test_exchange_verifier_requires_authlib(self, monkeypatch):
        """If authlib is not installed, exchange_verifier raises ImportError."""
        import builtins
        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "authlib.integrations.httpx_client":
                raise ImportError("No module named 'authlib'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)
        flow = OAuth1Flow(FakeSpec())
        with pytest.raises(ImportError, match="authlib"):
            flow.exchange_verifier("ck", "cs", "tok", "tok_sec", "verifier")
