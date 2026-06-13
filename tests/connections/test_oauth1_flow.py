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
        # Patch importlib.import_module (the seam require_authlib uses): a
        # builtins.__import__ patch is bypassed once authlib is cached in
        # sys.modules, which it is when authlib is installed in the test env.
        import importlib
        real_import_module = importlib.import_module

        def mock_import_module(name, *args, **kwargs):
            if name == "authlib.integrations.httpx_client":
                raise ImportError("No module named 'authlib'")
            return real_import_module(name, *args, **kwargs)

        monkeypatch.setattr(importlib, "import_module", mock_import_module)
        flow = OAuth1Flow(FakeSpec())
        with pytest.raises(ImportError, match="authlib"):
            flow.request_token("consumer_key", "consumer_secret")

    def test_exchange_verifier_requires_authlib(self, monkeypatch):
        """If authlib is not installed, exchange_verifier raises ImportError."""
        import importlib
        real_import_module = importlib.import_module

        def mock_import_module(name, *args, **kwargs):
            if name == "authlib.integrations.httpx_client":
                raise ImportError("No module named 'authlib'")
            return real_import_module(name, *args, **kwargs)

        monkeypatch.setattr(importlib, "import_module", mock_import_module)
        flow = OAuth1Flow(FakeSpec())
        with pytest.raises(ImportError, match="authlib"):
            flow.exchange_verifier("ck", "cs", "tok", "tok_sec", "verifier")


from mountainash_auth_client.errors import MalformedCallbackError


class _OAuth1Echo:
    """Test double whose obtain_callback returns a verifier (+ matching token)."""

    port = None

    def __init__(self, redirect_uri="http://localhost/cb", params=None):
        self.redirect_uri = redirect_uri
        self._params = params

    def obtain_callback(self, authorize_url):
        if self._params is not None:
            return self._params
        return {"oauth_verifier": "VERIF", "oauth_token": "REQTOKEN"}


def _stub_oauth1(flow, monkeypatch, sink):
    monkeypatch.setattr(
        flow, "request_token",
        lambda consumer_key, consumer_secret, callback_url:
            sink.update(callback_url=callback_url)
            or {"oauth_token": "REQTOKEN", "oauth_token_secret": "REQSECRET"})
    monkeypatch.setattr(
        flow, "exchange_verifier",
        lambda **kw: sink.update(kw) or {"oauth_token": "ACCESS", "oauth_token_secret": "ASEC"})


class TestOAuth1Authorize:
    def test_injected_server_drives_callback_url_and_verifier(self, monkeypatch):
        flow = OAuth1Flow(FakeSpec())
        sink = {}
        _stub_oauth1(flow, monkeypatch, sink)
        flow.authorize("ckey", "csec",
                       callback_server=lambda: _OAuth1Echo("https://INJECT/cb"))
        assert sink["callback_url"] == "https://INJECT/cb"
        assert sink["verifier"] == "VERIF"

    def test_manual_builtin_uses_literal_oob(self, monkeypatch):
        flow = OAuth1Flow(FakeSpec())
        sink = {}
        _stub_oauth1(flow, monkeypatch, sink)
        monkeypatch.setattr(
            "mountainash_auth_client.connections.server.manual.prompt_for_code",
            lambda url: {"code": "BAREVERIF"})
        flow.authorize("ckey", "csec", redirect_mode="manual")
        assert sink["callback_url"] == "oob"
        assert sink["verifier"] == "BAREVERIF"

    def test_missing_verifier_raises_malformed(self, monkeypatch):
        flow = OAuth1Flow(FakeSpec())
        sink = {}
        _stub_oauth1(flow, monkeypatch, sink)
        with pytest.raises(MalformedCallbackError):
            flow.authorize("ckey", "csec",
                           callback_server=lambda: _OAuth1Echo(params={"oauth_token": "REQTOKEN"}))

    def test_token_mismatch_raises_value_error(self, monkeypatch):
        flow = OAuth1Flow(FakeSpec())
        sink = {}
        _stub_oauth1(flow, monkeypatch, sink)
        with pytest.raises(ValueError, match="mismatch"):
            flow.authorize("ckey", "csec",
                           callback_server=lambda: _OAuth1Echo(
                               params={"oauth_verifier": "V", "oauth_token": "WRONG"}))


from contextlib import contextmanager
from unittest.mock import patch

from mountainash_auth_client.errors import AuthorizationRequired
from mountainash_settings.secrets.registry import clear_secrets_registry, register_secrets_backend


class _Mem1Backend:
    def __init__(self):
        self._store = {}

    def get(self, key):
        return self._store.get(key)

    def set(self, key, data):
        self._store[key] = data

    def delete(self, key):
        self._store.pop(key, None)

    @contextmanager
    def transaction(self, key):
        yield


class _Spec1:
    name = "testprovider_oauth1"

    @property
    def metadata(self):
        return {
            "request_token_url": "https://auth.example.com/request_token",
            "authorize_url": "https://auth.example.com/authorize",
            "access_token_url": "https://auth.example.com/access_token",
        }


class _Auth1:
    CONSUMER_KEY = "ck"
    CONSUMER_SECRET = property(
        lambda self: type("S", (), {"get_secret_value": lambda s: "cs"})()
    )
    SETTINGS_SOURCE_SECRETS_PROVIDER = "rtp_mem"

    def persist_key(self):
        return "rtp.oauth1"


@pytest.fixture(autouse=True)
def _clean_rtp():
    clear_secrets_registry()
    yield
    clear_secrets_registry()


@pytest.fixture
def rtp_backend():
    b = _Mem1Backend()
    register_secrets_backend("rtp_mem", b)
    return b


class TestResolveTokenPair:
    def test_returns_cached_pair(self, rtp_backend):
        rtp_backend.set("rtp.oauth1", {"oauth_token": "AT", "oauth_token_secret": "ATS"})
        pair = OAuth1Flow(_Spec1()).resolve_token_pair(_Auth1())
        assert pair == ("AT", "ATS")

    def test_raises_when_no_token_and_not_auto(self, rtp_backend):
        with pytest.raises(AuthorizationRequired) as exc:
            OAuth1Flow(_Spec1()).resolve_token_pair(_Auth1())
        assert exc.value.provider == "testprovider_oauth1"

    def test_auto_authorize_persists_and_returns_pair(self, rtp_backend):
        with patch.object(OAuth1Flow, "authorize", return_value={
            "oauth_token": "newAT", "oauth_token_secret": "newATS",
        }):
            pair = OAuth1Flow(_Spec1()).resolve_token_pair(_Auth1(), auto_authorize=True)
        assert pair == ("newAT", "newATS")
        assert rtp_backend.get("rtp.oauth1")["oauth_token"] == "newAT"

    def test_auto_authorize_forwards_callback_server(self, rtp_backend):
        sentinel = object()
        captured = {}

        def fake_authorize(**kwargs):
            captured.update(kwargs)
            return {"oauth_token": "AT", "oauth_token_secret": "ATS"}

        with patch.object(OAuth1Flow, "authorize", side_effect=fake_authorize):
            OAuth1Flow(_Spec1()).resolve_token_pair(
                _Auth1(), auto_authorize=True, callback_server=sentinel)
        assert captured["callback_server"] is sentinel
