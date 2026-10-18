"""Tests for OAuthFlow (OAuth2 authorization code flow)."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from threading import Event
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from mountainash_settings.secrets import MemorySecretStore, NamespacedSecretStore

from mountainash_auth_client.errors import (
    AuthorizationDeniedError,
    AuthorizationRequired,
    MalformedCallbackError,
    TokenExchangeError,
    TokenRefreshError,
)
from mountainash_auth_client.oauth.oauth2.flow import OAuthFlow
from mountainash_auth_client.oauth.oauth1.flow import OAuth1Flow
from mountainash_auth_client.oauth.providers.oauth1 import OAuth1ProviderProfile
from mountainash_auth_client.oauth.providers.oauth2 import OAuth2ProviderProfile


def _provider(**overrides):
    base = dict(
        NAME="testprovider",
        AUTHORIZE_URL="https://auth.example.com/authorize",
        TOKEN_URL="https://auth.example.com/token",
        BASE_URL="https://api.example.com",
    )
    base.update(overrides)
    return OAuth2ProviderProfile(**base)


class TestBuildAuthorizeUrl:
    def test_returns_url_with_client_id(self):
        flow = OAuthFlow(_provider())
        url, state = flow.build_authorize_url(
            client_id="my_client",
            redirect_uri="http://localhost:8080/callback",
        )
        assert "client_id=my_client" in url
        assert "https://auth.example.com/authorize" in url

    def test_returns_url_with_state(self):
        flow = OAuthFlow(_provider())
        url, state = flow.build_authorize_url(
            client_id="my_client",
            redirect_uri="http://localhost:8080/callback",
        )
        assert state in url
        assert len(state) > 0

    def test_no_pkce_by_default(self):
        flow = OAuthFlow(_provider())
        url, _ = flow.build_authorize_url(
            client_id="my_client",
            redirect_uri="http://localhost:8080/callback",
        )
        assert "code_challenge" not in url

    def test_pkce_adds_code_challenge_and_s256(self):
        flow = OAuthFlow(_provider(USE_PKCE=True))
        url, _ = flow.build_authorize_url(
            client_id="pkce_client",
            redirect_uri="http://localhost:8080/callback",
        )
        assert "code_challenge=" in url
        assert "code_challenge_method=S256" in url

    def test_scope_included_when_provided(self):
        flow = OAuthFlow(_provider())
        url, _ = flow.build_authorize_url(
            client_id="my_client",
            redirect_uri="http://localhost/cb",
            scope="read write",
        )
        assert "scope=" in url


class TestExchangeCode:
    def test_raises_token_exchange_error_on_http_error(self):
        flow = OAuthFlow(_provider())
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.text = "Bad Request"

        with patch("httpx.Client") as MockClient:
            mock_client_instance = MockClient.return_value.__enter__.return_value
            mock_client_instance.post.side_effect = httpx.HTTPStatusError(
                "error", request=MagicMock(), response=mock_response
            )

            with pytest.raises(TokenExchangeError) as exc_info:
                flow.exchange_code(
                    code="authcode",
                    redirect_uri="http://localhost/cb",
                    client_id="cid",
                    client_secret="csec",
                )
            assert exc_info.value.status_code == 400
            assert exc_info.value.url == "https://auth.example.com/token"

    def test_returns_token_dict_on_success(self):
        flow = OAuthFlow(_provider())
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "access_tok",
            "refresh_token": "refresh_tok",
            "expires_in": 3600,
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.Client") as MockClient:
            mock_client_instance = MockClient.return_value.__enter__.return_value
            mock_client_instance.post.return_value = mock_response

            result = flow.exchange_code(
                code="code123",
                redirect_uri="http://localhost/cb",
                client_id="cid",
                client_secret="csec",
            )
        assert result["access_token"] == "access_tok"
        assert result["refresh_token"] == "refresh_tok"
        assert result["token_expires_at"] is not None

    def test_raises_on_invalid_json_response(self):
        flow = OAuthFlow(_provider())
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html>not json</html>"
        mock_response.json.side_effect = ValueError("no json")
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.Client") as MockClient:
            mock_client_instance = MockClient.return_value.__enter__.return_value
            mock_client_instance.post.return_value = mock_response

            with pytest.raises(TokenExchangeError) as exc_info:
                flow.exchange_code(
                    code="code123",
                    redirect_uri="http://localhost/cb",
                    client_id="cid",
                    client_secret="csec",
                )
            assert "Invalid JSON" in exc_info.value.body

    def test_raises_when_access_token_missing(self):
        flow = OAuthFlow(_provider())
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"error": "invalid_grant"}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.Client") as MockClient:
            mock_client_instance = MockClient.return_value.__enter__.return_value
            mock_client_instance.post.return_value = mock_response

            with pytest.raises(TokenExchangeError) as exc_info:
                flow.exchange_code(
                    code="code123",
                    redirect_uri="http://localhost/cb",
                    client_id="cid",
                    client_secret="csec",
                )
            assert "access_token" in exc_info.value.body

    def test_pkce_verifier_keyed_by_state_survives_second_authorize(self):
        flow = OAuthFlow(_provider(USE_PKCE=True))

        # First flow generates a verifier bound to state_a.
        _, state_a = flow.build_authorize_url(
            client_id="cid", redirect_uri="http://localhost/cb"
        )
        # A second authorize starts before the first completes.
        flow.build_authorize_url(client_id="cid", redirect_uri="http://localhost/cb")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"access_token": "tok"}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.Client") as MockClient:
            mock_client_instance = MockClient.return_value.__enter__.return_value
            mock_client_instance.post.return_value = mock_response

            flow.exchange_code(
                code="code123",
                redirect_uri="http://localhost/cb",
                client_id="cid",
                client_secret="csec",
                state=state_a,
            )
            sent_data = mock_client_instance.post.call_args.kwargs["data"]
        # The first flow's verifier is recovered by its own state, not clobbered.
        assert "code_verifier" in sent_data


class TestValidateCallbackState:
    def test_matching_state_passes(self):
        flow = OAuthFlow(_provider())
        flow._validate_callback_state({"state": "abc"}, "abc")

    def test_mismatched_state_raises(self):
        flow = OAuthFlow(_provider())
        with pytest.raises(ValueError, match="CSRF"):
            flow._validate_callback_state({"state": "evil"}, "abc")

    def test_missing_state_raises(self):
        flow = OAuthFlow(_provider())
        with pytest.raises(ValueError, match="CSRF"):
            flow._validate_callback_state({}, "abc")


class TestRefresh:
    def test_raises_token_refresh_error_on_http_error(self):
        flow = OAuthFlow(_provider())
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"

        with patch("httpx.Client") as MockClient:
            mock_client_instance = MockClient.return_value.__enter__.return_value
            mock_client_instance.post.side_effect = httpx.HTTPStatusError(
                "error", request=MagicMock(), response=mock_response
            )

            with pytest.raises(TokenRefreshError) as exc_info:
                flow.refresh(
                    refresh_token="old_refresh",
                    client_id="cid",
                    client_secret="csec",
                )
            assert exc_info.value.status_code == 401
            assert exc_info.value.url == "https://auth.example.com/token"


class TestIsExpired:
    def test_none_returns_false(self):
        assert OAuthFlow.is_expired(None) is False

    def test_past_timestamp_returns_true(self):
        past = int(time.time()) - 1000
        assert OAuthFlow.is_expired(past) is True

    def test_far_future_returns_false(self):
        future = int(time.time()) + 10000
        assert OAuthFlow.is_expired(future) is False

    def test_near_future_returns_true_due_to_buffer(self):
        # Within the 300s buffer window
        near_future = int(time.time()) + 100
        assert OAuthFlow.is_expired(near_future) is True


class _EchoServer:
    """Test double: echoes the state from the authorize URL back as a callback."""

    port = None

    def __init__(self, redirect_uri="https://fake/cb", extra=None):
        self.redirect_uri = redirect_uri
        self._extra = extra or {}

    def obtain_callback(self, authorize_url):
        state = parse_qs(urlparse(authorize_url).query)["state"][0]
        return {"code": "CODE", "state": state, **self._extra}


def _no_http(flow, monkeypatch, sink):
    monkeypatch.setattr(flow, "exchange_code",
                        lambda **kw: sink.update(kw) or {"access_token": "tok"})


class TestAuthorizeInjection:
    def test_uses_injected_server_redirect_uri_and_params(self, monkeypatch):
        flow = OAuthFlow(_provider())
        sink = {}
        _no_http(flow, monkeypatch, sink)
        result = flow.authorize("cid", "csec",
                                callback_server=lambda: _EchoServer("https://INJECT/cb"))
        assert sink["redirect_uri"] == "https://INJECT/cb"
        assert sink["code"] == "CODE"
        assert result["access_token"] == "tok"

    def test_per_call_beats_construction_default(self, monkeypatch):
        flow = OAuthFlow(_provider(),
                         callback_server=lambda: _EchoServer("https://CONSTRUCT/cb"))
        sink = {}
        _no_http(flow, monkeypatch, sink)
        flow.authorize("cid", "csec",
                       callback_server=lambda: _EchoServer("https://PERCALL/cb"))
        assert sink["redirect_uri"] == "https://PERCALL/cb"

    def test_construction_default_shadows_redirect_mode(self, monkeypatch):
        flow = OAuthFlow(_provider(),
                         callback_server=lambda: _EchoServer("https://CONSTRUCT/cb"))
        sink = {}
        _no_http(flow, monkeypatch, sink)
        flow.authorize("cid", "csec", redirect_mode="manual")
        assert sink["redirect_uri"] == "https://CONSTRUCT/cb"

    def test_default_uses_local_callback_server(self, monkeypatch):
        import mountainash_auth_client.oauth.server.factory as factory
        monkeypatch.setattr(
            factory, "LocalCallbackServer",
            lambda port=0: _EchoServer(f"http://localhost/{port}/callback"))
        flow = OAuthFlow(_provider())
        sink = {}
        _no_http(flow, monkeypatch, sink)
        flow.authorize("cid", "csec")
        assert sink["redirect_uri"].startswith("http://localhost/")


class TestAuthorizeCallbackValidation:
    def test_denied_raises(self, monkeypatch):
        # A real denial carries `error` and NO `code`; this also proves the
        # `error` branch fires before the missing-`code` (MalformedCallbackError) path.
        class _Denied(_EchoServer):
            def obtain_callback(self, authorize_url):
                state = parse_qs(urlparse(authorize_url).query)["state"][0]
                return {"state": state, "error": "access_denied",
                        "error_description": "user declined"}

        flow = OAuthFlow(_provider())
        with pytest.raises(AuthorizationDeniedError) as ei:
            flow.authorize("cid", "csec", callback_server=lambda: _Denied())
        assert ei.value.error == "access_denied"
        assert ei.value.description == "user declined"

    def test_missing_code_raises_malformed(self, monkeypatch):
        class _NoCode(_EchoServer):
            def obtain_callback(self, authorize_url):
                state = parse_qs(urlparse(authorize_url).query)["state"][0]
                return {"state": state}

        flow = OAuthFlow(_provider())
        with pytest.raises(MalformedCallbackError):
            flow.authorize("cid", "csec", callback_server=lambda: _NoCode())


class _Auth:
    CLIENT_ID = "cid"
    CLIENT_SECRET = property(
        lambda self: type("S", (), {"get_secret_value": lambda s: "csec"})()
    )
    SCOPE = "read"

    def persist_key(self):
        return "rat.oauth2"


@pytest.fixture
def rat_env():
    # A real selected settings store, with a namespaced view for test setup.
    # `tokens` is the "oauth"-namespaced view the flow writes through, so tests
    # seed/read with the bare persist_key and the prefix is handled for them.
    store = MemorySecretStore()
    return SimpleNamespace(
        tokens=NamespacedSecretStore(store, "oauth"),
        store=store,
    )


class TestResolveAccessToken:
    def test_returns_cached_unexpired_token(self, rat_env):
        rat_env.tokens.set("rat.oauth2", {
            "access_token": "cached_tok",
            "refresh_token": "r",
            "token_expires_at": int(time.time()) + 3600,
        })
        token = OAuthFlow(_provider(), token_store=rat_env.store).resolve_access_token(_Auth())
        assert token == "cached_tok"

    def test_raises_when_no_token_and_not_auto(self, rat_env):
        with pytest.raises(AuthorizationRequired) as exc:
            OAuthFlow(_provider(), token_store=rat_env.store).resolve_access_token(_Auth())
        assert exc.value.provider == "testprovider"

    def test_raises_when_expired_and_no_refresh(self, rat_env):
        rat_env.tokens.set("rat.oauth2", {
            "access_token": "old",
            "refresh_token": None,
            "token_expires_at": int(time.time()) - 1000,
        })
        with pytest.raises(AuthorizationRequired):
            OAuthFlow(_provider(), token_store=rat_env.store).resolve_access_token(_Auth())

    def test_refresh_persists_and_returns_new_token(self, rat_env):
        rat_env.tokens.set("rat.oauth2", {
            "access_token": "old",
            "refresh_token": "r_xyz",
            "token_expires_at": int(time.time()) - 1000,
        })
        with patch.object(OAuthFlow, "refresh", return_value={
            "access_token": "new_tok",
            "refresh_token": "new_r",
            "token_expires_at": int(time.time()) + 3600,
        }):
            token = OAuthFlow(_provider(), token_store=rat_env.store).resolve_access_token(_Auth())
        assert token == "new_tok"
        assert rat_env.tokens.get("rat.oauth2")["access_token"] == "new_tok"

    def test_persists_under_oauth_namespace_in_raw_store(self, rat_env):
        # Lock the on-store key the flow actually writes: NamespacedSecretStore("oauth")
        # must dot-prefix so the key stays FilesystemSecretStore-compatible (its
        # _key_to_paths splits on "." and rejects "/" segments). Reading through
        # rat_env.tokens hides the delimiter; inspect the RAW store to pin it.
        rat_env.tokens.set("rat.oauth2", {
            "access_token": "old",
            "refresh_token": "r_xyz",
            "token_expires_at": int(time.time()) - 1000,
        })
        with patch.object(OAuthFlow, "refresh", return_value={
            "access_token": "new_tok",
            "refresh_token": "new_r",
            "token_expires_at": int(time.time()) + 3600,
        }):
            OAuthFlow(_provider(), token_store=rat_env.store).resolve_access_token(_Auth())
        assert rat_env.store.get("oauth.rat.oauth2")["access_token"] == "new_tok"
        assert rat_env.store.get("rat.oauth2") is None

    def test_persist_failure_after_refresh_propagates_and_keeps_token(self, rat_env):
        rat_env.tokens.set("rat.oauth2", {
            "access_token": "old",
            "refresh_token": "r_xyz",
            "token_expires_at": int(time.time()) - 1000,
        })

        def boom(key, data):
            raise RuntimeError("disk full")

        rat_env.store.set = boom
        with patch.object(OAuthFlow, "refresh", return_value={
            "access_token": "new_tok",
            "refresh_token": "new_r",
            "token_expires_at": int(time.time()) + 3600,
        }):
            with pytest.raises(RuntimeError, match="disk full"):
                OAuthFlow(_provider(), token_store=rat_env.store).resolve_access_token(_Auth())
        assert rat_env.tokens.get("rat.oauth2")["refresh_token"] == "r_xyz"

    def test_record_without_refresh_token_is_preserved(self, rat_env):
        # The decision uses only the record observed under the transaction.
        concurrent = {"access_token": "concurrent",
                      "token_expires_at": int(time.time()) - 1000}  # no refresh_token key
        rat_env.tokens.set("rat.oauth2", concurrent)

        deleted = {"called": False}
        real_delete = rat_env.store.delete

        def spy_delete(key):
            deleted["called"] = True
            return real_delete(key)

        rat_env.store.delete = spy_delete

        with patch.object(OAuthFlow, "refresh") as mock_refresh:
            with pytest.raises(AuthorizationRequired):
                OAuthFlow(_provider(), token_store=rat_env.store).resolve_access_token(_Auth())
            mock_refresh.assert_not_called()
        assert deleted["called"] is False
        assert rat_env.tokens.get("rat.oauth2") == concurrent

    def test_auto_authorize_forwards_callback_server(self, rat_env):
        sentinel = object()
        captured = {}

        def fake_authorize(**kwargs):
            captured.update(kwargs)
            return {"access_token": "auth_tok", "refresh_token": "", "token_expires_at": None}

        with patch.object(OAuthFlow, "authorize", side_effect=fake_authorize):
            token = OAuthFlow(_provider(), token_store=rat_env.store).resolve_access_token(
                _Auth(), auto_authorize=True, callback_server=sentinel)
        assert token == "auth_tok"
        assert captured["callback_server"] is sentinel

    def test_empty_cached_token_is_failclosed(self, rat_env):
        # An empty-string access_token with no refresh path must NOT be returned;
        # it fails closed to AuthorizationRequired (the `if not access_token` guard).
        rat_env.tokens.set("rat.oauth2", {
            "access_token": "",
            "refresh_token": None,
            "token_expires_at": int(time.time()) + 3600,
        })
        with pytest.raises(AuthorizationRequired):
            OAuthFlow(_provider(), token_store=rat_env.store).resolve_access_token(_Auth())

    def test_empty_token_from_authorize_is_failclosed(self, rat_env):
        # Even when authorize() succeeds, an empty access_token must fail closed
        # rather than be handed back as a valid Bearer (post-authorize guard).
        with patch.object(OAuthFlow, "authorize", return_value={
            "access_token": "", "refresh_token": "", "token_expires_at": None,
        }):
            with pytest.raises(AuthorizationRequired):
                OAuthFlow(_provider(), token_store=rat_env.store).resolve_access_token(
                    _Auth(), auto_authorize=True)

    def test_transient_refresh_failure_keeps_record(self, rat_env):
        rat_env.tokens.set("rat.oauth2", {
            "access_token": "old", "refresh_token": "r_xyz",
            "token_expires_at": int(time.time()) - 1000,
        })
        deleted = {"called": False}
        real_delete = rat_env.store.delete
        def spy_delete(key):
            deleted["called"] = True
            return real_delete(key)
        rat_env.store.delete = spy_delete
        with patch.object(OAuthFlow, "refresh", side_effect=httpx.ConnectError("down")):
            with pytest.raises(httpx.ConnectError):
                OAuthFlow(_provider(), token_store=rat_env.store).resolve_access_token(_Auth())
        assert deleted["called"] is False
        assert rat_env.tokens.get("rat.oauth2")["refresh_token"] == "r_xyz"

    def test_invalid_grant_clears_record(self, rat_env):
        rat_env.tokens.set("rat.oauth2", {
            "access_token": "old", "refresh_token": "r_xyz",
            "token_expires_at": int(time.time()) - 1000,
        })
        err = TokenRefreshError(url="https://t", status_code=401, body='{"error":"invalid_grant"}')
        with patch.object(OAuthFlow, "refresh", side_effect=err):
            with pytest.raises(AuthorizationRequired):
                OAuthFlow(_provider(), token_store=rat_env.store).resolve_access_token(_Auth())
        assert rat_env.tokens.get("rat.oauth2") is None


def test_refresh_derives_expiry_from_jwt_when_no_expires_in():
    import base64
    import json
    def _jwt(payload):
        def seg(d): return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
        return f"{seg({'alg':'ES256'})}.{seg(payload)}.{seg({'s':'x'})}"
    future = int(time.time()) + 900
    flow = OAuthFlow(_provider())
    resp = MagicMock(status_code=200)
    resp.json.return_value = {"access_token": _jwt({"exp": future}), "refresh_token": "r2"}
    resp.raise_for_status.return_value = None
    with patch("httpx.Client") as Client:
        Client.return_value.__enter__.return_value.post.return_value = resp
        out = flow.refresh(refresh_token="r1", client_id="c", client_secret="s")
    assert out["token_expires_at"] == future


def test_exchange_code_derives_expiry_from_jwt_when_no_expires_in():
    # Symmetric to the refresh test: when the token response omits `expires_in`,
    # exchange_code falls back to the access token's JWT `exp` claim.
    import base64
    import json
    def _jwt(payload):
        def seg(d): return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
        return f"{seg({'alg':'ES256'})}.{seg(payload)}.{seg({'s':'x'})}"
    future = int(time.time()) + 900
    flow = OAuthFlow(_provider())
    resp = MagicMock(status_code=200)
    resp.json.return_value = {"access_token": _jwt({"exp": future}), "refresh_token": "r2"}
    resp.raise_for_status.return_value = None
    with patch("httpx.Client") as Client:
        Client.return_value.__enter__.return_value.post.return_value = resp
        out = flow.exchange_code(code="authcode", redirect_uri="https://app/callback",
                                 client_id="c", client_secret="s")
    assert out["token_expires_at"] == future


def _privy_provider():
    return _provider(
        TOKEN_URL="https://auth.privy.io/api/oauth/v2/token",
        TOKEN_ENDPOINT_AUTH_METHOD="none",
        TOKEN_REQUEST_HEADERS={"privy-app-id": "cm6", "Origin": "https://superteam.fun"},
        TOKEN_REQUEST_CONTENT_TYPE="application/json",
    )


def _capture_post():
    resp = MagicMock(status_code=200)
    resp.json.return_value = {"access_token": "AT", "refresh_token": "RT2", "expires_in": 900}
    resp.raise_for_status.return_value = None
    client = MagicMock()
    client.__enter__.return_value.post.return_value = resp
    return client


def test_refresh_none_method_sends_headers_no_client_creds_json_body():
    flow = OAuthFlow(_privy_provider())
    client = _capture_post()
    with patch("httpx.Client", return_value=client):
        flow.refresh(refresh_token="RT1", client_id=None, client_secret=None)
    _, kwargs = client.__enter__.return_value.post.call_args
    assert kwargs["headers"]["privy-app-id"] == "cm6"
    assert kwargs["headers"]["Origin"] == "https://superteam.fun"
    assert kwargs["json"] == {"grant_type": "refresh_token", "refresh_token": "RT1"}
    assert "client_id" not in kwargs.get("json", {}) and "data" not in kwargs


def test_refresh_default_method_is_byte_identical():
    flow = OAuthFlow(_provider())
    client = _capture_post()
    with patch("httpx.Client", return_value=client):
        flow.refresh(refresh_token="RT1", client_id="c", client_secret="s")
    _, kwargs = client.__enter__.return_value.post.call_args
    assert kwargs["data"] == {
        "grant_type": "refresh_token", "refresh_token": "RT1",
        "client_id": "c", "client_secret": "s",
    }
    assert "headers" not in kwargs or kwargs["headers"] == {}
    assert "json" not in kwargs


class TestForceRefresh:
    def test_force_refresh_hits_endpoint_when_token_still_valid(self, rat_env):
        # Seed a NON-expired token with a refresh_token.
        rat_env.tokens.set("rat.oauth2", {
            "access_token": "valid_old_tok",
            "refresh_token": "r_xyz",
            "token_expires_at": int(time.time()) + 4000,
        })
        # Stub the HTTP refresh call to return a NEW token.
        with patch.object(OAuthFlow, "refresh", return_value={
            "access_token": "forced_new_tok",
            "refresh_token": "new_r",
            "token_expires_at": int(time.time()) + 3600,
        }):
            token = OAuthFlow(_provider(), token_store=rat_env.store).force_refresh(_Auth())

        assert token == "forced_new_tok"
        assert rat_env.tokens.get("rat.oauth2")["access_token"] == "forced_new_tok"

        # Sanity contrast: a plain resolve_access_token on the same (now-updated) store
        # returns the cached "forced_new_tok" without hitting the endpoint again.
        with patch.object(OAuthFlow, "refresh") as mock_refresh:
            cached = OAuthFlow(_provider(), token_store=rat_env.store).resolve_access_token(_Auth())
        assert cached == "forced_new_tok"
        mock_refresh.assert_not_called()

    def test_force_refresh_raises_without_refresh_token(self, rat_env):
        # Seed a valid token but with no refresh_token — force_refresh must raise.
        rat_env.tokens.set("rat.oauth2", {
            "access_token": "valid_tok",
            "refresh_token": None,
            "token_expires_at": int(time.time()) + 4000,
        })
        with pytest.raises(AuthorizationRequired):
            OAuthFlow(_provider(), token_store=rat_env.store).force_refresh(_Auth())


class _ObservedStore:
    """Real memory storage plus an interrupted-clear marker and lock observations."""

    def __init__(self, *, cleared=False):
        self.memory = MemorySecretStore()
        self.cleared = cleared
        self.held = False
        self.operations = []

    @contextmanager
    def transaction(self, key):
        with self.memory.transaction(key):
            assert not self.held, "nested transaction"
            self.held = True
            self.operations.append(("enter", key, True))
            try:
                yield
            finally:
                self.operations.append(("exit", key, True))
                self.held = False

    def get(self, key):
        self.operations.append(("get", key, self.held))
        return self.memory.get(key)

    def is_cleared(self, key):
        self.operations.append(("marker", key, self.held))
        assert self.held
        return self.cleared or self.memory.is_cleared(key)

    def set(self, key, data):
        assert self.held
        self.memory.set(key, data)
        self.cleared = False

    def delete(self, key):
        assert self.held
        self.memory.delete(key)


@pytest.fixture(params=["oauth1", "oauth2", "force_refresh"])
def selected_flow(request):
    auth = _Auth()
    auth.CONSUMER_KEY = "ck"
    auth.CONSUMER_SECRET = auth.CLIENT_SECRET
    if request.param == "oauth1":
        provider = OAuth1ProviderProfile(
            NAME="testprovider", REQUEST_TOKEN_URL="https://auth.example.com/request",
            AUTHORIZE_URL="https://auth.example.com/authorize",
            ACCESS_TOKEN_URL="https://auth.example.com/access",
            BASE_URL="https://api.example.com",
        )
        return OAuth1Flow, provider, auth, "resolve_token_pair", ("AT", "ATS")
    method = "force_refresh" if request.param == "force_refresh" else "resolve_access_token"
    return OAuthFlow, _provider(), auth, method, "AT"


@pytest.mark.parametrize("state", ["valid-cleared", "expired-cleared", "missing"])
def test_marker_precedes_retained_record(selected_flow, state):
    flow_type, provider, auth, method, _ = selected_flow
    store = _ObservedStore(cleared=state != "missing")
    if state != "missing":
        store.memory.set("oauth.rat.oauth2", {
            "oauth_token": "STALE", "oauth_token_secret": "STALE_SECRET",
            "access_token": "STALE", "refresh_token": "STALE_REFRESH",
            "token_expires_at": 1 if state == "expired-cleared" else int(time.time()) + 3600,
        })
    flow = flow_type(provider, token_store=store)
    with patch.object(flow, "authorize") as authorize, patch.object(
        OAuthFlow, "refresh"
    ) as refresh:
        with pytest.raises(AuthorizationRequired):
            getattr(flow, method)(auth)
        authorize.assert_not_called()
        refresh.assert_not_called()
    assert store.operations[0] == ("enter", "oauth.rat.oauth2", True)
    assert store.operations[1] == ("marker", "oauth.rat.oauth2", True)
    assert all(held for _, _, held in store.operations)
    if store.cleared:
        assert not any(op == "get" for op, _, _ in store.operations)


@pytest.mark.parametrize("selected_flow", ["oauth1", "oauth2"], indirect=True)
def test_selected_stores_isolate_same_key(selected_flow):
    flow_type, provider, auth, method, expected = selected_flow
    populated, empty = _ObservedStore(), _ObservedStore()
    populated.memory.set("oauth.rat.oauth2", {
        "oauth_token": "AT", "oauth_token_secret": "ATS",
        "access_token": "AT", "token_expires_at": None,
    })
    assert getattr(flow_type(provider, token_store=populated), method)(auth) == expected
    with pytest.raises(AuthorizationRequired):
        getattr(flow_type(provider, token_store=empty), method)(auth)
    assert all(held for _, _, held in populated.operations + empty.operations)
    assert [op for op, _, _ in populated.operations] == ["enter", "marker", "get", "exit"]


@pytest.mark.parametrize("selected_flow", ["oauth1", "oauth2"], indirect=True)
def test_explicit_authorization_replaces_marker_outside_lock(selected_flow):
    flow_type, provider, auth, method, expected = selected_flow
    store = _ObservedStore(cleared=True)
    store.memory.set("oauth.rat.oauth2", {
        "oauth_token": "STALE", "oauth_token_secret": "STALE_SECRET",
        "access_token": "STALE", "refresh_token": "STALE_REFRESH",
        "token_expires_at": 1,
    })
    flow = flow_type(provider, token_store=store)
    fresh = {"oauth_token": "AT", "oauth_token_secret": "ATS",
             "access_token": "AT", "refresh_token": "RT", "token_expires_at": None}

    def authorize(**kwargs):
        assert not store.held
        return fresh

    with patch.object(flow, "authorize", side_effect=authorize), patch.object(
        OAuthFlow, "refresh"
    ) as refresh:
        assert getattr(flow, method)(auth, auto_authorize=True) == expected
        refresh.assert_not_called()
    saved = store.memory.get("oauth.rat.oauth2")
    if flow_type is OAuthFlow:
        assert saved["access_token"] == "AT"
        assert saved["refresh_token"] == "RT"
    else:
        assert saved == fresh
    assert not store.cleared
    assert all(held for _, _, held in store.operations)


def test_persistence_requires_selected_store(selected_flow):
    flow_type, provider, auth, method, _ = selected_flow
    with pytest.raises(RuntimeError, match="OAuth persistence requires token_store"):
        getattr(flow_type(provider), method)(auth)


@pytest.mark.parametrize("operation", ["get", "is_cleared", "transaction"])
def test_store_errors_propagate(selected_flow, operation, monkeypatch):
    flow_type, provider, auth, method, _ = selected_flow
    store = MemorySecretStore()
    error = OSError("store unavailable")

    def fail(key):
        raise error

    monkeypatch.setattr(store, operation, fail)
    with pytest.raises(OSError) as caught:
        getattr(flow_type(provider, token_store=store), method)(auth)
    assert caught.value is error


def test_two_flows_refresh_single_flight(rat_env, monkeypatch):
    rat_env.tokens.set("rat.oauth2", {
        "access_token": "old", "refresh_token": "RT", "token_expires_at": 1,
    })
    entered, release, second_waiting = Event(), Event(), Event()
    real_transaction = rat_env.store.transaction

    @contextmanager
    def observed_transaction(key):
        if entered.is_set():
            second_waiting.set()
        with real_transaction(key):
            yield

    monkeypatch.setattr(rat_env.store, "transaction", observed_transaction)
    exchanges = []

    def post(client, url, **kwargs):
        exchanges.append(kwargs["data"])
        entered.set()
        assert release.wait(5)
        return httpx.Response(200, json={
            "access_token": "NEW", "refresh_token": "ROTATED", "expires_in": 3600,
        }, request=httpx.Request("POST", url))

    monkeypatch.setattr(httpx.Client, "post", post)
    first = OAuthFlow(_provider(), token_store=rat_env.store)
    second = OAuthFlow(_provider(), token_store=rat_env.store)
    with ThreadPoolExecutor(max_workers=2) as pool:
        a = pool.submit(first.resolve_access_token, _Auth())
        try:
            assert entered.wait(5)
            b = pool.submit(second.resolve_access_token, _Auth())
            assert second_waiting.wait(5)
        finally:
            release.set()
        assert a.result(timeout=5) == b.result(timeout=5) == "NEW"
    assert len(exchanges) == 1
    assert exchanges[0]["refresh_token"] == "RT"
    assert rat_env.tokens.get("rat.oauth2")["refresh_token"] == "ROTATED"


@pytest.mark.parametrize("encoding", ["application/json", "application/x-www-form-urlencoded"])
@pytest.mark.parametrize("operation", ["exchange", "refresh"])
def test_public_client_supplied_identity_reaches_token_endpoint(monkeypatch, encoding, operation):
    requests = []
    real_client = httpx.Client

    def endpoint(request):
        requests.append(request)
        return httpx.Response(200, json={"access_token": "accepted", "scope": "openid"})

    monkeypatch.setattr(httpx, "Client", lambda: real_client(transport=httpx.MockTransport(endpoint)))
    flow = OAuthFlow(_provider(TOKEN_ENDPOINT_AUTH_METHOD="none", TOKEN_REQUEST_CONTENT_TYPE=encoding))
    if operation == "exchange":
        tokens = flow.exchange_code("code", "http://127.0.0.1/callback",
                                    client_id="issued", client_secret="must-not-send", scope="openid invoke")
    else:
        tokens = flow.refresh("renewable", client_id="issued", client_secret="must-not-send")
    body = json.loads(requests[0].content) if encoding == "application/json" else {
        k: v[0] for k, v in parse_qs(requests[0].content.decode()).items()
    }
    assert body["client_id"] == "issued"
    assert "client_secret" not in body
    assert "authorization" not in requests[0].headers
    assert tokens["client_id"] == "issued"
    assert tokens["scope"] == "openid"


@pytest.mark.parametrize("returned, expected", [({}, "read"), ({"scope": ""}, ""), ({"scope": "narrow"}, "narrow")])
def test_managed_refresh_preserves_effective_grant_and_identity(monkeypatch, rat_env, returned, expected):
    record = {
        "access_token": "old", "refresh_token": "renewable", "token_expires_at": 1,
        "client_id": "issued", "scope": "read",
        "registration": {"subject": "account"}, "session_metadata": {"claims": {"nonce": "accepted"}},
    }
    rat_env.tokens.set("rat.oauth2", record)
    requests = []
    real_client = httpx.Client

    def endpoint(request):
        requests.append(parse_qs(request.content.decode()))
        return httpx.Response(200, json={"access_token": "new", "refresh_token": "rotated", "expires_in": 3600, **returned})

    monkeypatch.setattr(httpx, "Client", lambda: real_client(transport=httpx.MockTransport(endpoint)))
    flow = OAuthFlow(_provider(TOKEN_ENDPOINT_AUTH_METHOD="none"), token_store=rat_env.store)
    assert flow.resolve_access_token(_Auth()) == "new"
    saved = rat_env.tokens.get("rat.oauth2")
    assert requests[0]["client_id"] == ["issued"]
    assert saved["scope"] == expected
    assert saved["refresh_token"] == "rotated"
    assert saved["registration"] == {"subject": "account"}
    assert saved["session_metadata"] == {"claims": {"nonce": "accepted"}}


@pytest.mark.parametrize("requested, response_scope, expected", [
    ("read", {}, "read"), ("read", {"scope": ""}, ""), ("read", {"scope": "narrow"}, "narrow"),
    (None, {}, None), ("", {}, ""),
])
def test_exchange_uses_response_scope_without_truthy_fallback(monkeypatch, requested, response_scope, expected):
    real_client = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda: real_client(transport=httpx.MockTransport(
        lambda request: httpx.Response(200, json={"access_token": "accepted", **response_scope}),
    )))
    tokens = OAuthFlow(_provider()).exchange_code("code", "http://localhost/callback", scope=requested)
    assert tokens["scope"] == expected
