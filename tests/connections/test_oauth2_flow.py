"""Tests for OAuthFlow (OAuth2 authorization code flow)."""
from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import httpx
import pytest

from mountainash_auth_client.errors import TokenExchangeError, TokenRefreshError
from mountainash_auth_client.connections.oauth2.flow import OAuthFlow
from mountainash_auth_client.providers.oauth2 import OAuth2ProviderProfile


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


from urllib.parse import parse_qs, urlparse

from mountainash_auth_client.errors import (
    AuthorizationDeniedError,
    MalformedCallbackError,
)


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
        import mountainash_auth_client.connections.server.factory as factory
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


from types import SimpleNamespace

from mountainash_auth_client.errors import AuthorizationRequired
from mountainash_secrets import InMemoryStore, NamespacedStore, RegistryResolver


class _Auth:
    CLIENT_ID = "cid"
    CLIENT_SECRET = property(
        lambda self: type("S", (), {"get_secret_value": lambda s: "csec"})()
    )
    SCOPE = "read"
    SETTINGS_SOURCE_SECRETS_PROVIDER = "rat_mem"

    def persist_key(self):
        return "rat.oauth2"


@pytest.fixture
def rat_env():
    # A real mountainash-secrets store resolved by name exactly as the flow does.
    # `tokens` is the "oauth"-namespaced view the flow writes through, so tests
    # seed/read with the bare persist_key and the prefix is handled for them.
    store = InMemoryStore()
    return SimpleNamespace(
        resolver=RegistryResolver({"rat_mem": store}),
        tokens=NamespacedStore(store, "oauth"),
        store=store,
    )


class TestResolveAccessToken:
    def test_returns_cached_unexpired_token(self, rat_env):
        rat_env.tokens.set("rat.oauth2", {
            "access_token": "cached_tok",
            "refresh_token": "r",
            "token_expires_at": int(time.time()) + 3600,
        })
        token = OAuthFlow(_provider(), resolver=rat_env.resolver).resolve_access_token(_Auth())
        assert token == "cached_tok"

    def test_raises_when_no_token_and_not_auto(self, rat_env):
        with pytest.raises(AuthorizationRequired) as exc:
            OAuthFlow(_provider(), resolver=rat_env.resolver).resolve_access_token(_Auth())
        assert exc.value.provider == "testprovider"

    def test_raises_when_expired_and_no_refresh(self, rat_env):
        rat_env.tokens.set("rat.oauth2", {
            "access_token": "old",
            "refresh_token": None,
            "token_expires_at": int(time.time()) - 1000,
        })
        with pytest.raises(AuthorizationRequired):
            OAuthFlow(_provider(), resolver=rat_env.resolver).resolve_access_token(_Auth())

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
            token = OAuthFlow(_provider(), resolver=rat_env.resolver).resolve_access_token(_Auth())
        assert token == "new_tok"
        assert rat_env.tokens.get("rat.oauth2")["access_token"] == "new_tok"

    def test_persists_under_oauth_namespace_in_raw_store(self, rat_env):
        # Lock the on-store key the flow actually writes: NamespacedStore("oauth")
        # must dot-prefix so the key stays FilesystemStore-compatible (its
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
            OAuthFlow(_provider(), resolver=rat_env.resolver).resolve_access_token(_Auth())
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
                OAuthFlow(_provider(), resolver=rat_env.resolver).resolve_access_token(_Auth())
        assert rat_env.tokens.get("rat.oauth2")["refresh_token"] == "r_xyz"

    def test_refresh_branch_leaves_concurrent_record_when_refresh_token_vanished(self, rat_env):
        # Stale-read race: pre-lock we read an expired token WITH a refresh_token
        # and commit to the refresh branch. Under the lock, a concurrent writer has
        # replaced the record with one that has NO refresh_token (e.g. provider
        # rotation). The fix re-derives the decision from the re-read record: with
        # no refresh_token it must NOT subscript a missing key, must NOT delete the
        # concurrent writer's record, and must NOT attempt a refresh — it just fails
        # closed. (Old code did `tokens["refresh_token"]` -> KeyError -> except ->
        # backend.delete(key), destroying the other writer's record.)
        pre_lock = {"access_token": "old", "refresh_token": "r_xyz",
                    "token_expires_at": int(time.time()) - 1000}
        concurrent = {"access_token": "concurrent",
                      "token_expires_at": int(time.time()) - 1000}  # no refresh_token key

        n = {"get": 0}

        def racing_get(key):
            n["get"] += 1
            return pre_lock if n["get"] == 1 else concurrent

        rat_env.store.get = racing_get

        deleted = {"called": False}
        real_delete = rat_env.store.delete

        def spy_delete(key):
            deleted["called"] = True
            return real_delete(key)

        rat_env.store.delete = spy_delete

        with patch.object(OAuthFlow, "refresh") as mock_refresh:
            with pytest.raises(AuthorizationRequired):
                OAuthFlow(_provider(), resolver=rat_env.resolver).resolve_access_token(_Auth())
            mock_refresh.assert_not_called()
        assert deleted["called"] is False

    def test_auto_authorize_forwards_callback_server(self, rat_env):
        sentinel = object()
        captured = {}

        def fake_authorize(**kwargs):
            captured.update(kwargs)
            return {"access_token": "auth_tok", "refresh_token": "", "token_expires_at": None}

        with patch.object(OAuthFlow, "authorize", side_effect=fake_authorize):
            token = OAuthFlow(_provider(), resolver=rat_env.resolver).resolve_access_token(
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
            OAuthFlow(_provider(), resolver=rat_env.resolver).resolve_access_token(_Auth())

    def test_empty_token_from_authorize_is_failclosed(self, rat_env):
        # Even when authorize() succeeds, an empty access_token must fail closed
        # rather than be handed back as a valid Bearer (post-authorize guard).
        with patch.object(OAuthFlow, "authorize", return_value={
            "access_token": "", "refresh_token": "", "token_expires_at": None,
        }):
            with pytest.raises(AuthorizationRequired):
                OAuthFlow(_provider(), resolver=rat_env.resolver).resolve_access_token(
                    _Auth(), auto_authorize=True)
