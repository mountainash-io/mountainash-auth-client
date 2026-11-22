"""Tests for OAuth1Flow."""

from __future__ import annotations

import traceback
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import parse_qs, unquote, urlsplit
from urllib.request import parse_http_list

import httpx
import pytest
from mountainash_settings.secrets import MemorySecretStore, NamespacedSecretStore

import mountainash_auth_client.oauth.oauth1.flow as flow_module
from mountainash_auth_client.errors import (
    AuthorizationRequired,
    MalformedCallbackError,
    TokenExchangeError,
)
from mountainash_auth_client.oauth.oauth1.flow import OAuth1Flow
from tests._error_surfaces import exception_surfaces
from mountainash_auth_client.oauth.providers.oauth1 import OAuth1ProviderProfile


def _provider(**overrides):
    base = dict(
        NAME="testprovider_oauth1",
        REQUEST_TOKEN_URL="https://auth.example.com/oauth/request_token",
        AUTHORIZE_URL="https://auth.example.com/oauth/authorize",
        ACCESS_TOKEN_URL="https://auth.example.com/oauth/access_token",
        BASE_URL="https://api.example.com",
    )
    base.update(overrides)
    return OAuth1ProviderProfile(**base)


class TestOAuth1FlowBuildAuthorizeUrl:
    def test_contains_oauth_token_param(self):
        flow = OAuth1Flow(_provider())
        url = flow.build_authorize_url("test_oauth_token_123")
        assert "oauth_token=test_oauth_token_123" in url

    def test_contains_authorize_base_url(self):
        flow = OAuth1Flow(_provider())
        url = flow.build_authorize_url("tok")
        assert "https://auth.example.com/oauth/authorize" in url

    def test_properties_read_from_provider(self):
        flow = OAuth1Flow(_provider())
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
        flow = OAuth1Flow(_provider())
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
        flow = OAuth1Flow(_provider())
        with pytest.raises(ImportError, match="authlib"):
            flow.exchange_verifier("ck", "cs", "tok", "tok_sec", "verifier")


@pytest.fixture
def oauth_http(monkeypatch):
    # Authlib ships no typing marker; keep this dependency-local suppression checked.
    from authlib.integrations.httpx_client import OAuth1Client  # type: ignore[import-untyped]

    clients = []
    requests = []

    def install(handler):
        def deliver(request):
            requests.append(request)
            return handler(request)

        def construct(*args, **kwargs):
            client = OAuth1Client(*args, transport=httpx.MockTransport(deliver), **kwargs)
            clients.append(client)
            return client

        def load(*attrs):
            assert attrs == ("OAuth1Client",)
            return construct

        monkeypatch.setattr(flow_module, "require_authlib", load)
        return SimpleNamespace(flow=OAuth1Flow(_provider()), clients=clients, requests=requests)

    try:
        yield install
    finally:
        for client in clients:
            client.close()


def _fetch_token(flow, stage, callback=None):
    if stage == "request":
        if callback is None:
            return flow.request_token("ck", "cs")
        return flow.request_token("ck", "cs", callback_url=callback)
    return flow.exchange_verifier("ck", "cs", "RT", "RTS", "VERIFIER")


def _oauth_parameters(request):
    header = request.headers["Authorization"]
    assert header.startswith("OAuth ")
    return [
        (unquote(key), unquote(value.strip('"')))
        for item in parse_http_list(header[6:])
        for key, value in [item.split("=", 1)]
    ]


@pytest.mark.parametrize(
    ("stage", "callback", "status"),
    [
        ("request", None, 200),
        ("request", "https://app.example/cb?next=a%26b", 200),
        ("access", None, 200),
        ("request", None, 302),
        ("access", None, 302),
    ],
)
def test_token_endpoint_success(oauth_http, stage, callback, status):
    env = oauth_http(
        lambda request: httpx.Response(
            status,
            text="oauth_token=AT&oauth_token_secret=ATS&oauth_callback_confirmed=true",
        )
    )
    result = _fetch_token(env.flow, stage, callback)
    expected = {"oauth_token": "AT", "oauth_token_secret": "ATS"}
    if stage == "request":
        expected["oauth_callback_confirmed"] = "true"
    assert result == expected
    assert len(env.requests) == 1
    request = env.requests[0]
    assert request.method == "POST"
    parameters = _oauth_parameters(request)
    if stage == "request":
        callbacks = [value for key, value in parameters if key == "oauth_callback"]
        assert callbacks == [callback if callback is not None else "oob"]
        assert "oauth_callback" not in parse_qs(urlsplit(str(request.url)).query)
    else:
        assert dict(parameters)["oauth_token"] == "RT"
        assert dict(parameters)["oauth_verifier"] == "VERIFIER"
    assert env.clients[0].is_closed


class _ResponseStream(httpx.SyncByteStream):
    def __init__(self, body, failure=None):
        self.payload = body.encode("utf-8")
        self.failure = failure
        self.closed = False

    def __iter__(self):
        yield self.payload[:7]
        if self.failure is not None:
            raise self.failure
        yield self.payload[7:]

    def close(self):
        self.closed = True


@pytest.mark.parametrize(
    ("stage", "status", "kind"),
    [
        ("request", 401, "plain"),
        ("request", 500, "token"),
        ("access", 401, "plain"),
        ("access", 500, "token"),
        ("request", 401, "long"),
    ],
)
def test_http_rejection_is_redacted(oauth_http, stage, status, kind):
    marker = "BODY_" + "SENSITIVE_" + "MARKER"
    body = {
        "plain": marker,
        "token": "oauth_token=AT&oauth_token_secret=ATS&detail=" + marker,
        "long": marker + "é" * 2200,
    }[kind]
    stream = _ResponseStream(body)
    env = oauth_http(
        lambda request: httpx.Response(
            status,
            stream=stream,
            headers={"Content-Type": "text/plain; charset=utf-8"},
        )
    )
    with pytest.raises(TokenExchangeError) as caught:
        _fetch_token(env.flow, stage)
    error = caught.value
    endpoint = env.flow.request_token_url if stage == "request" else env.flow.access_token_url
    assert error.url == endpoint
    assert error.status_code == status
    assert error.body == ""  # non-JSON bodies are dropped entirely
    assert marker not in error.body
    assert marker not in str(error)
    assert marker not in repr(error)
    assert marker not in "".join(traceback.format_exception(error))
    assert len(env.requests) == 1
    assert stream.closed
    assert env.clients[0].is_closed


_SENTINEL = "P7_" + "PROVIDER_SECRET"


def _assert_safe(error, env, stage):
    surfaces = exception_surfaces(error)
    assert _SENTINEL not in surfaces
    assert "PROVIDER_SECRET" not in surfaces
    assert len(env.requests) == 1
    assert env.clients[0].is_closed


@pytest.mark.parametrize("stage", ["request", "access"])
def test_malformed_success_keeps_status_without_provider_prose(oauth_http, stage):
    env = oauth_http(lambda request: httpx.Response(200, text="oauth_problem=" + _SENTINEL))
    with pytest.raises(TokenExchangeError) as caught:
        _fetch_token(env.flow, stage)
    assert caught.value.status_code == 200
    assert caught.value.error_code is None
    assert caught.value.body == ""
    _assert_safe(caught.value, env, stage)


@pytest.mark.parametrize("stage", ["request", "access"])
@pytest.mark.parametrize(
    "text",
    [
        "oauth_token_secret=" + _SENTINEL,
        _SENTINEL,
    ],
)
def test_missing_oauth_token_is_response_backed_failure(oauth_http, stage, text):
    env = oauth_http(lambda request: httpx.Response(200, text=text))
    with pytest.raises(TokenExchangeError) as caught:
        _fetch_token(env.flow, stage)
    assert caught.value.status_code == 200
    assert caught.value.body == ""
    _assert_safe(caught.value, env, stage)


@pytest.mark.parametrize("stage", ["request", "access"])
def test_empty_oauth_token_is_present_and_preserved(oauth_http, stage):
    env = oauth_http(lambda request: httpx.Response(200, text="oauth_token=&oauth_token_secret=S"))
    result = _fetch_token(env.flow, stage)
    assert result["oauth_token"] == ""
    assert env.clients[0].is_closed


def test_request_token_without_secret_keeps_token_only_mapping(oauth_http):
    env = oauth_http(lambda request: httpx.Response(200, text="oauth_token=AT"))
    assert env.flow.request_token("ck", "cs") == {"oauth_token": "AT"}
    assert env.clients[0].is_closed


def test_exchange_verifier_without_secret_is_safe_status_200(oauth_http):
    env = oauth_http(lambda request: httpx.Response(200, text="oauth_token=AT&x=" + _SENTINEL))
    with pytest.raises(TokenExchangeError) as caught:
        env.flow.exchange_verifier("ck", "cs", "RT", "RTS", "VERIFIER")
    assert caught.value.status_code == 200
    assert caught.value.body == ""
    _assert_safe(caught.value, env, "access")


@pytest.mark.parametrize("stage", ["request", "access"])
@pytest.mark.parametrize("status", [200, 401])
def test_stream_failure_after_headers_is_safe_response_backed(oauth_http, stage, status):
    stream = _ResponseStream("partial response", failure=httpx.ReadError(_SENTINEL))
    env = oauth_http(lambda request: httpx.Response(status, stream=stream))
    with pytest.raises(TokenExchangeError) as caught:
        _fetch_token(env.flow, stage)
    assert caught.value.status_code == status
    assert caught.value.body == ""
    assert stream.closed
    _assert_safe(caught.value, env, stage)


@pytest.mark.parametrize("stage", ["request", "access"])
@pytest.mark.parametrize("error_type", [httpx.ConnectError, httpx.ReadTimeout])
def test_no_response_transport_failure_is_safe_runtime_error(oauth_http, stage, error_type):
    sentinel = error_type(_SENTINEL)

    def deliver(request):
        raise sentinel

    env = oauth_http(deliver)
    with pytest.raises(RuntimeError) as caught:
        _fetch_token(env.flow, stage)
    assert not isinstance(caught.value, TokenExchangeError)
    assert caught.value is not sentinel
    _assert_safe(caught.value, env, stage)


@pytest.mark.parametrize("stage", ["request", "access"])
def test_recursive_chain_stays_clean(oauth_http, stage):
    inner = ValueError(_SENTINEL)
    outer = httpx.ConnectError("wrapped")
    outer.__cause__ = inner
    inner.__context__ = outer  # cycle

    def deliver(request):
        raise outer

    env = oauth_http(deliver)
    with pytest.raises(RuntimeError) as caught:
        _fetch_token(env.flow, stage)
    _assert_safe(caught.value, env, stage)


@pytest.mark.parametrize("stage", ["request", "access"])
def test_client_construction_failure_is_safe(oauth_http, stage, monkeypatch):
    def construct(*args, **kwargs):
        raise OSError(_SENTINEL)

    oauth_http(lambda request: httpx.Response(200, text=""))
    env_flow = OAuth1Flow(_provider())
    monkeypatch.setattr(flow_module, "require_authlib", lambda *attrs: construct)
    with pytest.raises(RuntimeError) as caught:
        _fetch_token(env_flow, stage)
    assert not isinstance(caught.value, TokenExchangeError)
    assert _SENTINEL not in exception_surfaces(caught.value)


@pytest.mark.parametrize("stage", ["request", "access"])
def test_client_exit_failure_after_response_keeps_status(stage, monkeypatch):
    from authlib.integrations.httpx_client import OAuth1Client  # type: ignore[import-untyped]

    requests = []

    class FailingExit(OAuth1Client):
        def __exit__(self, *exc):
            super().__exit__(*exc)
            raise OSError(_SENTINEL)

    def deliver(request):
        requests.append(request)
        return httpx.Response(200, text="oauth_token=AT&oauth_token_secret=ATS")

    monkeypatch.setattr(
        flow_module,
        "require_authlib",
        lambda *attrs: lambda *a, **kw: FailingExit(*a, transport=httpx.MockTransport(deliver), **kw),
    )
    with pytest.raises(TokenExchangeError) as caught:
        _fetch_token(OAuth1Flow(_provider()), stage)
    assert caught.value.status_code == 200
    assert caught.value.body == ""
    assert _SENTINEL not in exception_surfaces(caught.value)
    assert len(requests) == 1


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
        flow,
        "request_token",
        lambda consumer_key, consumer_secret, callback_url: sink.update(callback_url=callback_url)
        or {"oauth_token": "REQTOKEN", "oauth_token_secret": "REQSECRET"},
    )
    monkeypatch.setattr(
        flow,
        "exchange_verifier",
        lambda **kw: sink.update(kw) or {"oauth_token": "ACCESS", "oauth_token_secret": "ASEC"},
    )


class TestOAuth1Authorize:
    def test_injected_server_drives_callback_url_and_verifier(self, monkeypatch):
        flow = OAuth1Flow(_provider())
        sink = {}
        _stub_oauth1(flow, monkeypatch, sink)
        flow.authorize("ckey", "csec", callback_server=lambda: _OAuth1Echo("https://INJECT/cb"))
        assert sink["callback_url"] == "https://INJECT/cb"
        assert sink["verifier"] == "VERIF"

    def test_manual_builtin_uses_literal_oob(self, monkeypatch):
        flow = OAuth1Flow(_provider())
        sink = {}
        _stub_oauth1(flow, monkeypatch, sink)
        monkeypatch.setattr(
            "mountainash_auth_client.oauth.server.manual.prompt_for_code", lambda url: {"code": "BAREVERIF"}
        )
        flow.authorize("ckey", "csec", redirect_mode="manual")
        assert sink["callback_url"] == "oob"
        assert sink["verifier"] == "BAREVERIF"

    def test_missing_verifier_raises_malformed(self, monkeypatch):
        flow = OAuth1Flow(_provider())
        sink = {}
        _stub_oauth1(flow, monkeypatch, sink)
        with pytest.raises(MalformedCallbackError):
            flow.authorize("ckey", "csec", callback_server=lambda: _OAuth1Echo(params={"oauth_token": "REQTOKEN"}))

    def test_token_mismatch_raises_value_error(self, monkeypatch):
        flow = OAuth1Flow(_provider())
        sink = {}
        _stub_oauth1(flow, monkeypatch, sink)
        with pytest.raises(ValueError, match="mismatch"):
            flow.authorize(
                "ckey",
                "csec",
                callback_server=lambda: _OAuth1Echo(params={"oauth_verifier": "V", "oauth_token": "WRONG"}),
            )

    def test_safe_token_failure_keeps_status_through_authorize(self, monkeypatch):
        flow = OAuth1Flow(_provider())
        failure = TokenExchangeError(url="https://auth.example.com/x", status_code=429, body="")
        monkeypatch.setattr(flow, "request_token", lambda *a, **kw: (_ for _ in ()).throw(failure))
        with pytest.raises(TokenExchangeError) as caught:
            flow.authorize("ckey", "csec", callback_server=lambda: _OAuth1Echo())
        assert caught.value.status_code == 429

    def test_server_factory_failure_is_safe(self):
        flow = OAuth1Flow(_provider())

        def factory():
            raise OSError(_SENTINEL)

        with pytest.raises(RuntimeError) as caught:
            flow.authorize("ckey", "csec", callback_server=factory)
        assert _SENTINEL not in exception_surfaces(caught.value)

    def test_callback_failure_is_safe_and_not_trusted_subclass(self, monkeypatch):
        flow = OAuth1Flow(_provider())
        _stub_oauth1(flow, monkeypatch, {})

        class PluginError(MalformedCallbackError):
            pass

        class Server(_OAuth1Echo):
            def obtain_callback(self, authorize_url):
                raise PluginError(_SENTINEL)

        with pytest.raises(Exception) as caught:
            flow.authorize("ckey", "csec", callback_server=Server)
        assert not isinstance(caught.value, PluginError)
        assert _SENTINEL not in exception_surfaces(caught.value)

    def test_plain_callback_failure_is_safe(self, monkeypatch):
        flow = OAuth1Flow(_provider())
        _stub_oauth1(flow, monkeypatch, {})

        class Server(_OAuth1Echo):
            def obtain_callback(self, authorize_url):
                raise RuntimeError(_SENTINEL)

        with pytest.raises(RuntimeError) as caught:
            flow.authorize("ckey", "csec", callback_server=Server)
        assert _SENTINEL not in exception_surfaces(caught.value)

    @pytest.mark.parametrize(
        ("params", "category"),
        [
            ({"oauth_verifier": "V", "oauth_token": "WRONG"}, ValueError),
            ({"oauth_token": "REQTOKEN"}, MalformedCallbackError),
        ],
    )
    def test_explicit_callback_failures_clear_active_context(self, monkeypatch, params, category):
        flow = OAuth1Flow(_provider())
        _stub_oauth1(flow, monkeypatch, {})
        try:
            raise RuntimeError(_SENTINEL)
        except RuntimeError:
            with pytest.raises(category) as caught:
                flow.authorize("ckey", "csec", callback_server=lambda: _OAuth1Echo(params=params))
        assert type(caught.value) is category
        assert caught.value.__context__ is None
        assert _SENTINEL not in exception_surfaces(caught.value)

    def test_malformed_callback_params_are_safe(self, monkeypatch):
        flow = OAuth1Flow(_provider())
        sink = {}
        _stub_oauth1(flow, monkeypatch, sink)
        with pytest.raises(RuntimeError) as caught:
            flow.authorize(
                "ckey",
                "csec",
                callback_server=lambda: _OAuth1Echo(params={"oauth_verifier": "V", "oauth_token": _SENTINEL + "\ud800"}),
            )
        assert _SENTINEL not in exception_surfaces(caught.value)
        assert "verifier" not in sink


class _Auth1:
    CONSUMER_KEY = "ck"
    CONSUMER_SECRET = property(lambda self: type("S", (), {"get_secret_value": lambda s: "cs"})())

    def persist_key(self):
        return "rtp.oauth1"


@pytest.fixture
def rtp_env():
    store = MemorySecretStore()
    return SimpleNamespace(
        tokens=NamespacedSecretStore(store, "oauth"),
        store=store,
    )


class TestResolveTokenPair:
    def test_returns_cached_pair(self, rtp_env):
        rtp_env.tokens.set("rtp.oauth1", {"oauth_token": "AT", "oauth_token_secret": "ATS"})
        pair = OAuth1Flow(_provider(), token_store=rtp_env.store).resolve_token_pair(_Auth1())
        assert pair == ("AT", "ATS")

    def test_raises_when_no_token_and_not_auto(self, rtp_env):
        with pytest.raises(AuthorizationRequired) as exc:
            OAuth1Flow(_provider(), token_store=rtp_env.store).resolve_token_pair(_Auth1())
        assert exc.value.provider == "testprovider_oauth1"

    def test_auto_authorize_persists_and_returns_pair(self, rtp_env):
        with patch.object(
            OAuth1Flow,
            "authorize",
            return_value={
                "oauth_token": "newAT",
                "oauth_token_secret": "newATS",
            },
        ):
            pair = OAuth1Flow(_provider(), token_store=rtp_env.store).resolve_token_pair(_Auth1(), auto_authorize=True)
        assert pair == ("newAT", "newATS")
        assert rtp_env.tokens.get("rtp.oauth1")["oauth_token"] == "newAT"

    def test_auto_authorize_forwards_callback_server(self, rtp_env):
        sentinel = object()
        captured = {}

        def fake_authorize(**kwargs):
            captured.update(kwargs)
            return {"oauth_token": "AT", "oauth_token_secret": "ATS"}

        with patch.object(OAuth1Flow, "authorize", side_effect=fake_authorize):
            OAuth1Flow(_provider(), token_store=rtp_env.store).resolve_token_pair(
                _Auth1(), auto_authorize=True, callback_server=sentinel
            )
        assert captured["callback_server"] is sentinel
