"""Secrets must not leak through repr(), exception surfaces, or retained logs.

OAuth2 token operations run through a real ``httpx.Client`` on ``MockTransport``;
only the transport answer (or its failure) is simulated.
"""
from __future__ import annotations

import errno
import json
import logging
import os

import httpx
import pytest

from mountainash_auth_client.errors import TokenExchangeError, TokenRefreshError
from mountainash_auth_client.oauth.lifecycle.credential import TokenCredential
from mountainash_auth_client.oauth.oauth2.flow import OAuthFlow
from mountainash_auth_client.oauth.providers.oauth2 import OAuth2ProviderProfile
from mountainash_auth_client.schemas.service_account import SERVICE_ACCOUNT_SPEC, ServiceAccountAuthProfile
from tests._error_surfaces import exception_surfaces

SENTINEL = "SENTINEL-SECRET-9f3a"
URL_USER = "SENTINEL-userinfo-1a"
URL_QUERY = "SENTINEL-query-2b"
URL_FRAGMENT = "SENTINEL-fragment-3c"
BODY = "SENTINEL-body-4d"
HEADER = "SENTINEL-header-5e"
REQUEST = "SENTINEL-request-6f"
LEAKS = (URL_USER, URL_QUERY, URL_FRAGMENT, BODY, HEADER, REQUEST)

TOKEN_URL = f"https://{URL_USER}:{URL_USER}@a.example/token?q={URL_QUERY}#{URL_FRAGMENT}"
RealClient = httpx.Client
HEADERS = {"x-leak": HEADER}


def _flow(flow_type=OAuthFlow, **overrides):
    return flow_type(OAuth2ProviderProfile(
        NAME="p", AUTHORIZE_URL="https://a.example/authorize",
        TOKEN_URL=TOKEN_URL, BASE_URL="https://api.example", **overrides,
    ))


OPERATIONS = {
    "exchange": (
        TokenExchangeError,
        lambda flow: flow.exchange_code(
            code=REQUEST, redirect_uri="http://127.0.0.1/cb", client_id="c", client_secret=REQUEST),
    ),
    "refresh": (
        TokenRefreshError,
        lambda flow: flow.refresh(refresh_token=REQUEST, client_id="c", client_secret=REQUEST),
    ),
}
operation = pytest.mark.parametrize("op", OPERATIONS)


class _ExitFailsClient(RealClient):
    def __exit__(self, *exc_info):
        super().__exit__(*exc_info)
        raise OSError(errno.EIO, os.strerror(errno.EIO), URL_QUERY)


class _EnterFailsClient(RealClient):
    def __enter__(self):
        raise ConnectionError(BODY)


class _FailingStream(httpx.SyncByteStream):
    """A response body that breaks after its headers were delivered."""

    def __init__(self):
        self.closed = False

    def __iter__(self):
        yield b'{"partial": "'
        raise httpx.ReadError(BODY) from OSError(BODY)

    def close(self):
        self.closed = True


class _Wire:
    """Install a real httpx.Client on MockTransport, recording requests and clients."""

    def __init__(self, monkeypatch, handler, client_type=RealClient):
        self.requests: list[httpx.Request] = []
        self.clients: list[httpx.Client] = []

        def dispatch(request):
            self.requests.append(request)
            return handler(request)

        def make(**kwargs):
            client = client_type(transport=httpx.MockTransport(dispatch), **kwargs)
            self.clients.append(client)
            return client

        monkeypatch.setattr(httpx, "Client", make)


def _ok(request):
    return httpx.Response(200, json={"access_token": "AT", "refresh_token": "RT", "expires_in": 3600})


def _assert_no_leaks(error):
    observed = exception_surfaces(error)
    for leak in LEAKS:
        assert leak not in observed


def test_token_credential_repr_hides_tokens():
    cred = TokenCredential(access_token=SENTINEL, refresh_token=SENTINEL + "r")
    assert SENTINEL not in repr(cred) and SENTINEL not in str(cred)


def test_service_account_info_is_secret():
    spec = next(p for p in SERVICE_ACCOUNT_SPEC.parameters if p.name == "INFO")
    assert spec.secret is True
    profile = ServiceAccountAuthProfile(INFO='{"private_key": "%s"}' % SENTINEL)
    assert SENTINEL not in repr(profile) and SENTINEL not in str(profile)


@operation
@pytest.mark.parametrize("status, response, code", [
    (400, {"error": "invalid_grant", "error_description": BODY, "refresh_token": BODY}, "invalid_grant"),
    (401, {"error": "invalid_token", "error_description": BODY}, "invalid_token"),
    (400, {"error": BODY, "error_description": BODY}, None),
    (500, {"error": "server_error", "access_token": BODY}, None),
])
def test_http_failure_keeps_status_and_recognised_code_only(monkeypatch, op, status, response, code):
    wire = _Wire(monkeypatch, lambda request: httpx.Response(status, json=response, headers=HEADERS))
    error_type, run = OPERATIONS[op]
    with pytest.raises(error_type) as caught:
        run(_flow())
    assert len(wire.requests) == 1 and all(c.is_closed for c in wire.clients)
    assert caught.value.status_code == status
    assert caught.value.error_code == code
    assert (json.loads(caught.value.body) if code else caught.value.body) == ({"error": code} if code else "")
    _assert_no_leaks(caught.value)


@operation
def test_non_json_http_failure_keeps_status_without_body(monkeypatch, op):
    _Wire(monkeypatch, lambda request: httpx.Response(502, text=f"gateway {BODY}", headers=HEADERS))
    error_type, run = OPERATIONS[op]
    with pytest.raises(error_type) as caught:
        run(_flow())
    assert (caught.value.status_code, caught.value.error_code, caught.value.body) == (502, None, "")
    _assert_no_leaks(caught.value)


@operation
@pytest.mark.parametrize("response", [
    lambda: httpx.Response(200, text=f"not json {BODY}", headers=HEADERS),
    lambda: httpx.Response(200, json=[BODY, {"access_token": BODY}], headers=HEADERS),
    lambda: httpx.Response(200, json={"refresh_token": BODY, "id_token": BODY}, headers=HEADERS),
    lambda: httpx.Response(200, json={"access_token": "AT", "expires_in": BODY}, headers=HEADERS),
], ids=["invalid-json", "non-dict-json", "missing-token", "nonnumeric-expires-in"])
def test_malformed_success_keeps_actual_status_and_echoes_nothing(monkeypatch, op, response):
    wire = _Wire(monkeypatch, lambda request: response())
    error_type, run = OPERATIONS[op]
    with pytest.raises(error_type) as caught:
        run(_flow())
    assert (caught.value.status_code, caught.value.error_code, caught.value.body) == (200, None, "")
    assert len(wire.requests) == 1 and all(c.is_closed for c in wire.clients)
    _assert_no_leaks(caught.value)


@operation
@pytest.mark.parametrize("failure", ["connect", "client_construction", "client_entry"])
def test_failure_without_a_response_is_safe_runtime_error(monkeypatch, op, failure):
    def refuse(request):
        raise httpx.ConnectError(BODY, request=request) from OSError(errno.ECONNREFUSED, BODY, URL_QUERY)

    wire = _Wire(
        monkeypatch, refuse,
        client_type=_EnterFailsClient if failure == "client_entry" else RealClient,
    )
    if failure == "client_construction":
        def construct(**kwargs):
            raise ValueError(BODY)

        monkeypatch.setattr(httpx, "Client", construct)
    error_type, run = OPERATIONS[op]
    with pytest.raises(RuntimeError) as caught:
        run(_flow())
    assert not isinstance(caught.value, (TokenExchangeError, TokenRefreshError))
    assert not hasattr(caught.value, "status_code") and not hasattr(caught.value, "error_code")
    _assert_no_leaks(caught.value)
    assert len(wire.requests) == int(failure == "connect")


@operation
@pytest.mark.parametrize("status", [200, 502])
def test_body_read_failure_keeps_status_and_closes_response(monkeypatch, op, status):
    stream = _FailingStream()
    wire = _Wire(monkeypatch, lambda request: httpx.Response(status, headers=HEADERS, stream=stream))
    error_type, run = OPERATIONS[op]
    with pytest.raises(error_type) as caught:
        run(_flow())
    assert (caught.value.status_code, caught.value.error_code, caught.value.body) == (status, None, "")
    assert stream.closed and all(c.is_closed for c in wire.clients)
    _assert_no_leaks(caught.value)


@operation
def test_client_exit_failure_after_response_keeps_status(monkeypatch, op):
    wire = _Wire(monkeypatch, _ok, client_type=_ExitFailsClient)
    error_type, run = OPERATIONS[op]
    with pytest.raises(error_type) as caught:
        run(_flow())
    assert (caught.value.status_code, caught.value.error_code, caught.value.body) == (200, None, "")
    assert len(wire.requests) == 1 and all(c.is_closed for c in wire.clients)
    _assert_no_leaks(caught.value)


def _marked(kind):
    if kind == "chained":
        try:
            raise RuntimeError(BODY)
        except RuntimeError as inner:
            error = ValueError(BODY)
            error.__cause__ = inner
            return error
    return OSError(errno.EIO, os.strerror(errno.EIO), URL_QUERY)


class _HookFlow(OAuthFlow):
    failing: str
    error: Exception

    def token_parameters(self, context):
        if self.failing == "token_parameters":
            raise self.error
        return {}

    def validate_token_response(self, response, context, previous, candidate):
        if self.failing == "validate_token_response":
            raise self.error
        return candidate


@operation
@pytest.mark.parametrize("kind", ["chained", "oserror"])
def test_response_validation_hook_failure_is_safe_and_response_backed(monkeypatch, op, kind):
    wire = _Wire(monkeypatch, _ok)
    flow = _flow(_HookFlow)
    flow.failing, flow.error = "validate_token_response", _marked(kind)
    error_type, run = OPERATIONS[op]
    with pytest.raises(error_type) as caught:
        run(flow)
    assert (caught.value.status_code, caught.value.error_code, caught.value.body) == (200, None, "")
    assert len(wire.requests) == 1 and all(c.is_closed for c in wire.clients)
    _assert_no_leaks(caught.value)


@operation
@pytest.mark.parametrize("kind", ["chained", "oserror"])
def test_request_parameter_hook_failure_is_safe_before_any_request(monkeypatch, op, kind):
    wire = _Wire(monkeypatch, _ok)
    flow = _flow(_HookFlow)
    flow.failing, flow.error = "token_parameters", _marked(kind)
    _, run = OPERATIONS[op]
    with pytest.raises(RuntimeError) as caught:
        run(flow)
    assert not hasattr(caught.value, "status_code")
    assert wire.requests == []
    _assert_no_leaks(caught.value)


@operation
@pytest.mark.parametrize("hook", ["token_parameters", "validate_token_response"])
def test_control_signals_are_not_sanitized(monkeypatch, op, hook):
    wire = _Wire(monkeypatch, _ok)
    flow = _flow(_HookFlow)
    flow.failing, flow.error = hook, KeyboardInterrupt()
    _, run = OPERATIONS[op]
    with pytest.raises(KeyboardInterrupt):
        run(flow)
    assert all(c.is_closed for c in wire.clients)


@pytest.mark.parametrize("failure", ["http", "success"])
def test_retained_logs_exclude_token_endpoint_secrets_and_success_is_unchanged(monkeypatch, caplog, failure):
    status = 400 if failure == "http" else 200
    _Wire(monkeypatch, lambda request: httpx.Response(
        status, headers=HEADERS,
        json={"error": "invalid_grant"} if status == 400 else
        {"access_token": "AT", "refresh_token": "RT", "expires_in": 3600},
    ))
    caplog.set_level(logging.DEBUG)
    flow = _flow()
    for error_type, run in OPERATIONS.values():
        if failure == "http":
            with pytest.raises(error_type):
                run(flow)
        else:
            tokens = run(flow)
            assert (tokens["access_token"], tokens["refresh_token"]) == ("AT", "RT")
    assert any("POST" in r.getMessage() for r in caplog.records)
    retained = "\n".join(f"{r.getMessage()} {r.args!r} {r.__dict__!r}" for r in caplog.records)
    for leak in LEAKS:
        assert leak not in retained


class _ProviderObject:
    """A bare OAuth2 provider protocol implementation, not a settings Profile."""

    NAME = "p"
    AUTHORIZE_URL = "https://a.example/authorize"
    TOKEN_URL = TOKEN_URL
    BASE_URL = "https://api.example"
    DEFAULT_SCOPE = None
    USE_PKCE = False
    CALLBACK_PORT = None

    def emit(self, target, *, base=None):
        return {}


class _UnknownMethodProvider(_ProviderObject):
    TOKEN_ENDPOINT_AUTH_METHOD = BODY


class _FailingConfigProvider(_ProviderObject):
    @property
    def TOKEN_REQUEST_HEADERS(self):
        raise OSError(errno.EIO, os.strerror(errno.EIO), BODY)


@operation
@pytest.mark.parametrize("provider, expected", [
    (_UnknownMethodProvider, ValueError), (_FailingConfigProvider, RuntimeError),
], ids=["unknown-auth-method", "native-config-failure"])
def test_request_preparation_failure_is_safe_before_any_request(monkeypatch, op, provider, expected):
    wire = _Wire(monkeypatch, _ok)
    _, run = OPERATIONS[op]
    try:
        raise RuntimeError(BODY)  # a caller's active exception must not become context
    except RuntimeError:
        with pytest.raises(expected) as caught:
            run(OAuthFlow(provider()))
    assert isinstance(caught.value, expected) and not isinstance(
        caught.value, (TokenExchangeError, TokenRefreshError),
    )
    assert not hasattr(caught.value, "status_code")
    assert caught.value.__context__ is None
    assert wire.requests == []
    _assert_no_leaks(caught.value)
