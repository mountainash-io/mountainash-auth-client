"""Tests for the built-in callback servers."""

from __future__ import annotations

import errno
import socket

import pytest

import mountainash_auth_client.oauth.server.callback as cb
import mountainash_auth_client.oauth.server.manual as man
from mountainash_auth_client.oauth.protocols import CallbackServerProtocol
from mountainash_auth_client.oauth.server.callback import LocalCallbackServer
from mountainash_auth_client.oauth.server.manual import ManualCallbackServer
from mountainash_auth_client.errors import CallbackTimeoutError


@pytest.fixture
def local_server():
    server = LocalCallbackServer(port=0)
    try:
        yield server
    finally:
        server._server.server_close()


def _assert_port_available(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("localhost", port))


def test_local_conforms_to_protocol():
    s = LocalCallbackServer(port=0)
    try:
        assert isinstance(s, CallbackServerProtocol)
        assert isinstance(s.port, int)
        assert s.redirect_uri == f"http://localhost:{s.port}/callback"
    finally:
        s._server.server_close()


def test_obtain_callback_opens_browser_and_returns_params(monkeypatch, local_server):
    opened = []
    port = local_server.port

    def browser(url):
        opened.append(url)
        return True

    monkeypatch.setattr(cb.webbrowser, "open", browser)
    monkeypatch.setattr(local_server, "wait_for_callback", lambda: {"code": "abc", "state": "xyz"})
    result = local_server.obtain_callback("https://auth/authorize?x=1")
    assert opened == ["https://auth/authorize?x=1"]
    assert result == {"code": "abc", "state": "xyz"}
    _assert_port_available(port)


def test_obtain_callback_prints_url_when_no_browser(monkeypatch, capsys, local_server):
    port = local_server.port
    monkeypatch.setattr(cb.webbrowser, "open", lambda url: False)
    monkeypatch.setattr(local_server, "wait_for_callback", lambda: {"code": "abc"})
    result = local_server.obtain_callback("https://auth/SHOWME")
    assert result == {"code": "abc"}
    assert "https://auth/SHOWME" in capsys.readouterr().out
    _assert_port_available(port)


@pytest.mark.parametrize(
    ("stage", "error_type"),
    [
        pytest.param("browser", RuntimeError, id="browser-error"),
        pytest.param("print", OSError, id="fallback-output-error"),
        pytest.param("wait", CallbackTimeoutError, id="timeout"),
        pytest.param("browser", KeyboardInterrupt, id="interrupted"),
    ],
)
def test_obtain_callback_releases_port_on_failure(monkeypatch, local_server, stage, error_type):
    port = local_server.port
    with pytest.raises(OSError) as busy:
        _assert_port_available(port)
    assert busy.value.errno == errno.EADDRINUSE
    sentinel = error_type("synthetic callback failure")
    waited = []

    def browser(url):
        if stage == "browser":
            raise sentinel
        return stage != "print"

    def fail_print(*args, **kwargs):
        raise sentinel

    def wait():
        waited.append(True)
        if stage == "wait":
            raise sentinel
        raise AssertionError("presentation failed but waiting was entered")

    monkeypatch.setattr(cb.webbrowser, "open", browser)
    monkeypatch.setattr(local_server, "wait_for_callback", wait)
    if stage == "print":
        monkeypatch.setattr(cb, "print", fail_print, raising=False)
    with pytest.raises(error_type) as caught:
        local_server.obtain_callback("https://auth.example/authorize")
    assert caught.value is sentinel
    assert bool(waited) == (stage == "wait")
    _assert_port_available(port)


def test_wait_for_callback_times_out_with_callback_timeout_error():
    s = LocalCallbackServer(port=0, timeout=1)
    try:
        with pytest.raises(CallbackTimeoutError):
            s.wait_for_callback()
    finally:
        s._server.server_close()


def test_manual_conforms_and_defaults_to_oauth2_oob():
    s = ManualCallbackServer()
    assert isinstance(s, CallbackServerProtocol)
    assert s.port is None
    assert s.redirect_uri == "urn:ietf:wg:oauth:2.0:oob"


def test_manual_accepts_custom_redirect_uri():
    assert ManualCallbackServer(redirect_uri="oob").redirect_uri == "oob"


def test_manual_obtain_callback_delegates_to_prompt(monkeypatch):
    monkeypatch.setattr(man, "prompt_for_code", lambda url: {"code": "PASTED", "seen": url})
    out = ManualCallbackServer().obtain_callback("https://auth/q")
    assert out == {"code": "PASTED", "seen": "https://auth/q"}
