"""Tests for the built-in callback servers."""
from __future__ import annotations

import pytest

import mountainash_auth_client.connections.server.callback as cb
from mountainash_auth_client.connections.protocols import CallbackServerProtocol
from mountainash_auth_client.connections.server.callback import LocalCallbackServer
from mountainash_auth_client.errors import CallbackTimeoutError


def test_local_conforms_to_protocol():
    s = LocalCallbackServer(port=0)
    try:
        assert isinstance(s, CallbackServerProtocol)
        assert isinstance(s.port, int)
        assert s.redirect_uri == f"http://localhost:{s.port}/callback"
    finally:
        s._server.server_close()


def test_obtain_callback_opens_browser_and_returns_params(monkeypatch):
    s = LocalCallbackServer(port=0)
    opened = {}
    monkeypatch.setattr(cb.webbrowser, "open", lambda url: opened.setdefault("url", url) or True)
    monkeypatch.setattr(s, "wait_for_callback", lambda: {"code": "abc", "state": "xyz"})
    result = s.obtain_callback("https://auth/authorize?x=1")
    assert opened["url"] == "https://auth/authorize?x=1"
    assert result == {"code": "abc", "state": "xyz"}


def test_obtain_callback_prints_url_when_no_browser(monkeypatch, capsys):
    s = LocalCallbackServer(port=0)
    monkeypatch.setattr(cb.webbrowser, "open", lambda url: False)
    monkeypatch.setattr(s, "wait_for_callback", lambda: {"code": "abc"})
    s.obtain_callback("https://auth/SHOWME")
    assert "https://auth/SHOWME" in capsys.readouterr().out


def test_obtain_callback_closes_socket_on_failure(monkeypatch):
    s = LocalCallbackServer(port=0)
    monkeypatch.setattr(cb.webbrowser, "open", lambda url: True)

    def boom():
        raise CallbackTimeoutError("nope")

    monkeypatch.setattr(s, "wait_for_callback", boom)
    calls = {"n": 0}
    real_close = s._server.server_close

    def counting_close():
        calls["n"] += 1
        real_close()

    monkeypatch.setattr(s._server, "server_close", counting_close)
    with pytest.raises(CallbackTimeoutError):
        s.obtain_callback("https://auth/x")
    assert calls["n"] >= 1


def test_wait_for_callback_times_out_with_callback_timeout_error():
    s = LocalCallbackServer(port=0, timeout=1)
    try:
        with pytest.raises(CallbackTimeoutError):
            s.wait_for_callback()
    finally:
        s._server.server_close()
