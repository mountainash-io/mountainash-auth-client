"""Tests for the built-in callback servers."""
from __future__ import annotations

import pytest

import mountainash_auth_client.oauth.server.callback as cb
from mountainash_auth_client.oauth.protocols import CallbackServerProtocol
from mountainash_auth_client.oauth.server.callback import LocalCallbackServer
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


import mountainash_auth_client.oauth.server.manual as man
from mountainash_auth_client.oauth.server.manual import ManualCallbackServer


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
