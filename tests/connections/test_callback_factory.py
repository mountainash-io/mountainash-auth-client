"""Tests for resolve_callback_factory precedence."""
from __future__ import annotations

from mountainash_auth_client.oauth.server.callback import LocalCallbackServer
from mountainash_auth_client.oauth.server.factory import resolve_callback_factory
from mountainash_auth_client.oauth.server.manual import ManualCallbackServer


def _explicit():
    return ManualCallbackServer(redirect_uri="EXPLICIT")


def _default():
    return ManualCallbackServer(redirect_uri="DEFAULT")


def test_per_call_callback_server_wins():
    f = resolve_callback_factory(
        redirect_mode="local_server", callback_server=_explicit,
        instance_default=_default, callback_port=None,
    )
    assert f().redirect_uri == "EXPLICIT"


def test_construction_default_beats_redirect_mode():
    f = resolve_callback_factory(
        redirect_mode="manual", callback_server=None,
        instance_default=_default, callback_port=None,
    )
    assert f().redirect_uri == "DEFAULT"


def test_manual_builtin_oauth2_default_urn():
    f = resolve_callback_factory(
        redirect_mode="manual", callback_server=None,
        instance_default=None, callback_port=None,
    )
    assert f().redirect_uri == "urn:ietf:wg:oauth:2.0:oob"


def test_manual_builtin_with_custom_oob():
    f = resolve_callback_factory(
        redirect_mode="manual", callback_server=None,
        instance_default=None, callback_port=None, manual_redirect_uri="oob",
    )
    assert f().redirect_uri == "oob"


def test_local_builtin_reads_metadata_port():
    f = resolve_callback_factory(
        redirect_mode="local_server", callback_server=None,
        instance_default=None, callback_port=0,
    )
    server = f()
    try:
        assert isinstance(server, LocalCallbackServer)
    finally:
        server._server.server_close()


def test_default_local_server_uses_callback_port():
    import mountainash_auth_client.oauth.server.factory as f

    captured = {}

    def fake_local(port=0):
        captured["port"] = port
        return object()

    import unittest.mock as m
    with m.patch.object(f, "LocalCallbackServer", fake_local):
        factory = f.resolve_callback_factory(
            redirect_mode="local_server",
            callback_server=None,
            instance_default=None,
            callback_port=8923,
        )
        factory()
    assert captured["port"] == 8923


def test_default_local_server_port_zero_when_none():
    import mountainash_auth_client.oauth.server.factory as f

    captured = {}

    def fake_local(port=0):
        captured["port"] = port
        return object()

    import unittest.mock as m
    with m.patch.object(f, "LocalCallbackServer", fake_local):
        f.resolve_callback_factory(
            redirect_mode="local_server",
            callback_server=None,
            instance_default=None,
            callback_port=None,
        )()
    assert captured["port"] == 0
