"""Public surface for the callback-server feature."""
from __future__ import annotations

import mountainash_auth_client as pkg
from mountainash_auth_client.connections import (
    CallbackServerProtocol,
    ManualCallbackServer,
)


def test_package_root_exports():
    for name in (
        "CallbackServerProtocol",
        "ManualCallbackServer",
        "CallbackError",
        "AuthorizationDeniedError",
        "MalformedCallbackError",
        "CallbackTimeoutError",
    ):
        assert name in pkg.__all__, name
        assert hasattr(pkg, name), name


def test_connections_exports():
    assert CallbackServerProtocol is not None
    assert ManualCallbackServer is not None
