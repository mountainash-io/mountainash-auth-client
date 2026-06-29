"""Public surface for the callback-server feature."""
from __future__ import annotations

import mountainash_auth_client as pkg
from mountainash_auth_client.oauth import (
    CallbackServerProtocol,
    ManualCallbackServer,
)


def test_package_root_exports():
    for name in (
        "CallbackServerProtocol",
        "CallbackServerFactory",
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


def test_provider_profiles_and_oauth1_exported_at_root():
    import mountainash_auth_client as pkg

    for name in (
        "OAuth2ProviderProfile",
        "OAuth1ProviderProfile",
        "OAuth1Connection",
        "OAuth1Flow",
    ):
        assert name in pkg.__all__, name
        assert hasattr(pkg, name), name
