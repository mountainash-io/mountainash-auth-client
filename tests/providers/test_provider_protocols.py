from __future__ import annotations

from mountainash_auth_client.providers.protocols import (
    OAuth1ProviderProfileProtocol,
    OAuth2ProviderProfileProtocol,
    ProviderProfileProtocol,
)
from mountainash_auth_client.providers.oauth1 import OAuth1ProviderProfile
from mountainash_auth_client.providers.oauth2 import OAuth2ProviderProfile
from mountainash_auth_client.targets import TargetFamily


def _oauth2():
    return OAuth2ProviderProfile(
        NAME="p",
        AUTHORIZE_URL="https://auth/authorize",
        TOKEN_URL="https://auth/token",
        BASE_URL="https://api",
    )


def _oauth1():
    return OAuth1ProviderProfile(
        NAME="p",
        REQUEST_TOKEN_URL="https://auth/request",
        AUTHORIZE_URL="https://auth/authorize",
        ACCESS_TOKEN_URL="https://auth/access",
        BASE_URL="https://api",
    )


def test_oauth2_concrete_satisfies_refinement_and_base():
    p = _oauth2()
    assert isinstance(p, OAuth2ProviderProfileProtocol)
    assert isinstance(p, ProviderProfileProtocol)


def test_oauth1_concrete_satisfies_refinement_and_base():
    p = _oauth1()
    assert isinstance(p, OAuth1ProviderProfileProtocol)
    assert isinstance(p, ProviderProfileProtocol)


def test_base_protocol_is_minimal():
    # A provider with only NAME + emit satisfies the base but NOT the OAuth
    # refinements — proving the base is genuinely auth-method-agnostic.
    class _Dummy:
        NAME = "d"

        def emit(self, target, *, base=None):
            return {}

    d = _Dummy()
    assert isinstance(d, ProviderProfileProtocol)
    assert not isinstance(d, OAuth2ProviderProfileProtocol)
    assert not isinstance(d, OAuth1ProviderProfileProtocol)


def test_emit_http_returns_base_url():
    # Locks the resource-emit contract the connection relies on.
    assert _oauth2().emit(TargetFamily.HTTP) == {"base_url": "https://api"}
    assert _oauth1().emit(TargetFamily.HTTP) == {"base_url": "https://api"}


def test_protocols_exported_at_package_root():
    import mountainash_auth_client as ac
    from mountainash_auth_client import (
        OAuth1ProviderProfileProtocol,
        OAuth2ProviderProfileProtocol,
        ProviderProfileProtocol,
    )

    exported = {
        "ProviderProfileProtocol": ProviderProfileProtocol,
        "OAuth2ProviderProfileProtocol": OAuth2ProviderProfileProtocol,
        "OAuth1ProviderProfileProtocol": OAuth1ProviderProfileProtocol,
    }
    for name, obj in exported.items():
        assert name in ac.__all__
        assert getattr(ac, name) is obj
