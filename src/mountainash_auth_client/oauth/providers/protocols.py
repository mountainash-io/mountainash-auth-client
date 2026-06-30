"""Runtime-checkable provider-profile contracts.

`ProviderProfileProtocol` is the structural minimum every provider profile
satisfies regardless of auth method: a `NAME` (for labels/logging) and a
target-parametric `emit`. It does NOT promise that `emit(TargetFamily.HTTP)`
returns HTTP-ready kwargs — that is a per-target precondition a connection states
of the providers it accepts (which is why `BASE_URL` lives on the HTTP-provider
refinements, not the base).

`runtime_checkable` checks member *presence* only (names, not types/signatures),
matching the ecosystem convention (the secrets capability protocols, the storage
protocols): structural conformance is asserted by tests, not promised by
`isinstance`.
"""
from __future__ import annotations

import typing as t

__all__ = [
    "ProviderProfileProtocol",
    "OAuth2ProviderProfileProtocol",
    "OAuth1ProviderProfileProtocol",
]


@t.runtime_checkable
class ProviderProfileProtocol(t.Protocol):
    """Resource-coordinate contract shared by every provider profile."""

    NAME: str

    # `target` is required at the protocol level; the concrete `Profile.emit`
    # supplies a default for internal convenience. Callers always pass a target.
    def emit(
        self, target: t.Hashable, *, base: dict[str, t.Any] | None = None
    ) -> dict[str, t.Any]: ...


@t.runtime_checkable
class OAuth2ProviderProfileProtocol(ProviderProfileProtocol, t.Protocol):
    """An OAuth2 authorization-code provider: base contract + auth-server URLs."""

    AUTHORIZE_URL: str
    TOKEN_URL: str
    BASE_URL: str
    DEFAULT_SCOPE: str | None
    USE_PKCE: bool
    CALLBACK_PORT: int | None


@t.runtime_checkable
class OAuth1ProviderProfileProtocol(ProviderProfileProtocol, t.Protocol):
    """An OAuth1 provider: base contract + the three-legged handshake URLs."""

    REQUEST_TOKEN_URL: str
    AUTHORIZE_URL: str
    ACCESS_TOKEN_URL: str
    BASE_URL: str
    CALLBACK_PORT: int | None
