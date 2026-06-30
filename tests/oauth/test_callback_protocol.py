"""Tests for CallbackServerProtocol conformance."""
from __future__ import annotations

from mountainash_auth_client.oauth.protocols import CallbackServerProtocol


class _Conforming:
    @property
    def port(self) -> int | None:
        return 1234

    @property
    def redirect_uri(self) -> str:
        return "http://localhost:1234/callback"

    def obtain_callback(self, authorize_url: str) -> dict[str, str]:
        return {"code": "abc"}


class _Incomplete:
    @property
    def redirect_uri(self) -> str:
        return "x"


def test_conforming_instance_passes_isinstance():
    assert isinstance(_Conforming(), CallbackServerProtocol)


def test_incomplete_instance_fails_isinstance():
    assert not isinstance(_Incomplete(), CallbackServerProtocol)
