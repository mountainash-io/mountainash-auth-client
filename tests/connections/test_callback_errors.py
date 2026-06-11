"""Tests for the OAuth callback error taxonomy."""
from __future__ import annotations

from mountainash_auth_client.errors import (
    AuthorizationDeniedError,
    CallbackError,
    CallbackTimeoutError,
    MalformedCallbackError,
)


def test_denied_is_callback_error_and_carries_fields():
    e = AuthorizationDeniedError(error="access_denied", description="user declined")
    assert isinstance(e, CallbackError)
    assert e.error == "access_denied"
    assert e.description == "user declined"
    assert "access_denied" in str(e)
    assert "user declined" in str(e)


def test_denied_without_description():
    e = AuthorizationDeniedError(error="access_denied")
    assert e.description == ""
    assert "access_denied" in str(e)


def test_malformed_is_callback_error():
    assert isinstance(MalformedCallbackError("missing code"), CallbackError)


def test_timeout_is_callback_error_and_builtin_timeout():
    e = CallbackTimeoutError("no callback in time")
    assert isinstance(e, CallbackError)
    assert isinstance(e, TimeoutError)
