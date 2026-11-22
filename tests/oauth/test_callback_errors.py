"""Tests for the OAuth callback error taxonomy and D4 denial allow-list."""
from __future__ import annotations

import pytest

from mountainash_auth_client.errors import (
    AuthorizationDeniedError,
    CallbackError,
    CallbackTimeoutError,
    MalformedCallbackError,
)
from tests._error_surfaces import exception_surfaces

AUTHORIZATION_CODES = [
    "invalid_request",
    "unauthorized_client",
    "access_denied",
    "unsupported_response_type",
    "invalid_scope",
    "server_error",
    "temporarily_unavailable",
]


@pytest.mark.parametrize("code", AUTHORIZATION_CODES)
def test_denied_keeps_recognized_code_and_drops_description(code):
    e = AuthorizationDeniedError(error=code, description="DESC_SECRET")
    assert isinstance(e, CallbackError)
    assert e.error == code
    assert e.description == ""
    assert code in str(e)
    assert "DESC_SECRET" not in exception_surfaces(e)


@pytest.mark.parametrize(
    "bad",
    ["ERROR_SECRET", "invalid_grant", "ACCESS_DENIED", "", "access_denied ", None, 7, ["access_denied"]],
)
def test_denied_unknown_code_becomes_unknown_error(bad):
    e = AuthorizationDeniedError(error=bad, description="DESC_SECRET")
    assert e.error == "unknown_error"
    assert e.description == ""
    observed = exception_surfaces(e)
    assert "ERROR_SECRET" not in observed
    assert "DESC_SECRET" not in observed


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
