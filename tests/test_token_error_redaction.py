"""D4: token-error constructors retain only recognised protocol data; helper boundary."""
from __future__ import annotations

import errno
import json

import pytest

from mountainash_auth_client.errors import (
    TokenExchangeError,
    TokenRefreshError,
)
from tests._error_surfaces import exception_surfaces

KINDS = [TokenExchangeError, TokenRefreshError]
TOKEN_CODES = [
    "invalid_request",
    "invalid_client",
    "invalid_grant",
    "unauthorized_client",
    "unsupported_grant_type",
    "invalid_scope",
    "invalid_token",
]
URL = "https://user:USERINFO_SECRET@host:8443/token?key=QUERY_SECRET#FRAGMENT_SECRET"
MARKERS = ("USERINFO_SECRET", "QUERY_SECRET", "FRAGMENT_SECRET", "BODY_SECRET")


@pytest.mark.parametrize("kind", KINDS)
def test_constructor_retains_only_recognized_protocol_data(kind):
    error = kind(
        url=URL,
        status_code=400,
        body=json.dumps({"error": "invalid_grant", "error_description": "BODY_SECRET"}),
    )
    assert error.url == "https://host:8443/token"
    assert error.status_code == 400
    assert error.error_code == "invalid_grant"
    assert json.loads(error.body) == {"error": "invalid_grant"}
    observed = exception_surfaces(error)
    for marker in MARKERS:
        assert marker not in observed


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("code", TOKEN_CODES)
def test_every_recognized_code_is_preserved(kind, code):
    error = kind(url="https://host/token", status_code=400, body=json.dumps({"error": code}))
    assert error.error_code == code
    assert json.loads(error.body) == {"error": code}


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize(
    "body",
    [
        json.dumps({"error": "BODY_SECRET"}),
        json.dumps({"error": ["invalid_grant", "BODY_SECRET"]}),
        json.dumps({"error": {"invalid_grant": "BODY_SECRET"}}),
        json.dumps({"error": 400, "error_description": "BODY_SECRET"}),
        json.dumps({"error": None, "BODY_SECRET": "BODY_SECRET"}),
        json.dumps(["invalid_grant", "BODY_SECRET"]),
        json.dumps("BODY_SECRET"),
        json.dumps(7),
        '{"error": "invalid_grant", BODY_SECRET',
        "upstream 500 BODY_SECRET",
        "",
    ],
)
def test_unrecognized_or_malformed_body_is_discarded(kind, body):
    error = kind(url="https://host/token", status_code=500, body=body)
    assert error.error_code is None
    assert error.body == ""
    assert "BODY_SECRET" not in exception_surfaces(error)


@pytest.mark.parametrize("kind", KINDS)
def test_known_code_drops_extra_keys_and_description(kind):
    body = json.dumps(
        {
            "error": "invalid_client",
            "error_description": "BODY_SECRET",
            "access_token": "BODY_SECRET",
            "BODY_SECRET": 1,
        }
    )
    error = kind(url="https://host/token", status_code=401, body=body)
    assert error.error_code == "invalid_client"
    assert json.loads(error.body) == {"error": "invalid_client"}
    assert "BODY_SECRET" not in exception_surfaces(error)


# ---- private helper boundary (symbols imported lazily; run only after helper exists) ----

NATIVE_MARKER = "NATIVE_SECRET"


class _Marked(Exception):
    def __init__(self):
        super().__init__(NATIVE_MARKER)
        self.token = NATIVE_MARKER


def _os_error():
    return OSError(errno.ECONNREFUSED, "Connection refused", "/NATIVE_SECRET/a", None, "/NATIVE_SECRET/b")


def test_safe_cause_none_is_none():
    from mountainash_auth_client._safe_errors import safe_cause

    assert safe_cause(None) is None


def test_safe_cause_rebuilds_oserror_from_errno_and_strerror_only():
    from mountainash_auth_client._safe_errors import safe_cause

    native = _os_error()
    native.__cause__ = _Marked()
    cause = safe_cause(native)
    assert isinstance(cause, OSError)
    assert cause is not native
    assert cause.errno == errno.ECONNREFUSED
    assert cause.strerror == "Connection refused"
    assert cause.filename is None
    assert cause.filename2 is None
    assert cause.__cause__ is None
    assert cause.__context__ is None
    assert NATIVE_MARKER not in exception_surfaces(cause)


def test_safe_cause_errnoless_oserror_has_no_cause():
    from mountainash_auth_client._safe_errors import safe_cause

    assert safe_cause(OSError(NATIVE_MARKER)) is None


def test_safe_cause_non_listed_exception_has_no_cause():
    from mountainash_auth_client._safe_errors import safe_cause

    assert safe_cause(_Marked()) is None
    assert safe_cause(ValueError(NATIVE_MARKER)) is None


def test_safe_detail_reports_class_and_never_native_text():
    from mountainash_auth_client._safe_errors import safe_detail

    detail = safe_detail(_Marked())
    assert "_Marked" in detail
    assert NATIVE_MARKER not in detail
    os_detail = safe_detail(_os_error())
    assert "Connection refused" in os_detail
    assert NATIVE_MARKER not in os_detail


def test_raise_safe_clears_context_inside_unrelated_active_exception():
    from mountainash_auth_client._safe_errors import raise_safe

    error = RuntimeError("fixed")
    try:
        try:
            raise _Marked()
        except _Marked:
            raise_safe(error)
    except RuntimeError as caught:
        assert caught is error
        assert caught.__context__ is None
        assert caught.__cause__ is None
        assert NATIVE_MARKER not in exception_surfaces(caught)
    else:  # pragma: no cover
        pytest.fail("raise_safe did not raise")


def test_raise_safe_uses_fresh_permitted_cause_and_hides_marker():
    from mountainash_auth_client._safe_errors import raise_safe

    native = _os_error()
    with pytest.raises(RuntimeError) as info:
        raise_safe(RuntimeError("fixed"), native)
    cause = info.value.__cause__
    assert isinstance(cause, OSError)
    assert cause is not native
    assert cause.errno == errno.ECONNREFUSED
    assert info.value.__context__ is None
    assert NATIVE_MARKER not in exception_surfaces(info.value)


def test_raise_safe_non_listed_native_leaves_no_cause():
    from mountainash_auth_client._safe_errors import raise_safe

    with pytest.raises(RuntimeError) as info:
        raise_safe(RuntimeError("fixed"), _Marked())
    assert info.value.__cause__ is None
    assert info.value.__context__ is None
    assert NATIVE_MARKER not in exception_surfaces(info.value)


@pytest.mark.parametrize("kind", KINDS)
def test_existing_token_error_chained_from_native_is_reraised_clean(kind):
    from mountainash_auth_client.errors import _raise_token_failure

    existing = kind(url="https://host/token", status_code=400, body=json.dumps({"error": "invalid_grant"}))
    existing.__cause__ = _Marked()
    existing.__context__ = _Marked()
    with pytest.raises(kind) as info:
        _raise_token_failure(kind, url="https://host/token", status_code=None, native=existing)
    assert info.value.status_code == 400
    assert info.value.error_code == "invalid_grant"
    assert info.value.__cause__ is None
    assert info.value.__context__ is None
    assert NATIVE_MARKER not in exception_surfaces(info.value)


@pytest.mark.parametrize("kind", KINDS)
def test_native_failure_with_status_becomes_empty_body_token_error(kind):
    from mountainash_auth_client.errors import _raise_token_failure

    with pytest.raises(kind) as info:
        try:
            raise _Marked()
        except _Marked as native:
            _raise_token_failure(kind, url=URL, status_code=200, native=native)
    error = info.value
    assert error.status_code == 200
    assert error.url == "https://host:8443/token"
    assert error.error_code is None
    assert error.body == ""
    assert error.__cause__ is None
    assert error.__context__ is None
    observed = exception_surfaces(error)
    for marker in (*MARKERS, NATIVE_MARKER):
        assert marker not in observed
    assert any("_Marked" in note for note in getattr(error, "__notes__", []))


@pytest.mark.parametrize("kind", KINDS)
def test_native_failure_without_status_becomes_safe_runtime_error(kind):
    from mountainash_auth_client.errors import _raise_token_failure

    with pytest.raises(RuntimeError) as info:
        try:
            raise _Marked()
        except _Marked as native:
            _raise_token_failure(kind, url=URL, status_code=None, native=native)
    error = info.value
    assert not isinstance(error, (TokenExchangeError, TokenRefreshError))
    assert "https://host:8443/token" in str(error)
    assert "_Marked" in str(error)
    assert error.__cause__ is None
    assert error.__context__ is None
    observed = exception_surfaces(error)
    for marker in (*MARKERS, NATIVE_MARKER):
        assert marker not in observed


@pytest.mark.parametrize("kind", KINDS)
def test_native_oserror_without_status_keeps_only_fresh_cause(kind):
    from mountainash_auth_client.errors import _raise_token_failure

    native = _os_error()
    with pytest.raises(RuntimeError) as info:
        _raise_token_failure(kind, url=URL, status_code=None, native=native)
    cause = info.value.__cause__
    assert isinstance(cause, OSError)
    assert cause is not native
    assert (cause.errno, cause.strerror) == (errno.ECONNREFUSED, "Connection refused")
    assert info.value.__context__ is None
    observed = exception_surfaces(info.value)
    for marker in (*MARKERS, NATIVE_MARKER):
        assert marker not in observed
