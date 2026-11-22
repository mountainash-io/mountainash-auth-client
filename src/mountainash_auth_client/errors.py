"""Auth-specific exceptions for mountainash-auth-client."""
from __future__ import annotations

import json as _json
import typing as t

from ._safe_errors import raise_safe as _raise_safe
from ._safe_errors import safe_detail as _safe_detail
from ._safe_errors import safe_location as _safe_location


_TOKEN_CODES = frozenset(
    {
        "invalid_request",
        "invalid_client",
        "invalid_grant",
        "unauthorized_client",
        "unsupported_grant_type",
        "invalid_scope",
        "invalid_token",
    }
)
_AUTHORIZATION_CODES = frozenset(
    {
        "invalid_request",
        "unauthorized_client",
        "access_denied",
        "unsupported_response_type",
        "invalid_scope",
        "server_error",
        "temporarily_unavailable",
    }
)


def _recognized_token_code(raw: object) -> str | None:
    """Parse a token-endpoint payload once; return only a recognised ``error`` code."""
    if isinstance(raw, (str, bytes)):
        try:
            raw = _json.loads(raw)
        except ValueError:
            return None
    if not isinstance(raw, dict):
        return None
    code = raw.get("error")
    return code if isinstance(code, str) and code in _TOKEN_CODES else None


def safe_error_body(raw: object) -> str:
    """Reduce a token-endpoint error payload to its recognised ``error`` code as JSON, else ``""``."""
    code = _recognized_token_code(raw)
    return "" if code is None else _json.dumps({"error": code})


class _TokenError(Exception):
    _operation = ""

    def __init__(self, *, url: str, status_code: int, body: str) -> None:
        self.url = _safe_location(url)
        self.status_code = status_code
        self.error_code = _recognized_token_code(body)
        self.body = "" if self.error_code is None else _json.dumps({"error": self.error_code})
        super().__init__(f"{self._operation} failed: HTTP {status_code} POST {self.url}")


class TokenExchangeError(_TokenError):
    """OAuth token endpoint returned an error during code exchange."""

    _operation = "Token exchange"


class TokenRefreshError(_TokenError):
    """OAuth token refresh failed."""

    _operation = "Token refresh"


def _raise_token_failure(
    error_type: type[_TokenError],
    *,
    url: str,
    status_code: int | None,
    native: BaseException,
) -> t.NoReturn:
    """Raise the safe form of *native* for a token operation; call inside its ``except``."""
    if type(native) in (TokenExchangeError, TokenRefreshError):
        _raise_safe(native)
    if status_code is not None:
        error = error_type(url=url, status_code=status_code, body="")
        error.add_note(_safe_detail(native))
        _raise_safe(error, native)
    _raise_safe(
        RuntimeError(
            f"{error_type._operation} failed at {_safe_location(url)}: {_safe_detail(native)}"
        ),
        native,
    )


class AuthorizationRequired(Exception):
    """No valid token exists and auto_authorize is False."""

    def __init__(self, *, provider: str, user: str) -> None:
        self.provider = provider
        self.user = user
        super().__init__(f"Authorization required for {provider}/{user}")


class CallbackError(Exception):
    """Base for failures while obtaining or validating an OAuth callback."""


class AuthorizationCancelled(CallbackError):
    """A pending authorization was superseded by local session clearing."""

    def __init__(self, *, remote_confirmed: bool) -> None:
        self.remote_confirmed = remote_confirmed
        super().__init__("Authorization cancelled by session clearing")


class AuthorizationDeniedError(CallbackError):
    """The provider returned an OAuth2 ``error`` instead of an authorization code."""

    def __init__(self, *, error: str, description: str = "") -> None:
        # Provider prose is never retained; only a recognised authorization-response code.
        self.error = error if isinstance(error, str) and error in _AUTHORIZATION_CODES else "unknown_error"
        self.description = ""
        super().__init__(f"Authorization denied: {self.error}")


class MalformedCallbackError(CallbackError):
    """Callback passed CSRF/state validation but is missing a required parameter."""


class CallbackTimeoutError(CallbackError, TimeoutError):
    """No OAuth callback was received before the deadline.

    Subclasses the builtin ``TimeoutError`` so existing ``except TimeoutError``
    handlers keep working while callers can also catch ``CallbackError``.
    """


class MalformedJWTError(Exception):
    """A token expected to be a compact JWS was not three base64url segments / did not decode."""

    def __init__(self, *, reason: str) -> None:
        self.reason = reason
        super().__init__(f"Malformed JWT: {reason}")
