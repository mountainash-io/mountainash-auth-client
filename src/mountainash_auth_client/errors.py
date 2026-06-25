"""Auth-specific exceptions for mountainash-auth-client."""
from __future__ import annotations


class TokenExchangeError(Exception):
    """OAuth token endpoint returned an error during code exchange."""

    def __init__(self, *, url: str, status_code: int, body: str) -> None:
        self.url = url
        self.status_code = status_code
        self.body = body
        super().__init__(f"Token exchange failed: HTTP {status_code} POST {url} — {body[:200]}")


class TokenRefreshError(Exception):
    """OAuth token refresh failed."""

    def __init__(self, *, url: str, status_code: int, body: str) -> None:
        self.url = url
        self.status_code = status_code
        self.body = body
        super().__init__(f"Token refresh failed: HTTP {status_code} POST {url} — {body[:200]}")


class AuthorizationRequired(Exception):
    """No valid token exists and auto_authorize is False."""

    def __init__(self, *, provider: str, user: str) -> None:
        self.provider = provider
        self.user = user
        super().__init__(f"Authorization required for {provider}/{user}")


class CallbackError(Exception):
    """Base for failures while obtaining or validating an OAuth callback."""


class AuthorizationDeniedError(CallbackError):
    """The provider returned an OAuth2 ``error`` instead of an authorization code."""

    def __init__(self, *, error: str, description: str = "") -> None:
        self.error = error
        self.description = description
        message = f"Authorization denied: {error}"
        if description:
            message += f" — {description}"
        super().__init__(message)


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
