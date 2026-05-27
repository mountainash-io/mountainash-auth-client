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
