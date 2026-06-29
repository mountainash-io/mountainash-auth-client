"""Typed OAuth token status model + OAuth2 expiry classifier."""
from __future__ import annotations

import enum
import time
from dataclasses import dataclass

from mountainash_auth_client.schemas.token import _decode_jwt_claims
from mountainash_auth_client.errors import MalformedJWTError

__all__ = ["TokenState", "TokenStatus", "classify_oauth2", "jwt_exp"]


class TokenState(str, enum.Enum):
    VALID = "valid"                    # present, outside the refresh buffer
    REFRESH_NEEDED = "refresh_needed"  # present, inside the buffer, not past expiry
    EXPIRED = "expired"                # present, at/past expiry
    MISSING = "missing"                # no record
    CLEARED = "cleared"                # explicitly revoked (tombstone)
    PRESENT = "present"                # OAuth1 only — non-expiring pair exists


@dataclass(frozen=True)
class TokenStatus:
    state: TokenState
    expires_at: int | None = None
    expires_in_seconds: int | None = None
    has_refresh_token: bool = False


def jwt_exp(access_token: str) -> int | None:
    """Best-effort `exp` from a JWT access token; None for opaque tokens or missing exp."""
    try:
        v = _decode_jwt_claims(access_token).get("exp")
    except MalformedJWTError:
        return None
    return int(v) if v is not None else None


def classify_oauth2(
    record: dict | None,
    *,
    buffer_seconds: int = 300,
    now: float | None = None,
) -> TokenStatus:
    """Classify an OAuth2 token record. `now` is injectable for tests.

    Buffer-aligned with the flow's is_expired(buffer=300) so status() and the
    flow's refresh decision agree at the boundary.
    """
    if record is None:
        return TokenStatus(TokenState.MISSING)
    has_refresh = bool(record.get("refresh_token"))
    expires_at = record.get("token_expires_at")
    if expires_at is None:
        return TokenStatus(TokenState.VALID, expires_at=None, has_refresh_token=has_refresh)
    current = time.time() if now is None else now
    if current >= expires_at:
        return TokenStatus(
            TokenState.EXPIRED, expires_at=expires_at, has_refresh_token=has_refresh
        )
    expires_in = int(expires_at - current)
    if current >= expires_at - buffer_seconds:
        return TokenStatus(
            TokenState.REFRESH_NEEDED,
            expires_at=expires_at,
            expires_in_seconds=expires_in,
            has_refresh_token=has_refresh,
        )
    return TokenStatus(
        TokenState.VALID,
        expires_at=expires_at,
        expires_in_seconds=expires_in,
        has_refresh_token=has_refresh,
    )
