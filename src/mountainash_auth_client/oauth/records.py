"""Normalized token results and explicit persisted-JSON boundaries."""
from __future__ import annotations

from typing import TYPE_CHECKING, NotRequired, TypedDict

if TYPE_CHECKING:
    from collections.abc import Mapping
    from mountainash_settings.secrets import SecretRecord


class OAuth1Tokens(TypedDict):
    oauth_token: str
    oauth_token_secret: str


class OAuth2Tokens(TypedDict):
    access_token: str
    refresh_token: NotRequired[str | None]
    token_expires_at: NotRequired[int | None]
    scope: NotRequired[str | None]


def token_string(value: object, *, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"Invalid OAuth token record field: {field}")
    return value


def token_expiry(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("Invalid OAuth token record field: token_expires_at")
    return value


def read_oauth2_record(record: SecretRecord) -> OAuth2Tokens:
    """Narrow consumed members without changing the stored record.

    An absent access token stays empty for the caller's acquisition guard.
    Absent/null refresh credentials are valid for access-only records.
    """
    access = token_string(record.get("access_token", ""), field="access_token")
    refresh = record.get("refresh_token")
    return {
        "access_token": access,
        "refresh_token": None if refresh is None else token_string(refresh, field="refresh_token"),
        "token_expires_at": token_expiry(record.get("token_expires_at")),
    }


def token_record(tokens: Mapping[str, object]) -> SecretRecord:
    """Copy flat normalized token results into the store's JSON dictionary."""
    record: SecretRecord = {}
    for field, value in tokens.items():
        if value is not None and not isinstance(value, (str, int)):
            raise ValueError(f"Invalid OAuth token record field: {field}")
        record[field] = value
    return record
