"""Normalized token results and explicit persisted-JSON boundaries."""
from __future__ import annotations
from copy import deepcopy
from typing import TYPE_CHECKING, NotRequired, TypedDict, cast

if TYPE_CHECKING:
    from collections.abc import Mapping

from mountainash_settings.secrets import JSONValue, SecretRecord


class OAuth1Tokens(TypedDict):
    oauth_token: str
    oauth_token_secret: str


class OAuth2Tokens(TypedDict):
    access_token: str
    refresh_token: NotRequired[str | None]
    token_expires_at: NotRequired[int | None]
    scope: NotRequired[str | None]
    client_id: NotRequired[str | None]
    registration: NotRequired[dict[str, JSONValue]]
    session_metadata: NotRequired[dict[str, JSONValue]]


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


def _optional_string(record: SecretRecord, field: str) -> str | None:
    value = record.get(field)
    return None if value is None else token_string(value, field=field)


def _metadata(record: SecretRecord, field: str) -> dict[str, JSONValue]:
    value = record.get(field, {})
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError(f"Invalid OAuth token record field: {field}")
    return deepcopy(value)


def read_oauth2_record(record: SecretRecord) -> OAuth2Tokens:
    """Narrow consumed members without changing the stored record."""
    return {
        "access_token": token_string(record.get("access_token", ""), field="access_token"),
        "refresh_token": _optional_string(record, "refresh_token"),
        "token_expires_at": token_expiry(record.get("token_expires_at")),
        "scope": _optional_string(record, "scope"),
        "client_id": _optional_string(record, "client_id"),
        "registration": _metadata(record, "registration"),
        "session_metadata": _metadata(record, "session_metadata"),
    }


def token_record(tokens: Mapping[str, object]) -> SecretRecord:
    """Copy normalized token results into the store's JSON dictionary."""
    record: SecretRecord = {}
    for field, value in tokens.items():
        if value is not None and not isinstance(value, (str, int, float, bool, list, dict)):
            raise ValueError(f"Invalid OAuth token record field: {field}")
        # The selected settings store validates nested JSON at its write boundary.
        record[field] = deepcopy(cast("JSONValue", value))
    return record


