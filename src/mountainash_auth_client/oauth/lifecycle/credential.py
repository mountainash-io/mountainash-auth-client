"""TokenCredential — the frozen token *output* of the OAuth2 acquisition seam.

A typed view of the token-store record (keys access_token / token_expires_at /
refresh_token). NOT a persisted credential schema — live token state is ops-managed
(Phase 2 evicted TOKEN_EXPIRES_AT from the schema). token_type is synthesized Bearer
(the record carries no token_type; these flows are Bearer-only).
"""
from __future__ import annotations

import dataclasses
from dataclasses import field
from typing import TYPE_CHECKING

from mountainash_auth_client.oauth.records import read_oauth2_record

if TYPE_CHECKING:
    from mountainash_settings.secrets import JSONValue, SecretRecord


@dataclasses.dataclass(frozen=True)
class TokenCredential:
    access_token: str = field(repr=False)
    token_type: str = "Bearer"
    expires_at: int | None = None
    refresh_token: str | None = field(default=None, repr=False)
    client_id: str | None = None
    scope: str | None = None
    registration: dict[str, JSONValue] = field(default_factory=dict, repr=False)
    session_metadata: dict[str, JSONValue] = field(default_factory=dict, repr=False)

    @classmethod
    def from_record(cls, record: SecretRecord) -> "TokenCredential":
        tokens = read_oauth2_record(record)
        return cls(
            access_token=tokens["access_token"],
            expires_at=tokens.get("token_expires_at"),
            refresh_token=tokens.get("refresh_token"),
            client_id=tokens.get("client_id"),
            scope=tokens.get("scope"),
            registration=tokens.get("registration", {}),
            session_metadata=tokens.get("session_metadata", {}),
        )


@dataclasses.dataclass(frozen=True)
class SignOutResult:
    """Local clearing completed; remote confirmation is a separate outcome."""

    remote_confirmed: bool
